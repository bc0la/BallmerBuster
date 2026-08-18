package devops_secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module scans Azure DevOps pipeline variable groups and build definitions for
// plaintext secrets — the Azure equivalent of scanning CodeBuild env vars.
type Module struct{}

func (Module) Name() string      { return "devops_secrets" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{} // uses DevOps REST API, no ARM permissions required
}

// ---------------------------------------------------------------------------
// Secret-detection patterns
// ---------------------------------------------------------------------------

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN .* PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ`)},
	{"Slack Token", regexp.MustCompile(`xox[bprs]-[0-9a-zA-Z-]+`)},
	{"Connection String", regexp.MustCompile(`(?i)(Server|Data Source|AccountKey|SharedAccessSignature)=`)},
	{"Azure Storage Key", regexp.MustCompile(`(?i)[a-zA-Z0-9/+]{86}==`)},
}

var secretKeyPattern = regexp.MustCompile(`(?i)(password|secret|token|api[_-]?key|connection[_-]?string|private[_-]?key|credentials?|account[_-]?key)`)

// ---------------------------------------------------------------------------
// Azure DevOps scope and helper
// ---------------------------------------------------------------------------

const devopsScope = "499b84ac-1321-427f-aa17-267ca6975798/.default"

func devopsGet(ctx context.Context, cred azcore.TokenCredential, url string, result any) error {
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{devopsScope},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("devops API %s: %d %s", url, resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(result)
}

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

type profileResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type accountsResponse struct {
	Value []struct {
		AccountID   string `json:"accountId"`
		AccountName string `json:"accountName"`
	} `json:"value"`
}

type projectsResponse struct {
	Value []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"value"`
}

type variableGroupsResponse struct {
	Value []variableGroup `json:"value"`
}

type variableGroup struct {
	ID        int                        `json:"id"`
	Name      string                     `json:"name"`
	Variables map[string]variablePayload `json:"variables"`
}

type variablePayload struct {
	Value    *string `json:"value"`
	IsSecret bool    `json:"isSecret"`
}

type buildDefinitionsResponse struct {
	Value []buildDefinition `json:"value"`
}

type buildDefinition struct {
	ID        int                        `json:"id"`
	Name      string                     `json:"name"`
	Variables map[string]variablePayload `json:"variables"`
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	// 1. Get authenticated user's profile.
	var profile profileResponse
	err := devopsGet(ctx, target.Credential,
		"https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1",
		&profile)
	if err != nil {
		_ = sink.LogEvent(ctx, "devops_secrets", target.SubscriptionID, "warn",
			fmt.Sprintf("cannot reach Azure DevOps profile API (user may lack DevOps access): %v", err))
		return nil
	}

	// 2. List organizations for this user.
	var accounts accountsResponse
	err = devopsGet(ctx, target.Credential,
		fmt.Sprintf("https://app.vssps.visualstudio.com/_apis/accounts?memberId=%s&api-version=7.1", profile.ID),
		&accounts)
	if err != nil {
		_ = sink.LogEvent(ctx, "devops_secrets", target.SubscriptionID, "warn",
			fmt.Sprintf("cannot list Azure DevOps organizations: %v", err))
		return nil
	}

	if len(accounts.Value) == 0 {
		_ = sink.LogEvent(ctx, "devops_secrets", target.SubscriptionID, "info",
			"no Azure DevOps organizations found for authenticated user")
		return nil
	}

	_ = sink.LogEvent(ctx, "devops_secrets", target.SubscriptionID, "info",
		fmt.Sprintf("discovered %d Azure DevOps organization(s)", len(accounts.Value)))

	for _, org := range accounts.Value {
		orgName := org.AccountName

		// 3. List projects in the organization.
		var projects projectsResponse
		err = devopsGet(ctx, target.Credential,
			fmt.Sprintf("https://dev.azure.com/%s/_apis/projects?api-version=7.1", orgName),
			&projects)
		if err != nil {
			_ = sink.LogEvent(ctx, "devops_secrets", target.SubscriptionID, "warn",
				fmt.Sprintf("org %s: cannot list projects: %v", orgName, err))
			continue
		}

		_ = sink.LogEvent(ctx, "devops_secrets", target.SubscriptionID, "info",
			fmt.Sprintf("org %s: scanning %d project(s)", orgName, len(projects.Value)))

		for _, proj := range projects.Value {
			scanVariableGroups(ctx, target, sink, orgName, proj.Name)
			scanBuildDefinitions(ctx, target, sink, orgName, proj.Name)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Variable groups
// ---------------------------------------------------------------------------

func scanVariableGroups(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink, orgName, projectName string) {
	var groups variableGroupsResponse
	err := devopsGet(ctx, target.Credential,
		fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/distributedtask/variablegroups?api-version=7.1", orgName, projectName),
		&groups)
	if err != nil {
		_ = sink.LogEvent(ctx, "devops_secrets", target.SubscriptionID, "warn",
			fmt.Sprintf("org %s / project %s: cannot list variable groups: %v", orgName, projectName, err))
		return
	}

	for _, vg := range groups.Value {
		resourceID := fmt.Sprintf("/devops/%s/%s/variablegroups/%d", orgName, projectName, vg.ID)
		scanVariables(ctx, target, sink, orgName, projectName, vg.Name, resourceID, vg.Variables)
	}
}

// ---------------------------------------------------------------------------
// Build definitions
// ---------------------------------------------------------------------------

func scanBuildDefinitions(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink, orgName, projectName string) {
	var defs buildDefinitionsResponse
	err := devopsGet(ctx, target.Credential,
		fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/build/definitions?api-version=7.1", orgName, projectName),
		&defs)
	if err != nil {
		_ = sink.LogEvent(ctx, "devops_secrets", target.SubscriptionID, "warn",
			fmt.Sprintf("org %s / project %s: cannot list build definitions: %v", orgName, projectName, err))
		return
	}

	for _, def := range defs.Value {
		resourceID := fmt.Sprintf("/devops/%s/%s/definitions/%d", orgName, projectName, def.ID)
		scanVariables(ctx, target, sink, orgName, projectName, def.Name, resourceID, def.Variables)
	}
}

// ---------------------------------------------------------------------------
// Shared variable scanner
// ---------------------------------------------------------------------------

func scanVariables(
	ctx context.Context,
	target creds.SubscriptionTarget,
	sink findings.Sink,
	orgName, projectName, sourceName, resourceID string,
	vars map[string]variablePayload,
) {
	for varName, v := range vars {
		// isSecret == true means the value is redacted — nothing to flag.
		if v.IsSecret {
			continue
		}

		value := ""
		if v.Value != nil {
			value = *v.Value
		}
		if value == "" {
			continue
		}

		// Check value against concrete secret patterns (High).
		if patName := matchSecretPattern(value); patName != "" {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         "global",
				Module:         "devops_secrets",
				Severity:       findings.SevHigh,
				ResourceID:     resourceID,
				Title: fmt.Sprintf("DevOps %s/%s variable %q in %q matches secret pattern (%s)",
					orgName, projectName, varName, sourceName, patName),
				Detail: map[string]any{
					"check":           "secret_pattern",
					"organization":    orgName,
					"project":         projectName,
					"source":          sourceName,
					"variable_name":   varName,
					"pattern_matched": patName,
					"resource_id":     resourceID,
					"value":           value,
				},
			})
			continue
		}

		// Check variable name against suspicious key pattern (Medium).
		if secretKeyPattern.MatchString(varName) {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         "global",
				Module:         "devops_secrets",
				Severity:       findings.SevMedium,
				ResourceID:     resourceID,
				Title: fmt.Sprintf("DevOps %s/%s variable %q in %q has suspicious name (plaintext, not marked secret)",
					orgName, projectName, varName, sourceName),
				Detail: map[string]any{
					"check":         "suspicious_name",
					"organization":  orgName,
					"project":       projectName,
					"source":        sourceName,
					"variable_name": varName,
					"reason":        "key name matches secret pattern and value is plaintext (not marked isSecret)",
					"resource_id":   resourceID,
					"value":         value,
				},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func matchSecretPattern(value string) string {
	for _, sp := range secretPatterns {
		if sp.pattern.MatchString(value) {
			return sp.name
		}
	}
	return ""
}
