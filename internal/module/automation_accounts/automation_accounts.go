package automation_accounts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module scans Azure Automation Accounts for secrets exposure in variables,
// runbook source code, job output, and connection configurations.
type Module struct{}

func (Module) Name() string      { return "automation_accounts" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Automation/automationAccounts/read",
		"Microsoft.Automation/automationAccounts/variables/read",
		"Microsoft.Automation/automationAccounts/runbooks/read",
		"Microsoft.Automation/automationAccounts/jobs/read",
	}
}

// Secret-detection patterns compiled once at package level.
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

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	log := func(level, msg string) {
		_ = sink.LogEvent(ctx, "automation_accounts", target.SubscriptionID, level, msg)
	}
	emit := func(f findings.Finding) {
		f.SubscriptionID = target.SubscriptionID
		f.Module = "automation_accounts"
		_ = sink.Write(ctx, f)
	}

	log("info", "starting Automation Accounts scan for subscription "+target.SubscriptionID)

	// 1. List all Automation Accounts.
	accounts, err := listAccounts(ctx, target.Credential, target.SubscriptionID)
	if err != nil {
		return fmt.Errorf("automation_accounts: list accounts: %w", err)
	}

	log("info", fmt.Sprintf("found %d Automation Accounts", len(accounts)))

	for i, acct := range accounts {
		acctName := acct.Name
		acctID := acct.ID
		acctLocation := acct.Location

		log("info", fmt.Sprintf("account %d/%d: %s", i+1, len(accounts), acctName))

		// a. Check variables.
		checkVariables(ctx, target.Credential, acctID, acctName, acctLocation, emit, log)

		// b. Check credentials (informational).
		checkCredentials(ctx, target.Credential, acctID, acctName, acctLocation, emit, log)

		// c. Check runbook source code.
		checkRunbooks(ctx, target.Credential, sink, target.SubscriptionID, acctID, acctName, acctLocation, emit, log)

		// d. Check recent job output.
		checkJobs(ctx, target.Credential, sink, target.SubscriptionID, acctID, acctName, acctLocation, emit, log)

		// e. Check connections.
		checkConnections(ctx, target.Credential, acctID, acctName, acctLocation, emit, log)
	}

	log("info", "Automation Accounts scan complete")
	return nil
}

// ---------------------------------------------------------------------------
// ARM REST helpers
// ---------------------------------------------------------------------------

func armGet(ctx context.Context, cred azcore.TokenCredential, url string, result any) error {
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
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
		return fmt.Errorf("ARM API %s: %d %s", url, resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(result)
}

// armGetRaw fetches a URL with ARM auth and returns the raw response body as
// text. Used for endpoints that return non-JSON content (runbook source,
// job output).
func armGetRaw(ctx context.Context, cred azcore.TokenCredential, url string) (string, error) {
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ARM API %s: %d %s", url, resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// armList paginates an ARM REST API endpoint using nextLink.
func armList(ctx context.Context, cred azcore.TokenCredential, url string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	for url != "" {
		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"nextLink"`
		}
		if err := armGet(ctx, cred, url, &page); err != nil {
			return all, err
		}
		all = append(all, page.Value...)
		url = page.NextLink
	}
	return all, nil
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

type account struct {
	ID       string
	Name     string
	Location string
}

// ---------------------------------------------------------------------------
// Listing helpers
// ---------------------------------------------------------------------------

func listAccounts(ctx context.Context, cred azcore.TokenCredential, subID string) ([]account, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01", subID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		return nil, err
	}

	var accounts []account
	for _, r := range raw {
		var a struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		}
		if err := json.Unmarshal(r, &a); err != nil {
			continue
		}
		accounts = append(accounts, account{ID: a.ID, Name: a.Name, Location: a.Location})
	}
	return accounts, nil
}

// ---------------------------------------------------------------------------
// Check a — Variables
// ---------------------------------------------------------------------------

func checkVariables(ctx context.Context, cred azcore.TokenCredential,
	acctID, acctName, acctLocation string,
	emit func(findings.Finding), log func(string, string)) {

	url := fmt.Sprintf("https://management.azure.com%s/variables?api-version=2023-11-01", acctID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		log("warn", fmt.Sprintf("list variables for %s: %v", acctName, err))
		return
	}

	for _, r := range raw {
		var v struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Props struct {
				IsEncrypted bool   `json:"isEncrypted"`
				Value       string `json:"value"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(r, &v); err != nil {
			continue
		}

		if v.Props.IsEncrypted {
			continue // encrypted variables are fine
		}

		// Check if the unencrypted value matches concrete secret patterns.
		if v.Props.Value != "" {
			if patName := matchSecretPattern(v.Props.Value); patName != "" {
				emit(findings.Finding{
					Region:     acctLocation,
					Severity:   findings.SevHigh,
					ResourceID: v.ID,
					Title: fmt.Sprintf("Automation Account %q unencrypted variable %q matches secret pattern (%s)",
						acctName, v.Name, patName),
					Detail: map[string]any{
						"account_name":    acctName,
						"variable_name":   v.Name,
						"is_encrypted":    false,
						"pattern_matched": patName,
						"value":           v.Props.Value,
					},
				})
				continue // don't double-report
			}
		}

		// Check if the variable name looks like a secret.
		if secretKeyPattern.MatchString(v.Name) {
			emit(findings.Finding{
				Region:     acctLocation,
				Severity:   findings.SevMedium,
				ResourceID: v.ID,
				Title: fmt.Sprintf("Automation Account %q has unencrypted variable %q with suspicious name",
					acctName, v.Name),
				Detail: map[string]any{
					"account_name":  acctName,
					"variable_name": v.Name,
					"is_encrypted":  false,
					"reason":        "variable name matches secret key pattern but is not encrypted",
					"value":         v.Props.Value,
				},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Check b — Credentials (informational)
// ---------------------------------------------------------------------------

func checkCredentials(ctx context.Context, cred azcore.TokenCredential,
	acctID, acctName, acctLocation string,
	emit func(findings.Finding), log func(string, string)) {

	url := fmt.Sprintf("https://management.azure.com%s/credentials?api-version=2023-11-01", acctID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		log("warn", fmt.Sprintf("list credentials for %s: %v", acctName, err))
		return
	}

	if len(raw) == 0 {
		return
	}

	var credNames []string
	for _, r := range raw {
		var c struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(r, &c); err != nil {
			continue
		}
		credNames = append(credNames, c.Name)
	}

	emit(findings.Finding{
		Region:     acctLocation,
		Severity:   findings.SevInfo,
		ResourceID: acctID,
		Title: fmt.Sprintf("Automation Account %q has %d stored credentials",
			acctName, len(credNames)),
		Detail: map[string]any{
			"account_name":     acctName,
			"credential_count": len(credNames),
			"credential_names": credNames,
		},
	})
}

// ---------------------------------------------------------------------------
// Check c — Runbooks
// ---------------------------------------------------------------------------

func checkRunbooks(ctx context.Context, cred azcore.TokenCredential,
	sink findings.Sink, subID, acctID, acctName, acctLocation string,
	emit func(findings.Finding), log func(string, string)) {

	url := fmt.Sprintf("https://management.azure.com%s/runbooks?api-version=2023-11-01", acctID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		log("warn", fmt.Sprintf("list runbooks for %s: %v", acctName, err))
		return
	}

	log("info", fmt.Sprintf("  %d runbooks in %s", len(raw), acctName))

	for _, r := range raw {
		var rb struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(r, &rb); err != nil {
			continue
		}

		contentURL := fmt.Sprintf("https://management.azure.com%s/runbooks/%s/content?api-version=2023-11-01", acctID, rb.Name)
		content, err := armGetRaw(ctx, cred, contentURL)
		if err != nil {
			log("warn", fmt.Sprintf("get runbook content %s/%s: %v", acctName, rb.Name, err))
			continue
		}

		// Save raw content to RawDir for manual review.
		if rawDir, err := sink.RawDir("automation_accounts", subID); err == nil {
			outPath := filepath.Join(rawDir, fmt.Sprintf("runbook-%s-%s.txt", acctName, rb.Name))
			_ = os.WriteFile(outPath, []byte(content), 0o600)
		}

		// Scan each line for secret patterns.
		lines := strings.Split(content, "\n")
		for lineNum, line := range lines {
			for _, sp := range secretPatterns {
				if sp.pattern.MatchString(line) {
					emit(findings.Finding{
						Region:     acctLocation,
						Severity:   findings.SevHigh,
						ResourceID: rb.ID,
						Title: fmt.Sprintf("Runbook %s/%s contains secret at line %d (%s pattern)",
							acctName, rb.Name, lineNum+1, sp.name),
						Detail: map[string]any{
							"account_name":    acctName,
							"runbook_name":    rb.Name,
							"line_number":     lineNum + 1,
							"pattern_matched": sp.name,
							"content":         line,
						},
					})
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Check d — Jobs
// ---------------------------------------------------------------------------

func checkJobs(ctx context.Context, cred azcore.TokenCredential,
	sink findings.Sink, subID, acctID, acctName, acctLocation string,
	emit func(findings.Finding), log func(string, string)) {

	url := fmt.Sprintf("https://management.azure.com%s/jobs?api-version=2023-11-01&$top=10", acctID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		log("warn", fmt.Sprintf("list jobs for %s: %v", acctName, err))
		return
	}

	log("info", fmt.Sprintf("  %d recent jobs in %s", len(raw), acctName))

	for _, r := range raw {
		var job struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(r, &job); err != nil {
			continue
		}

		runbookName := resolveRunbookName(r)

		outputURL := fmt.Sprintf("https://management.azure.com%s/output?api-version=2023-11-01", job.ID)
		output, err := armGetRaw(ctx, cred, outputURL)
		if err != nil {
			// Job output may not exist — skip gracefully.
			continue
		}

		if output == "" {
			continue
		}

		// Save raw output to RawDir for manual review.
		if rawDir, err := sink.RawDir("automation_accounts", subID); err == nil {
			outPath := filepath.Join(rawDir, fmt.Sprintf("job-%s-%s.txt", acctName, job.Name))
			_ = os.WriteFile(outPath, []byte(output), 0o600)
		}

		// Scan output for secret patterns.
		for _, sp := range secretPatterns {
			if sp.pattern.MatchString(output) {
				emit(findings.Finding{
					Region:     acctLocation,
					Severity:   findings.SevHigh,
					ResourceID: job.ID,
					Title: fmt.Sprintf("Job output %s/%s contains secret (%s pattern)",
						acctName, job.Name, sp.name),
					Detail: map[string]any{
						"account_name":    acctName,
						"job_id":          job.Name,
						"runbook_name":    runbookName,
						"pattern_matched": sp.name,
						"content":         output,
					},
				})
			}
		}
	}
}

// resolveRunbookName extracts the runbook name from a job's JSON properties.
// The API may return it as a nested object or a string.
func resolveRunbookName(raw json.RawMessage) string {
	var nested struct {
		Props struct {
			Runbook struct {
				Name string `json:"name"`
			} `json:"runbook"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &nested); err == nil && nested.Props.Runbook.Name != "" {
		return nested.Props.Runbook.Name
	}
	return ""
}

// ---------------------------------------------------------------------------
// Check e — Connections
// ---------------------------------------------------------------------------

// cloudConnectionTypes lists connection type names that indicate cloud provider
// access and warrant informational flagging.
var cloudConnectionTypes = map[string]bool{
	"azureserviceprincipal":    true,
	"azureclassiccertificate":  true,
	"azureclassicrunasaccount": true,
	"azure":                    true,
	"azurerm":                  true,
}

func checkConnections(ctx context.Context, cred azcore.TokenCredential,
	acctID, acctName, acctLocation string,
	emit func(findings.Finding), log func(string, string)) {

	url := fmt.Sprintf("https://management.azure.com%s/connections?api-version=2023-11-01", acctID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		log("warn", fmt.Sprintf("list connections for %s: %v", acctName, err))
		return
	}

	for _, r := range raw {
		var conn struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Props struct {
				ConnectionType struct {
					Name string `json:"name"`
				} `json:"connectionType"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(r, &conn); err != nil {
			continue
		}

		connTypeName := strings.ToLower(conn.Props.ConnectionType.Name)
		if cloudConnectionTypes[connTypeName] {
			emit(findings.Finding{
				Region:     acctLocation,
				Severity:   findings.SevInfo,
				ResourceID: conn.ID,
				Title: fmt.Sprintf("Automation Account %q has cloud provider connection %q (type: %s)",
					acctName, conn.Name, conn.Props.ConnectionType.Name),
				Detail: map[string]any{
					"account_name":    acctName,
					"connection_name": conn.Name,
					"connection_type": conn.Props.ConnectionType.Name,
				},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// matchSecretPattern returns the name of the first matching pattern, or "".
func matchSecretPattern(value string) string {
	for _, sp := range secretPatterns {
		if sp.pattern.MatchString(value) {
			return sp.name
		}
	}
	return ""
}

func resourceGroup(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func ptrVal[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
