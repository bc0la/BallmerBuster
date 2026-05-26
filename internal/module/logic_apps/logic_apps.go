package logic_apps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module scans Logic App run history for secrets exposed through unsecured
// action inputs/outputs and checks for HTTP triggers without access control.
type Module struct{}

func (Module) Name() string      { return "logic_apps" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Logic/workflows/read",
		"Microsoft.Logic/workflows/runs/read",
		"Microsoft.Logic/workflows/runs/actions/read",
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
		_ = sink.LogEvent(ctx, "logic_apps", target.SubscriptionID, level, msg)
	}
	emit := func(f findings.Finding) {
		f.SubscriptionID = target.SubscriptionID
		f.Module = "logic_apps"
		_ = sink.Write(ctx, f)
	}

	log("info", "starting Logic Apps scan for subscription "+target.SubscriptionID)

	// 1. List all Logic App workflows.
	workflows, err := listWorkflows(ctx, target.Credential, target.SubscriptionID)
	if err != nil {
		return fmt.Errorf("logic_apps: list workflows: %w", err)
	}

	log("info", fmt.Sprintf("found %d Logic App workflows", len(workflows)))

	for i, wf := range workflows {
		wfName := wf.Name
		wfID := wf.ID
		wfLocation := wf.Location

		log("info", fmt.Sprintf("workflow %d/%d: %s", i+1, len(workflows), wfName))

		// Check workflow triggers for open HTTP triggers.
		checkTriggers(ctx, target.Credential, wfID, wfName, wfLocation, emit, log)

		// 2. Get recent run history (last 5 runs).
		runs, err := listRuns(ctx, target.Credential, wfID)
		if err != nil {
			log("warn", fmt.Sprintf("list runs for %s: %v", wfName, err))
			continue
		}

		log("info", fmt.Sprintf("  %d recent runs", len(runs)))

		// 3. For each run, get actions and scan inputs/outputs.
		for _, run := range runs {
			actions, err := listRunActions(ctx, target.Credential, run.ID)
			if err != nil {
				log("warn", fmt.Sprintf("list actions for run %s: %v", run.Name, err))
				continue
			}

			for _, action := range actions {
				// 4. Fetch and scan input/output content for secrets.
				scanActionLink(ctx, action.InputsLinkURI, "inputs", wfName, wfLocation, wfID, action.Name, emit)
				scanActionLink(ctx, action.OutputsLinkURI, "outputs", wfName, wfLocation, wfID, action.Name, emit)
			}
		}
	}

	log("info", "Logic Apps scan complete")
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

type workflow struct {
	ID       string
	Name     string
	Location string
	State    string
	// AccessControl from workflow definition properties.
	AccessControl *accessControl
}

type accessControl struct {
	Triggers *accessControlEntry `json:"triggers"`
}

type accessControlEntry struct {
	AllowedCallerIPAddresses []any `json:"allowedCallerIpAddresses"`
}

type run struct {
	ID   string
	Name string
}

type action struct {
	Name           string
	InputsLinkURI  string
	OutputsLinkURI string
}

// ---------------------------------------------------------------------------
// Listing helpers
// ---------------------------------------------------------------------------

func listWorkflows(ctx context.Context, cred azcore.TokenCredential, subID string) ([]workflow, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Logic/workflows?api-version=2019-05-01", subID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		return nil, err
	}

	var workflows []workflow
	for _, r := range raw {
		var w struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
			Props    struct {
				State         string         `json:"state"`
				AccessControl *accessControl `json:"accessControl"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(r, &w); err != nil {
			continue
		}
		workflows = append(workflows, workflow{
			ID:            w.ID,
			Name:          w.Name,
			Location:      w.Location,
			State:         w.Props.State,
			AccessControl: w.Props.AccessControl,
		})
	}
	return workflows, nil
}

func listRuns(ctx context.Context, cred azcore.TokenCredential, workflowID string) ([]run, error) {
	url := fmt.Sprintf("https://management.azure.com%s/runs?api-version=2019-05-01&$top=5", workflowID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		return nil, err
	}

	var runs []run
	for _, r := range raw {
		var entry struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(r, &entry); err != nil {
			continue
		}
		runs = append(runs, run{ID: entry.ID, Name: entry.Name})
	}
	return runs, nil
}

func listRunActions(ctx context.Context, cred azcore.TokenCredential, runID string) ([]action, error) {
	url := fmt.Sprintf("https://management.azure.com%s/actions?api-version=2019-05-01", runID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		return nil, err
	}

	var actions []action
	for _, r := range raw {
		var entry struct {
			Name  string `json:"name"`
			Props struct {
				InputsLink  *linkInfo `json:"inputsLink"`
				OutputsLink *linkInfo `json:"outputsLink"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(r, &entry); err != nil {
			continue
		}
		a := action{Name: entry.Name}
		if entry.Props.InputsLink != nil {
			a.InputsLinkURI = entry.Props.InputsLink.URI
		}
		if entry.Props.OutputsLink != nil {
			a.OutputsLinkURI = entry.Props.OutputsLink.URI
		}
		actions = append(actions, a)
	}
	return actions, nil
}

type linkInfo struct {
	URI string `json:"uri"`
}

// ---------------------------------------------------------------------------
// Trigger access control check
// ---------------------------------------------------------------------------

func checkTriggers(ctx context.Context, cred azcore.TokenCredential, workflowID, wfName, wfLocation string,
	emit func(findings.Finding), log func(string, string)) {

	url := fmt.Sprintf("https://management.azure.com%s/triggers?api-version=2019-05-01", workflowID)
	raw, err := armList(ctx, cred, url)
	if err != nil {
		log("warn", fmt.Sprintf("list triggers for %s: %v", wfName, err))
		return
	}

	for _, r := range raw {
		var trigger struct {
			Name  string `json:"name"`
			Props struct {
				Type string `json:"type"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(r, &trigger); err != nil {
			continue
		}

		// Only flag HTTP request triggers.
		if !strings.EqualFold(trigger.Props.Type, "Request") {
			continue
		}

		// Check the parent workflow's accessControl property.
		// We need to check if access control is configured at the workflow level.
		hasAccessControl := false
		var wfDef struct {
			Props struct {
				AccessControl *accessControl `json:"accessControl"`
			} `json:"properties"`
		}
		wfURL := fmt.Sprintf("https://management.azure.com%s?api-version=2019-05-01", workflowID)
		if err := armGet(ctx, cred, wfURL, &wfDef); err == nil {
			if wfDef.Props.AccessControl != nil && wfDef.Props.AccessControl.Triggers != nil {
				hasAccessControl = true
			}
		}

		if !hasAccessControl {
			emit(findings.Finding{
				Region:     wfLocation,
				Severity:   findings.SevMedium,
				ResourceID: workflowID,
				Title:      fmt.Sprintf("Logic App %q has HTTP trigger %q without access control", wfName, trigger.Name),
				Detail: map[string]any{
					"workflow_name":  wfName,
					"trigger_name":   trigger.Name,
					"trigger_type":   "Request",
					"access_control": "none",
					"reason":         "HTTP trigger has no IP restrictions — anyone with the URL can invoke the workflow",
				},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Secret scanning of action inputs/outputs
// ---------------------------------------------------------------------------

func scanActionLink(ctx context.Context, uri, direction, wfName, wfLocation, wfID, actionName string,
	emit func(findings.Finding)) {

	if uri == "" {
		return
	}

	// The inputsLink/outputsLink URIs are SAS-signed blob URLs —
	// fetch directly without ARM auth.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	content := string(body)

	// Scan for secret patterns in the content.
	for _, sp := range secretPatterns {
		if sp.pattern.MatchString(content) {
			emit(findings.Finding{
				Region:     wfLocation,
				Severity:   findings.SevHigh,
				ResourceID: wfID,
				Title: fmt.Sprintf("Logic App %q action %q %s contain secret (%s pattern)",
					wfName, actionName, direction, sp.name),
				Detail: map[string]any{
					"workflow_name":   wfName,
					"action_name":    actionName,
					"direction":      direction,
					"pattern_matched": sp.name,
				},
			})
			// Report each pattern only once per action+direction.
		}
	}

	// Also check for suspicious key names in JSON content.
	if secretKeyPattern.MatchString(content) {
		emit(findings.Finding{
			Region:     wfLocation,
			Severity:   findings.SevMedium,
			ResourceID: wfID,
			Title: fmt.Sprintf("Logic App %q action %q %s contain suspicious key names",
				wfName, actionName, direction),
			Detail: map[string]any{
				"workflow_name": wfName,
				"action_name":  actionName,
				"direction":    direction,
				"reason":       "action data contains keys matching secret name patterns",
			},
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
