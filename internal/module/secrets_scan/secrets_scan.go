// Package secrets_scan collects text from the Azure locations where secrets are
// most often stored insecurely (VM user data, App Service settings, container
// env vars, ARM deployment history, Automation runbooks, Logic App definitions,
// and Blob Storage object contents) and feeds it all through kingfisher for
// detection. It is the Azure counterpart of BezosBuster's secrets_scan and, like
// it, coexists with the native regex scanners (function_app_env, aci_env, …) —
// kingfisher's rule set is far broader, and the blob sweep reaches file contents
// nothing else scans.
package secrets_scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

type Module struct{}

func init() { module.Register(Module{}) }

func (Module) Name() string      { return "secrets_scan" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Compute/virtualMachines/read",
		"Microsoft.Compute/virtualMachines/extensions/read",
		"Microsoft.Web/sites/read",
		"Microsoft.Web/sites/config/list/action",
		"Microsoft.ContainerInstance/containerGroups/read",
		"Microsoft.Resources/deployments/read",
		"Microsoft.Automation/automationAccounts/read",
		"Microsoft.Automation/automationAccounts/variables/read",
		"Microsoft.Automation/automationAccounts/runbooks/read",
		"Microsoft.Logic/workflows/read",
		"Microsoft.Storage/storageAccounts/read",
		"Microsoft.Storage/storageAccounts/blobServices/containers/read",
	}
}

// sample is a piece of text collected from an Azure source to scan for secrets.
type sample struct {
	Source   string
	Region   string
	Content  string
	Metadata map[string]string
}

// kfFinding matches kingfisher's nested JSON output structure.
type kfFinding struct {
	Rule    kfRule   `json:"rule"`
	Finding kfDetail `json:"finding"`
}

type kfRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type kfDetail struct {
	Snippet    string       `json:"snippet"`
	Path       string       `json:"path"`
	Line       int          `json:"line"`
	Confidence string       `json:"confidence"`
	Validation kfValidation `json:"validation"`
}

type kfValidation struct {
	Status string `json:"status"`
}

// kfReport is one document of kingfisher's --format json output. Findings is a
// RawMessage rather than []kfFinding because kingfisher emits the findings report
// ({"findings":[...]}) AND a trailing run summary that reuses the key as a count
// ({"findings":<number>,...}); decoding straight into a slice trips on the
// number. parseKingfisherJSON inspects the raw value and only harvests the array
// form.
type kfReport struct {
	Findings json.RawMessage `json:"findings"`
}

// parseKingfisherJSON extracts findings from kingfisher's (possibly multi-
// document) JSON output. It streams every document but only harvests the one
// whose "findings" is a JSON array; the summary document (a number) is skipped
// rather than logged as a decode error. Hard decode failures are returned as
// warning strings so the caller can surface them without aborting the scan.
func parseKingfisherJSON(out []byte) (all []kfFinding, warnings []string) {
	dec := json.NewDecoder(bytes.NewReader(out))
	docIdx := 0
	for dec.More() {
		var report kfReport
		if err := dec.Decode(&report); err != nil {
			off := int(dec.InputOffset())
			snippet := ""
			if off < len(out) {
				end := off + 200
				if end > len(out) {
					end = len(out)
				}
				snippet = string(out[off:end])
			}
			warnings = append(warnings, fmt.Sprintf(
				"kingfisher JSON decode error at doc %d offset %d: %s — next bytes: %q",
				docIdx, off, err.Error(), snippet))
			break
		}
		docIdx++
		raw := bytes.TrimSpace(report.Findings)
		if len(raw) == 0 || raw[0] != '[' {
			continue
		}
		var fs []kfFinding
		if err := json.Unmarshal(raw, &fs); err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"kingfisher: could not parse findings array in doc %d: %s", docIdx-1, err.Error()))
			continue
		}
		all = append(all, fs...)
	}
	return all, warnings
}

func (Module) Run(ctx context.Context, t creds.SubscriptionTarget, sink findings.Sink) error {
	kfPath, err := exec.LookPath("kingfisher")
	if err != nil {
		// Degrade gracefully: warn and skip rather than fail the scan. Install
		// kingfisher (https://github.com/mongodb/kingfisher) and put it on PATH,
		// or run the other secrets modules with --no-secrets-scan.
		_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "warn",
			"kingfisher not on PATH — skipping secrets_scan (install kingfisher and put it on PATH, or pass --no-secrets-scan)")
		return nil
	}

	// --- Phase 1: Collect non-blob samples concurrently ---
	type namedCollector struct {
		name string
		fn   func(ctx context.Context, t creds.SubscriptionTarget) []sample
	}
	collectors := []namedCollector{
		{"VM user data", collectVMUserData},
		{"VM Scale Sets", collectVMSS},
		{"App Service settings", collectAppServiceEnv},
		{"App Service code", collectAppServiceCode},
		{"Container Instances", collectACIEnv},
		{"ARM deployments", collectARMDeployments},
		{"Deployment Scripts", collectDeploymentScripts},
		{"Automation accounts", collectAutomation},
		{"Logic Apps", collectLogicApps},
		{"App Configuration", collectAppConfig},
		{"API Management named values", collectAPIM},
	}
	// Log Analytics is the most expensive/noisy source (it queries workspace
	// data-plane records), so it is opt-in via --secrets-log-analytics.
	if ctx.Value("bb.log_analytics") != nil {
		collectors = append(collectors, namedCollector{"Log Analytics", collectLogAnalytics})
	} else {
		_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
			"Log Analytics collection skipped (enable with --secrets-log-analytics)")
	}

	var mu sync.Mutex
	var allSamples []sample
	var wg sync.WaitGroup
	var doneCount int

	// Optional per-collector timeout from context.
	var timeoutMins int
	if v, ok := ctx.Value("bb.secrets_collector_timeout_mins").(int); ok {
		timeoutMins = v
	}

	for _, c := range collectors {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
				fmt.Sprintf("collecting: %s", c.name))

			collectCtx := ctx
			var cancel context.CancelFunc
			if timeoutMins > 0 {
				collectCtx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMins)*time.Minute)
				defer cancel()
			}

			samples := c.fn(collectCtx, t)
			mu.Lock()
			allSamples = append(allSamples, samples...)
			doneCount++
			done := doneCount
			mu.Unlock()
			timedOut := ""
			if collectCtx.Err() == context.DeadlineExceeded {
				timedOut = " (timed out — partial results kept)"
			}
			_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
				fmt.Sprintf("collected %d samples from %s (%d/%d collectors done)%s",
					len(samples), c.name, done, len(collectors), timedOut))
		}()
	}
	wg.Wait()

	_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
		fmt.Sprintf("collected %d total non-blob samples", len(allSamples)))

	if len(allSamples) > 0 {
		_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
			fmt.Sprintf("running kingfisher on %d non-blob samples", len(allSamples)))
		scanSamples(ctx, kfPath, allSamples, t, sink)
		_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info", "kingfisher non-blob scan complete")
	}

	// --- Phase 2: Blob Storage — scan per-container with cleanup ---
	if ctx.Value("bb.no_blob") != nil {
		_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info", "Blob scan skipped (--no-blob)")
	} else {
		_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info", "starting Blob Storage scan")
		scanBlobPerContainer(ctx, kfPath, t, sink)
	}

	return nil
}

// scanSamples writes samples to a temp dir, runs kingfisher, emits findings, cleans up.
func scanSamples(ctx context.Context, kfPath string, samples []sample, t creds.SubscriptionTarget, sink findings.Sink) {
	tmpDir, err := os.MkdirTemp("", "bb-secrets-*")
	if err != nil {
		return
	}
	defer os.RemoveAll(tmpDir)

	fileMap := map[string]*sample{}
	for i := range samples {
		s := &samples[i]
		safe := strings.ReplaceAll(s.Source, "/", "__")
		safe = strings.ReplaceAll(safe, ":", "_")
		fname := fmt.Sprintf("%04d_%s.txt", i, safe)
		fpath := filepath.Join(tmpDir, fname)
		if err := os.WriteFile(fpath, []byte(s.Content), 0600); err != nil {
			continue
		}
		fileMap[fname] = s
	}

	kfFindings := runKingfisher(ctx, kfPath, tmpDir, "non_blob", t, sink)
	emitFindings(kfFindings, fileMap, tmpDir, t, sink, ctx.Value("bb.redact_secrets") == nil)
}

// saveRawOutput writes kingfisher's raw output to
// <engagement>/secrets_scan/<subscription>/<phase>.json.
func saveRawOutput(phase string, out []byte, t creds.SubscriptionTarget, sink findings.Sink) {
	rawDir, err := sink.RawDir("secrets_scan", t.SubscriptionID)
	if err != nil {
		return
	}
	safe := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' {
			return '_'
		}
		return r
	}, phase)
	path := filepath.Join(rawDir, safe+".json")
	_ = os.WriteFile(path, out, 0600)
}

func runKingfisher(ctx context.Context, kfPath, dir, phase string, t creds.SubscriptionTarget, sink findings.Sink) []kfFinding {
	cmd := exec.CommandContext(ctx, kfPath, "scan", dir,
		"--format", "json",
		"--git-history", "none",
		"--no-validate",
	)

	tickDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-tickDone:
				return
			case <-ticker.C:
				_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
					fmt.Sprintf("kingfisher %s: still scanning… (%s elapsed)",
						phase, time.Since(start).Truncate(time.Second)))
			}
		}
	}()

	out, err := cmd.Output()
	close(tickDone)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 200 && exitErr.ExitCode() != 205 {
				_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "warn",
					fmt.Sprintf("kingfisher exit %d: %s", exitErr.ExitCode(), string(exitErr.Stderr)))
			}
			if len(out) == 0 {
				out = exitErr.Stderr
			}
		} else {
			return nil
		}
	}

	if len(out) > 0 {
		saveRawOutput(phase, out, t, sink)
	}

	all, warnings := parseKingfisherJSON(out)
	for _, w := range warnings {
		_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "warn", w)
	}
	_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
		fmt.Sprintf("kingfisher found %d findings, %d total bytes", len(all), len(out)))
	return all
}

// emitFindings writes one report finding per kingfisher hit. unredact defaults to
// true: the full secret value is stored so it's usable straight from the report
// UI, and the file that hit is copied into the engagement dir (see saveHitFile)
// with the finding's RawOutputPath pointing at it. Pass --redact-secrets to keep
// only a short redacted preview and skip saving files.
func emitFindings(kfFindings []kfFinding, fileMap map[string]*sample, tmpDir string, t creds.SubscriptionTarget, sink findings.Sink, unredact bool) {
	ctx := context.Background()
	for _, f := range kfFindings {
		fname := filepath.Base(f.Finding.Path)
		s, ok := fileMap[fname]
		if !ok {
			continue
		}

		sev := findings.SevHigh
		if strings.EqualFold(f.Finding.Validation.Status, "valid") {
			sev = findings.SevCritical
		} else if strings.EqualFold(f.Finding.Confidence, "low") {
			sev = findings.SevMedium
		}

		region := s.Region
		if region == "" {
			region = "global"
		}

		title := fmt.Sprintf("[%s] %s in %s", f.Rule.ID, f.Rule.Name, s.Source)
		match := redactMatch(f.Finding.Snippet)
		if unredact {
			match = f.Finding.Snippet
		}

		// The sample Source is "<sourcetype>/<resource>" (e.g. "appservice_env/app",
		// "blob/account/container/key"). Expose the leading source-type as a
		// filterable check facet, namespaced "kf:" so the report UI keeps
		// kingfisher hits visually distinct from the native secrets modules.
		sourceType := s.Source
		if i := strings.IndexByte(sourceType, '/'); i >= 0 {
			sourceType = sourceType[:i]
		}

		detail := map[string]any{
			"rule_id":     f.Rule.ID,
			"rule_name":   f.Rule.Name,
			"match":       match,
			"source":      s.Source,
			"source_type": sourceType,
			"check":       "kf:" + sourceType,
			"line":        f.Finding.Line,
			"confidence":  f.Finding.Confidence,
			"validation":  f.Finding.Validation.Status,
		}
		for k, v := range s.Metadata {
			detail[k] = v
		}

		// Command to re-fetch the raw resource by hand, so the finding is
		// actionable straight from the report.
		if cmd := pullCommand(sourceType, s.Metadata); cmd != "" {
			detail["pull_command"] = cmd
		}

		var rawOut string
		if unredact {
			if saved := saveHitFile(filepath.Join(tmpDir, fname), s.Source, t, sink); saved != "" {
				detail["saved_file"] = saved
				rawOut = filepath.Dir(saved)
			}
		}

		_ = sink.Write(ctx, findings.Finding{
			SubscriptionID: t.SubscriptionID,
			Region:         region,
			Module:         "secrets_scan",
			Severity:       sev,
			ResourceID:     s.Metadata["id"],
			Title:          title,
			Detail:         detail,
			RawOutputPath:  rawOut,
		})
	}
}

// saveHitFile copies a file kingfisher flagged into a browsable location under
// the engagement dir: <engagement>/secrets_scan/<subscription>/hits/<source>,
// where <source> is the sample Source (e.g. "blob/account/container/key")
// preserved as a nested path. Returns the destination path, or "" on any failure
// (best-effort).
//
// Sources are not always unique (e.g. two extensions on one VM); to avoid one
// hit clobbering another, an identical existing file is reused, otherwise the
// next free "<name>-N" suffix is chosen.
func saveHitFile(srcPath, source string, t creds.SubscriptionTarget, sink findings.Sink) string {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return ""
	}
	rawDir, err := sink.RawDir("secrets_scan", t.SubscriptionID)
	if err != nil {
		return ""
	}
	rel := sanitizeSourcePath(source)
	if rel == "" {
		return ""
	}
	base := filepath.Join(rawDir, "hits", rel)
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		return ""
	}
	dest := base
	for i := 2; ; i++ {
		existing, rerr := os.ReadFile(dest)
		if os.IsNotExist(rerr) {
			break
		}
		if rerr == nil && bytes.Equal(existing, data) {
			return dest
		}
		dest = fmt.Sprintf("%s-%d", base, i)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return ""
	}
	return dest
}

// sanitizeSourcePath turns a sample Source into a safe relative path, keeping "/"
// as directory separators but dropping empty/"."/".." segments (no traversal)
// and neutralising ":" / "\".
func sanitizeSourcePath(source string) string {
	repl := strings.NewReplacer(":", "_", "\\", "_")
	var clean []string
	for _, p := range strings.Split(source, "/") {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			continue
		}
		clean = append(clean, repl.Replace(p))
	}
	return filepath.Join(clean...)
}

// pullCommand returns an az CLI command that re-fetches the raw resource a
// kingfisher hit came from, so an analyst can pull the full object by hand.
// Returns "" for source types we can't reconstruct a command for.
func pullCommand(sourceType string, meta map[string]string) string {
	id := meta["id"]
	rg := meta["rg"]
	switch sourceType {
	case "vm_userdata":
		return "az vm show --ids " + id + " --include-user-data --query 'userData' -o tsv | base64 -d"
	case "vm_ext":
		return "az vm extension show --vm-name " + meta["vm"] + " -g " + rg + " -n " + meta["ext"] + " --query 'settings'"
	case "vmss_userdata":
		return "az vmss show --name " + meta["vmss"] + " -g " + rg + " --include-user-data --query 'virtualMachineProfile.userData' -o tsv | base64 -d"
	case "vmss_ext":
		return "az vmss extension show --vmss-name " + meta["vmss"] + " -g " + rg + " -n " + meta["ext"] + " --query 'settings'"
	case "appservice_env":
		return "az webapp config appsettings list -n " + meta["app"] + " -g " + rg
	case "appservice_connstr":
		return "az webapp config connection-string list -n " + meta["app"] + " -g " + rg
	case "appservice_code":
		return "az webapp deploy --name " + meta["app"] + " -g " + rg + " --type zip  # or: curl -H \"Authorization: Bearer $(az account get-access-token --query accessToken -o tsv)\" https://" + meta["app"] + ".scm.azurewebsites.net/api/zip/site/wwwroot/ -o site.zip"
	case "appconfig":
		return "az appconfig kv list --name " + meta["store"] + " --all"
	case "apim_named_value":
		return "az apim nv show --service-name " + meta["service"] + " -g " + rg + "   # per named value; secrets need --query or listValue"
	case "deploy_script":
		return "az deployment-scripts show -g " + rg + " -n " + meta["script"]
	case "log_analytics":
		return "az monitor log-analytics query -w " + meta["workspace"] + " --analytics-query '" + logAnalyticsQuery + "'"
	case "automation_job":
		return "az rest --method get --url 'https://management.azure.com" + id + "/output?api-version=2023-11-01'"
	case "aci_env":
		return "az container show -n " + meta["cg"] + " -g " + rg + " --query 'containers[].environmentVariables'"
	case "arm_deploy":
		return "az deployment group show -g " + rg + " -n " + meta["deployment"]
	case "automation_var":
		return "az rest --method get --url 'https://management.azure.com" + id + "?api-version=2023-11-01'"
	case "automation_runbook":
		return "az rest --method get --url 'https://management.azure.com" + id + "/content?api-version=2023-11-01'"
	case "logic_app":
		return "az rest --method get --url 'https://management.azure.com" + id + "?api-version=2016-06-01'"
	case "blob":
		return "az storage blob download --account-name " + meta["account"] + " -c " + meta["container"] +
			" -n '" + meta["key"] + "' --auth-mode login -f -"
	}
	return ""
}

func redactMatch(s string) string {
	if len(s) <= 12 {
		return s[:min(4, len(s))] + "..."
	}
	return s[:6] + "..." + s[len(s)-4:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
