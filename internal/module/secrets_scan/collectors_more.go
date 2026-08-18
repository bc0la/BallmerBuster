package secrets_scan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/you/ballmerbuster/internal/creds"
)

// scannableExts is the allowlist of extensions worth extracting from downloaded
// App Service site zips (the Kudu wwwroot). Everything else is skipped.
var scannableExts = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".go": true, ".java": true,
	".rb": true, ".php": true, ".cs": true, ".sh": true, ".bash": true,
	".ps1": true, ".json": true, ".yml": true, ".yaml": true, ".xml": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".env": true,
	".properties": true, ".config": true, ".tf": true, ".sql": true, ".txt": true,
	".md": true, ".html": true, ".htm": true, ".csv": true,
}

const maxCodeZipSize = 50 * 1024 * 1024 // 50MB cap on a downloaded site zip

// --- App Configuration key-values (the SSM Parameter Store analog) ---

func collectAppConfig(ctx context.Context, t creds.SubscriptionTarget) []sample {
	stores, err := armList(ctx, t.Credential,
		fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.AppConfiguration/configurationStores?api-version=2023-03-01", t.SubscriptionID))
	if err != nil {
		return nil
	}

	token, terr := tokenForScope(ctx, t.Credential, "https://azconfig.io/.default")
	if terr != nil {
		return nil
	}

	var out []sample
	for _, r := range stores {
		var store struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
			Props    struct {
				Endpoint string `json:"endpoint"`
			} `json:"properties"`
		}
		if json.Unmarshal(r, &store) != nil || store.Props.Endpoint == "" {
			continue
		}

		var lines []string
		next := store.Props.Endpoint + "/kv?api-version=1.0"
		for pages := 0; next != "" && pages < 20; pages++ {
			var body struct {
				Items []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
					Label string `json:"label"`
				} `json:"items"`
				NextLink string `json:"@nextLink"`
			}
			if err := httpJSON(ctx, http.MethodGet, token, next, nil, &body); err != nil {
				break
			}
			for _, it := range body.Items {
				lines = append(lines, it.Key+"="+it.Value)
			}
			next = resolveNextLink(store.Props.Endpoint, body.NextLink)
		}
		if len(lines) == 0 {
			continue
		}
		out = append(out, sample{
			Source: "appconfig/" + store.Name, Region: store.Location,
			Content:  strings.Join(lines, "\n"),
			Metadata: map[string]string{"id": store.ID, "store": store.Name, "rg": resourceGroup(store.ID)},
		})
	}
	return out
}

// resolveNextLink turns App Configuration's possibly-relative @nextLink into an
// absolute URL against the store endpoint.
func resolveNextLink(endpoint, next string) string {
	if next == "" {
		return ""
	}
	if strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") {
		return next
	}
	return strings.TrimRight(endpoint, "/") + "/" + strings.TrimLeft(next, "/")
}

// --- API Management named values ---

func collectAPIM(ctx context.Context, t creds.SubscriptionTarget) []sample {
	services, err := armList(ctx, t.Credential,
		fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.ApiManagement/service?api-version=2022-08-01", t.SubscriptionID))
	if err != nil {
		return nil
	}

	var out []sample
	for _, r := range services {
		var svc struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		}
		if json.Unmarshal(r, &svc) != nil || svc.ID == "" {
			continue
		}

		nvs, _ := armList(ctx, t.Credential,
			fmt.Sprintf("https://management.azure.com%s/namedValues?api-version=2022-08-01", svc.ID))
		var lines []string
		for _, nr := range nvs {
			var nv struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				Props struct {
					DisplayName string `json:"displayName"`
					Value       string `json:"value"`
					Secret      bool   `json:"secret"`
				} `json:"properties"`
			}
			if json.Unmarshal(nr, &nv) != nil {
				continue
			}
			value := nv.Props.Value
			if nv.Props.Secret {
				// Secret values are omitted from the list response; fetch each
				// explicitly (requires Microsoft.ApiManagement/.../listValue).
				var lv struct {
					Value string `json:"value"`
				}
				if err := armPost(ctx, t.Credential,
					fmt.Sprintf("https://management.azure.com%s/listValue?api-version=2022-08-01", nv.ID),
					nil, &lv); err == nil {
					value = lv.Value
				}
			}
			if value != "" {
				lines = append(lines, nv.Props.DisplayName+"="+value)
			}
		}
		if len(lines) == 0 {
			continue
		}
		out = append(out, sample{
			Source: "apim_named_value/" + svc.Name, Region: svc.Location,
			Content:  strings.Join(lines, "\n"),
			Metadata: map[string]string{"id": svc.ID, "service": svc.Name, "rg": resourceGroup(svc.ID)},
		})
	}
	return out
}

// --- VM Scale Sets (custom/user data + extension settings) ---

func collectVMSS(ctx context.Context, t creds.SubscriptionTarget) []sample {
	client, err := armcompute.NewVirtualMachineScaleSetsClient(t.SubscriptionID, t.Credential, nil)
	if err != nil {
		return nil
	}
	var out []sample
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vmss := range page.Value {
			name := ptrVal(vmss.Name)
			id := ptrVal(vmss.ID)
			location := ptrVal(vmss.Location)
			rg := resourceGroup(id)
			meta := map[string]string{"id": id, "vmss": name, "rg": rg}
			if vmss.Properties == nil || vmss.Properties.VirtualMachineProfile == nil {
				continue
			}
			prof := vmss.Properties.VirtualMachineProfile

			if prof.OSProfile != nil {
				if cd := ptrVal(prof.OSProfile.CustomData); cd != "" {
					if dec, derr := base64.StdEncoding.DecodeString(cd); derr == nil {
						out = append(out, sample{
							Source: "vmss_userdata/" + name + "/custom_data", Region: location,
							Content: string(dec), Metadata: meta,
						})
					}
				}
			}
			if ud := ptrVal(prof.UserData); ud != "" {
				if dec, derr := base64.StdEncoding.DecodeString(ud); derr == nil {
					out = append(out, sample{
						Source: "vmss_userdata/" + name + "/user_data", Region: location,
						Content: string(dec), Metadata: meta,
					})
				}
			}
			if prof.ExtensionProfile != nil {
				for _, ext := range prof.ExtensionProfile.Extensions {
					if ext == nil || ext.Properties == nil || ext.Properties.Settings == nil {
						continue
					}
					extName := ptrVal(ext.Name)
					if b, merr := json.Marshal(ext.Properties.Settings); merr == nil {
						em := map[string]string{"id": id, "vmss": name, "rg": rg, "ext": extName}
						out = append(out, sample{
							Source: "vmss_ext/" + name + "/" + extName, Region: location,
							Content: string(b), Metadata: em,
						})
					}
				}
			}
		}
	}
	return out
}

// --- Deployment Scripts (inline scripts + arguments + env vars) ---

func collectDeploymentScripts(ctx context.Context, t creds.SubscriptionTarget) []sample {
	scripts, err := armList(ctx, t.Credential,
		fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Resources/deploymentScripts?api-version=2020-10-01", t.SubscriptionID))
	if err != nil {
		return nil
	}
	var out []sample
	for _, r := range scripts {
		var ds struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
			Props    struct {
				ScriptContent string `json:"scriptContent"`
				Arguments     string `json:"arguments"`
				EnvVars       []struct {
					Name        string `json:"name"`
					Value       string `json:"value"`
					SecureValue string `json:"secureValue"`
				} `json:"environmentVariables"`
			} `json:"properties"`
		}
		if json.Unmarshal(r, &ds) != nil || ds.ID == "" {
			continue
		}
		var b strings.Builder
		if ds.Props.ScriptContent != "" {
			b.WriteString(ds.Props.ScriptContent)
			b.WriteString("\n")
		}
		if ds.Props.Arguments != "" {
			b.WriteString("arguments=" + ds.Props.Arguments + "\n")
		}
		for _, ev := range ds.Props.EnvVars {
			// secureValue is redacted on read; value is plaintext.
			if ev.Value != "" {
				b.WriteString(ev.Name + "=" + ev.Value + "\n")
			}
		}
		content := b.String()
		if strings.TrimSpace(content) == "" {
			continue
		}
		out = append(out, sample{
			Source: "deploy_script/" + ds.Name, Region: ds.Location,
			Content:  content,
			Metadata: map[string]string{"id": ds.ID, "script": ds.Name, "rg": resourceGroup(ds.ID)},
		})
	}
	return out
}

// --- App Service / Function App deployed code (Kudu wwwroot zip) ---

// collectAppServiceCode downloads each app's site content from the Kudu SCM
// endpoint and extracts scannable text files. Best-effort: Kudu AAD access can
// be disabled or the SCM host unreachable, in which case the app is skipped.
func collectAppServiceCode(ctx context.Context, t creds.SubscriptionTarget) []sample {
	stores, err := armList(ctx, t.Credential,
		fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Web/sites?api-version=2023-12-01", t.SubscriptionID))
	if err != nil {
		return nil
	}
	token, terr := armToken(ctx, t.Credential)
	if terr != nil {
		return nil
	}

	var out []sample
	for _, r := range stores {
		var app struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Loc   string `json:"location"`
			Props struct {
				DefaultHostName  string   `json:"defaultHostName"`
				EnabledHostNames []string `json:"enabledHostNames"`
			} `json:"properties"`
		}
		if json.Unmarshal(r, &app) != nil || app.Name == "" {
			continue
		}
		scmHost := kuduHost(app.Name, app.Props.EnabledHostNames)
		url := "https://" + scmHost + "/api/zip/site/wwwroot/"

		data, derr := kuduDownload(ctx, token, url)
		if derr != nil || len(data) == 0 {
			continue
		}
		zr, zerr := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if zerr != nil {
			continue
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || !scannableExts[strings.ToLower(filepath.Ext(f.Name))] {
				continue
			}
			if f.UncompressedSize64 == 0 || f.UncompressedSize64 > maxBlobFileSize {
				continue
			}
			rc, oerr := f.Open()
			if oerr != nil {
				continue
			}
			body, rerr := io.ReadAll(io.LimitReader(rc, maxBlobFileSize))
			rc.Close()
			if rerr != nil || len(body) == 0 || isBinaryContent(body) {
				continue
			}
			out = append(out, sample{
				Source: "appservice_code/" + app.Name + "/" + f.Name, Region: app.Loc,
				Content: string(body),
				Metadata: map[string]string{
					"id": app.ID, "app": app.Name, "rg": resourceGroup(app.ID), "path": f.Name,
				},
			})
		}
	}
	return out
}

// kuduHost picks the SCM (Kudu) hostname for an app: prefer an enabled hostname
// containing ".scm.", else fall back to the public-cloud convention.
func kuduHost(name string, enabled []string) string {
	for _, h := range enabled {
		if strings.Contains(h, ".scm.") {
			return h
		}
	}
	return name + ".scm.azurewebsites.net"
}

func kuduDownload(ctx context.Context, token, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/zip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("kudu %s: %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxCodeZipSize))
}

// --- Log Analytics workspaces (recent records) ---

// logAnalyticsQuery samples recent rows across all tables. It is deliberately
// capped (take + 1-day window) to bound query cost; a per-collector timeout
// (--secrets-timeout) bounds wall-clock. This is the noisiest/most expensive
// collector — see the module docs.
const logAnalyticsQuery = "union isfuzzy=true * | where TimeGenerated > ago(1d) | take 500"

func collectLogAnalytics(ctx context.Context, t creds.SubscriptionTarget) []sample {
	workspaces, err := armList(ctx, t.Credential,
		fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01", t.SubscriptionID))
	if err != nil {
		return nil
	}
	token, terr := tokenForScope(ctx, t.Credential, "https://api.loganalytics.io/.default")
	if terr != nil {
		return nil
	}

	var out []sample
	for _, r := range workspaces {
		var ws struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
			Props    struct {
				CustomerID string `json:"customerId"`
			} `json:"properties"`
		}
		if json.Unmarshal(r, &ws) != nil || ws.Props.CustomerID == "" {
			continue
		}
		var result struct {
			Tables []struct {
				Rows [][]any `json:"rows"`
			} `json:"tables"`
		}
		url := "https://api.loganalytics.io/v1/workspaces/" + ws.Props.CustomerID + "/query"
		if err := httpJSON(ctx, http.MethodPost, token, url,
			map[string]any{"query": logAnalyticsQuery}, &result); err != nil {
			continue
		}
		var lines []string
		for _, tbl := range result.Tables {
			for _, row := range tbl.Rows {
				cells := make([]string, 0, len(row))
				for _, c := range row {
					if c != nil {
						cells = append(cells, fmt.Sprintf("%v", c))
					}
				}
				if len(cells) > 0 {
					lines = append(lines, strings.Join(cells, " | "))
				}
			}
		}
		if len(lines) == 0 {
			continue
		}
		out = append(out, sample{
			Source: "log_analytics/" + ws.Name, Region: ws.Location,
			Content:  strings.Join(lines, "\n"),
			Metadata: map[string]string{"id": ws.ID, "workspace": ws.Name, "rg": resourceGroup(ws.ID)},
		})
	}
	return out
}

// --- REST helpers: management-plane POST + generic scoped JSON request ---

func armPost(ctx context.Context, cred azcore.TokenCredential, url string, body, result any) error {
	token, err := armToken(ctx, cred)
	if err != nil {
		return err
	}
	return httpJSON(ctx, http.MethodPost, token, url, body, result)
}

// httpJSON performs a bearer-authenticated request. If body is non-nil it is
// JSON-encoded; if result is non-nil the response is JSON-decoded into it.
func httpJSON(ctx context.Context, method, token, url string, body, result any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %d %s", method, url, resp.StatusCode, string(b))
	}
	if result == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(result)
}
