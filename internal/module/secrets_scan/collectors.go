package secrets_scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
)

const maxBlobFileSize = 10 * 1024 * 1024 // 10MB

// defaultBlobMaxPages caps ListBlobsFlat pagination per container. Kingfisher
// samples enough to catch secrets without paginating for hours on containers
// holding millions of blobs. Override (or disable, with 0) via --blob-max-pages.
const defaultBlobMaxPages = 25

// blobMaxPages resolves the per-container page cap from context, falling back to
// the default. 0 means unlimited.
func blobMaxPages(ctx context.Context) int {
	if v, ok := ctx.Value("bb.blob_max_pages").(int); ok {
		return v
	}
	return defaultBlobMaxPages
}

// --- VM user data / custom data / extension settings ---

func collectVMUserData(ctx context.Context, t creds.SubscriptionTarget) []sample {
	vmClient, err := armcompute.NewVirtualMachinesClient(t.SubscriptionID, t.Credential, nil)
	if err != nil {
		return nil
	}
	extClient, err := armcompute.NewVirtualMachineExtensionsClient(t.SubscriptionID, t.Credential, nil)
	if err != nil {
		return nil
	}

	var out []sample
	pager := vmClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, vm := range page.Value {
			vmName := ptrVal(vm.Name)
			vmID := ptrVal(vm.ID)
			location := ptrVal(vm.Location)
			rg := resourceGroup(vmID)
			if vm.Properties == nil {
				continue
			}

			// custom data (base64 cloud-init) — usually null on read, but keep it.
			if vm.Properties.OSProfile != nil {
				if cd := ptrVal(vm.Properties.OSProfile.CustomData); cd != "" {
					if decoded, derr := base64.StdEncoding.DecodeString(cd); derr == nil {
						out = append(out, sample{
							Source: "vm_userdata/" + vmName + "/custom_data", Region: location,
							Content:  string(decoded),
							Metadata: map[string]string{"id": vmID, "vm": vmName, "rg": rg},
						})
					}
				}
			}

			// userData — direct EC2-user-data equivalent; not returned by List.
			if rg != "" {
				if getResp, gerr := vmClient.Get(ctx, rg, vmName, &armcompute.VirtualMachinesClientGetOptions{
					Expand: to.Ptr(armcompute.InstanceViewTypesUserData),
				}); gerr == nil && getResp.Properties != nil {
					if ud := ptrVal(getResp.Properties.UserData); ud != "" {
						if decoded, derr := base64.StdEncoding.DecodeString(ud); derr == nil {
							out = append(out, sample{
								Source: "vm_userdata/" + vmName + "/user_data", Region: location,
								Content:  string(decoded),
								Metadata: map[string]string{"id": vmID, "vm": vmName, "rg": rg},
							})
						}
					}
				}
			}

			// Extension public settings (protectedSettings are never returned).
			if rg == "" {
				continue
			}
			extResp, eerr := extClient.List(ctx, rg, vmName, nil)
			if eerr != nil || extResp.Value == nil {
				continue
			}
			for _, ext := range extResp.Value {
				if ext.Properties == nil || ext.Properties.Settings == nil {
					continue
				}
				extName := ptrVal(ext.Name)
				if b, merr := json.Marshal(ext.Properties.Settings); merr == nil {
					out = append(out, sample{
						Source: "vm_ext/" + vmName + "/" + extName, Region: location,
						Content:  string(b),
						Metadata: map[string]string{"id": vmID, "vm": vmName, "rg": rg, "ext": extName},
					})
				}
			}
		}
	}
	return out
}

// --- App Service / Function App application settings ---

func collectAppServiceEnv(ctx context.Context, t creds.SubscriptionTarget) []sample {
	webClient, err := armappservice.NewWebAppsClient(t.SubscriptionID, t.Credential, nil)
	if err != nil {
		return nil
	}
	var out []sample
	pager := webClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, app := range page.Value {
			appName := ptrVal(app.Name)
			appID := ptrVal(app.ID)
			rg := resourceGroup(appID)
			if rg == "" {
				continue
			}
			meta := map[string]string{"id": appID, "app": appName, "rg": rg}
			region := ptrVal(app.Location)

			// Application settings (env vars).
			if resp, err := webClient.ListApplicationSettings(ctx, rg, appName, nil); err == nil && resp.Properties != nil {
				var lines []string
				for k, v := range resp.Properties {
					lines = append(lines, k+"="+ptrVal(v))
				}
				if len(lines) > 0 {
					out = append(out, sample{
						Source: "appservice_env/" + appName, Region: region,
						Content: strings.Join(lines, "\n"), Metadata: meta,
					})
				}
			}

			// Connection strings (a separate API from app settings — this is
			// where DB/storage credentials most often live).
			if resp, err := webClient.ListConnectionStrings(ctx, rg, appName, nil); err == nil && resp.Properties != nil {
				var lines []string
				for k, v := range resp.Properties {
					if v != nil {
						lines = append(lines, k+"="+ptrVal(v.Value))
					}
				}
				if len(lines) > 0 {
					out = append(out, sample{
						Source: "appservice_connstr/" + appName, Region: region,
						Content: strings.Join(lines, "\n"), Metadata: meta,
					})
				}
			}

			// Deployment slots each carry their own settings + connection strings.
			slotPager := webClient.NewListSlotsPager(rg, appName, nil)
			for slotPager.More() {
				sPage, serr := slotPager.NextPage(ctx)
				if serr != nil {
					break
				}
				for _, slot := range sPage.Value {
					slotName := afterLastSlash(ptrVal(slot.Name))
					if slotName == "" {
						continue
					}
					slotMeta := map[string]string{"id": ptrVal(slot.ID), "app": appName, "rg": rg, "slot": slotName}
					if resp, err := webClient.ListApplicationSettingsSlot(ctx, rg, appName, slotName, nil); err == nil && resp.Properties != nil {
						var lines []string
						for k, v := range resp.Properties {
							lines = append(lines, k+"="+ptrVal(v))
						}
						if len(lines) > 0 {
							out = append(out, sample{
								Source:  "appservice_env/" + appName + "/slot/" + slotName,
								Region:  region,
								Content: strings.Join(lines, "\n"), Metadata: slotMeta,
							})
						}
					}
					if resp, err := webClient.ListConnectionStringsSlot(ctx, rg, appName, slotName, nil); err == nil && resp.Properties != nil {
						var lines []string
						for k, v := range resp.Properties {
							if v != nil {
								lines = append(lines, k+"="+ptrVal(v.Value))
							}
						}
						if len(lines) > 0 {
							out = append(out, sample{
								Source:  "appservice_connstr/" + appName + "/slot/" + slotName,
								Region:  region,
								Content: strings.Join(lines, "\n"), Metadata: slotMeta,
							})
						}
					}
				}
			}
		}
	}
	return out
}

// afterLastSlash returns the segment after the final "/" (App Service slot
// resources are named "<app>/<slot>").
func afterLastSlash(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// --- Azure Container Instances env vars ---

func collectACIEnv(ctx context.Context, t creds.SubscriptionTarget) []sample {
	client, err := armcontainerinstance.NewContainerGroupsClient(t.SubscriptionID, t.Credential, nil)
	if err != nil {
		return nil
	}
	var out []sample
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, cg := range page.Value {
			cgName := ptrVal(cg.Name)
			cgID := ptrVal(cg.ID)
			location := ptrVal(cg.Location)
			rg := resourceGroup(cgID)
			if cg.Properties == nil {
				continue
			}
			collect := func(containerName string, envs []*armcontainerinstance.EnvironmentVariable) {
				var lines []string
				for _, ev := range envs {
					if ev == nil {
						continue
					}
					// secureValue is redacted on read (empty Value); skip empties.
					if v := ptrVal(ev.Value); v != "" {
						lines = append(lines, ptrVal(ev.Name)+"="+v)
					}
				}
				if len(lines) == 0 {
					return
				}
				out = append(out, sample{
					Source: "aci_env/" + cgName + "/" + containerName, Region: location,
					Content: strings.Join(lines, "\n"),
					Metadata: map[string]string{
						"id": cgID, "cg": cgName, "rg": rg, "container": containerName,
					},
				})
			}
			for _, c := range cg.Properties.Containers {
				if c.Properties != nil {
					collect(ptrVal(c.Name), c.Properties.EnvironmentVariables)
				}
			}
			for _, c := range cg.Properties.InitContainers {
				if c.Properties != nil {
					collect(ptrVal(c.Name), c.Properties.EnvironmentVariables)
				}
			}
		}
	}
	return out
}

// --- ARM deployment parameters / outputs ---

func collectARMDeployments(ctx context.Context, t creds.SubscriptionTarget) []sample {
	rgClient, err := armresources.NewResourceGroupsClient(t.SubscriptionID, t.Credential, nil)
	if err != nil {
		return nil
	}
	deplClient, err := armresources.NewDeploymentsClient(t.SubscriptionID, t.Credential, nil)
	if err != nil {
		return nil
	}
	var rgs []string
	rgPager := rgClient.NewListPager(nil)
	for rgPager.More() {
		page, err := rgPager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, rg := range page.Value {
			rgs = append(rgs, ptrVal(rg.Name))
		}
	}

	var out []sample
	for _, rg := range rgs {
		deplPager := deplClient.NewListByResourceGroupPager(rg, nil)
		for deplPager.More() {
			page, err := deplPager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, depl := range page.Value {
				if depl.Properties == nil {
					continue
				}
				deplName := ptrVal(depl.Name)
				deplID := ptrVal(depl.ID)
				content := deploymentText(depl.Properties.Parameters, depl.Properties.Outputs)
				if content == "" {
					continue
				}
				out = append(out, sample{
					Source:   "arm_deploy/" + rg + "/" + deplName,
					Content:  content,
					Metadata: map[string]string{"id": deplID, "rg": rg, "deployment": deplName},
				})
			}
		}
	}
	return out
}

// deploymentText flattens a deployment's parameters and outputs (each of shape
// key -> {"value": ...}) into "key=value" lines for scanning. secureString
// entries have a null value and are naturally skipped.
func deploymentText(parameters, outputs any) string {
	var lines []string
	add := func(prefix string, raw any) {
		m, ok := raw.(map[string]any)
		if !ok {
			return
		}
		for key, entry := range m {
			em, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			v, has := em["value"]
			if !has || v == nil {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s.%s=%v", prefix, key, v))
		}
	}
	add("parameter", parameters)
	add("output", outputs)
	return strings.Join(lines, "\n")
}

// --- Automation account variables + runbook source ---

func collectAutomation(ctx context.Context, t creds.SubscriptionTarget) []sample {
	accounts, err := armList(ctx, t.Credential,
		fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01", t.SubscriptionID))
	if err != nil {
		return nil
	}

	var out []sample
	for _, r := range accounts {
		var acct struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		}
		if json.Unmarshal(r, &acct) != nil || acct.ID == "" {
			continue
		}
		rg := resourceGroup(acct.ID)

		// Unencrypted variables.
		vars, _ := armList(ctx, t.Credential,
			fmt.Sprintf("https://management.azure.com%s/variables?api-version=2023-11-01", acct.ID))
		var lines []string
		for _, vr := range vars {
			var v struct {
				Name  string `json:"name"`
				Props struct {
					IsEncrypted bool   `json:"isEncrypted"`
					Value       string `json:"value"`
				} `json:"properties"`
			}
			if json.Unmarshal(vr, &v) != nil || v.Props.IsEncrypted {
				continue
			}
			if v.Props.Value != "" {
				lines = append(lines, v.Name+"="+v.Props.Value)
			}
		}
		if len(lines) > 0 {
			out = append(out, sample{
				Source: "automation_var/" + acct.Name, Region: acct.Location,
				Content:  strings.Join(lines, "\n"),
				Metadata: map[string]string{"id": acct.ID + "/variables", "account": acct.Name, "rg": rg},
			})
		}

		// Runbook source code.
		runbooks, _ := armList(ctx, t.Credential,
			fmt.Sprintf("https://management.azure.com%s/runbooks?api-version=2023-11-01", acct.ID))
		for _, rb := range runbooks {
			var b struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if json.Unmarshal(rb, &b) != nil || b.Name == "" {
				continue
			}
			content, cerr := armGetRaw(ctx, t.Credential,
				fmt.Sprintf("https://management.azure.com%s/runbooks/%s/content?api-version=2023-11-01", acct.ID, b.Name))
			if cerr != nil || content == "" {
				continue
			}
			out = append(out, sample{
				Source: "automation_runbook/" + acct.Name + "/" + b.Name, Region: acct.Location,
				Content:  content,
				Metadata: map[string]string{"id": b.ID, "account": acct.Name, "rg": rg, "runbook": b.Name},
			})
		}

		// Recent job output — runbooks frequently print secrets to stdout.
		jobs, _ := armList(ctx, t.Credential,
			fmt.Sprintf("https://management.azure.com%s/jobs?api-version=2023-11-01&$top=10", acct.ID))
		for _, jr := range jobs {
			var job struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if json.Unmarshal(jr, &job) != nil || job.ID == "" {
				continue
			}
			output, oerr := armGetRaw(ctx, t.Credential,
				fmt.Sprintf("https://management.azure.com%s/output?api-version=2023-11-01", job.ID))
			if oerr != nil || output == "" {
				continue
			}
			out = append(out, sample{
				Source: "automation_job/" + acct.Name + "/" + job.Name, Region: acct.Location,
				Content:  output,
				Metadata: map[string]string{"id": job.ID, "account": acct.Name, "rg": rg, "job": job.Name},
			})
		}
	}
	return out
}

// --- Logic App workflow definitions ---

func collectLogicApps(ctx context.Context, t creds.SubscriptionTarget) []sample {
	workflows, err := armList(ctx, t.Credential,
		fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Logic/workflows?api-version=2016-06-01", t.SubscriptionID))
	if err != nil {
		return nil
	}
	var out []sample
	for _, r := range workflows {
		var wf struct {
			ID       string          `json:"id"`
			Name     string          `json:"name"`
			Location string          `json:"location"`
			Props    json.RawMessage `json:"properties"`
		}
		if json.Unmarshal(r, &wf) != nil || wf.Name == "" {
			continue
		}
		out = append(out, sample{
			Source: "logic_app/" + wf.Name, Region: wf.Location,
			Content:  string(wf.Props),
			Metadata: map[string]string{"id": wf.ID, "workflow": wf.Name, "rg": resourceGroup(wf.ID)},
		})
	}
	return out
}

// --- Blob Storage — per-container download + kingfisher (the S3 equivalent) ---

func scanBlobPerContainer(ctx context.Context, kfPath string, t creds.SubscriptionTarget, sink findings.Sink) {
	acctClient, err := armstorage.NewAccountsClient(t.SubscriptionID, t.Credential, nil)
	if err != nil {
		return
	}
	containerClient, err := armstorage.NewBlobContainersClient(t.SubscriptionID, t.Credential, nil)
	if err != nil {
		return
	}

	var accounts []*armstorage.Account
	pager := acctClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return
		}
		accounts = append(accounts, page.Value...)
	}
	_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
		fmt.Sprintf("Blob: scanning %d storage accounts", len(accounts)))

	maxPages := blobMaxPages(ctx)

	for ai, acct := range accounts {
		acctName := ptrVal(acct.Name)
		location := ptrVal(acct.Location)
		rg := resourceGroup(ptrVal(acct.ID))
		if rg == "" {
			continue
		}
		_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
			fmt.Sprintf("Blob: account %d/%d: %s", ai+1, len(accounts), acctName))

		blobClient, berr := azblob.NewClient(
			fmt.Sprintf("https://%s.blob.core.windows.net/", acctName), t.Credential, nil)
		if berr != nil {
			_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "warn",
				fmt.Sprintf("Blob: create client for %s: %v", acctName, berr))
			continue
		}

		cPager := containerClient.NewListPager(rg, acctName, nil)
		for cPager.More() {
			cPage, err := cPager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, c := range cPage.Value {
				containerName := ptrVal(c.Name)
				scanOneContainer(ctx, kfPath, blobClient, acctName, containerName, location, maxPages, t, sink)
			}
		}
	}
}

func scanOneContainer(ctx context.Context, kfPath string, blobClient *azblob.Client,
	acctName, containerName, location string, maxPages int, t creds.SubscriptionTarget, sink findings.Sink) {

	tmpDir, err := os.MkdirTemp("", "bb-blob-*")
	if err != nil {
		return
	}
	defer os.RemoveAll(tmpDir)

	fileMap := map[string]*sample{}
	fileIdx := 0
	examined := 0

	pager := blobClient.NewListBlobsFlatPager(containerName, nil)
	pageNum := 0
	for pager.More() {
		if maxPages > 0 && pageNum >= maxPages {
			_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "warn",
				fmt.Sprintf("Blob: %s/%s reached the %d-page cap — stopping; raise/disable with --blob-max-pages",
					acctName, containerName, maxPages))
			break
		}
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		pageNum++
		for _, b := range page.Segment.BlobItems {
			key := ptrVal(b.Name)
			var size int64
			if b.Properties != nil && b.Properties.ContentLength != nil {
				size = *b.Properties.ContentLength
			}
			examined++
			if examined%250 == 0 {
				_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
					fmt.Sprintf("Blob: %s/%s: examined %d blobs, %d kept", acctName, containerName, examined, fileIdx))
			}
			if size == 0 || size > maxBlobFileSize || isBinaryExt(key) {
				continue
			}
			resp, derr := blobClient.DownloadStream(ctx, containerName, key, nil)
			if derr != nil {
				continue
			}
			body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBlobFileSize))
			resp.Body.Close()
			if rerr != nil || len(body) == 0 || isBinaryContent(body) {
				continue
			}
			safe := strings.ReplaceAll(key, "/", "__")
			safe = strings.ReplaceAll(safe, ":", "_")
			fname := fmt.Sprintf("%04d_%s", fileIdx, safe)
			if len(fname) > 200 {
				fname = fmt.Sprintf("%04d_%s", fileIdx, safe[:190])
			}
			if err := os.WriteFile(filepath.Join(tmpDir, fname), body, 0600); err != nil {
				continue
			}
			fileMap[fname] = &sample{
				Source: "blob/" + acctName + "/" + containerName + "/" + key, Region: location,
				Metadata: map[string]string{
					"id":        fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", acctName, containerName, key),
					"account":   acctName,
					"container": containerName,
					"key":       key,
				},
			}
			fileIdx++
		}
	}

	if fileIdx > 0 {
		_ = sink.LogEvent(ctx, "secrets_scan", t.SubscriptionID, "info",
			fmt.Sprintf("Blob: scanning %d files from %s/%s with kingfisher", fileIdx, acctName, containerName))
		kfFindings := runKingfisher(ctx, kfPath, tmpDir, "blob_"+acctName+"_"+containerName, t, sink)
		emitFindings(kfFindings, fileMap, tmpDir, t, sink, ctx.Value("bb.redact_secrets") == nil)
	}
}

// isBinaryExt returns true for file extensions that are definitely not text.
func isBinaryExt(key string) bool {
	switch strings.ToLower(filepath.Ext(key)) {
	case ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
		".mp3", ".mp4", ".avi", ".mov", ".mkv", ".flv", ".wav", ".ogg",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib",
		".whl", ".egg", ".class", ".jar", ".war",
		".bin", ".dat", ".img", ".iso", ".dmg",
		".ttf", ".otf", ".woff", ".woff2", ".eot",
		".parquet", ".avro", ".orc",
		".sqlite", ".db", ".mdb":
		return true
	}
	return false
}

// isBinaryContent checks if the first 512 bytes look like binary data.
func isBinaryContent(data []byte) bool {
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	nullCount := 0
	for _, b := range check {
		if b == 0 {
			nullCount++
		}
	}
	return nullCount > 5
}

// --- ARM REST helpers (bearer-token GET), used by the collectors above that
// have no typed SDK client wired in (Automation, Logic Apps). ---

// armMgmtScope is the AAD scope for the Azure Resource Manager control plane.
const armMgmtScope = "https://management.azure.com/.default"

// tokenForScope fetches a bearer token for an arbitrary AAD scope. Data-plane
// APIs (App Configuration, Log Analytics) need their own audience, not ARM's.
func tokenForScope(ctx context.Context, cred azcore.TokenCredential, scope string) (string, error) {
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return "", err
	}
	return tok.Token, nil
}

func armToken(ctx context.Context, cred azcore.TokenCredential) (string, error) {
	return tokenForScope(ctx, cred, armMgmtScope)
}

func armGet(ctx context.Context, cred azcore.TokenCredential, url string, result any) error {
	token, err := armToken(ctx, cred)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

func armGetRaw(ctx context.Context, cred azcore.TokenCredential, url string) (string, error) {
	token, err := armToken(ctx, cred)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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
