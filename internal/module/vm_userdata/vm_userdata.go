package vm_userdata

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module scans VMs for secrets in user data / custom data (the Azure
// equivalents of EC2 user data) and in VM extension settings (CustomScript
// inline scripts, agent configs, etc.). protectedSettings are write-only and
// never returned by the API, so only public settings are visible.
type Module struct{}

func (Module) Name() string      { return "vm_userdata" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Compute/virtualMachines/read",
		"Microsoft.Compute/virtualMachines/extensions/read",
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
	vmClient, err := armcompute.NewVirtualMachinesClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("vm_userdata: create VM client: %w", err)
	}
	extClient, err := armcompute.NewVirtualMachineExtensionsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("vm_userdata: create extensions client: %w", err)
	}

	// 1. List all VMs.
	var vms []*armcompute.VirtualMachine
	pager := vmClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("vm_userdata: list VMs: %w", err)
		}
		vms = append(vms, page.Value...)
	}

	_ = sink.LogEvent(ctx, "vm_userdata", target.SubscriptionID, "info",
		fmt.Sprintf("scanning %d virtual machines", len(vms)))

	for i, vm := range vms {
		vmName := ptrVal(vm.Name)
		vmID := ptrVal(vm.ID)
		location := ptrVal(vm.Location)
		rg := resourceGroup(vmID)

		_ = sink.LogEvent(ctx, "vm_userdata", target.SubscriptionID, "info",
			fmt.Sprintf("VM %d/%d: %s", i+1, len(vms), vmName))

		if vm.Properties == nil {
			continue
		}

		// 2a. Check custom data (base64 cloud-init). Note: Azure usually
		// returns customData as null on read (write-only after create), so
		// userData below is the reliable source.
		if vm.Properties.OSProfile != nil {
			customData := ptrVal(vm.Properties.OSProfile.CustomData)
			if customData != "" {
				decoded, err := base64.StdEncoding.DecodeString(customData)
				if err == nil {
					scanScriptText(ctx, sink, target.SubscriptionID, location, vmID, vmName, "custom_data", string(decoded))
				}
			}

			// 3. Check for password auth on Linux VMs.
			if vm.Properties.OSProfile.LinuxConfiguration != nil {
				lc := vm.Properties.OSProfile.LinuxConfiguration
				if lc.DisablePasswordAuthentication != nil && !*lc.DisablePasswordAuthentication {
					_ = sink.Write(ctx, findings.Finding{
						SubscriptionID: target.SubscriptionID,
						Region:         location,
						Module:         "vm_userdata",
						Severity:       findings.SevMedium,
						ResourceID:     vmID,
						Title:          fmt.Sprintf("Linux VM %s has password authentication enabled", vmName),
						Detail: map[string]any{
							"check":                           "password_auth",
							"vm_name":                         vmName,
							"resource_group":                  rg,
							"disable_password_authentication": false,
						},
					})
				}
			}
		}

		// 2a-2. userData — the direct Azure equivalent of EC2 user data. It is
		// NOT returned by List, so fetch it explicitly with expand=userData.
		if rg != "" {
			getResp, gerr := vmClient.Get(ctx, rg, vmName, &armcompute.VirtualMachinesClientGetOptions{
				Expand: to.Ptr(armcompute.InstanceViewTypesUserData),
			})
			if gerr != nil {
				_ = sink.LogEvent(ctx, "vm_userdata", target.SubscriptionID, "warn",
					fmt.Sprintf("get userData for %s: %v", vmName, gerr))
			} else if getResp.Properties != nil {
				if ud := ptrVal(getResp.Properties.UserData); ud != "" {
					if decoded, derr := base64.StdEncoding.DecodeString(ud); derr == nil {
						scanScriptText(ctx, sink, target.SubscriptionID, location, vmID, vmName, "user_data", string(decoded))
					}
				}
			}
		}

		// 2b-c. List and inspect VM extensions.
		if rg == "" {
			continue
		}

		extResp, err := extClient.List(ctx, rg, vmName, nil)
		if err != nil {
			_ = sink.LogEvent(ctx, "vm_userdata", target.SubscriptionID, "warn",
				fmt.Sprintf("list extensions for %s: %v", vmName, err))
			continue
		}

		if extResp.Value == nil {
			continue
		}

		for _, ext := range extResp.Value {
			if ext.Properties == nil || ext.Properties.Settings == nil {
				continue
			}
			extName := ptrVal(ext.Name)
			extType := ptrVal(ext.Properties.Type)

			// Scan every extension's public settings — any extension can carry
			// hardcoded secrets (CustomScript commands/inline scripts, agent
			// configs, SAS URLs in fileUris, ...). protectedSettings are
			// write-only and never returned by the API.
			settingsJSON, err := json.Marshal(ext.Properties.Settings)
			if err == nil {
				scanExtensionSettings(ctx, sink, target.SubscriptionID, location, vmID, vmName, extName, extType, string(settingsJSON))
			}
		}
	}

	return nil
}

// scanScriptText scans decoded script/user-data text line-by-line for secret
// patterns. source labels the origin (custom_data, user_data, an extension
// script, ...).
func scanScriptText(ctx context.Context, sink findings.Sink, subID, location, vmID, vmName, source, data string) {
	lines := strings.Split(data, "\n")
	for lineNum, line := range lines {
		if patName := matchSecretPattern(line); patName != "" {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: subID,
				Region:         location,
				Module:         "vm_userdata",
				Severity:       findings.SevHigh,
				ResourceID:     vmID,
				Title:          fmt.Sprintf("VM %s %s contains secret at line %d (%s pattern)", vmName, source, lineNum+1, patName),
				Detail: map[string]any{
					"check":           "secret_pattern",
					"vm_name":         vmName,
					"source":          source,
					"line_number":     lineNum + 1,
					"pattern_matched": patName,
					"content":         line,
				},
			})
		}
	}
}

// scanExtensionSettings scans an extension's public settings JSON for secret
// patterns, decodes any base64 inline script, and flags suspicious keys.
func scanExtensionSettings(ctx context.Context, sink findings.Sink, subID, location, vmID, vmName, extName, extType, settingsJSON string) {
	if patName := matchSecretPattern(settingsJSON); patName != "" {
		_ = sink.Write(ctx, findings.Finding{
			SubscriptionID: subID,
			Region:         location,
			Module:         "vm_userdata",
			Severity:       findings.SevHigh,
			ResourceID:     vmID,
			Title:          fmt.Sprintf("VM %s extension %s (%s) settings contain secret (%s pattern)", vmName, extName, extType, patName),
			Detail: map[string]any{
				"check":           "secret_pattern",
				"vm_name":         vmName,
				"extension":       extName,
				"extension_type":  extType,
				"source":          "extension_settings",
				"pattern_matched": patName,
				"content":         settingsJSON,
			},
		})
	}

	var settingsMap map[string]any
	if err := json.Unmarshal([]byte(settingsJSON), &settingsMap); err == nil {
		// CustomScript stores the inline script base64-encoded in "script";
		// decode and scan its contents (regexes won't match the base64 blob).
		if s, ok := settingsMap["script"].(string); ok && s != "" {
			if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
				scanScriptText(ctx, sink, subID, location, vmID, vmName,
					fmt.Sprintf("extension %s inline script", extName), string(decoded))
			}
		}
		scanMapKeys(ctx, sink, subID, location, vmID, vmName, extName, extType, settingsMap)
	}
}

// scanMapKeys recursively checks a settings map for keys matching secret patterns.
func scanMapKeys(ctx context.Context, sink findings.Sink, subID, location, vmID, vmName, extName, extType string, m map[string]any) {
	for key, val := range m {
		if secretKeyPattern.MatchString(key) {
			if val != nil {
				valStr := fmt.Sprintf("%v", val)
				if valStr != "" && valStr != "<nil>" {
					_ = sink.Write(ctx, findings.Finding{
						SubscriptionID: subID,
						Region:         location,
						Module:         "vm_userdata",
						Severity:       findings.SevMedium,
						ResourceID:     vmID,
						Title:          fmt.Sprintf("VM %s extension %s has suspicious setting key %q", vmName, extName, key),
						Detail: map[string]any{
							"check":          "suspicious_name",
							"vm_name":        vmName,
							"extension":      extName,
							"extension_type": extType,
							"source":         "extension_settings",
							"key":            key,
							"reason":         "key name matches secret pattern in non-protected settings",
							"value":          valStr,
						},
					})
				}
			}
		}

		// Recurse into nested maps.
		if nested, ok := val.(map[string]any); ok {
			scanMapKeys(ctx, sink, subID, location, vmID, vmName, extName, extType, nested)
		}
	}
}

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
