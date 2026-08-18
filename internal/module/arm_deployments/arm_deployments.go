package arm_deployments

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module scans ARM template deployment history for secret values leaked through
// parameters or outputs that were not marked as secureString.
type Module struct{}

func (Module) Name() string      { return "arm_deployments" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"Microsoft.Resources/deployments/read"}
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
	rgClient, err := armresources.NewResourceGroupsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("arm_deployments: create resource groups client: %w", err)
	}
	deplClient, err := armresources.NewDeploymentsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("arm_deployments: create deployments client: %w", err)
	}

	// 1. List all resource groups.
	var rgs []string
	rgPager := rgClient.NewListPager(nil)
	for rgPager.More() {
		page, err := rgPager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("arm_deployments: list resource groups: %w", err)
		}
		for _, rg := range page.Value {
			rgs = append(rgs, ptrVal(rg.Name))
		}
	}

	_ = sink.LogEvent(ctx, "arm_deployments", target.SubscriptionID, "info",
		fmt.Sprintf("scanning deployments across %d resource groups", len(rgs)))

	// 2. For each resource group, list deployments.
	for i, rg := range rgs {
		_ = sink.LogEvent(ctx, "arm_deployments", target.SubscriptionID, "info",
			fmt.Sprintf("resource group %d/%d: %s", i+1, len(rgs), rg))

		deplPager := deplClient.NewListByResourceGroupPager(rg, nil)
		for deplPager.More() {
			page, err := deplPager.NextPage(ctx)
			if err != nil {
				_ = sink.LogEvent(ctx, "arm_deployments", target.SubscriptionID, "warn",
					fmt.Sprintf("list deployments in %s: %v", rg, err))
				break
			}

			for _, depl := range page.Value {
				deplName := ptrVal(depl.Name)
				deplID := ptrVal(depl.ID)

				if depl.Properties == nil {
					continue
				}

				// 3-5. Scan parameters.
				scanParamMap(ctx, sink, target.SubscriptionID, deplID, rg, deplName, "parameter", depl.Properties.Parameters)
				// 6. Scan outputs.
				scanParamMap(ctx, sink, target.SubscriptionID, deplID, rg, deplName, "output", depl.Properties.Outputs)
			}
		}
	}

	return nil
}

// scanParamMap inspects a parameters or outputs map for leaked secrets.
// The map structure is: key -> {"type": "String", "value": "the-value"}.
func scanParamMap(ctx context.Context, sink findings.Sink, subID, deplID, rg, deplName, source string, raw any) {
	m, ok := raw.(map[string]any)
	if !ok || m == nil {
		return
	}

	for key, entry := range m {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		val, hasValue := entryMap["value"]
		if !hasValue || val == nil {
			// secureString — value is redacted (null). This is correct behavior.
			continue
		}

		valStr := fmt.Sprintf("%v", val)

		// Check value against concrete secret patterns.
		if patName := matchSecretPattern(valStr); patName != "" {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: subID,
				Module:         "arm_deployments",
				Severity:       findings.SevHigh,
				ResourceID:     deplID,
				Title:          fmt.Sprintf("Deployment %s %s %q contains secret (%s pattern)", deplName, source, key, patName),
				Detail: map[string]any{
					"check":           "secret_pattern",
					"deployment":      deplName,
					"resource_group":  rg,
					"source":          source,
					"key":             key,
					"pattern_matched": patName,
					"value":           valStr,
				},
			})
			continue
		}

		// Check key name against suspicious name pattern.
		if secretKeyPattern.MatchString(key) {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: subID,
				Module:         "arm_deployments",
				Severity:       findings.SevMedium,
				ResourceID:     deplID,
				Title:          fmt.Sprintf("Deployment %s %s %q has suspicious name and is not secureString", deplName, source, key),
				Detail: map[string]any{
					"check":          "suspicious_name",
					"deployment":     deplName,
					"resource_group": rg,
					"source":         source,
					"key":            key,
					"reason":         "key name matches secret pattern but parameter type is not secureString",
					"value":          valStr,
				},
			})
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
