package aci_env

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module scans Azure Container Instances for plaintext environment variables
// that contain secrets, and flags container groups with public IP addresses.
type Module struct{}

func (Module) Name() string      { return "aci_env" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"Microsoft.ContainerInstance/containerGroups/read"}
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
	client, err := armcontainerinstance.NewContainerGroupsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("aci_env: create container groups client: %w", err)
	}

	// 1. List all container groups.
	var groups []*armcontainerinstance.ContainerGroup
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("aci_env: list container groups: %w", err)
		}
		groups = append(groups, page.Value...)
	}

	_ = sink.LogEvent(ctx, "aci_env", target.SubscriptionID, "info",
		fmt.Sprintf("scanning %d container groups", len(groups)))

	for i, cg := range groups {
		cgName := ptrVal(cg.Name)
		cgID := ptrVal(cg.ID)
		location := ptrVal(cg.Location)

		_ = sink.LogEvent(ctx, "aci_env", target.SubscriptionID, "info",
			fmt.Sprintf("container group %d/%d: %s", i+1, len(groups), cgName))

		if cg.Properties == nil {
			continue
		}

		// 7. Flag container groups with public IP.
		if cg.Properties.IPAddress != nil && cg.Properties.IPAddress.Type != nil {
			if *cg.Properties.IPAddress.Type == armcontainerinstance.ContainerGroupIPAddressTypePublic {
				_ = sink.Write(ctx, findings.Finding{
					SubscriptionID: target.SubscriptionID,
					Region:         location,
					Module:         "aci_env",
					Severity:       findings.SevMedium,
					ResourceID:     cgID,
					Title:          fmt.Sprintf("Container group %s has a public IP address", cgName),
					Detail: map[string]any{
						"check":           "public_ip",
						"container_group": cgName,
						"ip_type":         "Public",
						"ip_address":      ptrVal(cg.Properties.IPAddress.IP),
					},
				})
			}
		}

		// 2-5. Scan regular containers.
		for _, container := range cg.Properties.Containers {
			containerName := ptrVal(container.Name)
			if container.Properties == nil {
				continue
			}
			scanEnvVars(ctx, sink, target.SubscriptionID, location, cgID, cgName, containerName, container.Properties.EnvironmentVariables)
		}

		// 6. Scan init containers.
		for _, initContainer := range cg.Properties.InitContainers {
			containerName := ptrVal(initContainer.Name)
			if initContainer.Properties == nil {
				continue
			}
			scanEnvVars(ctx, sink, target.SubscriptionID, location, cgID, cgName, containerName, initContainer.Properties.EnvironmentVariables)
		}
	}

	return nil
}

// scanEnvVars inspects a slice of environment variables for leaked secrets.
func scanEnvVars(ctx context.Context, sink findings.Sink, subID, location, cgID, cgName, containerName string, envVars []*armcontainerinstance.EnvironmentVariable) {
	for _, ev := range envVars {
		if ev == nil {
			continue
		}

		name := ptrVal(ev.Name)
		value := ptrVal(ev.Value)

		// If value is empty, this is likely a secureValue (redacted). Skip.
		if value == "" {
			continue
		}

		// Check value against concrete secret patterns.
		if patName := matchSecretPattern(value); patName != "" {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: subID,
				Region:         location,
				Module:         "aci_env",
				Severity:       findings.SevHigh,
				ResourceID:     cgID,
				Title:          fmt.Sprintf("Container %s/%s env var %q matches secret pattern (%s)", cgName, containerName, name, patName),
				Detail: map[string]any{
					"check":           "secret_pattern",
					"container_group": cgName,
					"container":       containerName,
					"env_var_name":    name,
					"pattern_matched": patName,
					"value":           value,
				},
			})
			continue
		}

		// Check key name against suspicious name pattern.
		if secretKeyPattern.MatchString(name) {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: subID,
				Region:         location,
				Module:         "aci_env",
				Severity:       findings.SevMedium,
				ResourceID:     cgID,
				Title:          fmt.Sprintf("Container %s/%s env var %q has suspicious name (plaintext, not secureValue)", cgName, containerName, name),
				Detail: map[string]any{
					"check":           "suspicious_name",
					"container_group": cgName,
					"container":       containerName,
					"env_var_name":    name,
					"reason":          "key name matches secret pattern and value is plaintext (not secureValue)",
					"value":           value,
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
