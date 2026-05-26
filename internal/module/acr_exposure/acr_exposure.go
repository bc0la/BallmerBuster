package acr_exposure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module inspects Azure Container Registries for admin user access,
// public network exposure, and missing customer-managed encryption.
type Module struct{}

func (Module) Name() string      { return "acr_exposure" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"Microsoft.ContainerRegistry/registries/read"}
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	client, err := armcontainerregistry.NewRegistriesClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("acr_exposure: create client: %w", err)
	}

	var registries []*armcontainerregistry.Registry
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("acr_exposure: list registries: %w", err)
		}
		registries = append(registries, page.Value...)
	}

	_ = sink.LogEvent(ctx, "acr_exposure", target.SubscriptionID, "info",
		fmt.Sprintf("scanning %d container registries", len(registries)))

	for i, reg := range registries {
		regName := ptrVal(reg.Name)
		regID := ptrVal(reg.ID)
		location := ptrVal(reg.Location)

		_ = sink.LogEvent(ctx, "acr_exposure", target.SubscriptionID, "info",
			fmt.Sprintf("registry %d/%d: %s", i+1, len(registries), regName))

		if reg.Properties == nil {
			continue
		}
		props := reg.Properties

		// Admin user enabled — credentials are often leaked.
		if props.AdminUserEnabled != nil && *props.AdminUserEnabled {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         location,
				Module:         "acr_exposure",
				Severity:       findings.SevMedium,
				ResourceID:     regID,
				Title:          fmt.Sprintf("Container registry %s has admin user enabled", regName),
				Detail: map[string]any{
					"registry_name": regName,
					"admin_user":    true,
				},
			})
		}

		// Public network access with no restrictions.
		publicAccess := isPublicAccess(props)
		if publicAccess {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         location,
				Module:         "acr_exposure",
				Severity:       findings.SevMedium,
				ResourceID:     regID,
				Title:          fmt.Sprintf("Container registry %s has unrestricted public network access", regName),
				Detail: map[string]any{
					"registry_name":         regName,
					"public_network_access": true,
				},
			})
		}

		// No customer-managed key encryption.
		if props.Encryption == nil || ptrVal(props.Encryption.Status) != armcontainerregistry.EncryptionStatusEnabled {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         location,
				Module:         "acr_exposure",
				Severity:       findings.SevInfo,
				ResourceID:     regID,
				Title:          fmt.Sprintf("Container registry %s does not use customer-managed key encryption", regName),
				Detail: map[string]any{
					"registry_name": regName,
					"cmk_enabled":   false,
				},
			})
		}
	}

	return nil
}

// isPublicAccess returns true when the registry allows unrestricted public
// network access.
func isPublicAccess(props *armcontainerregistry.RegistryProperties) bool {
	if props.PublicNetworkAccess != nil && *props.PublicNetworkAccess == armcontainerregistry.PublicNetworkAccessDisabled {
		return false
	}
	// PublicNetworkAccess is Enabled or not set — check NetworkRuleSet.
	if props.NetworkRuleSet == nil {
		return true
	}
	if props.NetworkRuleSet.DefaultAction == nil ||
		*props.NetworkRuleSet.DefaultAction == armcontainerregistry.DefaultActionAllow {
		return true
	}
	return false
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
