package keyvault_exposure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module inspects Azure Key Vaults for public network access,
// overly permissive access policies, and missing soft-delete / purge protection.
type Module struct{}

func (Module) Name() string      { return "keyvault_exposure" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"Microsoft.KeyVault/vaults/read"}
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	client, err := armkeyvault.NewVaultsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("keyvault_exposure: create client: %w", err)
	}

	// Collect vault resource stubs from the list endpoint.
	type vaultRef struct {
		Name     string
		RG       string
		ID       string
		Location string
	}
	var refs []vaultRef
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("keyvault_exposure: list vaults: %w", err)
		}
		for _, v := range page.Value {
			name := ptrVal(v.Name)
			id := ptrVal(v.ID)
			rg := resourceGroup(id)
			if rg == "" || name == "" {
				continue
			}
			refs = append(refs, vaultRef{
				Name:     name,
				RG:       rg,
				ID:       id,
				Location: ptrVal(v.Location),
			})
		}
	}

	_ = sink.LogEvent(ctx, "keyvault_exposure", target.SubscriptionID, "info",
		fmt.Sprintf("scanning %d Key Vaults", len(refs)))

	for i, ref := range refs {
		_ = sink.LogEvent(ctx, "keyvault_exposure", target.SubscriptionID, "info",
			fmt.Sprintf("vault %d/%d: %s", i+1, len(refs), ref.Name))

		resp, err := client.Get(ctx, ref.RG, ref.Name, nil)
		if err != nil {
			_ = sink.LogEvent(ctx, "keyvault_exposure", target.SubscriptionID, "warn",
				fmt.Sprintf("get vault %s: %v", ref.Name, err))
			continue
		}
		vault := resp.Vault
		if vault.Properties == nil {
			_ = sink.LogEvent(ctx, "keyvault_exposure", target.SubscriptionID, "warn",
				fmt.Sprintf("vault %s: properties nil", ref.Name))
			continue
		}
		props := vault.Properties

		// --- Network exposure checks ---
		exposure := checkNetworkExposure(props)
		publicNetwork := exposure.public
		permissiveCount := countOverlyPermissivePolicies(props)

		_ = sink.LogEvent(ctx, "keyvault_exposure", target.SubscriptionID, "info",
			fmt.Sprintf("vault %s state: publicNetworkAccess=%s defaultAction=%s bypass=%s public=%t bypassAzure=%t permissivePolicies=%d softDelete=%s purgeProtection=%s rbac=%s",
				ref.Name,
				strPtr(props.PublicNetworkAccess),
				networkActionStr(props.NetworkACLs),
				networkBypassStr(props.NetworkACLs),
				publicNetwork, exposure.bypassAzure, permissiveCount,
				boolPtr(props.EnableSoftDelete),
				boolPtr(props.EnablePurgeProtection),
				boolPtr(props.EnableRbacAuthorization),
			))

		if exposure.bypassAzure && !publicNetwork {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         ref.Location,
				Module:         "keyvault_exposure",
				Severity:       findings.SevMedium,
				ResourceID:     ref.ID,
				Title:          fmt.Sprintf("Key Vault %s bypasses firewall for Azure services", ref.Name),
				Detail: map[string]any{
					"vault_name":          ref.Name,
					"default_action":      "Deny",
					"bypass":              "AzureServices",
					"public_network":      false,
				},
			})
		}

		if publicNetwork && permissiveCount > 0 {
			// High: public access combined with overly permissive policies.
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         ref.Location,
				Module:         "keyvault_exposure",
				Severity:       findings.SevHigh,
				ResourceID:     ref.ID,
				Title: fmt.Sprintf("Key Vault %s has public network access with %d overly permissive access policies",
					ref.Name, permissiveCount),
				Detail: map[string]any{
					"vault_name":              ref.Name,
					"public_network_access":   true,
					"permissive_policy_count": permissiveCount,
				},
			})
		} else if publicNetwork {
			// Low: public network access alone.
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         ref.Location,
				Module:         "keyvault_exposure",
				Severity:       findings.SevLow,
				ResourceID:     ref.ID,
				Title:          fmt.Sprintf("Key Vault %s has public network access with no IP restrictions", ref.Name),
				Detail: map[string]any{
					"vault_name":            ref.Name,
					"public_network_access": true,
				},
			})
		}

		if permissiveCount > 0 && !publicNetwork {
			// Still flag overly permissive policies even without public access.
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         ref.Location,
				Module:         "keyvault_exposure",
				Severity:       findings.SevHigh,
				ResourceID:     ref.ID,
				Title: fmt.Sprintf("Key Vault %s has %d overly permissive access policies",
					ref.Name, permissiveCount),
				Detail: map[string]any{
					"vault_name":              ref.Name,
					"permissive_policy_count": permissiveCount,
				},
			})
		}

		// --- Soft-delete check ---
		// Soft-delete is mandatory in Azure since 2020; the API may omit the
		// field (nil) when enabled. Only fire when explicitly false.
		softDeleteEnabled := props.EnableSoftDelete == nil || *props.EnableSoftDelete
		if !softDeleteEnabled {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         ref.Location,
				Module:         "keyvault_exposure",
				Severity:       findings.SevMedium,
				ResourceID:     ref.ID,
				Title:          fmt.Sprintf("Key Vault %s has soft-delete disabled", ref.Name),
				Detail: map[string]any{
					"vault_name":  ref.Name,
					"soft_delete": false,
				},
			})
		}

		// --- Purge protection check (only relevant if soft-delete is enabled) ---
		if softDeleteEnabled {
			purgeProtection := props.EnablePurgeProtection != nil && *props.EnablePurgeProtection
			if !purgeProtection {
				_ = sink.Write(ctx, findings.Finding{
					SubscriptionID: target.SubscriptionID,
					Region:         ref.Location,
					Module:         "keyvault_exposure",
					Severity:       findings.SevMedium,
					ResourceID:     ref.ID,
					Title:          fmt.Sprintf("Key Vault %s has purge protection disabled", ref.Name),
					Detail: map[string]any{
						"vault_name":       ref.Name,
						"purge_protection": false,
					},
				})
			}
		}
	}

	return nil
}

// networkExposure describes how a vault is exposed.
type networkExposure struct {
	public        bool
	bypassAzure   bool
}

// checkNetworkExposure evaluates the vault's network configuration.
func checkNetworkExposure(props *armkeyvault.VaultProperties) networkExposure {
	if props.PublicNetworkAccess != nil && strings.EqualFold(*props.PublicNetworkAccess, "Disabled") {
		return networkExposure{}
	}
	if props.NetworkACLs == nil {
		return networkExposure{public: true}
	}
	acls := props.NetworkACLs
	if acls.DefaultAction == nil || *acls.DefaultAction == armkeyvault.NetworkRuleActionAllow {
		return networkExposure{public: true}
	}
	// DefaultAction is Deny — check if Bypass allows AzureServices.
	bypass := false
	if acls.Bypass != nil && *acls.Bypass == armkeyvault.NetworkRuleBypassOptionsAzureServices {
		bypass = true
	}
	return networkExposure{bypassAzure: bypass}
}

// isPublicAccess returns true when the vault's network configuration allows
// unrestricted public access.
func isPublicAccess(props *armkeyvault.VaultProperties) bool {
	return checkNetworkExposure(props).public
}

// countOverlyPermissivePolicies counts access policies where any permission
// category contains "all".
func countOverlyPermissivePolicies(props *armkeyvault.VaultProperties) int {
	count := 0
	for _, policy := range props.AccessPolicies {
		if policy.Permissions == nil {
			continue
		}
		if hasAllSecretPerm(policy.Permissions.Secrets) ||
			hasAllKeyPerm(policy.Permissions.Keys) ||
			hasAllCertPerm(policy.Permissions.Certificates) {
			count++
		}
	}
	return count
}

func hasAllSecretPerm(perms []*armkeyvault.SecretPermissions) bool {
	for _, p := range perms {
		if p != nil && strings.EqualFold(string(*p), "all") {
			return true
		}
	}
	return false
}

func hasAllKeyPerm(perms []*armkeyvault.KeyPermissions) bool {
	for _, p := range perms {
		if p != nil && strings.EqualFold(string(*p), "all") {
			return true
		}
	}
	return false
}

func hasAllCertPerm(perms []*armkeyvault.CertificatePermissions) bool {
	for _, p := range perms {
		if p != nil && strings.EqualFold(string(*p), "all") {
			return true
		}
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

func strPtr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func boolPtr(p *bool) string {
	if p == nil {
		return "<nil>"
	}
	if *p {
		return "true"
	}
	return "false"
}

func networkActionStr(acls *armkeyvault.NetworkRuleSet) string {
	if acls == nil {
		return "<nil-acls>"
	}
	if acls.DefaultAction == nil {
		return "<nil>"
	}
	return string(*acls.DefaultAction)
}

func networkBypassStr(acls *armkeyvault.NetworkRuleSet) string {
	if acls == nil || acls.Bypass == nil {
		return "<nil>"
	}
	return string(*acls.Bypass)
}
