package external_trust

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module surfaces external-trust and federated-credential takeover surface:
// federated identity credentials (on app registrations and user-assigned
// managed identities) and cross-tenant access policy partners. These are
// high-volume, manual-review-heavy findings, split out from iam_integrations
// so they get their own report tab and can be skipped with --no-external-trust.
// (Dangling OAuth redirect/reply URIs live in the redirect_uris module.)
type Module struct{}

func (Module) Name() string      { return "external_trust" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Directory.Read.All",
		"Application.Read.All",
		"Microsoft.ManagedIdentity/userAssignedIdentities/read",
		"Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read",
	}
}

// seenTenant tracks tenants whose tenant-wide Microsoft Graph checks have
// already run, so they are not duplicated across subscriptions in the same
// tenant. LoadOrStore is atomic, electing a single winner per tenant.
var seenTenant sync.Map

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	log := func(level, msg string) {
		_ = sink.LogEvent(ctx, "external_trust", target.SubscriptionID, level, msg)
	}
	emit := func(f findings.Finding) {
		f.SubscriptionID = target.SubscriptionID
		f.Module = "external_trust"
		_ = sink.Write(ctx, f)
	}

	log("info", "starting external-trust / federated-credential checks for subscription "+target.SubscriptionID+" (tenant "+target.TenantID+")")

	// --- Subscription-scoped (ARM) check — run for every subscription. ---
	log("info", "checking federated identity credentials on managed identities")
	if err := checkManagedIdentityFICs(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("managed identity federated credentials: %v", err))
	}

	// --- Tenant-scoped (Microsoft Graph) checks — run once per tenant. ---
	if _, already := seenTenant.LoadOrStore(target.TenantID, true); already {
		log("info", fmt.Sprintf("tenant-wide Graph checks already run for tenant %s via another subscription — skipping to avoid duplicates", target.TenantID))
		log("info", "external-trust checks complete")
		return nil
	}

	// Federated identity credentials on app registrations.
	log("info", "checking federated identity credentials on app registrations")
	if err := checkAppRegistrationFICs(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("app registration federated credentials: %v", err))
	}

	// Cross-tenant access policy partners.
	log("info", "checking cross-tenant access policy partners")
	if err := checkCrossTenantAccess(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("cross-tenant access: %v", err))
	}

	log("info", "external-trust checks complete")
	return nil
}

// ---------------------------------------------------------------------------
// Graph API helpers
// ---------------------------------------------------------------------------

func graphGet(ctx context.Context, cred azcore.TokenCredential, url string, result any) error {
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("graph API %s: %d %s", url, resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(result)
}

func graphList(ctx context.Context, cred azcore.TokenCredential, url string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	for url != "" {
		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := graphGet(ctx, cred, url, &page); err != nil {
			return all, err
		}
		all = append(all, page.Value...)
		url = page.NextLink
	}
	return all, nil
}

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

func ptrVal[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
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

func boolVal(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// ---------------------------------------------------------------------------
// Cross-tenant access settings (Graph API)
// ---------------------------------------------------------------------------

func checkCrossTenantAccess(ctx context.Context, target creds.SubscriptionTarget,
	emit func(findings.Finding), log func(string, string)) error {

	const url = "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners"
	raw, err := graphList(ctx, target.Credential, url)
	if err != nil {
		return err
	}

	log("info", fmt.Sprintf("found %d cross-tenant access policy partners", len(raw)))

	for _, r := range raw {
		var partner struct {
			TenantID     string `json:"tenantId"`
			InboundTrust *struct {
				IsMFAAccepted                 *bool `json:"isMfaAccepted"`
				IsCompliantDeviceAccepted     *bool `json:"isCompliantDeviceAccepted"`
				IsHybridAzureADJoinedAccepted *bool `json:"isHybridAzureADJoinedAccepted"`
			} `json:"inboundTrust"`
			B2BCollaborationInbound *struct {
				Applications *struct {
					AccessType string `json:"accessType"`
				} `json:"applications"`
			} `json:"b2bCollaborationInbound"`
		}
		if err := json.Unmarshal(r, &partner); err != nil {
			continue
		}

		partnerTenantID := partner.TenantID

		broadAccess := false
		if partner.B2BCollaborationInbound != nil &&
			partner.B2BCollaborationInbound.Applications != nil &&
			strings.EqualFold(partner.B2BCollaborationInbound.Applications.AccessType, "allowed") {
			broadAccess = true
		}

		hasInboundTrust := false
		if partner.InboundTrust != nil {
			if boolVal(partner.InboundTrust.IsMFAAccepted) ||
				boolVal(partner.InboundTrust.IsCompliantDeviceAccepted) ||
				boolVal(partner.InboundTrust.IsHybridAzureADJoinedAccepted) {
				hasInboundTrust = true
			}
		}

		sev := findings.SevMedium
		title := fmt.Sprintf("Cross-tenant inbound trust configured for tenant %s", partnerTenantID)

		switch {
		case broadAccess && hasInboundTrust:
			sev = findings.SevHigh
			title = fmt.Sprintf("Cross-tenant partner %s has inbound trust AND allows all applications", partnerTenantID)
		case broadAccess:
			sev = findings.SevHigh
			title = fmt.Sprintf("Cross-tenant partner %s allows all applications for B2B collaboration", partnerTenantID)
		case !hasInboundTrust && !broadAccess:
			sev = findings.SevInfo
			title = fmt.Sprintf("Cross-tenant partner %s configured (no inbound trust, no broad app access)", partnerTenantID)
		}

		detail := map[string]any{
			"tenant_id":         target.TenantID,
			"partner_tenant_id": partnerTenantID,
			"has_inbound_trust": hasInboundTrust,
			"broad_app_access":  broadAccess,
		}
		if partner.B2BCollaborationInbound != nil && partner.B2BCollaborationInbound.Applications != nil {
			detail["b2b_inbound_access_type"] = partner.B2BCollaborationInbound.Applications.AccessType
		}
		if partner.InboundTrust != nil {
			detail["mfa_accepted"] = boolVal(partner.InboundTrust.IsMFAAccepted)
			detail["compliant_device_accepted"] = boolVal(partner.InboundTrust.IsCompliantDeviceAccepted)
			detail["hybrid_ad_joined_accepted"] = boolVal(partner.InboundTrust.IsHybridAzureADJoinedAccepted)
		}

		emit(findings.Finding{
			Region:     "global",
			Severity:   sev,
			ResourceID: fmt.Sprintf("/tenants/%s/policies/crossTenantAccessPolicy/partners/%s", target.TenantID, partnerTenantID),
			Title:      title,
			Detail:     detail,
		})
	}
	return nil
}
