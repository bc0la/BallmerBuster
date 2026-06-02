package iam_integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module performs comprehensive identity and access management analysis —
// the Azure equivalent of BezosBuster's iam_integrations which checks
// SAML/OIDC providers, role trust policies, confused deputy, and Cognito.
type Module struct{}

func (Module) Name() string      { return "iam_integrations" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Compute/virtualMachines/read",
		"Microsoft.Authorization/roleAssignments/read",
		"Microsoft.ManagedIdentity/userAssignedIdentities/read",
		"Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read",
		"Directory.Read.All",
		"Application.Read.All",
	}
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	log := func(level, msg string) {
		_ = sink.LogEvent(ctx, "iam_integrations", target.SubscriptionID, level, msg)
	}
	emit := func(f findings.Finding) {
		f.SubscriptionID = target.SubscriptionID
		f.Module = "iam_integrations"
		_ = sink.Write(ctx, f)
	}

	log("info", "starting IAM integration checks for subscription "+target.SubscriptionID+" (tenant "+target.TenantID+")")

	// 1. Managed identity exposure (ARM SDK).
	log("info", "checking managed identity exposure on VMs")
	if err := checkManagedIdentityExposure(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("managed identity exposure: %v", err))
	}

	// 2. Enterprise apps with no assignment required (Graph API).
	log("info", "checking enterprise apps without user assignment requirement")
	if err := checkNoAssignmentRequired(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("enterprise app assignment: %v", err))
	}

	// 3. Service principals with dangerous API permissions (Graph API).
	log("info", "checking service principals for dangerous API permissions")
	if err := checkDangerousAppPermissions(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("dangerous API permissions: %v", err))
	}

	// 4. Cross-tenant access settings (Graph API).
	log("info", "checking cross-tenant access policy partners")
	if err := checkCrossTenantAccess(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("cross-tenant access: %v", err))
	}

	// 5. Federated identity credentials on app registrations (Graph API).
	log("info", "checking federated identity credentials on app registrations")
	if err := checkAppRegistrationFICs(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("app registration federated credentials: %v", err))
	}

	// 6. Federated identity credentials on user-assigned managed identities (ARM).
	log("info", "checking federated identity credentials on managed identities")
	if err := checkManagedIdentityFICs(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("managed identity federated credentials: %v", err))
	}

	// 7. Dangling OAuth redirect / reply / logout URIs (Graph API + DNS).
	log("info", "checking redirect/reply URIs for dangling hosts")
	if err := checkDanglingRedirectURIs(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("dangling redirect URIs: %v", err))
	}

	log("info", "IAM integration checks complete")
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
	// Required for $filter on advanced properties (servicePrincipalType, etc.).
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
// Helpers
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

func lastSegment(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// ---------------------------------------------------------------------------
// Check 1 — Managed Identity Exposure (ARM SDK)
// ---------------------------------------------------------------------------

// dangerousRoleNames maps built-in role definition GUIDs to their names.
var dangerousRoleNames = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
}

// roleSeverity returns the severity for a dangerous role assignment on a
// managed identity. Owner and User Access Administrator are Critical
// (full tenant takeover), Contributor is High.
func roleSeverity(roleName string) findings.Severity {
	switch roleName {
	case "Owner", "User Access Administrator":
		return findings.SevCritical
	case "Contributor":
		return findings.SevHigh
	default:
		return findings.SevHigh
	}
}

func checkManagedIdentityExposure(ctx context.Context, target creds.SubscriptionTarget,
	emit func(findings.Finding), log func(string, string)) error {

	// List all VMs in the subscription.
	vmClient, err := armcompute.NewVirtualMachinesClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("create VM client: %w", err)
	}

	var vms []*armcompute.VirtualMachine
	pager := vmClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list VMs: %w", err)
		}
		vms = append(vms, page.Value...)
	}

	log("info", fmt.Sprintf("found %d VMs, filtering for managed identities", len(vms)))

	// Collect all principal IDs from VMs with managed identities.
	type vmIdentity struct {
		vmName      string
		vmID        string
		principalID string
		identType   string // "SystemAssigned" or "UserAssigned"
		uamiName    string // populated only for user-assigned
	}

	var identities []vmIdentity
	for _, vm := range vms {
		if vm.Identity == nil {
			continue
		}
		vmName := ptrVal(vm.Name)
		vmID := ptrVal(vm.ID)

		// System-assigned identity.
		if vm.Identity.PrincipalID != nil && ptrVal(vm.Identity.PrincipalID) != "" {
			identities = append(identities, vmIdentity{
				vmName:      vmName,
				vmID:        vmID,
				principalID: ptrVal(vm.Identity.PrincipalID),
				identType:   "SystemAssigned",
			})
		}

		// User-assigned identities.
		for uamiID, uami := range vm.Identity.UserAssignedIdentities {
			if uami == nil || uami.PrincipalID == nil {
				continue
			}
			identities = append(identities, vmIdentity{
				vmName:      vmName,
				vmID:        vmID,
				principalID: ptrVal(uami.PrincipalID),
				identType:   "UserAssigned",
				uamiName:    lastSegment(uamiID),
			})
		}
	}

	if len(identities) == 0 {
		log("info", "no VMs with managed identities found")
		return nil
	}

	log("info", fmt.Sprintf("found %d managed identity principals across VMs, checking role assignments", len(identities)))

	// Build a set of principal IDs for fast lookup.
	principalSet := make(map[string][]vmIdentity)
	for _, id := range identities {
		principalSet[id.principalID] = append(principalSet[id.principalID], id)
	}

	// List all role assignments in the subscription.
	raClient, err := armauthorization.NewRoleAssignmentsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("create role assignments client: %w", err)
	}

	raPager := raClient.NewListForSubscriptionPager(nil)
	for raPager.More() {
		page, err := raPager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list role assignments: %w", err)
		}
		for _, ra := range page.Value {
			if ra.Properties == nil {
				continue
			}
			principalID := ptrVal(ra.Properties.PrincipalID)
			vmIdents, ok := principalSet[principalID]
			if !ok {
				continue
			}

			roleDefID := ptrVal(ra.Properties.RoleDefinitionID)
			roleDefName := lastSegment(roleDefID)
			roleName, isDangerous := dangerousRoleNames[roleDefName]
			if !isDangerous {
				continue
			}

			scope := ptrVal(ra.Properties.Scope)
			sev := roleSeverity(roleName)

			for _, vmi := range vmIdents {
				identLabel := vmi.identType
				if vmi.uamiName != "" {
					identLabel = fmt.Sprintf("UserAssigned(%s)", vmi.uamiName)
				}

				emit(findings.Finding{
					Region:     resourceGroup(vmi.vmID),
					Severity:   sev,
					ResourceID: vmi.vmID,
					Title: fmt.Sprintf("VM %q %s managed identity has %s role — SSRF to IMDS can escalate to %s",
						vmi.vmName, identLabel, roleName, roleName),
					Detail: map[string]any{
						"vm_name":            vmi.vmName,
						"vm_id":              vmi.vmID,
						"principal_id":       vmi.principalID,
						"identity_type":      vmi.identType,
						"uami_name":          vmi.uamiName,
						"role":               roleName,
						"role_definition_id": roleDefID,
						"scope":              scope,
						"assignment_id":      ptrVal(ra.ID),
					},
				})
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Check 2 — Enterprise Apps with No Assignment Required (Graph API)
// ---------------------------------------------------------------------------

type spBasic struct {
	ID                        string `json:"id"`
	AppID                     string `json:"appId"`
	DisplayName               string `json:"displayName"`
	AppRoleAssignmentRequired bool   `json:"appRoleAssignmentRequired"`
}

func checkNoAssignmentRequired(ctx context.Context, target creds.SubscriptionTarget,
	emit func(findings.Finding), log func(string, string)) error {

	const url = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appRoleAssignmentRequired&$filter=servicePrincipalType eq 'Application'"
	raw, err := graphList(ctx, target.Credential, url)
	if err != nil {
		return err
	}

	log("info", fmt.Sprintf("found %d application service principals", len(raw)))

	for _, r := range raw {
		var sp spBasic
		if err := json.Unmarshal(r, &sp); err != nil {
			continue
		}
		if sp.AppRoleAssignmentRequired {
			continue
		}

		emit(findings.Finding{
			Region:     "global",
			Severity:   findings.SevMedium,
			ResourceID: fmt.Sprintf("/tenants/%s/servicePrincipals/%s", target.TenantID, sp.ID),
			Title:      fmt.Sprintf("Enterprise app %q does not require user assignment", sp.DisplayName),
			Detail: map[string]any{
				"tenant_id":    target.TenantID,
				"sp_id":        sp.ID,
				"app_id":       sp.AppID,
				"display_name": sp.DisplayName,
			},
		})
	}
	return nil
}

// ---------------------------------------------------------------------------
// Check 3 — Service Principals with Dangerous API Permissions (Graph API)
// ---------------------------------------------------------------------------

// dangerousAppRoles maps Microsoft Graph application permission values to
// their severity.
var dangerousAppRoles = map[string]findings.Severity{
	"Directory.ReadWrite.All":            findings.SevCritical,
	"RoleManagement.ReadWrite.Directory": findings.SevCritical,
	"Application.ReadWrite.All":          findings.SevCritical,
	"Mail.ReadWrite":                     findings.SevHigh,
	"Mail.Send":                          findings.SevHigh,
	"Files.ReadWrite.All":                findings.SevHigh,
	"User.ReadWrite.All":                 findings.SevHigh,
	"GroupMember.ReadWrite.All":          findings.SevHigh,
	"Sites.ReadWrite.All":                findings.SevHigh,
}

type appRoleAssignment struct {
	ID                  string `json:"id"`
	AppRoleID           string `json:"appRoleId"`
	ResourceDisplayName string `json:"resourceDisplayName"`
	ResourceID          string `json:"resourceId"`
}

type appRole struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

func checkDangerousAppPermissions(ctx context.Context, target creds.SubscriptionTarget,
	emit func(findings.Finding), log func(string, string)) error {

	// Step 1: list all application service principals.
	const spURL = "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=servicePrincipalType eq 'Application'&$select=id,appId,displayName"
	spRaw, err := graphList(ctx, target.Credential, spURL)
	if err != nil {
		return err
	}

	log("info", fmt.Sprintf("checking app role assignments for %d service principals", len(spRaw)))

	// Step 2: fetch and cache the Microsoft Graph service principal's appRoles
	// so we can resolve appRoleId -> role value.
	graphRoleMap, err := buildGraphRoleMap(ctx, target.Credential)
	if err != nil {
		log("warn", fmt.Sprintf("could not fetch Microsoft Graph app roles (will skip role resolution): %v", err))
		graphRoleMap = map[string]string{} // proceed without role resolution
	}

	// Step 3: for each SP, list its appRoleAssignments and check for dangerous ones.
	for _, r := range spRaw {
		var sp struct {
			ID          string `json:"id"`
			AppID       string `json:"appId"`
			DisplayName string `json:"displayName"`
		}
		if err := json.Unmarshal(r, &sp); err != nil {
			continue
		}

		araURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoleAssignments?$select=id,appRoleId,resourceDisplayName,resourceId", sp.ID)
		araRaw, err := graphList(ctx, target.Credential, araURL)
		if err != nil {
			log("warn", fmt.Sprintf("list appRoleAssignments for SP %s (%s): %v", sp.DisplayName, sp.ID, err))
			continue
		}

		for _, ar := range araRaw {
			var assignment appRoleAssignment
			if err := json.Unmarshal(ar, &assignment); err != nil {
				continue
			}

			// Only check Microsoft Graph assignments.
			if assignment.ResourceDisplayName != "Microsoft Graph" {
				continue
			}

			roleValue, ok := graphRoleMap[assignment.AppRoleID]
			if !ok {
				continue
			}

			sev, isDangerous := dangerousAppRoles[roleValue]
			if !isDangerous {
				continue
			}

			emit(findings.Finding{
				Region:     "global",
				Severity:   sev,
				ResourceID: fmt.Sprintf("/tenants/%s/servicePrincipals/%s", target.TenantID, sp.ID),
				Title: fmt.Sprintf("Service principal %q has dangerous Graph permission %s",
					sp.DisplayName, roleValue),
				Detail: map[string]any{
					"tenant_id":     target.TenantID,
					"sp_id":         sp.ID,
					"app_id":        sp.AppID,
					"display_name":  sp.DisplayName,
					"role_value":    roleValue,
					"app_role_id":   assignment.AppRoleID,
					"assignment_id": assignment.ID,
					"resource_id":   assignment.ResourceID,
				},
			})
		}
	}
	return nil
}

// buildGraphRoleMap fetches the Microsoft Graph service principal and returns
// a map from appRole ID -> appRole value (e.g. "Directory.ReadWrite.All").
func buildGraphRoleMap(ctx context.Context, cred azcore.TokenCredential) (map[string]string, error) {
	const url = "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=displayName eq 'Microsoft Graph'&$select=id,appRoles"
	raw, err := graphList(ctx, cred, url)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("Microsoft Graph service principal not found")
	}

	var graphSP struct {
		ID       string    `json:"id"`
		AppRoles []appRole `json:"appRoles"`
	}
	if err := json.Unmarshal(raw[0], &graphSP); err != nil {
		return nil, fmt.Errorf("unmarshal Graph SP: %w", err)
	}

	roleMap := make(map[string]string, len(graphSP.AppRoles))
	for _, r := range graphSP.AppRoles {
		roleMap[r.ID] = r.Value
	}
	return roleMap, nil
}

// ---------------------------------------------------------------------------
// Check 4 — Cross-Tenant Access Settings (Graph API)
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

		// Check for broad application access — all apps allowed inbound.
		broadAccess := false
		if partner.B2BCollaborationInbound != nil &&
			partner.B2BCollaborationInbound.Applications != nil &&
			strings.EqualFold(partner.B2BCollaborationInbound.Applications.AccessType, "allowed") {
			broadAccess = true
		}

		// Check for inbound trust (accepting MFA/compliance claims from partner).
		hasInboundTrust := false
		if partner.InboundTrust != nil {
			if boolVal(partner.InboundTrust.IsMFAAccepted) ||
				boolVal(partner.InboundTrust.IsCompliantDeviceAccepted) ||
				boolVal(partner.InboundTrust.IsHybridAzureADJoinedAccepted) {
				hasInboundTrust = true
			}
		}

		// Every cross-tenant partner is an external trust relationship —
		// surface all of them. Benign partners (no inbound trust, no broad
		// app access) become info findings so the analyst can review every
		// external tenant the directory trusts.
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

func boolVal(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}
