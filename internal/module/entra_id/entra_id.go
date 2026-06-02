package entra_id

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module detects Entra ID (Azure AD) misconfigurations via the
// Microsoft Graph REST API.
type Module struct{}

func (Module) Name() string      { return "entra_id" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"Directory.Read.All"}
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	log := func(level, msg string) {
		_ = sink.LogEvent(ctx, "entra_id", target.SubscriptionID, level, msg)
	}
	emit := func(f findings.Finding) {
		f.SubscriptionID = target.SubscriptionID
		f.Module = "entra_id"
		_ = sink.Write(ctx, f)
	}

	log("info", "starting Entra ID checks for tenant "+target.TenantID)

	// 1. Multi-tenant app registrations.
	log("info", "checking multi-tenant app registrations")
	if err := checkMultiTenantApps(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("multi-tenant apps: %v", err))
	}

	// 2. OAuth2 permission grants (admin consent).
	// NOTE: federated identity credential checks (app registrations AND
	// user-assigned managed identities) live in the iam_integrations module.
	log("info", "checking OAuth2 admin-consented permission grants")
	if err := checkOAuth2PermissionGrants(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("oauth2 permission grants: %v", err))
	}

	log("info", "Entra ID checks complete")
	return nil
}

// ---------------------------------------------------------------------------
// Graph API helper
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

// graphList fetches all pages of a collection endpoint and returns every item
// as a slice of json.RawMessage so callers can decode into concrete types.
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
// Check 1 — multi-tenant app registrations
// ---------------------------------------------------------------------------

type appRegistration struct {
	ID             string `json:"id"`
	AppID          string `json:"appId"`
	DisplayName    string `json:"displayName"`
	SignInAudience string `json:"signInAudience"`
}

func checkMultiTenantApps(ctx context.Context, target creds.SubscriptionTarget, emit func(findings.Finding), log func(string, string)) error {
	const url = "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,signInAudience"
	raw, err := graphList(ctx, target.Credential, url)
	if err != nil {
		return err
	}

	log("info", fmt.Sprintf("found %d app registrations", len(raw)))

	for _, r := range raw {
		var app appRegistration
		if err := json.Unmarshal(r, &app); err != nil {
			continue
		}
		switch app.SignInAudience {
		case "AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount":
			emit(findings.Finding{
				Region:     "global",
				Severity:   findings.SevHigh,
				ResourceID: fmt.Sprintf("/tenants/%s/applications/%s", target.TenantID, app.AppID),
				Title:      fmt.Sprintf("App registration %q is multi-tenant (%s)", app.DisplayName, app.SignInAudience),
				Detail: map[string]any{
					"tenant_id":        target.TenantID,
					"app_object_id":    app.ID,
					"app_id":           app.AppID,
					"display_name":     app.DisplayName,
					"sign_in_audience": app.SignInAudience,
				},
			})
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Check 2 — OAuth2 permission grants (admin consent)
// ---------------------------------------------------------------------------

type oauth2PermissionGrant struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"`
	ConsentType string `json:"consentType"`
	ResourceID  string `json:"resourceId"`
	Scope       string `json:"scope"`
}

var dangerousScopeSeverity = map[string]findings.Severity{
	"Directory.ReadWrite.All":            findings.SevCritical,
	"RoleManagement.ReadWrite.Directory": findings.SevCritical,
	"Application.ReadWrite.All":          findings.SevCritical,
	"Mail.ReadWrite":                     findings.SevHigh,
	"Files.ReadWrite.All":                findings.SevHigh,
	"User.ReadWrite.All":                 findings.SevHigh,
}

func checkOAuth2PermissionGrants(ctx context.Context, target creds.SubscriptionTarget, emit func(findings.Finding), log func(string, string)) error {
	// Fetch all permission grants (not just AllPrincipals) to catch dangerous
	// single-principal grants too.
	const url = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
	raw, err := graphList(ctx, target.Credential, url)
	if err != nil {
		return err
	}

	log("info", fmt.Sprintf("found %d OAuth2 permission grants", len(raw)))

	for _, r := range raw {
		var grant oauth2PermissionGrant
		if err := json.Unmarshal(r, &grant); err != nil {
			continue
		}

		scopes := strings.Fields(grant.Scope)
		for _, scope := range scopes {
			sev, ok := dangerousScopeSeverity[scope]
			if !ok {
				continue
			}

			consentLabel := "admin-consented (all principals)"
			if grant.ConsentType != "AllPrincipals" {
				consentLabel = fmt.Sprintf("principal-consented (%s)", grant.ConsentType)
				if sev == findings.SevCritical {
					sev = findings.SevHigh
				}
			}

			emit(findings.Finding{
				Region:     "global",
				Severity:   sev,
				ResourceID: fmt.Sprintf("/tenants/%s/oauth2PermissionGrants/%s", target.TenantID, grant.ID),
				Title:      fmt.Sprintf("Dangerous scope %q %s to service principal %s", scope, consentLabel, grant.ClientID),
				Detail: map[string]any{
					"tenant_id":    target.TenantID,
					"grant_id":     grant.ID,
					"client_id":    grant.ClientID,
					"resource_id":  grant.ResourceID,
					"consent_type": grant.ConsentType,
					"scope":        scope,
					"all_scopes":   grant.Scope,
				},
			})
		}
	}
	return nil
}
