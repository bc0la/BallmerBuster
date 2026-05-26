package entra_id

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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

	// 2. Service principals with password credentials.
	log("info", "checking service principal password credentials")
	if err := checkSPPasswordCredentials(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("service principal passwords: %v", err))
	}

	// 3. Federated identity credentials.
	log("info", "checking federated identity credentials")
	if err := checkFederatedIdentityCredentials(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("federated identity credentials: %v", err))
	}

	// 4. OAuth2 permission grants (admin consent).
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
// Check 2 — service principals with password credentials
// ---------------------------------------------------------------------------

type passwordCredential struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
	StartDT     string `json:"startDateTime"`
	EndDT       string `json:"endDateTime"`
}

type servicePrincipal struct {
	ID                  string               `json:"id"`
	AppID               string               `json:"appId"`
	DisplayName         string               `json:"displayName"`
	PasswordCredentials []passwordCredential `json:"passwordCredentials"`
}

func checkSPPasswordCredentials(ctx context.Context, target creds.SubscriptionTarget, emit func(findings.Finding), log func(string, string)) error {
	const url = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,passwordCredentials&$filter=servicePrincipalType eq 'Application'"
	raw, err := graphList(ctx, target.Credential, url)
	if err != nil {
		return err
	}

	log("info", fmt.Sprintf("found %d application service principals", len(raw)))

	now := time.Now().UTC()
	twoYears := 2 * 365 * 24 * time.Hour

	for _, r := range raw {
		var sp servicePrincipal
		if err := json.Unmarshal(r, &sp); err != nil {
			continue
		}
		if len(sp.PasswordCredentials) == 0 {
			continue
		}

		for _, pc := range sp.PasswordCredentials {
			sev := findings.SevMedium
			title := fmt.Sprintf("Service principal %q has password credential %q", sp.DisplayName, pc.DisplayName)

			startTime, _ := time.Parse(time.RFC3339, pc.StartDT)
			endTime, endErr := time.Parse(time.RFC3339, pc.EndDT)

			longLived := false
			expired := false

			if endErr == nil {
				if !startTime.IsZero() && endTime.Sub(startTime) > twoYears {
					longLived = true
					sev = findings.SevHigh
					title = fmt.Sprintf("Service principal %q has long-lived (>2yr) password credential %q", sp.DisplayName, pc.DisplayName)
				}
				if endTime.Before(now) {
					expired = true
					sev = findings.SevHigh
					title = fmt.Sprintf("Service principal %q has expired but unremoved password credential %q", sp.DisplayName, pc.DisplayName)
				}
			}

			emit(findings.Finding{
				Region:     "global",
				Severity:   sev,
				ResourceID: fmt.Sprintf("/tenants/%s/servicePrincipals/%s", target.TenantID, sp.ID),
				Title:      title,
				Detail: map[string]any{
					"tenant_id":       target.TenantID,
					"sp_id":           sp.ID,
					"app_id":          sp.AppID,
					"display_name":    sp.DisplayName,
					"credential_id":   pc.KeyID,
					"credential_name": pc.DisplayName,
					"start_date":      pc.StartDT,
					"end_date":        pc.EndDT,
					"long_lived":      longLived,
					"expired":         expired,
				},
			})
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Check 3 — federated identity credentials
// ---------------------------------------------------------------------------

type federatedIdentityCredential struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Description string   `json:"description"`
	Audiences   []string `json:"audiences"`
}

func checkFederatedIdentityCredentials(ctx context.Context, target creds.SubscriptionTarget, emit func(findings.Finding), log func(string, string)) error {
	// First, get all app registrations (we need the object IDs).
	const appsURL = "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName"
	raw, err := graphList(ctx, target.Credential, appsURL)
	if err != nil {
		return err
	}

	log("info", fmt.Sprintf("checking federated identity credentials on %d app registrations", len(raw)))

	for _, r := range raw {
		var app appRegistration
		if err := json.Unmarshal(r, &app); err != nil {
			continue
		}

		fedURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/applications/%s/federatedIdentityCredentials", app.ID)
		fedRaw, err := graphList(ctx, target.Credential, fedURL)
		if err != nil {
			log("warn", fmt.Sprintf("list federated creds for app %s: %v", app.DisplayName, err))
			continue
		}

		for _, fr := range fedRaw {
			var fic federatedIdentityCredential
			if err := json.Unmarshal(fr, &fic); err != nil {
				continue
			}

			sev, title := evaluateFederatedCredential(app, fic, target.TenantID)
			if sev == "" {
				continue
			}

			emit(findings.Finding{
				Region:     "global",
				Severity:   sev,
				ResourceID: fmt.Sprintf("/tenants/%s/applications/%s/federatedIdentityCredentials/%s", target.TenantID, app.AppID, fic.ID),
				Title:      title,
				Detail: map[string]any{
					"tenant_id":    target.TenantID,
					"app_id":       app.AppID,
					"display_name": app.DisplayName,
					"fic_id":       fic.ID,
					"fic_name":     fic.Name,
					"issuer":       fic.Issuer,
					"subject":      fic.Subject,
					"audiences":    fic.Audiences,
					"description":  fic.Description,
				},
			})
		}
	}
	return nil
}

func evaluateFederatedCredential(app appRegistration, fic federatedIdentityCredential, tenantID string) (findings.Severity, string) {
	subject := fic.Subject
	issuer := fic.Issuer

	isGitHub := strings.Contains(issuer, "token.actions.githubusercontent.com")

	// Wildcard or empty subject is critical.
	if subject == "*" || subject == "" {
		return findings.SevCritical, fmt.Sprintf("App %q has federated credential %q with unrestricted subject", app.DisplayName, fic.Name)
	}

	if isGitHub {
		// repo:* — matches everything.
		if subject == "repo:*" {
			return findings.SevCritical, fmt.Sprintf("App %q has GitHub OIDC credential %q with wildcard repo subject", app.DisplayName, fic.Name)
		}
		// repo:org/* without specific repo — org-wide.
		if strings.HasPrefix(subject, "repo:") && strings.Count(subject, "/") == 1 && strings.HasSuffix(subject, "/*") {
			return findings.SevCritical, fmt.Sprintf("App %q has GitHub OIDC credential %q scoped to entire org (%s)", app.DisplayName, fic.Name, subject)
		}
		// PR-triggered — ref:refs/pull/.
		if strings.Contains(subject, "ref:refs/pull/") || strings.Contains(subject, ":pull_request") {
			return findings.SevHigh, fmt.Sprintf("App %q has GitHub OIDC credential %q triggered by pull requests", app.DisplayName, fic.Name)
		}
	}

	// Generic wildcard in subject.
	if strings.Contains(subject, "*") {
		return findings.SevCritical, fmt.Sprintf("App %q has federated credential %q with wildcard in subject (%s)", app.DisplayName, fic.Name, subject)
	}

	return "", ""
}

// ---------------------------------------------------------------------------
// Check 4 — OAuth2 permission grants (admin consent)
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
