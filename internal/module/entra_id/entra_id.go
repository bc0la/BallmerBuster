package entra_id

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

	// 2. Federated identity credentials (incl. GitHub takeover probes).
	log("info", "checking federated identity credentials")
	if err := checkFederatedIdentityCredentials(ctx, target, emit, log); err != nil {
		log("warn", fmt.Sprintf("federated identity credentials: %v", err))
	}

	// 3. OAuth2 permission grants (admin consent).
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
// Check 2 — federated identity credentials
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

	ghc := newGitHubCache()
	if ghc.authenticated {
		log("info", "using GITHUB_TOKEN for authenticated GitHub API probes (5000 req/hr)")
	} else {
		log("info", "no GITHUB_TOKEN set — GitHub probes are unauthenticated (60 req/hr; private repos may yield false positives)")
	}

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

			assess := evaluateFederatedCredential(app, fic)
			detail := map[string]any{
				"tenant_id":    target.TenantID,
				"app_id":       app.AppID,
				"display_name": app.DisplayName,
				"fic_id":       fic.ID,
				"fic_name":     fic.Name,
				"issuer":       fic.Issuer,
				"subject":      fic.Subject,
				"audiences":    fic.Audiences,
				"description":  fic.Description,
			}
			if assess.Category != "" {
				detail["category"] = assess.Category
				detail["reason"] = assess.Reason
			}

			// GitHub Actions OIDC takeover probe: if the subject names a
			// specific owner/repo, check whether the owner and repo still
			// exist. A missing owner means the username is claimable on
			// github.com — anyone can register it, recreate the repo, and
			// claim OIDC tokens for this app.
			if strings.Contains(fic.Issuer, githubOIDCIssuer) {
				owner, repo := parseGitHubSubjectRepo(fic.Subject)
				if owner != "" && repo != "" {
					ownerExists := ghc.ownerExists(ctx, owner)
					repoExists := ownerExists && ghc.repoExists(ctx, owner, repo)
					detail["github_owner"] = owner
					detail["github_repo"] = repo
					detail["github_owner_exists"] = ownerExists
					detail["github_repo_exists"] = repoExists
					detail["github_probe_authenticated"] = ghc.authenticated

					switch {
					case !ownerExists:
						assess.Severity = findings.SevCritical
						assess.Title = fmt.Sprintf("App %q GitHub OIDC owner %q is claimable — register username, recreate %s, mint tokens",
							app.DisplayName, owner, repo)
						assess.Category = "github_oidc_owner_claimable"
					case !repoExists:
						if ghc.authenticated {
							assess.Severity = findings.SevHigh
							assess.Title = fmt.Sprintf("App %q GitHub OIDC repo %s/%s is missing — recreate in that org to claim tokens",
								app.DisplayName, owner, repo)
							assess.Category = "github_oidc_repo_missing"
						} else if assess.Severity == "" {
							assess.Severity = findings.SevMedium
							assess.Title = fmt.Sprintf("App %q GitHub OIDC repo %s/%s 404s unauthenticated (deleted or private — verify with GITHUB_TOKEN)",
								app.DisplayName, owner, repo)
							assess.Category = "github_oidc_repo_404_unauth"
						}
					}
				}
			}

			if assess.Severity == "" {
				continue
			}
			if assess.Category != "" {
				detail["category"] = assess.Category
			}

			emit(findings.Finding{
				Region:     "global",
				Severity:   assess.Severity,
				ResourceID: fmt.Sprintf("/tenants/%s/applications/%s/federatedIdentityCredentials/%s", target.TenantID, app.AppID, fic.ID),
				Title:      assess.Title,
				Detail:     detail,
			})
		}
	}
	return nil
}

// federatedAssessment is the result of a non-takeover-probe classification
// of a federated identity credential. The GH-specific takeover probe runs
// on top of this in the caller.
type federatedAssessment struct {
	Severity findings.Severity
	Title    string
	Category string
	Reason   string
}

func evaluateFederatedCredential(app appRegistration, fic federatedIdentityCredential) federatedAssessment {
	isGitHub := strings.Contains(fic.Issuer, githubOIDCIssuer)
	if isGitHub {
		risk := analyzeGitHubSub(fic.Subject)
		if risk.Severity == "" {
			return federatedAssessment{}
		}
		return federatedAssessment{
			Severity: risk.Severity,
			Title: fmt.Sprintf("App %q has GitHub OIDC credential %q with %s — %s",
				app.DisplayName, fic.Name, risk.Category, risk.Reason),
			Category: risk.Category,
			Reason:   risk.Reason,
		}
	}

	// Non-GitHub issuer — generic wildcard / empty checks. Azure FIC v1.0
	// requires exact subject match, so wildcards are misconfigurations
	// unless paired with claimsMatchingExpression.
	subject := strings.TrimSpace(fic.Subject)
	if subject == "" {
		return federatedAssessment{
			Severity: findings.SevHigh,
			Title:    fmt.Sprintf("App %q has federated credential %q with empty subject", app.DisplayName, fic.Name),
			Category: "fed_empty_sub",
			Reason:   "empty subject — FIC will not authenticate any token without claimsMatchingExpression",
		}
	}
	if strings.Contains(subject, "*") {
		return federatedAssessment{
			Severity: findings.SevMedium,
			Title: fmt.Sprintf("App %q has federated credential %q with wildcard in subject (%s)",
				app.DisplayName, fic.Name, subject),
			Category: "fed_wildcard_sub",
			Reason:   "subject contains a wildcard; Azure FIC v1.0 requires exact match unless claimsMatchingExpression is set",
		}
	}
	return federatedAssessment{}
}

// parseGitHubSubjectRepo extracts the "Owner/Repo" pair from a GitHub Actions
// OIDC subject like "repo:Owner/Repo:ref:refs/heads/main". Returns empty
// strings if the subject does not start with "repo:" or is malformed.
func parseGitHubSubjectRepo(subject string) (owner, repo string) {
	if !strings.HasPrefix(subject, "repo:") {
		return "", ""
	}
	rest := strings.TrimPrefix(subject, "repo:")
	end := strings.Index(rest, ":")
	if end == -1 {
		end = len(rest)
	}
	ownerRepo := rest[:end]
	slash := strings.Index(ownerRepo, "/")
	if slash <= 0 || slash == len(ownerRepo)-1 {
		return "", ""
	}
	owner = ownerRepo[:slash]
	repo = ownerRepo[slash+1:]
	if strings.ContainsAny(owner, "*") || strings.ContainsAny(repo, "*") {
		return "", ""
	}
	return owner, repo
}

// gitHubCache memoizes GitHub API probes for repo/owner existence.
type gitHubCache struct {
	repos         map[string]bool
	owners        map[string]bool
	client        *http.Client
	token         string
	authenticated bool
}

func newGitHubCache() *gitHubCache {
	token := os.Getenv("GITHUB_TOKEN")
	return &gitHubCache{
		repos:         map[string]bool{},
		owners:        map[string]bool{},
		client:        &http.Client{Timeout: 10 * time.Second},
		token:         token,
		authenticated: token != "",
	}
}

func (c *gitHubCache) statusFor(ctx context.Context, url string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return -1
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func (c *gitHubCache) ownerExists(ctx context.Context, owner string) bool {
	if v, ok := c.owners[owner]; ok {
		return v
	}
	exists := false
	if c.statusFor(ctx, "https://api.github.com/users/"+owner) == 200 {
		exists = true
	} else if c.statusFor(ctx, "https://api.github.com/orgs/"+owner) == 200 {
		exists = true
	}
	c.owners[owner] = exists
	return exists
}

func (c *gitHubCache) repoExists(ctx context.Context, owner, repo string) bool {
	key := owner + "/" + repo
	if v, ok := c.repos[key]; ok {
		return v
	}
	exists := c.statusFor(ctx, "https://api.github.com/repos/"+key) == 200
	c.repos[key] = exists
	return exists
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
