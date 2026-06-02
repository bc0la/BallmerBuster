package external_trust

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
)

// ---------------------------------------------------------------------------
// Federated identity credentials (app registrations + user-assigned managed
// identities)
// ---------------------------------------------------------------------------
//
// A federated identity credential (FIC) configures an Azure principal to trust
// tokens minted by an external OIDC provider (GitHub Actions, GitLab CI, a
// Kubernetes cluster, another Entra tenant, ...). FICs can be attached to two
// different Azure object types:
//
//   - App registrations  — read via Microsoft Graph
//     (/applications/{id}/federatedIdentityCredentials)
//   - User-assigned managed identities — read via ARM
//     (Microsoft.ManagedIdentity/userAssignedIdentities/.../federatedIdentityCredentials)
//
// The Graph-only enumeration that previously lived in entra_id missed every
// managed-identity FIC, which is the more common workload-identity-federation
// surface (AKS workload identity, GitHub Actions -> managed identity). Both
// are covered here.

// federatedIdentityCredential is the source-agnostic view of a FIC. The Graph
// path unmarshals directly into it (json tags); the ARM path maps the typed
// armmsi model into it.
type federatedIdentityCredential struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Description string   `json:"description"`
	Audiences   []string `json:"audiences"`
}

// federatedAssessment is the subject-pattern classification of a FIC (scoping
// to a specific repo/org/ref, wildcard misconfigurations, unknown issuers).
type federatedAssessment struct {
	Severity findings.Severity
	Title    string
	Category string
	Reason   string
}

// ficSource describes the Azure object that owns a FIC, for finding output.
type ficSource struct {
	Kind       string         // "App registration" | "Managed identity"
	Name       string         // display name / identity name
	ResourceID string         // finding ResourceID
	Detail     map[string]any // base identifying detail merged into every finding
}

func ficHTTPClient() *http.Client {
	return &http.Client{Timeout: 8 * time.Second}
}

func severityRank(s findings.Severity) int {
	switch s {
	case findings.SevCritical:
		return 5
	case findings.SevHigh:
		return 4
	case findings.SevMedium:
		return 3
	case findings.SevLow:
		return 2
	case findings.SevInfo:
		return 1
	}
	return 0
}

// evaluateFederatedCredential classifies a FIC subject for its issuer,
// enforcing that GitHub/GitLab/Kubernetes subjects are scoped to a specific
// repo/project/service-account rather than an org-wide or wildcard pattern.
// Returns an empty Severity for well-scoped subjects.
func evaluateFederatedCredential(ownerDesc string, fic federatedIdentityCredential) federatedAssessment {
	switch {
	case strings.Contains(fic.Issuer, githubOIDCIssuer):
		risk := analyzeGitHubSub(fic.Subject)
		if risk.Severity == "" {
			return federatedAssessment{}
		}
		return federatedAssessment{
			Severity: risk.Severity,
			Title:    fmt.Sprintf("%s has GitHub OIDC credential %q (%s) — %s", ownerDesc, fic.Name, risk.Category, risk.Reason),
			Category: risk.Category,
			Reason:   risk.Reason,
		}
	case looksLikeK8sIssuer(fic.Issuer):
		risk := analyzeK8sSub(fic.Subject)
		if risk.Severity == "" {
			return federatedAssessment{}
		}
		return federatedAssessment{
			Severity: risk.Severity,
			Title:    fmt.Sprintf("%s has Kubernetes OIDC credential %q (%s) — %s", ownerDesc, fic.Name, risk.Category, risk.Reason),
			Category: risk.Category,
			Reason:   risk.Reason,
		}
	case looksLikeGitLabIssuer(fic.Issuer):
		risk := analyzeGitLabSub(fic.Subject)
		if risk.Severity == "" {
			return federatedAssessment{}
		}
		return federatedAssessment{
			Severity: risk.Severity,
			Title:    fmt.Sprintf("%s has GitLab CI OIDC credential %q (%s) — %s", ownerDesc, fic.Name, risk.Category, risk.Reason),
			Category: risk.Category,
			Reason:   risk.Reason,
		}
	}

	// Non-recognized issuer — generic wildcard / empty checks. Azure FIC
	// v1.0 requires exact subject match, so wildcards are misconfigurations
	// unless paired with claimsMatchingExpression.
	subject := strings.TrimSpace(fic.Subject)
	if subject == "" {
		return federatedAssessment{
			Severity: findings.SevHigh,
			Title:    fmt.Sprintf("%s has federated credential %q with empty subject (issuer %s)", ownerDesc, fic.Name, fic.Issuer),
			Category: "fed_empty_sub",
			Reason:   "empty subject — FIC will not authenticate any token without claimsMatchingExpression",
		}
	}
	if strings.Contains(subject, "*") {
		return federatedAssessment{
			Severity: findings.SevMedium,
			Title:    fmt.Sprintf("%s has federated credential %q with wildcard in subject (%s, issuer %s)", ownerDesc, fic.Name, subject, fic.Issuer),
			Category: "fed_wildcard_sub",
			Reason:   "subject contains a wildcard; Azure FIC v1.0 requires exact match unless claimsMatchingExpression is set",
		}
	}
	if !knownOIDCIssuer(fic.Issuer) {
		return federatedAssessment{
			Severity: findings.SevLow,
			Title:    fmt.Sprintf("%s has federated credential %q with unrecognized issuer %s", ownerDesc, fic.Name, fic.Issuer),
			Category: "fed_unknown_issuer",
			Reason:   "issuer is not a known provider (GitHub, GitLab, K8s, Terraform Cloud, etc.) — verify the OIDC provider is trustworthy and the subject is appropriately scoped",
		}
	}
	return federatedAssessment{}
}

// processFIC runs subject-pattern analysis and a best-effort claimability
// probe on a single FIC and emits one finding (info for well-scoped, benign
// credentials, escalated when the subject is poorly scoped or the trusted
// external owner is claimable).
func processFIC(ctx context.Context, emit func(findings.Finding), client *http.Client, src ficSource, fic federatedIdentityCredential) {
	ownerDesc := fmt.Sprintf("%s %q", src.Kind, src.Name)
	assess := evaluateFederatedCredential(ownerDesc, fic)

	severity := assess.Severity
	title := assess.Title
	category := assess.Category
	reason := assess.Reason
	if severity == "" {
		severity = findings.SevInfo
		title = fmt.Sprintf("%s has federated identity credential %q (issuer %s)", ownerDesc, fic.Name, fic.Issuer)
		category = "fed_reviewed"
		reason = "federated identity credential reviewed; subject appears appropriately scoped for its issuer"
	}

	detail := map[string]any{
		"fic_id":      fic.ID,
		"fic_name":    fic.Name,
		"issuer":      fic.Issuer,
		"subject":     fic.Subject,
		"audiences":   fic.Audiences,
		"description": fic.Description,
		"category":    category,
	}
	for k, v := range src.Detail {
		detail[k] = v
	}

	// Best-effort takeover / claimability assessment of the trusted external
	// subject owner (GitHub org/repo, GitLab group, Terraform Cloud org, ...).
	takeover := assessFICTakeover(ctx, client, fic.Issuer, fic.Subject)
	if takeover.Found {
		detail["external_provider"] = takeover.Principal.Provider
		detail["external_owner"] = takeover.Principal.Owner
		if takeover.Principal.Repo != "" {
			detail["external_repo"] = takeover.Principal.Repo
			detail["scope"] = "repository (" + takeover.Principal.Owner + "/" + takeover.Principal.Repo + ")"
		} else {
			detail["scope"] = "owner-only — not pinned to a specific repository"
		}
		detail["claimability"] = takeover.Status
		detail["claimability_detail"] = takeover.Reason
		if takeover.RepoNote != "" {
			detail["repo_note"] = takeover.RepoNote
		}

		if takeover.Severity != "" && severityRank(takeover.Severity) > severityRank(severity) {
			severity = takeover.Severity
			category = "fed_takeover"
			title = fmt.Sprintf("%s federated credential %q — possible takeover: %s owner %q is claimable",
				ownerDesc, fic.Name, takeover.Principal.Provider, takeover.Principal.Owner)
		}
		reason = reason + " | " + takeover.Reason
	}

	// Best-effort claimability of the issuer domain itself. A dangling
	// self-hosted/custom issuer is the most severe vector: it defeats subject
	// scoping entirely (attacker hosts their own JWKS and mints any token).
	if claimable, host, skipped, err := assessIssuerDomain(ctx, fic.Issuer); err == nil && !skipped {
		detail["issuer_host"] = host
		detail["issuer_claimable"] = claimable
		if claimable && severityRank(findings.SevCritical) > severityRank(severity) {
			severity = findings.SevCritical
			category = "fed_issuer_takeover"
			title = fmt.Sprintf("%s federated credential %q — issuer domain %q is claimable (arbitrary token minting)",
				ownerDesc, fic.Name, host)
			reason = reason + fmt.Sprintf(" | issuer domain %q returns NXDOMAIN and is claimable; an attacker who registers it can serve a malicious OIDC discovery document + JWKS and mint tokens that satisfy this credential regardless of subject scoping", host)
		}
	}

	detail["category"] = category
	detail["reason"] = reason

	emit(findings.Finding{
		Region:     "global",
		Severity:   severity,
		ResourceID: src.ResourceID,
		Title:      title,
		Detail:     detail,
	})
}

// ---------------------------------------------------------------------------
// Check 5 — App registration federated identity credentials (Graph API)
// ---------------------------------------------------------------------------

type appReg struct {
	ID          string `json:"id"`
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`
}

func checkAppRegistrationFICs(ctx context.Context, target creds.SubscriptionTarget,
	emit func(findings.Finding), log func(string, string)) error {

	const appsURL = "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName"
	raw, err := graphList(ctx, target.Credential, appsURL)
	if err != nil {
		return err
	}

	log("info", fmt.Sprintf("checking federated identity credentials on %d app registrations", len(raw)))
	client := ficHTTPClient()

	for _, r := range raw {
		var app appReg
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
			processFIC(ctx, emit, client, ficSource{
				Kind:       "App registration",
				Name:       app.DisplayName,
				ResourceID: fmt.Sprintf("/tenants/%s/applications/%s/federatedIdentityCredentials/%s", target.TenantID, app.AppID, fic.ID),
				Detail: map[string]any{
					"tenant_id":     target.TenantID,
					"app_id":        app.AppID,
					"app_object_id": app.ID,
					"display_name":  app.DisplayName,
					"owner_type":    "application",
				},
			}, fic)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Check 6 — User-assigned managed identity federated identity credentials (ARM)
// ---------------------------------------------------------------------------

func checkManagedIdentityFICs(ctx context.Context, target creds.SubscriptionTarget,
	emit func(findings.Finding), log func(string, string)) error {

	uaClient, err := armmsi.NewUserAssignedIdentitiesClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("create user-assigned identities client: %w", err)
	}
	ficClient, err := armmsi.NewFederatedIdentityCredentialsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("create federated identity credentials client: %w", err)
	}

	var identities []*armmsi.Identity
	pager := uaClient.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list user-assigned managed identities: %w", err)
		}
		identities = append(identities, page.Value...)
	}

	log("info", fmt.Sprintf("checking federated identity credentials on %d user-assigned managed identities", len(identities)))
	client := ficHTTPClient()

	for _, id := range identities {
		name := ptrVal(id.Name)
		rid := ptrVal(id.ID)
		rg := resourceGroup(rid)
		if name == "" || rg == "" {
			continue
		}

		fp := ficClient.NewListPager(rg, name, nil)
		for fp.More() {
			page, err := fp.NextPage(ctx)
			if err != nil {
				log("warn", fmt.Sprintf("list federated creds for managed identity %s: %v", name, err))
				break
			}
			for _, f := range page.Value {
				if f.Properties == nil {
					continue
				}
				fic := federatedIdentityCredential{
					ID:        ptrVal(f.ID),
					Name:      ptrVal(f.Name),
					Issuer:    ptrVal(f.Properties.Issuer),
					Subject:   ptrVal(f.Properties.Subject),
					Audiences: derefStrings(f.Properties.Audiences),
				}
				processFIC(ctx, emit, client, ficSource{
					Kind:       "Managed identity",
					Name:       name,
					ResourceID: rid + "/federatedIdentityCredentials/" + fic.Name,
					Detail: map[string]any{
						"subscription_id": target.SubscriptionID,
						"identity_name":   name,
						"identity_id":     rid,
						"resource_group":  rg,
						"owner_type":      "userAssignedIdentity",
					},
				}, fic)
			}
		}
	}
	return nil
}

func derefStrings(in []*string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p != nil {
			out = append(out, *p)
		}
	}
	return out
}
