package iam_integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
)

// ---------------------------------------------------------------------------
// Check 7 — Dangling OAuth redirect / reply / logout URIs
// ---------------------------------------------------------------------------
//
// If an app registration's redirect URI (or a service principal's reply URL,
// or a front-channel logout URL) points at a host that has been deleted and is
// re-registrable, an attacker who claims the host receives OAuth authorization
// codes / tokens sent there — an account / application takeover.
//
// This is especially dangerous when the host is a native Azure service
// hostname (e.g. <app>.azurewebsites.net): unlike a custom domain, the native
// hostname has NO domain-ownership (asuid) verification gate, so re-registering
// the freed resource name directly returns control of the hostname.

// uriEntry is a single redirect/reply/logout URI with provenance.
type uriEntry struct {
	URI   string
	Field string // "web.redirectUris", "spa.redirectUris", "publicClient.redirectUris", "web.logoutUrl", "replyUrls"
}

type appWithURIs struct {
	ID          string `json:"id"`
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`
	Web         *struct {
		RedirectUris []string `json:"redirectUris"`
		LogoutURL    string   `json:"logoutUrl"`
	} `json:"web"`
	Spa *struct {
		RedirectUris []string `json:"redirectUris"`
	} `json:"spa"`
	PublicClient *struct {
		RedirectUris []string `json:"redirectUris"`
	} `json:"publicClient"`
}

func checkDanglingRedirectURIs(ctx context.Context, target creds.SubscriptionTarget,
	emit func(findings.Finding), log func(string, string), priv map[string]delegPriv) error {

	// Per-run DNS cache so repeated hosts are resolved once.
	type nxResult struct {
		nx  bool
		err error
	}
	dnsCache := map[string]nxResult{}
	hostNX := func(host string) (bool, error) {
		if r, ok := dnsCache[host]; ok {
			return r.nx, r.err
		}
		nx, err := hostIsNXDOMAIN(ctx, host)
		dnsCache[host] = nxResult{nx, err}
		return nx, err
	}

	emitForURI := func(ownerDesc, resourceID, appID string, baseDetail map[string]any, e uriEntry) {
		host := redirectHost(e.URI)
		if host == "" {
			return
		}
		nx, err := hostNX(host)
		if err != nil || !nx {
			return // resolves (not dangling) or DNS inconclusive
		}
		azure := isClaimableAzureHost(host)

		// Severity scales with what a captured (delegated) token could do.
		// Floor at Medium: token capture always impersonates the user to the
		// app, and a refresh token enables persistence, even with low scopes.
		dp := priv[appID]
		sev := redirectSeverity(azure, dp)

		hostNote := fmt.Sprintf("redirect/reply target host %q returns NXDOMAIN (dangling); if the host is re-registrable an attacker can receive OAuth authorization codes/tokens sent to %s", host, e.URI)
		if azure {
			hostNote = fmt.Sprintf("redirect/reply target host %q is a native Azure service hostname returning NXDOMAIN — re-registering the freed resource name directly returns control of the host (no asuid verification gate), letting an attacker capture OAuth authorization codes/tokens sent to %s", host, e.URI)
		}
		privNote := "app has no dangerous delegated permissions granted, so a captured token is limited — but it still impersonates the user to this application and a refresh token grants persistence"
		if !dp.Known {
			privNote = "app's delegated permissions could not be determined (no service principal / grants readable); severity reflects the host only — validate the app's scopes manually"
		} else if dp.Dangerous {
			privNote = fmt.Sprintf("app holds dangerous delegated permissions (%s) — a captured token is high-impact", strings.Join(dp.DangerousScopes, ", "))
		}

		detail := map[string]any{
			"redirect_uri":         e.URI,
			"uri_field":            e.Field,
			"target_host":          host,
			"host_status":          "NXDOMAIN",
			"azure_native_host":    azure,
			"app_privilege_known":  dp.Known,
			"app_privileged":       dp.Dangerous,
			"app_dangerous_scopes": dp.DangerousScopes,
			"app_delegated_scopes": dp.AllScopes,
			"reason":               hostNote + " | " + privNote,
		}
		for k, v := range baseDetail {
			detail[k] = v
		}
		emit(findings.Finding{
			Region:     "global",
			Severity:   sev,
			ResourceID: resourceID,
			Title:      fmt.Sprintf("%s has dangling redirect/reply URI -> %s (%s)", ownerDesc, e.URI, host),
			Detail:     detail,
		})
	}

	// --- App registrations: web/spa/publicClient redirect URIs + logout URL.
	const appsURL = "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,web,spa,publicClient"
	appsRaw, err := graphList(ctx, target.Credential, appsURL)
	if err != nil {
		return err
	}
	log("info", fmt.Sprintf("checking redirect URIs on %d app registrations", len(appsRaw)))

	for _, r := range appsRaw {
		var app appWithURIs
		if err := json.Unmarshal(r, &app); err != nil {
			continue
		}
		var entries []uriEntry
		if app.Web != nil {
			for _, u := range app.Web.RedirectUris {
				entries = append(entries, uriEntry{u, "web.redirectUris"})
			}
			if app.Web.LogoutURL != "" {
				entries = append(entries, uriEntry{app.Web.LogoutURL, "web.logoutUrl"})
			}
		}
		if app.Spa != nil {
			for _, u := range app.Spa.RedirectUris {
				entries = append(entries, uriEntry{u, "spa.redirectUris"})
			}
		}
		if app.PublicClient != nil {
			for _, u := range app.PublicClient.RedirectUris {
				entries = append(entries, uriEntry{u, "publicClient.redirectUris"})
			}
		}
		ownerDesc := fmt.Sprintf("App registration %q", app.DisplayName)
		resourceID := fmt.Sprintf("/tenants/%s/applications/%s", target.TenantID, app.AppID)
		base := map[string]any{
			"tenant_id":    target.TenantID,
			"app_id":       app.AppID,
			"display_name": app.DisplayName,
			"owner_type":   "application",
		}
		for _, e := range entries {
			emitForURI(ownerDesc, resourceID, app.AppID, base, e)
		}
	}

	// --- Service principals: reply URLs.
	const spURL = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,replyUrls"
	spRaw, err := graphList(ctx, target.Credential, spURL)
	if err != nil {
		log("warn", fmt.Sprintf("list service principal reply URLs: %v", err))
		return nil
	}
	log("info", fmt.Sprintf("checking reply URLs on %d service principals", len(spRaw)))

	for _, r := range spRaw {
		var sp struct {
			ID          string   `json:"id"`
			AppID       string   `json:"appId"`
			DisplayName string   `json:"displayName"`
			ReplyURLs   []string `json:"replyUrls"`
		}
		if err := json.Unmarshal(r, &sp); err != nil {
			continue
		}
		if len(sp.ReplyURLs) == 0 {
			continue
		}
		ownerDesc := fmt.Sprintf("Service principal %q", sp.DisplayName)
		resourceID := fmt.Sprintf("/tenants/%s/servicePrincipals/%s", target.TenantID, sp.ID)
		base := map[string]any{
			"tenant_id":    target.TenantID,
			"sp_id":        sp.ID,
			"app_id":       sp.AppID,
			"display_name": sp.DisplayName,
			"owner_type":   "servicePrincipal",
		}
		for _, u := range sp.ReplyURLs {
			emitForURI(ownerDesc, resourceID, sp.AppID, base, uriEntry{u, "replyUrls"})
		}
	}

	return nil
}

// redirectSeverity scales the severity of a dangling redirect/reply URI by the
// host's claimability and what a captured delegated token could do. It never
// drops below Medium: capturing the OAuth response always impersonates the user
// to the application and a refresh token grants persistence.
func redirectSeverity(azureHost bool, dp delegPriv) findings.Severity {
	switch {
	case azureHost && dp.Dangerous:
		return findings.SevCritical
	case azureHost:
		return findings.SevHigh // native host fully claimable; impact bounded by limited/unknown scopes
	case dp.Dangerous:
		return findings.SevHigh
	default:
		return findings.SevMedium
	}
}

// redirectHost extracts the hostname from an http/https redirect URI, skipping
// non-web schemes, loopback, and Microsoft-owned hosts that are never
// attacker-claimable.
func redirectHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "" // urn:, ms-app://, custom-scheme native clients, etc.
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "", host == "localhost", host == "127.0.0.1", host == "::1":
		return ""
	case strings.HasSuffix(host, ".localhost"), strings.HasSuffix(host, ".local"):
		return ""
	case host == "login.microsoftonline.com", host == "login.windows.net",
		strings.HasSuffix(host, ".microsoftonline.com"):
		return ""
	}
	return host
}
