package iam_integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/you/ballmerbuster/internal/creds"
)

// ---------------------------------------------------------------------------
// Delegated-privilege index (for redirect/reply URI severity modulation)
// ---------------------------------------------------------------------------
//
// A dangling redirect/reply URI lets an attacker capture the OAuth response
// for an app. That response carries *delegated* (on-behalf-of-the-user) tokens
// — so the blast radius is bounded by the delegated permissions the app holds,
// not by its application (client-credentials) permissions. We index each app's
// granted delegated scopes so the redirect check can scale severity to what a
// captured token could actually do.
//
// NOTE: this is necessary-but-not-sufficient for "harmless". Even a
// low-scope app can be damaging — capturing the token still impersonates the
// user *to that application* (whose own backend may gate sensitive data behind
// the login), a refresh token grants persistence, and the dangling host serves
// as a valid-TLS phishing platform. So severity is floored, never zeroed.

// dangerousDelegatedScopes are Microsoft Graph delegated permission values that
// make a captured user token high-impact.
var dangerousDelegatedScopes = map[string]bool{
	"Directory.ReadWrite.All":            true,
	"Directory.AccessAsUser.All":         true,
	"RoleManagement.ReadWrite.Directory": true,
	"Application.ReadWrite.All":          true,
	"AppRoleAssignment.ReadWrite.All":    true,
	"User.ReadWrite.All":                 true,
	"Group.ReadWrite.All":                true,
	"GroupMember.ReadWrite.All":          true,
	"Mail.ReadWrite":                     true,
	"Mail.Send":                          true,
	"Files.ReadWrite.All":                true,
	"Sites.ReadWrite.All":                true,
	"full_access_as_user":                true,
}

// delegPriv summarizes an app's granted delegated permissions.
type delegPriv struct {
	Known           bool
	Dangerous       bool
	AllScopes       []string
	DangerousScopes []string
}

// buildDelegatedPrivIndex returns a map keyed by application (client) appId,
// describing the delegated scopes granted to that app's service principal.
// Apps absent from the map have no observed delegated grants (or could not be
// read). The boolean reports whether the index was populated at all.
func buildDelegatedPrivIndex(ctx context.Context, target creds.SubscriptionTarget,
	log func(string, string)) (map[string]delegPriv, bool) {

	// Map service principal objectId -> appId.
	const spURL = "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId"
	spRaw, err := graphList(ctx, target.Credential, spURL)
	if err != nil {
		log("warn", fmt.Sprintf("delegated-privilege index: list service principals: %v", err))
		return nil, false
	}
	spToApp := make(map[string]string, len(spRaw))
	for _, r := range spRaw {
		var sp struct {
			ID    string `json:"id"`
			AppID string `json:"appId"`
		}
		if err := json.Unmarshal(r, &sp); err == nil && sp.ID != "" {
			spToApp[sp.ID] = sp.AppID
		}
	}

	const grantURL = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
	grantRaw, err := graphList(ctx, target.Credential, grantURL)
	if err != nil {
		log("warn", fmt.Sprintf("delegated-privilege index: list oauth2 grants: %v", err))
		return nil, false
	}

	index := map[string]delegPriv{}
	for _, r := range grantRaw {
		var g struct {
			ClientID string `json:"clientId"`
			Scope    string `json:"scope"`
		}
		if err := json.Unmarshal(r, &g); err != nil {
			continue
		}
		appID, ok := spToApp[g.ClientID]
		if !ok || appID == "" {
			continue
		}
		dp := index[appID]
		dp.Known = true
		for _, scope := range strings.Fields(g.Scope) {
			dp.AllScopes = append(dp.AllScopes, scope)
			if dangerousDelegatedScopes[scope] {
				dp.Dangerous = true
				dp.DangerousScopes = append(dp.DangerousScopes, scope)
			}
		}
		index[appID] = dp
	}

	return index, true
}
