package dynamic_groups

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

// seenTenant ensures these tenant-wide Graph findings run once per tenant
// rather than once per subscription. LoadOrStore is atomic.
var seenTenant sync.Map

// Module enumerates Entra ID dynamic groups and surfaces their membership
// rules (the "who can join" policy). Dynamic membership is a privilege-flow
// surface: anyone who can set the directory attributes a rule keys on (and many
// such attributes are user- or guest-settable) gets auto-joined to the group,
// inheriting whatever access — including directory roles — the group confers.
type Module struct{}

func (Module) Name() string      { return "dynamic_groups" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"Directory.Read.All"}
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	log := func(level, msg string) {
		_ = sink.LogEvent(ctx, "dynamic_groups", target.SubscriptionID, level, msg)
	}
	emit := func(f findings.Finding) {
		f.SubscriptionID = target.SubscriptionID
		f.Module = "dynamic_groups"
		f.Region = "global"
		_ = sink.Write(ctx, f)
	}

	if _, already := seenTenant.LoadOrStore(target.TenantID, true); already {
		log("info", fmt.Sprintf("dynamic-group checks already run for tenant %s — skipping to avoid duplicates", target.TenantID))
		return nil
	}

	log("info", "enumerating Entra ID dynamic groups for tenant "+target.TenantID)

	const url = "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description,groupTypes,membershipRule,membershipRuleProcessingState,securityEnabled,mailEnabled,isAssignableToRole,visibility&$top=999"
	raw, err := graphList(ctx, target.Credential, url)
	if err != nil {
		return fmt.Errorf("dynamic_groups: list groups: %w", err)
	}

	dynamicCount := 0
	for _, r := range raw {
		var g group
		if err := json.Unmarshal(r, &g); err != nil {
			continue
		}
		if !isDynamic(g) {
			continue
		}
		dynamicCount++

		attrs := referencedAttributes(g.MembershipRule)
		risky := riskyAttributes(attrs)

		sev := findings.SevLow
		reasons := []string{}

		// A role-assignable dynamic group is the sharpest edge: satisfying the
		// rule grants a directory role with no human approval.
		if g.IsAssignableToRole {
			sev = findings.SevHigh
			reasons = append(reasons, "group is role-assignable — auto-membership grants directory role(s) with no approval")
		}
		if len(risky) > 0 {
			if sev != findings.SevHigh {
				sev = findings.SevMedium
			}
			reasons = append(reasons, fmt.Sprintf("rule keys on user/guest-influenceable attribute(s): %s", strings.Join(risky, ", ")))
		}
		if strings.EqualFold(g.MembershipRuleProcessingState, "Paused") {
			reasons = append(reasons, "membership rule processing is Paused (rule shown but not currently enforced)")
		}
		if len(reasons) == 0 {
			reasons = append(reasons, "dynamic group surfaced for membership-rule review")
		}

		emit(findings.Finding{
			Severity:   sev,
			ResourceID: fmt.Sprintf("/tenants/%s/groups/%s", target.TenantID, g.ID),
			Title:      fmt.Sprintf("Dynamic group %q membership rule: %s", g.DisplayName, summarizeRule(g.MembershipRule)),
			Detail: map[string]any{
				"tenant_id":                        target.TenantID,
				"group_id":                         g.ID,
				"display_name":                     g.DisplayName,
				"description":                      g.Description,
				"membership_rule":                  g.MembershipRule,
				"membership_rule_processing_state": g.MembershipRuleProcessingState,
				"referenced_attributes":            attrs,
				"risky_attributes":                 risky,
				"is_assignable_to_role":            g.IsAssignableToRole,
				"security_enabled":                 g.SecurityEnabled,
				"group_types":                      g.GroupTypes,
				"reasons":                          reasons,
			},
		})
	}

	log("info", fmt.Sprintf("found %d dynamic groups (of %d total groups)", dynamicCount, len(raw)))
	return nil
}

type group struct {
	ID                            string   `json:"id"`
	DisplayName                   string   `json:"displayName"`
	Description                   string   `json:"description"`
	GroupTypes                    []string `json:"groupTypes"`
	MembershipRule                string   `json:"membershipRule"`
	MembershipRuleProcessingState string   `json:"membershipRuleProcessingState"`
	SecurityEnabled               bool     `json:"securityEnabled"`
	MailEnabled                   bool     `json:"mailEnabled"`
	IsAssignableToRole            bool     `json:"isAssignableToRole"`
	Visibility                    string   `json:"visibility"`
}

func isDynamic(g group) bool {
	for _, t := range g.GroupTypes {
		if strings.EqualFold(t, "DynamicMembership") {
			return true
		}
	}
	// Fallback: a populated membership rule implies dynamic membership.
	return strings.TrimSpace(g.MembershipRule) != ""
}

// riskyDirectoryAttributes are membership-rule attributes that a user — or in
// many tenants an external/guest user — can influence, making the dynamic
// group's "who can join" rule attacker-reachable.
var riskyDirectoryAttributes = map[string]bool{
	"otherMails":                 true,
	"mail":                       true,
	"mailNickname":               true,
	"displayName":                true,
	"givenName":                  true,
	"surname":                    true,
	"jobTitle":                   true,
	"department":                 true,
	"companyName":                true,
	"city":                       true,
	"country":                    true,
	"state":                      true,
	"physicalDeliveryOfficeName": true,
	"streetAddress":              true,
	"userType":                   true, // Guest vs Member — central to guest self-join paths
	"preferredLanguage":          true,
	"facsimileTelephoneNumber":   true,
	"telephoneNumber":            true,
	"mobile":                     true,
}

func init() {
	// extensionAttribute1..15 are commonly writable and frequently used in rules.
	for i := 1; i <= 15; i++ {
		riskyDirectoryAttributes[fmt.Sprintf("extensionAttribute%d", i)] = true
	}
}

// referencedAttributes extracts the directory attribute names a membership rule
// references (e.g. "user.department", "user.otherMails").
func referencedAttributes(rule string) []string {
	seen := map[string]bool{}
	var out []string
	tokens := strings.FieldsFunc(rule, func(r rune) bool {
		return !(r == '.' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
	for _, tok := range tokens {
		// Rules reference attributes as "user.<attr>" or "device.<attr>".
		prefix := ""
		switch {
		case strings.HasPrefix(tok, "user."):
			prefix = "user."
		case strings.HasPrefix(tok, "device."):
			prefix = "device."
		default:
			continue
		}
		attr := strings.TrimPrefix(tok, prefix)
		if attr == "" || seen[attr] {
			continue
		}
		seen[attr] = true
		out = append(out, attr)
	}
	return out
}

func riskyAttributes(attrs []string) []string {
	var out []string
	for _, a := range attrs {
		if riskyDirectoryAttributes[a] {
			out = append(out, a)
		}
	}
	return out
}

// summarizeRule trims a membership rule for use in a finding title.
func summarizeRule(rule string) string {
	r := strings.Join(strings.Fields(rule), " ")
	if r == "" {
		return "(empty)"
	}
	const max = 160
	if len(r) > max {
		return r[:max] + "…"
	}
	return r
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
