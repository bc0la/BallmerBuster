package entra_users

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
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
// rather than once per subscription.
var seenTenant sync.Map

// Module pulls Entra ID user accounts and surfaces their descriptive /
// free-text attributes (jobTitle, department, office, on-prem extension
// attributes, otherMails, ...). Two payoffs: (1) secrets are a classic find in
// these fields — admins stash passwords/keys in description-style attributes
// just like the legacy on-prem AD `description` trick — and (2) the attribute
// dump itself is useful recon for triage. Reading values is intentional and
// authorized for this engagement.
type Module struct{}

func (Module) Name() string      { return "entra_users" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"Directory.Read.All", "User.Read.All"}
}

// Secret-detection patterns, mirroring vm_userdata's set.
var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN .* PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ`)},
	{"Slack Token", regexp.MustCompile(`xox[bprs]-[0-9a-zA-Z-]+`)},
	{"Connection String", regexp.MustCompile(`(?i)(AccountKey|SharedAccessSignature|Password)=`)},
	{"Password Keyword", regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api[_-]?key|credential)s?\s*[:=]\s*\S`)},
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	log := func(level, msg string) {
		_ = sink.LogEvent(ctx, "entra_users", target.SubscriptionID, level, msg)
	}
	emit := func(f findings.Finding) {
		f.SubscriptionID = target.SubscriptionID
		f.Module = "entra_users"
		f.Region = "global"
		_ = sink.Write(ctx, f)
	}

	if _, already := seenTenant.LoadOrStore(target.TenantID, true); already {
		log("info", fmt.Sprintf("entra_users checks already run for tenant %s — skipping to avoid duplicates", target.TenantID))
		return nil
	}

	log("info", "pulling Entra ID user attributes for tenant "+target.TenantID)

	const url = "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName,givenName,surname,jobTitle,department,companyName,employeeId,employeeType,officeLocation,streetAddress,city,state,country,mail,otherMails,userType,accountEnabled,onPremisesExtensionAttributes&$top=999"
	raw, err := graphList(ctx, target.Credential, url)
	if err != nil {
		return fmt.Errorf("entra_users: list users: %w", err)
	}

	log("info", fmt.Sprintf("retrieved %d users", len(raw)))

	secretHits, surfaced := 0, 0
	for _, r := range raw {
		var u user
		if err := json.Unmarshal(r, &u); err != nil {
			continue
		}

		fields := u.freeTextFields()

		// 1. Secret scan across every free-text field.
		for _, f := range fields {
			if pat := matchSecretPattern(f.value); pat != "" {
				secretHits++
				emit(findings.Finding{
					Severity:   findings.SevHigh,
					ResourceID: fmt.Sprintf("/tenants/%s/users/%s", target.TenantID, u.ID),
					Title:      fmt.Sprintf("User %s field %q contains a secret (%s pattern)", u.upn(), f.name, pat),
					Detail: map[string]any{
						"tenant_id":           target.TenantID,
						"user_id":             u.ID,
						"user_principal_name": u.UserPrincipalName,
						"display_name":        u.DisplayName,
						"user_type":           u.UserType,
						"field":               f.name,
						"value":               f.value,
						"pattern_matched":     pat,
					},
				})
			}
		}

		// 2. Surface populated descriptive fields for review (skips bare accounts
		// with nothing but a UPN/displayName to keep volume sane).
		populated := map[string]any{}
		for _, f := range fields {
			if f.value != "" {
				populated[f.name] = f.value
			}
		}
		if len(populated) == 0 {
			continue
		}
		surfaced++

		sev := findings.SevInfo
		title := fmt.Sprintf("User %s attributes (%d populated field(s))", u.upn(), len(populated))
		if strings.EqualFold(u.UserType, "Guest") {
			// Guests are externally controlled; their attributes feed dynamic-group
			// rules and are more interesting for review.
			sev = findings.SevLow
			title = fmt.Sprintf("Guest user %s attributes (%d populated field(s))", u.upn(), len(populated))
		}

		detail := map[string]any{
			"tenant_id":           target.TenantID,
			"user_id":             u.ID,
			"user_principal_name": u.UserPrincipalName,
			"display_name":        u.DisplayName,
			"user_type":           u.UserType,
			"account_enabled":     u.AccountEnabled,
			"fields":              populated,
		}
		emit(findings.Finding{
			Severity:   sev,
			ResourceID: fmt.Sprintf("/tenants/%s/users/%s", target.TenantID, u.ID),
			Title:      title,
			Detail:     detail,
		})
	}

	log("info", fmt.Sprintf("entra_users complete: %d secret hit(s), %d user(s) with descriptive fields", secretHits, surfaced))
	return nil
}

type user struct {
	ID                            string             `json:"id"`
	UserPrincipalName             string             `json:"userPrincipalName"`
	DisplayName                   string             `json:"displayName"`
	GivenName                     string             `json:"givenName"`
	Surname                       string             `json:"surname"`
	JobTitle                      string             `json:"jobTitle"`
	Department                    string             `json:"department"`
	CompanyName                   string             `json:"companyName"`
	EmployeeID                    string             `json:"employeeId"`
	EmployeeType                  string             `json:"employeeType"`
	OfficeLocation                string             `json:"officeLocation"`
	StreetAddress                 string             `json:"streetAddress"`
	City                          string             `json:"city"`
	State                         string             `json:"state"`
	Country                       string             `json:"country"`
	Mail                          string             `json:"mail"`
	OtherMails                    []string           `json:"otherMails"`
	UserType                      string             `json:"userType"`
	AccountEnabled                *bool              `json:"accountEnabled"`
	OnPremisesExtensionAttributes map[string]*string `json:"onPremisesExtensionAttributes"`
}

func (u user) upn() string {
	if u.UserPrincipalName != "" {
		return u.UserPrincipalName
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.ID
}

type field struct {
	name  string
	value string
}

// freeTextFields returns the descriptive fields worth scanning/surfacing, in a
// stable order. displayName/UPN are excluded (they're identifiers, not content).
func (u user) freeTextFields() []field {
	out := []field{
		{"jobTitle", u.JobTitle},
		{"department", u.Department},
		{"companyName", u.CompanyName},
		{"employeeId", u.EmployeeID},
		{"employeeType", u.EmployeeType},
		{"officeLocation", u.OfficeLocation},
		{"streetAddress", u.StreetAddress},
		{"city", u.City},
		{"state", u.State},
		{"country", u.Country},
	}
	if len(u.OtherMails) > 0 {
		out = append(out, field{"otherMails", strings.Join(u.OtherMails, ", ")})
	}
	// On-prem extension attributes (extensionAttribute1..15) in stable order.
	keys := make([]string, 0, len(u.OnPremisesExtensionAttributes))
	for k := range u.OnPremisesExtensionAttributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := u.OnPremisesExtensionAttributes[k]; v != nil && *v != "" {
			out = append(out, field{"onPremisesExtensionAttributes." + k, *v})
		}
	}
	// Drop empties from the simple string fields.
	filtered := out[:0]
	for _, f := range out {
		if strings.TrimSpace(f.value) != "" {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func matchSecretPattern(value string) string {
	for _, sp := range secretPatterns {
		if sp.pattern.MatchString(value) {
			return sp.name
		}
	}
	return ""
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
