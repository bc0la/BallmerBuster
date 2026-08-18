package module

// moduleRating is the realistic worst-case severity a module can produce — its
// "potential severity", independent of what any given engagement actually
// finds. The report UI stamps this onto every section/module/check filter so an
// analyst can triage which filters are worth looking at first.
//
// Ratings are deliberately conservative-realistic, not theoretical-maximum:
//   - critical: a single finding here is typically a direct breach or full
//     tenant/subscription compromise (anonymous data access, internet-reachable
//     database, live credentials, externally-assumable identity).
//   - high: serious exposure that usually needs one more step (valid creds, a
//     restore, an SSRF) or leaks sensitive material.
//   - medium: real weakness, but impact is bounded or commonly non-sensitive.
//   - low/info: hygiene / informational.
var moduleRating = map[string]string{
	// --- critical: direct breach / full compromise ---
	"blob_anon":        "critical", // anonymous blob container listing / public objects = data breach
	"public_sql":       "critical", // internet-reachable SQL/PG/MySQL → weak-cred data theft
	"secrets_scan":     "critical", // live credentials in code/config/logs/blobs = full compromise
	"devops_secrets":   "critical", // live credentials in pipeline variables = full compromise
	"iam_integrations": "critical", // dangling/over-broad trust = external identity takeover
	"external_trust":   "critical", // federated credential takeover = app/identity impersonation

	// --- high: serious exposure, usually one step from breach ---
	"function_app_env":    "high", // secrets in Function App settings
	"aci_env":             "high", // secrets in container env vars
	"arm_deployments":     "high", // secrets in deployment parameters/outputs
	"automation_accounts": "high", // secrets in runbooks/variables/stored credentials
	"logic_apps":          "high", // secrets in workflow definitions
	"vm_userdata":         "high", // secrets in VM userData / extension settings
	"keyvault_exposure":   "high", // Key Vault reachable from the public internet
	"acr_exposure":        "high", // registry anonymous pull / admin user (image/secret leak)
	"subdomain_takeover":  "high", // dangling DNS record → takeover/phishing
	"redirect_uris":       "high", // dangling reply URL → OAuth token theft / account takeover
	"rbac_review":         "high", // role assignments granting privilege-escalation paths

	// --- medium: real weakness, bounded/commonly non-sensitive impact ---
	"nsg_exposure":   "medium", // NSG rule opens a port to the internet (exposure prerequisite)
	"entra_id":       "medium", // app registration / SP posture misconfig
	"entra_users":    "medium", // user/identity hygiene (MFA, guest, stale)
	"dynamic_groups": "medium", // dynamic membership rule → unintended group membership
}

// RatingOf returns the potential-severity rating for a module, defaulting to
// "medium" for any module not explicitly rated (so a new module surfaces with
// a visible, non-alarming default rather than nothing).
func RatingOf(name string) string {
	if r, ok := moduleRating[name]; ok {
		return r
	}
	return "medium"
}
