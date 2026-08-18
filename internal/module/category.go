package module

// Category groups modules into the top-level sections shown in the report UI.
// It is the single source of truth for that grouping: the report server reads
// it via CategoryOf/Categories so a module can never appear in the nav without
// a home. Adding a module without adding it to moduleCategory below drops it
// into the "other" bucket (surfaced in the UI), which is the loud-failure we
// want rather than a silently missing tab.
type Category struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// categoryOrder is the display order of sections in the report nav. It mirrors
// the AWS tool's four sections one-for-one, so the two reports read the same.
// "Best Practices" currently has no Azure members (no posture-benchmark modules
// yet) but is kept so the nav lines up and future modules have a home.
var categoryOrder = []Category{
	{Key: "best_practices", Label: "Best Practices"},
	{Key: "secrets", Label: "Secrets Management"},
	{Key: "iam", Label: "IAM & Access"},
	{Key: "exposure", Label: "Public Exposure"},
}

// moduleCategory maps each registered module's Name() to a category key.
var moduleCategory = map[string]string{
	// Secrets management — exposed credentials/secrets in configs, code, and
	// deployment artifacts.
	"secrets_scan":        "secrets",
	"devops_secrets":      "secrets",
	"function_app_env":    "secrets",
	"aci_env":             "secrets",
	"arm_deployments":     "secrets",
	"automation_accounts": "secrets",
	"logic_apps":          "secrets",
	"vm_userdata":         "secrets",

	// IAM & access — Entra ID identity, overly-permissive trust, privilege
	// escalation, external takeover vectors.
	"iam_integrations": "iam",
	"entra_id":         "iam",
	"entra_users":      "iam",
	"dynamic_groups":   "iam",
	"external_trust":   "iam",
	"redirect_uris":    "iam",
	"rbac_review":      "iam",

	// Public exposure / attack surface.
	"blob_anon":          "exposure",
	"public_sql":         "exposure",
	"nsg_exposure":       "exposure",
	"acr_exposure":       "exposure",
	"keyvault_exposure":  "exposure",
	"subdomain_takeover": "exposure",
}

// CategoryOf returns the category key for a module name, or "other" if the
// module has not been assigned one.
func CategoryOf(name string) string {
	if c, ok := moduleCategory[name]; ok {
		return c
	}
	return "other"
}

// Categories returns the ordered list of sections for the report nav.
func Categories() []Category {
	return append([]Category(nil), categoryOrder...)
}
