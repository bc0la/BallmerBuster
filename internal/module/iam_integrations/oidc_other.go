package iam_integrations

import (
	"strings"

	"github.com/you/ballmerbuster/internal/findings"
)

// oidcSubjectRisk is a generic classification returned by per-issuer
// subject analyzers (Kubernetes, GitLab, etc.). Returns Severity == ""
// for well-scoped subjects.
type oidcSubjectRisk struct {
	Pattern  string
	Severity findings.Severity
	Category string
	Reason   string
}

// ---------------------------------------------------------------------------
// Kubernetes service-account OIDC
// ---------------------------------------------------------------------------
//
// K8s service-account tokens (used for workload identity federation from
// EKS, AKS-self-hosted, GKE, on-prem clusters, etc.) have:
//
//	subject: system:serviceaccount:<namespace>:<service-account>
//	issuer : the cluster's OIDC discovery URL
//	         e.g. https://oidc.eks.<region>.amazonaws.com/id/<UID>
//	              https://<aks-cluster>.<region>.oic.prod-aks.azure.com/<uid>/
//
// Wildcards in the subject are never honored by Azure FIC v1.0
// (subject is matched exactly), so they're misconfigurations — but
// they're also a red flag that whoever wrote the FIC believed
// wildcards worked, which means there may be a claimsMatchingExpression
// in play, and there a wildcard granting tokens to any pod in any
// namespace IS a takeover vector.

// k8sSAOIDCHints matches issuer URLs that emit Kubernetes service-account
// tokens. The check is intentionally generous — there are many ways to
// stand up a K8s OIDC issuer.
func looksLikeK8sIssuer(issuer string) bool {
	low := strings.ToLower(issuer)
	switch {
	case strings.Contains(low, "oidc.eks."), strings.Contains(low, ".eks.amazonaws.com"):
		return true
	case strings.Contains(low, ".oic.prod-aks.azure.com"):
		return true
	case strings.Contains(low, "container.googleapis.com"):
		return true
	case strings.Contains(low, "kubernetes.default.svc"):
		return true
	}
	return false
}

const k8sSubjectPrefix = "system:serviceaccount:"

// analyzeK8sSub classifies a Kubernetes service-account subject.
func analyzeK8sSub(subject string) oidcSubjectRisk {
	v := strings.TrimSpace(subject)
	if v == "" {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "k8s_oidc_empty_sub",
			Reason:   "empty subject — FIC will never match a real K8s SA token"}
	}
	if v == "*" || strings.HasPrefix(v, "*") {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevMedium,
			Category: "k8s_oidc_universal_sub",
			Reason:   "subject is a wildcard; Azure FIC v1.0 needs an exact match — but with claimsMatchingExpression this grants any K8s pod a token"}
	}
	if !strings.HasPrefix(v, k8sSubjectPrefix) {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "k8s_oidc_unrecognized_sub",
			Reason:   "subject does not start with `system:serviceaccount:` — K8s tokens always do; this FIC will not authenticate any real pod"}
	}
	rest := strings.TrimPrefix(v, k8sSubjectPrefix)
	// rest = "<namespace>:<service-account>"
	colon := strings.Index(rest, ":")
	if colon == -1 {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "k8s_oidc_no_serviceaccount",
			Reason:   "subject pins a namespace but no service account — K8s does not emit such subjects"}
	}
	ns := rest[:colon]
	sa := rest[colon+1:]
	if ns == "*" || strings.Contains(ns, "*") {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevMedium,
			Category: "k8s_oidc_wildcard_namespace",
			Reason:   "namespace is wildcarded; with claimsMatchingExpression any pod in any namespace can mint tokens for this app"}
	}
	if sa == "" {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "k8s_oidc_empty_sa",
			Reason:   "service-account segment is empty — FIC will not match any real token"}
	}
	if sa == "*" || strings.Contains(sa, "*") {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevMedium,
			Category: "k8s_oidc_wildcard_serviceaccount",
			Reason:   "service-account name is wildcarded; with claimsMatchingExpression any SA in `" + ns + "` can mint tokens"}
	}
	// Default SA in default namespace is essentially anonymous in
	// many clusters — flag it.
	if ns == "default" && sa == "default" {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "k8s_oidc_default_namespace_default_sa",
			Reason:   "subject is `system:serviceaccount:default:default` — any unprivileged pod in the cluster can use the default SA and mint tokens"}
	}
	return oidcSubjectRisk{Pattern: subject, Severity: "", Category: "k8s_oidc_scoped"}
}

// ---------------------------------------------------------------------------
// GitLab CI/CD OIDC
// ---------------------------------------------------------------------------
//
// GitLab job_jwt tokens have subjects like:
//
//	project_path:<group>/<project>:ref_type:branch:ref:<branch>
//	project_path:<group>/<project>:ref_type:tag:ref:<tag>
//	project_path:<group>/<project>:environment:<env>
//	project_path:<group>/<project>:pipeline_source:merge_request_event
//	project_path:<group>/<project>:user_id:<id>
//
// Issuer is https://gitlab.com (or a self-hosted instance URL).

func looksLikeGitLabIssuer(issuer string) bool {
	low := strings.ToLower(issuer)
	return strings.Contains(low, "gitlab.com") || strings.Contains(low, "gitlab.")
}

const gitlabSubjectPrefix = "project_path:"

// analyzeGitLabSub classifies a GitLab CI OIDC subject.
func analyzeGitLabSub(subject string) oidcSubjectRisk {
	v := strings.TrimSpace(subject)
	if v == "" {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "gitlab_oidc_empty_sub",
			Reason:   "empty subject — FIC will never authenticate any GitLab CI job"}
	}
	if v == "*" || strings.HasPrefix(v, "*") {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevMedium,
			Category: "gitlab_oidc_universal_sub",
			Reason:   "subject is a wildcard; Azure FIC v1.0 needs an exact match — but with claimsMatchingExpression any GitLab project can mint tokens"}
	}
	if !strings.HasPrefix(v, gitlabSubjectPrefix) {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "gitlab_oidc_unrecognized_sub",
			Reason:   "subject does not start with `project_path:` — GitLab CI tokens always do; this FIC will not authenticate any real job"}
	}
	rest := strings.TrimPrefix(v, gitlabSubjectPrefix)
	colon := strings.Index(rest, ":")
	var projectPath, tail string
	if colon == -1 {
		projectPath = rest
	} else {
		projectPath = rest[:colon]
		tail = rest[colon+1:]
	}
	if projectPath == "" {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "gitlab_oidc_empty_project",
			Reason:   "project_path segment is empty"}
	}
	if strings.Contains(projectPath, "*") {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevMedium,
			Category: "gitlab_oidc_wildcard_project",
			Reason:   "project_path is wildcarded; with claimsMatchingExpression any GitLab project matching the pattern can mint tokens"}
	}
	if tail == "" {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "gitlab_oidc_no_qualifier",
			Reason:   "subject pins project but no ref/environment/pipeline qualifier — GitLab does not emit such subjects, FIC will not match"}
	}
	if tail == "*" || strings.HasPrefix(tail, "*") {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevMedium,
			Category: "gitlab_oidc_any_qualifier_wildcard",
			Reason:   "qualifier is wildcarded; with claimsMatchingExpression any branch/environment/pipeline in this project can mint tokens"}
	}
	// Merge-request-triggered subjects are dangerous: anyone with fork
	// access can open an MR and trigger the job.
	if strings.Contains(tail, "pipeline_source:merge_request_event") ||
		strings.Contains(tail, "ref_type:merge_request") {
		return oidcSubjectRisk{Pattern: subject, Severity: findings.SevHigh,
			Category: "gitlab_oidc_merge_request",
			Reason:   "subject allows merge_request runs — untrusted MRs from forks can mint tokens"}
	}
	return oidcSubjectRisk{Pattern: subject, Severity: "", Category: "gitlab_oidc_scoped"}
}

// ---------------------------------------------------------------------------
// Generic unknown-issuer detection
// ---------------------------------------------------------------------------

// knownOIDCIssuer returns true if the issuer URL matches one of the
// well-known providers we have specific analyzers for.
func knownOIDCIssuer(issuer string) bool {
	if strings.Contains(issuer, githubOIDCIssuer) {
		return true
	}
	if looksLikeK8sIssuer(issuer) {
		return true
	}
	if looksLikeGitLabIssuer(issuer) {
		return true
	}
	// Microsoft Entra cross-tenant workload identity federation.
	if strings.HasPrefix(issuer, "https://sts.windows.net/") ||
		strings.HasPrefix(issuer, "https://login.microsoftonline.com/") {
		return true
	}
	// Google Cloud workload identity.
	if strings.Contains(issuer, "accounts.google.com") {
		return true
	}
	// Terraform Cloud.
	if strings.Contains(issuer, "app.terraform.io") {
		return true
	}
	// CircleCI.
	if strings.Contains(issuer, "oidc.circleci.com") {
		return true
	}
	return false
}
