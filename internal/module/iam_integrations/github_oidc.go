package iam_integrations

import (
	"strings"

	"github.com/you/ballmerbuster/internal/findings"
)

// GitHub Actions OIDC issuer.
const githubOIDCIssuer = "token.actions.githubusercontent.com"

// ghSubjectRisk classifies a GitHub Actions OIDC subject claim on an Azure
// federated identity credential.
//
// The GitHub OIDC `sub` claim has the shape:
//
//	repo:<owner>/<repo>:ref:refs/heads/<branch>
//	repo:<owner>/<repo>:environment:<env>
//	repo:<owner>/<repo>:pull_request
//
// Azure FIC v1.0 matches `subject` against `sub` *exactly* — wildcards in
// the subject value will never match a real token unless the FIC also has
// a `claimsMatchingExpression` (a beta Graph feature). Wildcard patterns
// are therefore flagged as misconfigurations rather than direct takeover
// risks, with a hint to verify whether claimsMatchingExpression is in
// play. PR-triggered subjects and missing-qualifier patterns remain real
// attack surface.
type ghSubjectRisk struct {
	Pattern  string
	Severity findings.Severity
	Category string
	Reason   string
}

// analyzeGitHubSub returns a risk classification for a GitHub OIDC subject.
// Returns Severity == "" for well-scoped subjects.
func analyzeGitHubSub(subject string) ghSubjectRisk {
	v := strings.TrimSpace(subject)

	if v == "" {
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevHigh,
			Category: "github_oidc_empty_sub",
			Reason:   "empty subject — FIC will never match a real GitHub OIDC token (unless paired with claimsMatchingExpression)",
		}
	}

	if v == "*" || v == "repo:*" || strings.HasPrefix(v, "*") {
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevMedium,
			Category: "github_oidc_universal_sub",
			Reason:   "subject is a wildcard; Azure FIC v1.0 requires an exact match against the sub claim — this will never authenticate unless a claimsMatchingExpression is configured",
		}
	}

	if !strings.HasPrefix(v, "repo:") {
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevHigh,
			Category: "github_oidc_unrecognized_sub",
			Reason:   "subject does not start with `repo:` — GitHub OIDC tokens always have a repo: prefix; this FIC will not authenticate any real token",
		}
	}

	rest := strings.TrimPrefix(v, "repo:")

	// repo:<owner>/<repo>[:rest]
	slash := strings.Index(rest, "/")
	if slash == -1 {
		// repo:owner (no slash, no repo at all).
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevHigh,
			Category: "github_oidc_no_repo",
			Reason:   "subject pins an owner but no repository — GitHub does not emit such subjects",
		}
	}
	owner := rest[:slash]
	afterOwner := rest[slash+1:]

	if strings.Contains(owner, "*") {
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevMedium,
			Category: "github_oidc_wildcard_owner",
			Reason:   "owner segment contains a wildcard; Azure FIC v1.0 requires exact match — verify whether a claimsMatchingExpression is in use",
		}
	}

	// Organization-wide wildcard: repo:owner/*, repo:owner/*:*
	if afterOwner == "*" || strings.HasPrefix(afterOwner, "*:") || afterOwner == "*:*" {
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevMedium,
			Category: "github_oidc_org_wide_wildcard",
			Reason:   "wildcard after the owner; without a claimsMatchingExpression this FIC will never match a real token",
		}
	}

	colon := strings.Index(afterOwner, ":")
	var repo, tail string
	if colon == -1 {
		repo = afterOwner
	} else {
		repo = afterOwner[:colon]
		tail = afterOwner[colon+1:]
	}

	if strings.Contains(repo, "*") {
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevMedium,
			Category: "github_oidc_wildcard_repo",
			Reason:   "repo segment contains a wildcard; Azure FIC v1.0 requires exact match — verify whether a claimsMatchingExpression is in use",
		}
	}

	// repo:owner/repo with no qualifier — GitHub never emits this format.
	if tail == "" {
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevHigh,
			Category: "github_oidc_no_qualifier",
			Reason:   "subject pins owner/repo but no :ref/:environment/:pull_request qualifier — GitHub does not emit such subjects, FIC will not match",
		}
	}

	if tail == "*" || strings.HasPrefix(tail, "*") {
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevMedium,
			Category: "github_oidc_any_qualifier_wildcard",
			Reason:   "qualifier is a wildcard; Azure FIC v1.0 requires exact match — verify whether a claimsMatchingExpression is in use",
		}
	}

	// PR-triggered subjects are real attack surface: anyone can open a PR
	// from a fork and a pull_request_target workflow will mint a token.
	if strings.HasPrefix(tail, "pull_request") || strings.Contains(v, ":ref:refs/pull/") {
		return ghSubjectRisk{
			Pattern:  subject,
			Severity: findings.SevHigh,
			Category: "github_oidc_pull_request",
			Reason:   "subject allows pull_request runs — untrusted fork PRs can mint tokens if the workflow uses pull_request_target",
		}
	}

	// Well-scoped: specific ref or environment.
	return ghSubjectRisk{
		Pattern:  subject,
		Severity: "",
		Category: "github_oidc_scoped",
		Reason:   "subject is pinned to a specific ref/environment",
	}
}
