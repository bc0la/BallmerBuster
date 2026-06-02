package iam_integrations

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/you/ballmerbuster/internal/findings"
)

// ---------------------------------------------------------------------------
// Federated credential takeover detection
// ---------------------------------------------------------------------------
//
// A federated identity credential (on an app registration or a user-assigned
// managed identity) trusts an *external* identity provider to mint tokens for
// an Azure principal. If the external identity it trusts is deleted and its
// namespace can be re-registered by anyone — e.g. a GitHub organization/user
// or a GitLab group that no longer exists — an attacker can claim that name,
// recreate the repository + workflow, and obtain tokens as the Azure
// principal. This is the federated-credential analogue of a subdomain
// takeover.
//
// Detection is best-effort: we parse the claimable owner out of the subject
// and, for providers with a public namespace we can probe unauthenticated
// (GitHub, gitlab.com), issue a single HTTP GET — a 404/410 on the owner means
// the name is unregistered and claimable. Any inconclusive result is reported
// for manual validation rather than suppressed.

// externalPrincipal is the claimable external identity referenced by a FIC
// subject.
type externalPrincipal struct {
	Provider string // "github" | "gitlab"
	Owner    string // org / user / group — the claimable namespace
	Repo     string // repository / project, when pinned
	ProbeURL string // unauthenticated URL whose 404 means "claimable"; "" = no probe
}

// parseExternalPrincipal extracts the claimable owner (and repo, when pinned)
// from a FIC subject for issuers whose identity namespace is publicly
// registrable. Wildcarded or unparseable owners return ok=false (the
// subject-pattern analyzer already handles those as misconfigurations).
func parseExternalPrincipal(issuer, subject string) (externalPrincipal, bool) {
	s := strings.TrimSpace(subject)
	switch {
	case strings.Contains(issuer, githubOIDCIssuer):
		rest := strings.TrimPrefix(s, "repo:")
		if rest == s {
			return externalPrincipal{}, false
		}
		slash := strings.Index(rest, "/")
		if slash <= 0 {
			return externalPrincipal{}, false
		}
		owner := rest[:slash]
		if owner == "" || strings.Contains(owner, "*") {
			return externalPrincipal{}, false
		}
		after := rest[slash+1:]
		repo := after
		if c := strings.Index(after, ":"); c != -1 {
			repo = after[:c]
		}
		ep := externalPrincipal{Provider: "github", Owner: owner, ProbeURL: "https://github.com/" + owner}
		if repo != "" && !strings.Contains(repo, "*") {
			ep.Repo = repo
		}
		return ep, true

	case looksLikeGitLabIssuer(issuer):
		rest := strings.TrimPrefix(s, gitlabSubjectPrefix)
		if rest == s {
			return externalPrincipal{}, false
		}
		path := rest
		if c := strings.Index(rest, ":"); c != -1 {
			path = rest[:c]
		}
		seg := strings.SplitN(path, "/", 2)
		group := seg[0]
		if group == "" || strings.Contains(group, "*") {
			return externalPrincipal{}, false
		}
		ep := externalPrincipal{Provider: "gitlab", Owner: group}
		// Only gitlab.com has a namespace we can probe unauthenticated;
		// self-hosted instances are left for manual validation.
		if strings.Contains(strings.ToLower(issuer), "gitlab.com") {
			ep.ProbeURL = "https://gitlab.com/" + group
		}
		if len(seg) == 2 && seg[1] != "" && !strings.Contains(seg[1], "*") {
			ep.Repo = seg[1]
		}
		return ep, true
	}
	return externalPrincipal{}, false
}

// takeoverResult is the outcome of a best-effort claimability assessment.
type takeoverResult struct {
	Principal externalPrincipal
	Found     bool              // a claimable principal was parsed
	Status    string            // "claimable" | "exists" | "inconclusive" | "n/a"
	Severity  findings.Severity // SevHigh when confirmed claimable; "" otherwise
	Reason    string
}

// assessFICTakeover parses the external principal and, when possible, probes
// whether its namespace is claimable.
func assessFICTakeover(ctx context.Context, client *http.Client, issuer, subject string) takeoverResult {
	ep, ok := parseExternalPrincipal(issuer, subject)
	if !ok {
		return takeoverResult{Status: "n/a"}
	}
	res := takeoverResult{Principal: ep, Found: true, Status: "inconclusive"}

	if ep.ProbeURL == "" {
		res.Reason = fmt.Sprintf("external identity %q (%s) is referenced; claimability was not probed for this issuer — validate manually that you control it", ep.Owner, ep.Provider)
		return res
	}

	claimable, status, err := probeClaimable(ctx, client, ep.ProbeURL)
	if err != nil {
		res.Reason = fmt.Sprintf("could not verify whether %s owner %q is claimable (%v) — validate manually", ep.Provider, ep.Owner, err)
		return res
	}
	if claimable {
		res.Status = "claimable"
		res.Severity = findings.SevHigh
		res.Reason = fmt.Sprintf("the trusted %s owner %q does not exist (HTTP %d) and can be re-registered by anyone; an attacker who claims it can recreate the repo/workflow and mint tokens as this identity (federated credential takeover)", ep.Provider, ep.Owner, status)
		return res
	}
	res.Status = "exists"
	res.Reason = fmt.Sprintf("trusted %s owner %q exists (HTTP %d); not claimable via owner-deletion — confirm you actually control it", ep.Provider, ep.Owner, status)
	return res
}

// probeClaimable issues a single unauthenticated GET. A 404/410 means the
// namespace is unregistered (claimable).
func probeClaimable(ctx context.Context, client *http.Client, url string) (bool, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("User-Agent", "ballmerbuster-fic-takeover-check")
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusGone:
		return true, resp.StatusCode, nil
	default:
		return false, resp.StatusCode, nil
	}
}
