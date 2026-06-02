package iam_integrations

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/you/ballmerbuster/internal/findings"
)

// ---------------------------------------------------------------------------
// Federated credential takeover detection
// ---------------------------------------------------------------------------
//
// A federated identity credential (on an app registration or a user-assigned
// managed identity) trusts an *external* identity provider to mint tokens for
// an Azure principal. There are three distinct external-takeover vectors:
//
//  1. The trusted *subject owner* is claimable — e.g. a GitHub org/user or a
//     gitlab.com group that no longer exists. An attacker re-registers the
//     name, recreates the repo/workflow, and obtains tokens. (assessFICTakeover)
//  2. The *issuer domain itself* is claimable — for self-hosted / custom OIDC
//     issuers, if the issuer hostname's DNS is dangling, an attacker who
//     registers it can serve a malicious discovery doc + JWKS and mint
//     arbitrary tokens, defeating subject scoping entirely. (assessIssuerDomain)
//  3. (Separate file) Dangling OAuth redirect/reply/logout URIs whose host is
//     claimable — OAuth code/token theft. (redirect_uris.go)
//
// All probes are best-effort: inconclusive results are reported for manual
// validation rather than suppressed.

// claimableAzureSuffixes are native Azure service hostnames that become
// directly re-registrable (no domain-ownership verification) once the
// underlying resource is deleted.
var claimableAzureSuffixes = []string{
	"azurewebsites.net",
	"azurefd.net",
	"azureedge.net",
	"cloudapp.azure.com",
	"cloudapp.net",
	"blob.core.windows.net",
	"trafficmanager.net",
	"azurecontainer.io",
	"azure-api.net",
	"azurecr.io",
	"azurehdinsight.net",
	"azuremicroservices.io",
}

func isClaimableAzureHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suf := range claimableAzureSuffixes {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	return false
}

// vendorIssuerSuffixes are OIDC issuer domains owned by a provider and thus
// never claimable. Everything else is treated as self-hosted/custom and is
// probed for a dangling issuer domain.
var vendorIssuerSuffixes = []string{
	"githubusercontent.com",
	"gitlab.com",
	"login.microsoftonline.com",
	"windows.net", // sts.windows.net, *.oic.prod-aks.azure.com is *.azure.com
	"azure.com",
	"amazonaws.com",
	"accounts.google.com",
	"container.googleapis.com",
	"app.terraform.io",
	"oidc.circleci.com",
}

func issuerIsVendorOwned(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suf := range vendorIssuerSuffixes {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	return false
}

// hostIsNXDOMAIN resolves host and reports whether the lookup returned
// NXDOMAIN (the name no longer exists).
func hostIsNXDOMAIN(ctx context.Context, host string) (bool, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(c, strings.TrimSuffix(host, "."))
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// externalPrincipal is the claimable external identity referenced by a FIC
// subject.
type externalPrincipal struct {
	Provider string // "github" | "gitlab" | "terraform"
	Owner    string // org / user / group — the claimable namespace
	Repo     string // repository / project, when pinned
	ProbeURL string // unauthenticated URL whose 404 means "claimable"; "" = no probe
	RepoURL  string // optional repo-level existence probe (best-effort, no escalation)
}

// parseExternalPrincipal extracts the claimable owner (and repo, when pinned)
// from a FIC subject for issuers whose identity namespace is publicly
// registrable.
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
			ep.RepoURL = "https://github.com/" + owner + "/" + repo
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
		// Only gitlab.com has a public namespace we can probe; self-hosted
		// instances are covered by the issuer-domain check instead.
		if strings.Contains(strings.ToLower(issuer), "gitlab.com") {
			ep.ProbeURL = "https://gitlab.com/" + group
		}
		if len(seg) == 2 && seg[1] != "" && !strings.Contains(seg[1], "*") {
			ep.Repo = seg[1]
		}
		return ep, true

	case strings.Contains(issuer, "app.terraform.io"):
		// subject: organization:<org>:project:<proj>:workspace:<ws>:run_phase:<phase>
		rest := strings.TrimPrefix(s, "organization:")
		if rest == s {
			return externalPrincipal{}, false
		}
		org := rest
		if c := strings.Index(rest, ":"); c != -1 {
			org = rest[:c]
		}
		if org == "" || strings.Contains(org, "*") {
			return externalPrincipal{}, false
		}
		// Terraform Cloud org pages require auth, so we can't reliably probe
		// claimability unauthenticated — surface for manual validation.
		return externalPrincipal{Provider: "terraform", Owner: org}, true
	}
	return externalPrincipal{}, false
}

// takeoverResult is the outcome of a best-effort claimability assessment of
// the trusted subject owner.
type takeoverResult struct {
	Principal externalPrincipal
	Found     bool              // a claimable principal was parsed
	Status    string            // "claimable" | "exists" | "inconclusive" | "n/a"
	RepoNote  string            // best-effort repo-level existence note
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

	// Best-effort repo-level existence (no escalation: a missing repo under an
	// existing org is only recreatable by the org owner, not an attacker).
	if ep.RepoURL != "" {
		if missing, rstatus, rerr := probeClaimable(ctx, client, ep.RepoURL); rerr == nil {
			if missing {
				res.RepoNote = fmt.Sprintf("repo %q returns HTTP %d (deleted/renamed) — recreatable only by the owner, not directly by an attacker", ep.Repo, rstatus)
			} else {
				res.RepoNote = fmt.Sprintf("repo %q exists (HTTP %d)", ep.Repo, rstatus)
			}
		}
	}
	return res
}

// assessIssuerDomain probes whether a self-hosted / custom OIDC issuer's
// hostname is dangling (claimable). Vendor-owned issuers are skipped.
func assessIssuerDomain(ctx context.Context, issuer string) (claimable bool, host string, skipped bool, err error) {
	u, e := url.Parse(strings.TrimSpace(issuer))
	if e != nil || u.Hostname() == "" {
		return false, "", true, e
	}
	host = u.Hostname()
	if issuerIsVendorOwned(host) {
		return false, host, true, nil
	}
	nx, e := hostIsNXDOMAIN(ctx, host)
	if e != nil {
		return false, host, false, e
	}
	return nx, host, false, nil
}

// probeClaimable issues a single unauthenticated GET. A 404/410 means the
// namespace is unregistered (claimable).
func probeClaimable(ctx context.Context, client *http.Client, target string) (bool, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
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
