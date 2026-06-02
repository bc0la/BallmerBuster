package redirect_uris

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module flags dangling OAuth redirect / reply / logout URIs on app
// registrations and service principals — URIs whose target host no longer
// resolves and is therefore potentially re-registrable, letting an attacker
// capture authorization codes/tokens. Severity is scaled by each app's granted
// delegated permissions. Split into its own module so it gets its own report
// tab and can be skipped with --no-redirect-uris.
type Module struct{}

func (Module) Name() string      { return "redirect_uris" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Directory.Read.All",
		"Application.Read.All",
	}
}

// seenTenant gates this tenant-wide Graph module so it runs once per tenant
// rather than once per subscription.
var seenTenant sync.Map

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	log := func(level, msg string) {
		_ = sink.LogEvent(ctx, "redirect_uris", target.SubscriptionID, level, msg)
	}
	emit := func(f findings.Finding) {
		f.SubscriptionID = target.SubscriptionID
		f.Module = "redirect_uris"
		_ = sink.Write(ctx, f)
	}

	if _, already := seenTenant.LoadOrStore(target.TenantID, true); already {
		log("info", fmt.Sprintf("redirect URI checks already run for tenant %s via another subscription — skipping to avoid duplicates", target.TenantID))
		return nil
	}

	log("info", "checking redirect/reply URIs for dangling hosts")
	privIndex, _ := buildDelegatedPrivIndex(ctx, target, log)
	if err := checkDanglingRedirectURIs(ctx, target, emit, log, privIndex); err != nil {
		log("warn", fmt.Sprintf("dangling redirect URIs: %v", err))
	}

	log("info", "redirect URI checks complete")
	return nil
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

// ---------------------------------------------------------------------------
// DNS / Azure-host helpers
// ---------------------------------------------------------------------------

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
