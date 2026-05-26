package blob_anon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module scans storage accounts for publicly accessible blob containers.
type Module struct{}

func (Module) Name() string      { return "blob_anon" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Storage/storageAccounts/read",
		"Microsoft.Storage/storageAccounts/blobServices/containers/read",
	}
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	acctClient, err := armstorage.NewAccountsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("blob_anon: create accounts client: %w", err)
	}
	containerClient, err := armstorage.NewBlobContainersClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("blob_anon: create containers client: %w", err)
	}

	// Collect all storage accounts.
	var accounts []*armstorage.Account
	pager := acctClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("blob_anon: list accounts: %w", err)
		}
		accounts = append(accounts, page.Value...)
	}

	_ = sink.LogEvent(ctx, "blob_anon", target.SubscriptionID, "info",
		fmt.Sprintf("scanning %d storage accounts", len(accounts)))

	httpClient := &http.Client{Timeout: 5 * time.Second}

	for i, acct := range accounts {
		acctName := ptrVal(acct.Name)
		_ = sink.LogEvent(ctx, "blob_anon", target.SubscriptionID, "info",
			fmt.Sprintf("account %d/%d: %s", i+1, len(accounts), acctName))

		// If AllowBlobPublicAccess is explicitly false, skip.
		if acct.Properties != nil && acct.Properties.AllowBlobPublicAccess != nil && !*acct.Properties.AllowBlobPublicAccess {
			continue
		}

		rg := resourceGroup(ptrVal(acct.ID))
		if rg == "" {
			continue
		}

		cPager := containerClient.NewListPager(rg, acctName, nil)
		for cPager.More() {
			cPage, err := cPager.NextPage(ctx)
			if err != nil {
				_ = sink.LogEvent(ctx, "blob_anon", target.SubscriptionID, "warn",
					fmt.Sprintf("list containers for %s: %v", acctName, err))
				break
			}
			for _, c := range cPage.Value {
				if c.Properties == nil || c.Properties.PublicAccess == nil {
					continue
				}
				access := *c.Properties.PublicAccess
				if access == armstorage.PublicAccessNone {
					continue
				}

				containerName := ptrVal(c.Name)
				detail := map[string]any{
					"account_name":     acctName,
					"container_name":   containerName,
					"public_access":    string(access),
					"probe_listable":   false,
					"probe_status":     "",
				}

				sev := findings.SevHigh // default for Blob-level access

				if access == armstorage.PublicAccessContainer {
					// Probe anonymous listing.
					listable, status := probeAnonymousList(ctx, httpClient, acctName, containerName)
					detail["probe_listable"] = listable
					detail["probe_status"] = status
					if listable {
						sev = findings.SevCritical
					}
				}

				_ = sink.Write(ctx, findings.Finding{
					SubscriptionID: target.SubscriptionID,
					Region:         ptrVal(acct.Location),
					Module:         "blob_anon",
					Severity:       sev,
					ResourceID:     ptrVal(c.ID),
					Title:          fmt.Sprintf("Public blob access on %s/%s (%s)", acctName, containerName, access),
					Detail:         detail,
				})
			}
		}
	}

	return nil
}

// probeAnonymousList performs an unauthenticated GET to the container's
// list-blobs endpoint and returns true when the response is a 200 with XML.
func probeAnonymousList(ctx context.Context, client *http.Client, account, container string) (bool, string) {
	url := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", account, container)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Sprintf("request error: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("probe error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	// Read a small prefix to confirm XML.
	buf := make([]byte, 512)
	n, _ := io.ReadAtLeast(resp.Body, buf, 1)
	body := string(buf[:n])
	if strings.Contains(body, "<?xml") || strings.Contains(body, "<EnumerationResults") {
		return true, "HTTP 200 (XML listing)"
	}
	return false, fmt.Sprintf("HTTP 200 (non-XML body, %d bytes)", n)
}

func resourceGroup(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func ptrVal[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
