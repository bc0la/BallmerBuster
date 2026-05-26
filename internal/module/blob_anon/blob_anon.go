package blob_anon

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

type Module struct{}

func (Module) Name() string      { return "blob_anon" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Storage/storageAccounts/read",
		"Microsoft.Storage/storageAccounts/blobServices/containers/read",
	}
}

const (
	probeTimeout = 10 * time.Second
	probeWorkers = 10
	maxBlobsPerContainer = 20
)

var anonClient = &http.Client{Timeout: probeTimeout}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	acctClient, err := armstorage.NewAccountsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("blob_anon: create accounts client: %w", err)
	}
	containerClient, err := armstorage.NewBlobContainersClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("blob_anon: create containers client: %w", err)
	}

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

	for i, acct := range accounts {
		acctName := ptrVal(acct.Name)
		_ = sink.LogEvent(ctx, "blob_anon", target.SubscriptionID, "info",
			fmt.Sprintf("account %d/%d: %s", i+1, len(accounts), acctName))

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
				_ = sink.LogEvent(ctx, "blob_anon", target.SubscriptionID, "info",
					fmt.Sprintf("%s/%s: public_access=%s — probing", acctName, containerName, access))

				listInfo := probeAnonList(ctx, acctName, containerName)

				var blobHits []anonBlobHit
				if access == armstorage.PublicAccessBlob || access == armstorage.PublicAccessContainer {
					var keys []string
					if listInfo.listable {
						keys = listInfo.sampleKeys
					}
					if len(keys) > 0 {
						blobHits = probeBlobs(ctx, acctName, containerName, keys)
					}
				}

				sev := findings.SevHigh
				if listInfo.listable {
					sev = findings.SevCritical
				}

				var title string
				switch {
				case listInfo.listable && len(blobHits) > 0:
					title = fmt.Sprintf("Storage %s/%s: anonymously listable + %d readable blob(s)", acctName, containerName, len(blobHits))
				case listInfo.listable:
					title = fmt.Sprintf("Storage %s/%s: anonymously listable", acctName, containerName)
				case len(blobHits) > 0:
					title = fmt.Sprintf("Storage %s/%s: %d anonymously-readable blob(s)", acctName, containerName, len(blobHits))
				default:
					title = fmt.Sprintf("Storage %s/%s: public access level %s", acctName, containerName, access)
				}

				detail := map[string]any{
					"account_name":       acctName,
					"container_name":     containerName,
					"public_access":      string(access),
					"anonymously_listable": listInfo.listable,
				}

				var curls []string

				if listInfo.listable {
					detail["list_curl"] = listInfo.curl
					detail["list_sample_keys"] = listInfo.sampleKeys
					detail["list_total_returned"] = listInfo.totalSeen
					curls = append(curls, listInfo.curl)
				}

				if len(blobHits) > 0 {
					objs := make([]map[string]any, 0, len(blobHits))
					for _, h := range blobHits {
						curls = append(curls, h.curl)
						objs = append(objs, map[string]any{
							"key":          h.key,
							"url":          h.url,
							"status":       h.status,
							"content_type": h.contentType,
							"size":         h.size,
						})
					}
					detail["blobs_public"] = objs
				}

				if len(curls) > 0 {
					detail["curl"] = curls
				}

				_ = sink.Write(ctx, findings.Finding{
					SubscriptionID: target.SubscriptionID,
					Region:         ptrVal(acct.Location),
					Module:         "blob_anon",
					Severity:       sev,
					ResourceID:     ptrVal(c.ID),
					Title:          title,
					Detail:         detail,
				})
			}
		}
	}

	return nil
}

type anonListInfo struct {
	listable   bool
	curl       string
	sampleKeys []string
	totalSeen  int
}

func probeAnonList(ctx context.Context, account, container string) anonListInfo {
	u := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list&maxresults=%d",
		account, container, maxBlobsPerContainer)
	info := anonListInfo{curl: fmt.Sprintf("curl -s '%s'", u)}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return info
	}
	resp, err := anonClient.Do(req)
	if err != nil {
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info
	}

	var parsed struct {
		XMLName xml.Name `xml:"EnumerationResults"`
		Blobs   struct {
			Blob []struct {
				Name string `xml:"Name"`
			} `xml:"Blob"`
		} `xml:"Blobs"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return info
	}
	info.listable = true
	info.totalSeen = len(parsed.Blobs.Blob)
	for i, b := range parsed.Blobs.Blob {
		if i >= maxBlobsPerContainer {
			break
		}
		info.sampleKeys = append(info.sampleKeys, b.Name)
	}
	return info
}

type anonBlobHit struct {
	key         string
	url         string
	status      int
	contentType string
	size        string
	curl        string
}

func probeBlobs(ctx context.Context, account, container string, keys []string) []anonBlobHit {
	if len(keys) == 0 {
		return nil
	}
	results := make([]anonBlobHit, len(keys))
	ok := make([]bool, len(keys))

	type job struct {
		idx int
		key string
	}
	jobs := make(chan job)
	var wg sync.WaitGroup

	workers := probeWorkers
	if workers > len(keys) {
		workers = len(keys)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if h, found := probeOneBlob(ctx, account, container, j.key); found {
					results[j.idx] = h
					ok[j.idx] = true
				}
			}
		}()
	}
	for i, k := range keys {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return collectHits(results, ok)
		case jobs <- job{idx: i, key: k}:
		}
	}
	close(jobs)
	wg.Wait()
	return collectHits(results, ok)
}

func collectHits(results []anonBlobHit, ok []bool) []anonBlobHit {
	var hits []anonBlobHit
	for i, h := range results {
		if ok[i] {
			hits = append(hits, h)
		}
	}
	return hits
}

func probeOneBlob(ctx context.Context, account, container, key string) (anonBlobHit, bool) {
	u := blobURL(account, container, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return anonBlobHit{}, false
	}
	resp, err := anonClient.Do(req)
	if err != nil {
		return anonBlobHit{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return anonBlobHit{}, false
	}
	return anonBlobHit{
		key:         key,
		url:         u,
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		size:        resp.Header.Get("Content-Length"),
		curl:        fmt.Sprintf("curl -sI '%s'", u),
	}, true
}

func blobURL(account, container, key string) string {
	return fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s",
		account, container, url.PathEscape(key))
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
