package subdomain_takeover

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

//go:embed fingerprints.json
var fingerprintsJSON []byte

// fingerprint describes a known third-party service pattern for subdomain
// takeover (GitHub Pages, Heroku, Shopify, ...). Azure services are handled
// separately in azureServices because their takeover signal is structural
// (NXDOMAIN on the resource hostname) rather than an HTTP body string.
type fingerprint struct {
	Service     string   `json:"service"`
	CNAME       []string `json:"cname"`
	Fingerprint string   `json:"fingerprint"`
	HTTPStatus  int      `json:"http_status"`
	NXDomain    bool     `json:"nxdomain"`
	Vulnerable  bool     `json:"vulnerable"`
}

var fingerprints []fingerprint

func init() {
	if err := json.Unmarshal(fingerprintsJSON, &fingerprints); err != nil {
		panic("subdomain_takeover: parse fingerprints.json: " + err.Error())
	}
}

// ---------------------------------------------------------------------------
// Azure service catalogue
// ---------------------------------------------------------------------------

// azureService is an Azure resource type whose public hostname can be claimed
// by an attacker if the underlying resource is deleted but a CNAME still
// points at it. The canonical takeover signal for every one of these is the
// same: the target hostname (e.g. theapp.azurewebsites.net) resolves to
// NXDOMAIN, meaning the resource no longer exists and the name is free to
// re-register. See https://www.stratussecurity.com/post/azure-subdomain-takeover-guide
type azureService struct {
	Suffix  string
	Service string
	// VerificationProtected is true for services that additionally require a
	// domain-ownership verification record (asuid TXT / awverify) before a
	// custom domain can be bound. Re-registering the resource name is NOT by
	// itself sufficient to serve content on the victim's custom domain, so a
	// dangling CNAME alone is a weaker (manual-confirmation) finding rather
	// than a confirmed takeover.
	VerificationProtected bool
}

// azureServices is matched longest-suffix-first so that, e.g.,
// blob.core.windows.net wins over a hypothetical windows.net entry.
var azureServices = []azureService{
	{Suffix: "azurewebsites.net", Service: "App Service", VerificationProtected: true},
	{Suffix: "azurestaticapps.net", Service: "Static Web Apps", VerificationProtected: true},
	{Suffix: "cloudapp.net", Service: "Cloud Services (classic)"},
	{Suffix: "cloudapp.azure.com", Service: "Virtual Machine public IP"},
	{Suffix: "azureedge.net", Service: "Azure CDN"},
	{Suffix: "azurefd.net", Service: "Front Door (classic)"},
	{Suffix: "trafficmanager.net", Service: "Traffic Manager"},
	{Suffix: "blob.core.windows.net", Service: "Blob Storage"},
	{Suffix: "azure-api.net", Service: "API Management"},
	{Suffix: "database.windows.net", Service: "Azure SQL"},
	{Suffix: "azuredatalakestore.net", Service: "Data Lake Store Gen1"},
	{Suffix: "search.windows.net", Service: "AI Search"},
	{Suffix: "azurecr.io", Service: "Container Registry"},
	{Suffix: "azurecontainer.io", Service: "Container Instances"},
	{Suffix: "redis.cache.windows.net", Service: "Redis Cache"},
	{Suffix: "servicebus.windows.net", Service: "Service Bus"},
	{Suffix: "azurehdinsight.net", Service: "HDInsight"},
	{Suffix: "azuremicroservices.io", Service: "Service Fabric Mesh"},
}

// matchAzureService returns the most specific Azure service whose suffix the
// host matches, or nil if the host is not an Azure service hostname.
func matchAzureService(host string) *azureService {
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	var best *azureService
	for i := range azureServices {
		svc := &azureServices[i]
		if lower == svc.Suffix || strings.HasSuffix(lower, "."+svc.Suffix) {
			if best == nil || len(svc.Suffix) > len(best.Suffix) {
				best = svc
			}
		}
	}
	return best
}

// Module scans Azure DNS zones for dangling CNAME records that are
// susceptible to subdomain takeover.
type Module struct{}

func (Module) Name() string      { return "subdomain_takeover" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Network/dnsZones/read",
		"Microsoft.Network/dnsZones/recordsets/read",
	}
}

// probeResult holds the outcome of a CNAME DNS+HTTP probe (third-party path).
type probeResult struct {
	NXDomain   bool
	HTTPStatus int
	Body       string
	Err        error
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	log := func(level, msg string) {
		_ = sink.LogEvent(ctx, "subdomain_takeover", target.SubscriptionID, level, msg)
	}

	zonesClient, err := armdns.NewZonesClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("subdomain_takeover: create zones client: %w", err)
	}
	recordsClient, err := armdns.NewRecordSetsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("subdomain_takeover: create record sets client: %w", err)
	}

	// Collect all DNS zones.
	type zoneInfo struct {
		Name string
		ID   string
		RG   string
	}
	var zones []zoneInfo
	zPager := zonesClient.NewListPager(nil)
	for zPager.More() {
		page, err := zPager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("subdomain_takeover: list zones: %w", err)
		}
		for _, z := range page.Value {
			name := ptrVal(z.Name)
			id := ptrVal(z.ID)
			rg := resourceGroup(id)
			if rg == "" {
				continue
			}
			zones = append(zones, zoneInfo{Name: name, ID: id, RG: rg})
		}
	}

	log("info", fmt.Sprintf("found %d DNS zones", len(zones)))

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for zi, zone := range zones {
		log("info", fmt.Sprintf("zone %d/%d: %s", zi+1, len(zones), zone.Name))

		// Gather every record set in the zone up front so we can both iterate
		// CNAMEs and look up the domain-verification (asuid/awverify) records
		// that accompany App Service / Static Web Apps custom domains.
		type cnameRecord struct {
			ID    string
			Name  string
			FQDN  string
			CNAME string
		}
		var cnames []cnameRecord
		recordNames := map[string]bool{}

		rPager := recordsClient.NewListAllByDNSZonePager(zone.RG, zone.Name, nil)
		for rPager.More() {
			page, err := rPager.NextPage(ctx)
			if err != nil {
				log("warn", fmt.Sprintf("list records for zone %s: %v", zone.Name, err))
				break
			}
			for _, rs := range page.Value {
				rsName := ptrVal(rs.Name)
				recordNames[strings.ToLower(rsName)] = true
				if rs.Properties == nil || rs.Properties.CnameRecord == nil {
					continue
				}
				cnameValue := ptrVal(rs.Properties.CnameRecord.Cname)
				if cnameValue == "" {
					continue
				}
				fqdn := zone.Name
				if rsName != "@" {
					fqdn = rsName + "." + zone.Name
				}
				cnames = append(cnames, cnameRecord{
					ID: ptrVal(rs.ID), Name: rsName, FQDN: fqdn, CNAME: cnameValue,
				})
			}
		}

		for _, rec := range cnames {
			if svc := matchAzureService(rec.CNAME); svc != nil {
				scanAzureCNAME(ctx, sink, target, zone.Name, rec.ID, rec.Name, rec.FQDN, rec.CNAME, svc, recordNames, log)
				continue
			}

			// Non-Azure target: fall back to the third-party fingerprint
			// catalogue (resolves-but-dangling HTTP bodies, NXDOMAIN, ...).
			scanThirdPartyCNAME(ctx, httpClient, sink, target, zone.Name, rec.ID, rec.Name, rec.FQDN, rec.CNAME)
		}
	}

	log("info", "subdomain takeover checks complete")
	return nil
}

// scanAzureCNAME applies the structural NXDOMAIN-on-target check to a CNAME
// pointing at an Azure service hostname.
func scanAzureCNAME(
	ctx context.Context,
	sink findings.Sink,
	target creds.SubscriptionTarget,
	zoneName, recordID, recordName, fqdn, cnameTarget string,
	svc *azureService,
	recordNames map[string]bool,
	log func(level, msg string),
) {
	nx, err := targetIsNXDomain(ctx, cnameTarget)
	if err != nil {
		log("warn", fmt.Sprintf("resolve %s: %v", cnameTarget, err))
		return
	}
	if !nx {
		// The Azure resource still exists (the hostname resolves), so it is
		// owned by someone and cannot be claimed. This is the case that
		// previously caused false positives: a live App Service whose custom
		// domain happens to be unbound still serves a "Web Site not found"
		// page, but is NOT takeoverable. Emit nothing.
		return
	}

	// Target is NXDOMAIN: the named resource is gone and the hostname is free
	// to re-register.
	detail := map[string]any{
		"fqdn":          fqdn,
		"cname_target":  cnameTarget,
		"service":       svc.Service,
		"target_status": "NXDOMAIN",
		"zone":          zoneName,
		"record_set":    recordName,
	}

	if svc.VerificationProtected {
		// App Service / Static Web Apps are protected ONLY if the customer
		// opted in by publishing an asuid.{label} TXT record holding their
		// app's Domain Verification ID. Per Microsoft's guidance, when that
		// record exists no other subscription can validate the custom domain,
		// so a takeover is blocked even though the freed app name is
		// re-registrable. When the record is ABSENT (the common case), an
		// attacker who re-creates the app with the freed name can validate the
		// custom domain via the dangling CNAME itself, completing the takeover.
		asuidName, hasASUID := lookupVerificationRecord(recordNames, recordName)
		detail["asuid_record_present"] = hasASUID
		if hasASUID {
			detail["asuid_record"] = asuidName
			detail["reason"] = "the target resource name is unregistered and claimable, but an asuid domain-verification TXT record is present. Per Azure, while this record exists no other subscription can validate the custom domain, so takeover is blocked unless the verification ID itself is recoverable. Low risk — still clean up the dangling CNAME."
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         "global",
				Module:         "subdomain_takeover",
				Severity:       findings.SevLow,
				ResourceID:     recordID,
				Title:          fmt.Sprintf("Dangling CNAME %s -> %s (%s name claimable; protected by asuid verification)", fqdn, cnameTarget, svc.Service),
				Detail:         detail,
			})
			return
		}
		detail["reason"] = "the target resource name is unregistered and claimable, and NO asuid domain-verification TXT record is present. An attacker can re-create the " + svc.Service + " with this name and validate the custom domain using the dangling CNAME itself, completing the takeover."
		_ = sink.Write(ctx, findings.Finding{
			SubscriptionID: target.SubscriptionID,
			Region:         "global",
			Module:         "subdomain_takeover",
			Severity:       findings.SevHigh,
			ResourceID:     recordID,
			Title:          fmt.Sprintf("Dangling CNAME %s -> %s (%s, takeover likely; no domain-verification record)", fqdn, cnameTarget, svc.Service),
			Detail:         detail,
		})
		return
	}

	// Non-verification Azure services: re-registering the resource name with
	// the same hostname is sufficient to take over the subdomain.
	_ = sink.Write(ctx, findings.Finding{
		SubscriptionID: target.SubscriptionID,
		Region:         "global",
		Module:         "subdomain_takeover",
		Severity:       findings.SevCritical,
		ResourceID:     recordID,
		Title:          fmt.Sprintf("Dangling CNAME %s -> %s (%s, takeover likely)", fqdn, cnameTarget, svc.Service),
		Detail:         detail,
	})
}

// scanThirdPartyCNAME handles CNAMEs that point outside Azure, using the
// HTTP-body / NXDOMAIN fingerprint catalogue.
func scanThirdPartyCNAME(
	ctx context.Context,
	httpClient *http.Client,
	sink findings.Sink,
	target creds.SubscriptionTarget,
	zoneName, recordID, recordName, fqdn, cnameTarget string,
) {
	result := probeCNAME(ctx, httpClient, fqdn)

	if result.NXDomain {
		if fp := matchNXDomainFingerprint(cnameTarget, fingerprints); fp != nil {
			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         "global",
				Module:         "subdomain_takeover",
				Severity:       findings.SevCritical,
				ResourceID:     recordID,
				Title:          fmt.Sprintf("Dangling CNAME %s -> %s (%s, takeover likely)", fqdn, cnameTarget, fp.Service),
				Detail: map[string]any{
					"fqdn":         fqdn,
					"cname_target": cnameTarget,
					"service":      fp.Service,
					"nxdomain":     true,
					"zone":         zoneName,
					"record_set":   recordName,
				},
			})
		}
		return
	}

	if result.Err != nil {
		return
	}

	// Host resolves — check HTTP body fingerprints.
	if fp := matchHTTPFingerprint(cnameTarget, result.Body, result.HTTPStatus, fingerprints); fp != nil {
		_ = sink.Write(ctx, findings.Finding{
			SubscriptionID: target.SubscriptionID,
			Region:         "global",
			Module:         "subdomain_takeover",
			Severity:       findings.SevCritical,
			ResourceID:     recordID,
			Title:          fmt.Sprintf("Dangling CNAME %s -> %s (%s, HTTP fingerprint matched)", fqdn, cnameTarget, fp.Service),
			Detail: map[string]any{
				"fqdn":         fqdn,
				"cname_target": cnameTarget,
				"service":      fp.Service,
				"http_status":  result.HTTPStatus,
				"nxdomain":     false,
				"zone":         zoneName,
				"record_set":   recordName,
			},
		})
	}
}

// lookupVerificationRecord reports whether the zone contains an App Service /
// Static Web Apps domain-verification record (asuid.{label} TXT, or asuid at
// the apex) for the given CNAME label. Only asuid confers protection; the
// legacy awverify method is deprecated and does not block takeover.
func lookupVerificationRecord(recordNames map[string]bool, label string) (string, bool) {
	candidate := "asuid." + label
	if label == "@" {
		candidate = "asuid"
	}
	if recordNames[strings.ToLower(candidate)] {
		return candidate, true
	}
	return "", false
}

// targetIsNXDomain resolves host directly and reports whether the lookup
// returned NXDOMAIN (the resource hostname no longer exists).
func targetIsNXDomain(ctx context.Context, host string) (bool, error) {
	h := strings.TrimSuffix(host, ".")
	_, err := net.DefaultResolver.LookupHost(ctx, h)
	if err != nil {
		if isNXDomain(err) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// probeCNAME performs a DNS lookup on host. If the host resolves, it
// issues an HTTP GET and captures the response status and body (up to 64KB).
// If the DNS lookup returns NXDOMAIN, NXDomain is set to true.
func probeCNAME(ctx context.Context, client *http.Client, host string) probeResult {
	_, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		if isNXDomain(err) {
			return probeResult{NXDomain: true}
		}
		return probeResult{Err: err}
	}

	// Host resolves — attempt HTTP probe (HTTPS first, then HTTP).
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		return probeResult{
			HTTPStatus: resp.StatusCode,
			Body:       string(body),
		}
	}
	return probeResult{Err: fmt.Errorf("HTTP probe failed for %s", host)}
}

func isNXDomain(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	msg := err.Error()
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "NXDOMAIN")
}

// matchNXDomainFingerprint returns the first fingerprint whose CNAME
// pattern matches the given host and is marked as vulnerable via NXDOMAIN.
func matchNXDomainFingerprint(host string, fps []fingerprint) *fingerprint {
	lower := strings.ToLower(host)
	for i := range fps {
		fp := &fps[i]
		if !fp.NXDomain || !fp.Vulnerable {
			continue
		}
		for _, cn := range fp.CNAME {
			if strings.HasSuffix(lower, "."+cn) || lower == cn {
				return fp
			}
		}
	}
	return nil
}

// matchHTTPFingerprint returns the first fingerprint whose CNAME pattern
// matches the host and whose HTTP body fingerprint / status matches the probe
// result.
func matchHTTPFingerprint(host, body string, status int, fps []fingerprint) *fingerprint {
	lower := strings.ToLower(host)
	for i := range fps {
		fp := &fps[i]
		if !fp.Vulnerable {
			continue
		}
		cnameMatch := false
		for _, cn := range fp.CNAME {
			if strings.HasSuffix(lower, "."+cn) || lower == cn {
				cnameMatch = true
				break
			}
		}
		if !cnameMatch {
			continue
		}
		if fp.Fingerprint == "" {
			continue
		}
		if fp.HTTPStatus != 0 && status != fp.HTTPStatus {
			continue
		}
		if strings.Contains(body, fp.Fingerprint) {
			return fp
		}
	}
	return nil
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
