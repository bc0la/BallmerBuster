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

// fingerprint describes a known service pattern for subdomain takeover.
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

// verificationProtectedSuffixes are Azure service domains where binding a
// custom domain requires proving ownership of the source DNS name first
// (the `asuid.<host>` / `awverify` TXT verification record). For these, a
// dangling or NXDOMAIN CNAME is NOT directly takeoverable: even if an
// attacker recreates a resource with the same hostname, Azure refuses to
// bind the victim's custom domain without the verification record. Flagging
// these as critical takeovers produces false positives, so we downgrade
// them to an informational Low finding.
var verificationProtectedSuffixes = []string{
	"azurewebsites.net",  // App Service
	"azurestaticapps.net", // Static Web Apps
}

// isVerificationProtected reports whether the CNAME target points at an
// Azure service that enforces domain-ownership verification.
func isVerificationProtected(host string) bool {
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suf := range verificationProtectedSuffixes {
		if lower == suf || strings.HasSuffix(lower, "."+suf) {
			return true
		}
	}
	return false
}

// probeResult holds the outcome of a CNAME DNS+HTTP probe.
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

		rPager := recordsClient.NewListAllByDNSZonePager(zone.RG, zone.Name, nil)
		for rPager.More() {
			page, err := rPager.NextPage(ctx)
			if err != nil {
				log("warn", fmt.Sprintf("list records for zone %s: %v", zone.Name, err))
				break
			}

			for _, rs := range page.Value {
				if rs.Properties == nil || rs.Properties.CnameRecord == nil {
					continue
				}
				cnameValue := ptrVal(rs.Properties.CnameRecord.Cname)
				if cnameValue == "" {
					continue
				}

				// Build the FQDN of this record.
				rsName := ptrVal(rs.Name)
				var fqdn string
				if rsName == "@" {
					fqdn = zone.Name
				} else {
					fqdn = rsName + "." + zone.Name
				}

				result := probeCNAME(ctx, httpClient, fqdn)

				// Verification-protected services (App Service, Static Web
				// Apps) require an asuid/awverify TXT record before a custom
				// domain can be bound, so a dangling CNAME is not directly
				// takeoverable. Downgrade to an informational Low finding
				// instead of a critical/high takeover claim, and only when
				// the record actually appears dangling.
				if isVerificationProtected(cnameValue) {
					dangling := result.NXDomain ||
						(result.Err == nil && matchHTTPFingerprint(cnameValue, result.Body, result.HTTPStatus, fingerprints) != nil)
					if dangling {
						_ = sink.Write(ctx, findings.Finding{
							SubscriptionID: target.SubscriptionID,
							Region:         "global",
							Module:         "subdomain_takeover",
							Severity:       findings.SevLow,
							ResourceID:     ptrVal(rs.ID),
							Title:          fmt.Sprintf("Dangling CNAME %s -> %s (verification-protected, takeover unlikely)", fqdn, cnameValue),
							Detail: map[string]any{
								"fqdn":         fqdn,
								"cname_target": cnameValue,
								"nxdomain":     result.NXDomain,
								"zone":         zone.Name,
								"record_set":   rsName,
								"reason":       "target service requires domain-ownership verification (asuid/awverify TXT record) before a custom domain can be bound, so this dangling CNAME is not directly takeoverable",
							},
						})
					}
					continue
				}

				if result.NXDomain {
					// Check if the CNAME target matches a known vulnerable service.
					fp := matchNXDomainFingerprint(cnameValue, fingerprints)
					if fp != nil {
						_ = sink.Write(ctx, findings.Finding{
							SubscriptionID: target.SubscriptionID,
							Region:         "global",
							Module:         "subdomain_takeover",
							Severity:       findings.SevCritical,
							ResourceID:     ptrVal(rs.ID),
							Title:          fmt.Sprintf("Dangling CNAME %s -> %s (%s, takeover likely)", fqdn, cnameValue, fp.Service),
							Detail: map[string]any{
								"fqdn":         fqdn,
								"cname_target": cnameValue,
								"service":      fp.Service,
								"nxdomain":     true,
								"zone":         zone.Name,
								"record_set":   rsName,
							},
						})
					} else {
						// NXDOMAIN but no fingerprint match — still suspicious.
						_ = sink.Write(ctx, findings.Finding{
							SubscriptionID: target.SubscriptionID,
							Region:         "global",
							Module:         "subdomain_takeover",
							Severity:       findings.SevHigh,
							ResourceID:     ptrVal(rs.ID),
							Title:          fmt.Sprintf("Dangling CNAME %s -> %s (NXDOMAIN, unverified service)", fqdn, cnameValue),
							Detail: map[string]any{
								"fqdn":         fqdn,
								"cname_target": cnameValue,
								"nxdomain":     true,
								"zone":         zone.Name,
								"record_set":   rsName,
							},
						})
					}
				} else if result.Err == nil {
					// DNS resolved — check HTTP fingerprints.
					fp := matchHTTPFingerprint(cnameValue, result.Body, result.HTTPStatus, fingerprints)
					if fp != nil {
						_ = sink.Write(ctx, findings.Finding{
							SubscriptionID: target.SubscriptionID,
							Region:         "global",
							Module:         "subdomain_takeover",
							Severity:       findings.SevCritical,
							ResourceID:     ptrVal(rs.ID),
							Title:          fmt.Sprintf("Dangling CNAME %s -> %s (%s, HTTP fingerprint matched)", fqdn, cnameValue, fp.Service),
							Detail: map[string]any{
								"fqdn":         fqdn,
								"cname_target": cnameValue,
								"service":      fp.Service,
								"http_status":  result.HTTPStatus,
								"nxdomain":     false,
								"zone":         zone.Name,
								"record_set":   rsName,
							},
						})
					}
				}
			}
		}
	}

	log("info", "subdomain takeover checks complete")
	return nil
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
