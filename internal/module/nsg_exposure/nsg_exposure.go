package nsg_exposure

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module inspects Network Security Groups for inbound rules that expose
// sensitive ports to the public internet. A wide-open rule is only actually
// reachable if the NSG is attached (directly, or via its subnet) to a resource
// that has a public IP — so the module correlates each NSG to the public IPs
// behind it and TCP-probes the exposed ports to confirm real exposure.
type Module struct{}

func (Module) Name() string      { return "nsg_exposure" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Network/networkSecurityGroups/read",
		"Microsoft.Network/networkInterfaces/read",
		"Microsoft.Network/publicIPAddresses/read",
	}
}

// probeTimeout bounds each TCP reachability check.
const probeTimeout = 3 * time.Second

// sensitivePort describes a port considered dangerous when exposed publicly.
type sensitivePort struct {
	Port     int
	Service  string
	Severity findings.Severity
}

var sensitivePorts = []sensitivePort{
	{22, "SSH", findings.SevCritical},
	{3389, "RDP", findings.SevCritical},
	{1433, "MSSQL", findings.SevHigh},
	{3306, "MySQL", findings.SevHigh},
	{5432, "PostgreSQL", findings.SevHigh},
	{445, "SMB", findings.SevMedium},
	{139, "NetBIOS", findings.SevMedium},
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	nsgClient, err := armnetwork.NewSecurityGroupsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("nsg_exposure: create nsg client: %w", err)
	}
	nicClient, err := armnetwork.NewInterfacesClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("nsg_exposure: create nic client: %w", err)
	}
	pipClient, err := armnetwork.NewPublicIPAddressesClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("nsg_exposure: create public-ip client: %w", err)
	}

	log := func(level, msg string) {
		_ = sink.LogEvent(ctx, "nsg_exposure", target.SubscriptionID, level, msg)
	}

	// Build the public-IP correlation maps once for the subscription.
	nicPublicIPs, subnetPublicIPs, err := buildPublicIPIndex(ctx, nicClient, pipClient)
	if err != nil {
		// Non-fatal: we can still report rule exposure without reachability.
		log("warn", fmt.Sprintf("could not build public-IP index (reachability will be skipped): %v", err))
	}

	var nsgs []*armnetwork.SecurityGroup
	pager := nsgClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("nsg_exposure: list NSGs: %w", err)
		}
		nsgs = append(nsgs, page.Value...)
	}

	log("info", fmt.Sprintf("scanning %d NSGs", len(nsgs)))

	for i, nsg := range nsgs {
		nsgName := ptrVal(nsg.Name)
		log("info", fmt.Sprintf("NSG %d/%d: %s", i+1, len(nsgs), nsgName))

		if nsg.Properties == nil {
			continue
		}

		// Public IPs reachable through this NSG (via attached NICs or subnets).
		publicIPs := nsgPublicIPs(nsg, nicPublicIPs, subnetPublicIPs)

		// Inspect both custom security rules and default security rules.
		allRules := make([]*armnetwork.SecurityRule, 0, len(nsg.Properties.SecurityRules)+len(nsg.Properties.DefaultSecurityRules))
		allRules = append(allRules, nsg.Properties.SecurityRules...)
		allRules = append(allRules, nsg.Properties.DefaultSecurityRules...)

		for _, rule := range allRules {
			if rule.Properties == nil {
				continue
			}

			// Only inbound allow rules.
			if rule.Properties.Direction == nil || *rule.Properties.Direction != armnetwork.SecurityRuleDirectionInbound {
				continue
			}
			if rule.Properties.Access == nil || *rule.Properties.Access != armnetwork.SecurityRuleAccessAllow {
				continue
			}

			// Check if source is the public internet.
			if !isPublicSource(rule.Properties) {
				continue
			}

			// Collect all destination port ranges from both singular and plural fields.
			portRanges := collectPortRanges(rule.Properties)

			// Check which sensitive ports are exposed.
			matched := matchSensitivePorts(portRanges)
			if len(matched) == 0 {
				continue
			}

			// Base severity is the highest among matched ports.
			baseSev := findings.SevMedium
			for _, m := range matched {
				if severityRank(m.Severity) > severityRank(baseSev) {
					baseSev = m.Severity
				}
			}

			matchedNames := make([]string, 0, len(matched))
			for _, m := range matched {
				matchedNames = append(matchedNames, fmt.Sprintf("%d/%s", m.Port, m.Service))
			}

			ruleName := ptrVal(rule.Name)
			sourcePrefix := sourcePrefixes(rule.Properties)

			// Reachability: only meaningful when a public IP sits behind this NSG.
			var reachable []string
			probed := false
			if len(publicIPs) > 0 {
				probed = true
				reachable = probeReachable(ctx, publicIPs, matched)
			}

			// Exposure-aware severity:
			//   - no public IP behind the NSG  -> downgrade (latent rule only)
			//   - public IP but not reachable  -> downgrade (host down / filtered)
			//   - confirmed TCP-reachable      -> keep the port's full severity
			sev := baseSev
			exposure := ""
			switch {
			case len(publicIPs) == 0:
				sev = downgrade(baseSev)
				exposure = "no public-IP-bearing resource is attached to this NSG; rule is latent until one is added"
			case len(reachable) == 0:
				sev = downgrade(baseSev)
				exposure = fmt.Sprintf("attached to %d public IP(s) but none answered on the exposed port(s) — host down or filtered upstream", len(publicIPs))
			default:
				exposure = fmt.Sprintf("CONFIRMED reachable: %s", strings.Join(reachable, ", "))
			}

			title := fmt.Sprintf("NSG %s rule %q exposes %s from %s",
				nsgName, ruleName, strings.Join(matchedNames, ", "), sourcePrefix)
			if len(reachable) > 0 {
				title = fmt.Sprintf("NSG %s rule %q exposes %s to the internet and is TCP-reachable (%s)",
					nsgName, ruleName, strings.Join(matchedNames, ", "), strings.Join(reachable, ", "))
			}

			detail := map[string]any{
				"nsg_name":            nsgName,
				"rule_name":           ruleName,
				"source_prefix":       sourcePrefix,
				"port_ranges":         portRanges,
				"matched_ports":       matchedNames,
				"attached_public_ips": publicIPs,
				"tcp_probed":          probed,
				"tcp_reachable":       reachable,
				"exposure":            exposure,
			}

			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         ptrVal(nsg.Location),
				Module:         "nsg_exposure",
				Severity:       sev,
				ResourceID:     ptrVal(nsg.ID),
				Title:          title,
				Detail:         detail,
			})
		}
	}

	return nil
}

// buildPublicIPIndex lists every NIC and public IP in the subscription and
// returns two maps: NIC resource ID -> public IPs on that NIC, and subnet
// resource ID -> public IPs of NICs sitting in that subnet. All keys are
// lower-cased for case-insensitive matching against NSG references.
func buildPublicIPIndex(ctx context.Context, nicClient *armnetwork.InterfacesClient, pipClient *armnetwork.PublicIPAddressesClient) (nicIPs, subnetIPs map[string][]string, err error) {
	// 1. Resolve public-IP resource IDs to their actual addresses.
	pipByID := map[string]string{}
	pipPager := pipClient.NewListAllPager(nil)
	for pipPager.More() {
		page, perr := pipPager.NextPage(ctx)
		if perr != nil {
			return nil, nil, fmt.Errorf("list public IPs: %w", perr)
		}
		for _, p := range page.Value {
			if p.ID == nil || p.Properties == nil {
				continue
			}
			if ip := ptrVal(p.Properties.IPAddress); ip != "" {
				pipByID[strings.ToLower(*p.ID)] = ip
			}
		}
	}

	// 2. Walk NICs, attaching public IPs to the NIC and to its subnet(s).
	nicIPs = map[string][]string{}
	subnetIPs = map[string][]string{}
	nicPager := nicClient.NewListAllPager(nil)
	for nicPager.More() {
		page, nerr := nicPager.NextPage(ctx)
		if nerr != nil {
			return nil, nil, fmt.Errorf("list NICs: %w", nerr)
		}
		for _, nic := range page.Value {
			if nic.ID == nil || nic.Properties == nil {
				continue
			}
			var ips []string
			var subnets []string
			for _, cfg := range nic.Properties.IPConfigurations {
				if cfg.Properties == nil {
					continue
				}
				if cfg.Properties.PublicIPAddress != nil && cfg.Properties.PublicIPAddress.ID != nil {
					if ip, ok := pipByID[strings.ToLower(*cfg.Properties.PublicIPAddress.ID)]; ok {
						ips = append(ips, ip)
					}
				}
				if cfg.Properties.Subnet != nil && cfg.Properties.Subnet.ID != nil {
					subnets = append(subnets, strings.ToLower(*cfg.Properties.Subnet.ID))
				}
			}
			if len(ips) == 0 {
				continue
			}
			nicIPs[strings.ToLower(*nic.ID)] = ips
			for _, s := range subnets {
				subnetIPs[s] = append(subnetIPs[s], ips...)
			}
		}
	}
	return nicIPs, subnetIPs, nil
}

// nsgPublicIPs returns the deduplicated set of public IPs reachable through an
// NSG, following both its directly-attached NICs and its attached subnets.
func nsgPublicIPs(nsg *armnetwork.SecurityGroup, nicIPs, subnetIPs map[string][]string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	if nsg.Properties == nil {
		return out
	}
	for _, ni := range nsg.Properties.NetworkInterfaces {
		if ni == nil || ni.ID == nil {
			continue
		}
		for _, ip := range nicIPs[strings.ToLower(*ni.ID)] {
			add(ip)
		}
	}
	for _, sn := range nsg.Properties.Subnets {
		if sn == nil || sn.ID == nil {
			continue
		}
		for _, ip := range subnetIPs[strings.ToLower(*sn.ID)] {
			add(ip)
		}
	}
	return out
}

// probeReachable TCP-dials each (public IP, matched port) pair and returns the
// "ip:port/service" labels that accepted a connection.
func probeReachable(ctx context.Context, ips []string, ports []sensitivePort) []string {
	var reachable []string
	for _, ip := range ips {
		for _, sp := range ports {
			if probeTCP(ctx, ip, strconv.Itoa(sp.Port)) {
				reachable = append(reachable, fmt.Sprintf("%s:%d/%s", ip, sp.Port, sp.Service))
			}
		}
	}
	return reachable
}

// probeTCP attempts a TCP dial to host:port within probeTimeout.
func probeTCP(ctx context.Context, host, port string) bool {
	var d net.Dialer
	c, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := d.DialContext(c, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// isPublicSource returns true when the rule's source address prefix indicates
// unrestricted internet access.
func isPublicSource(props *armnetwork.SecurityRulePropertiesFormat) bool {
	prefix := ptrVal(props.SourceAddressPrefix)
	if isInternetPrefix(prefix) {
		return true
	}
	// Also check SourceAddressPrefixes (plural).
	for _, p := range props.SourceAddressPrefixes {
		if p != nil && isInternetPrefix(*p) {
			return true
		}
	}
	return false
}

func isInternetPrefix(prefix string) bool {
	switch prefix {
	case "*", "0.0.0.0/0", "Internet", "::/0":
		return true
	}
	return false
}

// sourcePrefixes renders the rule's source for display.
func sourcePrefixes(props *armnetwork.SecurityRulePropertiesFormat) string {
	if p := ptrVal(props.SourceAddressPrefix); p != "" {
		return p
	}
	var all []string
	for _, p := range props.SourceAddressPrefixes {
		if p != nil && *p != "" {
			all = append(all, *p)
		}
	}
	return strings.Join(all, ",")
}

// collectPortRanges gathers all destination port range strings from a rule.
func collectPortRanges(props *armnetwork.SecurityRulePropertiesFormat) []string {
	var ranges []string
	if props.DestinationPortRange != nil && *props.DestinationPortRange != "" {
		ranges = append(ranges, *props.DestinationPortRange)
	}
	for _, r := range props.DestinationPortRanges {
		if r != nil && *r != "" {
			ranges = append(ranges, *r)
		}
	}
	return ranges
}

// matchSensitivePorts checks which sensitive ports fall within the given ranges.
func matchSensitivePorts(portRanges []string) []sensitivePort {
	var matched []sensitivePort
	for _, sp := range sensitivePorts {
		for _, pr := range portRanges {
			if portInRange(sp.Port, pr) {
				matched = append(matched, sp)
				break
			}
		}
	}
	return matched
}

// portInRange returns true if port falls within a port-range string.
// Accepted formats: "*" (all), "22" (single), "100-200" (range).
func portInRange(port int, rangeStr string) bool {
	rangeStr = strings.TrimSpace(rangeStr)
	if rangeStr == "*" {
		return true
	}
	if before, after, ok := strings.Cut(rangeStr, "-"); ok {
		lo, errLo := strconv.Atoi(strings.TrimSpace(before))
		hi, errHi := strconv.Atoi(strings.TrimSpace(after))
		if errLo != nil || errHi != nil {
			return false
		}
		return port >= lo && port <= hi
	}
	single, err := strconv.Atoi(rangeStr)
	if err != nil {
		return false
	}
	return port == single
}

func severityRank(s findings.Severity) int {
	switch s {
	case findings.SevCritical:
		return 4
	case findings.SevHigh:
		return 3
	case findings.SevMedium:
		return 2
	case findings.SevLow:
		return 1
	default:
		return 0
	}
}

// downgrade lowers a severity by one rank (floor: Low).
func downgrade(s findings.Severity) findings.Severity {
	switch s {
	case findings.SevCritical:
		return findings.SevHigh
	case findings.SevHigh:
		return findings.SevMedium
	default:
		return findings.SevLow
	}
}

func ptrVal[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
