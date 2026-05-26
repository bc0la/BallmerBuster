package nsg_exposure

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module inspects Network Security Groups for inbound rules that expose
// sensitive ports to the public internet.
type Module struct{}

func (Module) Name() string      { return "nsg_exposure" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{"Microsoft.Network/networkSecurityGroups/read"}
}

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
		return fmt.Errorf("nsg_exposure: create client: %w", err)
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

	_ = sink.LogEvent(ctx, "nsg_exposure", target.SubscriptionID, "info",
		fmt.Sprintf("scanning %d NSGs", len(nsgs)))

	for i, nsg := range nsgs {
		nsgName := ptrVal(nsg.Name)
		_ = sink.LogEvent(ctx, "nsg_exposure", target.SubscriptionID, "info",
			fmt.Sprintf("NSG %d/%d: %s", i+1, len(nsgs), nsgName))

		if nsg.Properties == nil {
			continue
		}

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

			// Use the highest severity among matched ports.
			sev := findings.SevMedium
			for _, m := range matched {
				if severityRank(m.Severity) > severityRank(sev) {
					sev = m.Severity
				}
			}

			matchedNames := make([]string, 0, len(matched))
			for _, m := range matched {
				matchedNames = append(matchedNames, fmt.Sprintf("%d/%s", m.Port, m.Service))
			}

			ruleName := ptrVal(rule.Name)
			sourcePrefix := ptrVal(rule.Properties.SourceAddressPrefix)

			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         ptrVal(nsg.Location),
				Module:         "nsg_exposure",
				Severity:       sev,
				ResourceID:     ptrVal(nsg.ID),
				Title: fmt.Sprintf("NSG %s rule %q exposes %s from %s",
					nsgName, ruleName, strings.Join(matchedNames, ", "), sourcePrefix),
				Detail: map[string]any{
					"nsg_name":       nsgName,
					"rule_name":      ruleName,
					"source_prefix":  sourcePrefix,
					"port_ranges":    portRanges,
					"matched_ports":  matchedNames,
				},
			})
		}
	}

	return nil
}

// isPublicSource returns true when the rule's source address prefix indicates
// unrestricted internet access.
func isPublicSource(props *armnetwork.SecurityRulePropertiesFormat) bool {
	prefix := ptrVal(props.SourceAddressPrefix)
	switch prefix {
	case "*", "0.0.0.0/0", "Internet":
		return true
	}
	// Also check SourceAddressPrefixes (plural).
	for _, p := range props.SourceAddressPrefixes {
		if p == nil {
			continue
		}
		switch *p {
		case "*", "0.0.0.0/0", "Internet":
			return true
		}
	}
	return false
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

func ptrVal[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
