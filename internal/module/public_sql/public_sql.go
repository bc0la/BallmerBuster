package public_sql

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module scans Azure SQL servers for public network exposure and
// overly permissive firewall rules.
type Module struct{}

func (Module) Name() string      { return "public_sql" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Sql/servers/read",
		"Microsoft.Sql/servers/firewallRules/read",
	}
}

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	serverClient, err := armsql.NewServersClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("public_sql: create servers client: %w", err)
	}
	fwClient, err := armsql.NewFirewallRulesClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("public_sql: create firewall client: %w", err)
	}

	// Collect all SQL servers.
	var servers []*armsql.Server
	pager := serverClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("public_sql: list servers: %w", err)
		}
		servers = append(servers, page.Value...)
	}

	_ = sink.LogEvent(ctx, "public_sql", target.SubscriptionID, "info",
		fmt.Sprintf("scanning %d SQL servers", len(servers)))

	for i, srv := range servers {
		serverName := ptrVal(srv.Name)
		rg := resourceGroup(ptrVal(srv.ID))
		if rg == "" {
			continue
		}

		_ = sink.LogEvent(ctx, "public_sql", target.SubscriptionID, "info",
			fmt.Sprintf("server %d/%d: %s", i+1, len(servers), serverName))

		// Check public network access.
		publicAccess := false
		if srv.Properties != nil && srv.Properties.PublicNetworkAccess != nil {
			publicAccess = *srv.Properties.PublicNetworkAccess == armsql.ServerNetworkAccessFlagEnabled
		}

		// Enumerate firewall rules.
		var rules []*armsql.FirewallRule
		fwPager := fwClient.NewListByServerPager(rg, serverName, nil)
		for fwPager.More() {
			fwPage, err := fwPager.NextPage(ctx)
			if err != nil {
				_ = sink.LogEvent(ctx, "public_sql", target.SubscriptionID, "warn",
					fmt.Sprintf("list firewall rules for %s: %v", serverName, err))
				break
			}
			rules = append(rules, fwPage.Value...)
		}

		fqdn := ""
		if srv.Properties != nil {
			fqdn = ptrVal(srv.Properties.FullyQualifiedDomainName)
		}

		for _, rule := range rules {
			if rule.Properties == nil {
				continue
			}
			startIP := ptrVal(rule.Properties.StartIPAddress)
			endIP := ptrVal(rule.Properties.EndIPAddress)
			ruleName := ptrVal(rule.Name)

			var sev findings.Severity
			var title string

			switch {
			case startIP == "0.0.0.0" && endIP == "255.255.255.255":
				sev = findings.SevCritical
				title = fmt.Sprintf("SQL server %s: firewall rule %q allows all internet traffic (0.0.0.0-255.255.255.255)", serverName, ruleName)
			case startIP == "0.0.0.0" && endIP == "0.0.0.0":
				sev = findings.SevMedium
				title = fmt.Sprintf("SQL server %s: firewall rule %q allows all Azure services (0.0.0.0-0.0.0.0)", serverName, ruleName)
			default:
				continue
			}

			// TCP probe for reachability when publicly accessible.
			tcpReachable := false
			if publicAccess && fqdn != "" && sev == findings.SevCritical {
				tcpReachable = probeTCP(ctx, fqdn, "1433", 3*time.Second)
			}

			detail := map[string]any{
				"server_name":       serverName,
				"fqdn":              fqdn,
				"rule_name":         ruleName,
				"start_ip":          startIP,
				"end_ip":            endIP,
				"public_access":     publicAccess,
				"tcp_reachable":     tcpReachable,
			}

			_ = sink.Write(ctx, findings.Finding{
				SubscriptionID: target.SubscriptionID,
				Region:         ptrVal(srv.Location),
				Module:         "public_sql",
				Severity:       sev,
				ResourceID:     ptrVal(rule.ID),
				Title:          title,
				Detail:         detail,
			})
		}

		// Also flag if public network access is enabled but no dangerously wide
		// rule was found — informational awareness.
		if publicAccess {
			hasDangerous := false
			for _, rule := range rules {
				if rule.Properties == nil {
					continue
				}
				startIP := ptrVal(rule.Properties.StartIPAddress)
				endIP := ptrVal(rule.Properties.EndIPAddress)
				if (startIP == "0.0.0.0" && endIP == "255.255.255.255") ||
					(startIP == "0.0.0.0" && endIP == "0.0.0.0") {
					hasDangerous = true
					break
				}
			}
			if !hasDangerous {
				_ = sink.Write(ctx, findings.Finding{
					SubscriptionID: target.SubscriptionID,
					Region:         ptrVal(srv.Location),
					Module:         "public_sql",
					Severity:       findings.SevLow,
					ResourceID:     ptrVal(srv.ID),
					Title:          fmt.Sprintf("SQL server %s has public network access enabled", serverName),
					Detail: map[string]any{
						"server_name":   serverName,
						"fqdn":          fqdn,
						"public_access": true,
						"firewall_rules": len(rules),
					},
				})
			}
		}
	}

	return nil
}

// probeTCP attempts a TCP dial to host:port with the given timeout.
func probeTCP(_ context.Context, host, port string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
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
