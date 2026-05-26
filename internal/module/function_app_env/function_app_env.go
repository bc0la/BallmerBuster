package function_app_env

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
	"github.com/you/ballmerbuster/internal/module"
)

func init() { module.Register(Module{}) }

// Module scans Function App and App Service application settings for secrets
// leaked into environment variables.
type Module struct{}

func (Module) Name() string      { return "function_app_env" }
func (Module) Kind() module.Kind { return module.KindNative }
func (Module) Requires() []string {
	return []string{
		"Microsoft.Web/sites/read",
		"Microsoft.Web/sites/config/list/action",
	}
}

// Compiled patterns (built once, reused across all apps).
var (
	keyPattern   = regexp.MustCompile(`(?i)(password|secret|token|api[_\-]?key|connection[_\-]?string|private[_\-]?key|credentials?)`)
	valAWSKey    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	valPEM       = regexp.MustCompile(`-----BEGIN .* PRIVATE KEY-----`)
	valJWT       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ`)
	valSlack     = regexp.MustCompile(`xox[bprs]-[0-9a-zA-Z-]+`)
	valuePatterns = []*regexp.Regexp{valAWSKey, valPEM, valJWT, valSlack}
	valueLabels   = []string{"AWS access key", "PEM private key", "JWT token", "Slack token"}
)

func (Module) Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error {
	webClient, err := armappservice.NewWebAppsClient(target.SubscriptionID, target.Credential, nil)
	if err != nil {
		return fmt.Errorf("function_app_env: create web apps client: %w", err)
	}

	// Collect all web apps / function apps.
	var apps []*armappservice.Site
	pager := webClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("function_app_env: list web apps: %w", err)
		}
		apps = append(apps, page.Value...)
	}

	_ = sink.LogEvent(ctx, "function_app_env", target.SubscriptionID, "info",
		fmt.Sprintf("scanning %d web apps", len(apps)))

	for i, app := range apps {
		appName := ptrVal(app.Name)
		rg := resourceGroup(ptrVal(app.ID))
		if rg == "" {
			continue
		}

		_ = sink.LogEvent(ctx, "function_app_env", target.SubscriptionID, "info",
			fmt.Sprintf("app %d/%d: %s", i+1, len(apps), appName))

		resp, err := webClient.ListApplicationSettings(ctx, rg, appName, nil)
		if err != nil {
			_ = sink.LogEvent(ctx, "function_app_env", target.SubscriptionID, "warn",
				fmt.Sprintf("list app settings for %s: %v", appName, err))
			continue
		}

		if resp.Properties == nil {
			continue
		}

		for key, val := range resp.Properties {
			value := ptrVal(val)

			// Check value against concrete secret patterns first.
			if matched, label := matchValuePattern(value); matched {
				_ = sink.Write(ctx, findings.Finding{
					SubscriptionID: target.SubscriptionID,
					Region:         ptrVal(app.Location),
					Module:         "function_app_env",
					Severity:       findings.SevHigh,
					ResourceID:     ptrVal(app.ID),
					Title:          fmt.Sprintf("App %s setting %q matches secret pattern (%s)", appName, key, label),
					Detail: map[string]any{
						"app_name":        appName,
						"setting_key":     key,
						"pattern_matched": label,
					},
				})
				continue // don't double-report for the same key
			}

			// Check key name against suspicious patterns.
			if keyPattern.MatchString(key) && len(value) > 0 {
				_ = sink.Write(ctx, findings.Finding{
					SubscriptionID: target.SubscriptionID,
					Region:         ptrVal(app.Location),
					Module:         "function_app_env",
					Severity:       findings.SevMedium,
					ResourceID:     ptrVal(app.ID),
					Title:          fmt.Sprintf("App %s setting %q has suspicious key name", appName, key),
					Detail: map[string]any{
						"app_name":    appName,
						"setting_key": key,
						"reason":      "key name matches secret pattern",
					},
				})
			}
		}
	}

	return nil
}

// matchValuePattern checks value against all concrete secret regexps.
func matchValuePattern(value string) (bool, string) {
	for i, pat := range valuePatterns {
		if pat.MatchString(value) {
			return true, valueLabels[i]
		}
	}
	return false, ""
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
