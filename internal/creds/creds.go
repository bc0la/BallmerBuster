package creds

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

type SubscriptionTarget struct {
	SubscriptionID string
	DisplayName    string
	TenantID       string
	Credential     azcore.TokenCredential
}

type Options struct {
	Subscription    string
	Subscriptions   []string
	AllSubs         bool
	ManagementGroup string
}

func newCredential() (azcore.TokenCredential, error) {
	// Try Azure CLI first — most common for interactive use.
	if cli, err := azidentity.NewAzureCLICredential(nil); err == nil {
		return cli, nil
	}
	// Fall back to the full chain (env vars, managed identity, etc).
	return azidentity.NewDefaultAzureCredential(nil)
}

func Detect(ctx context.Context, opts Options) ([]SubscriptionTarget, error) {
	cred, err := newCredential()
	if err != nil {
		return nil, fmt.Errorf("azure auth failed — run `az login` or set AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET: %w", err)
	}

	if len(opts.Subscriptions) > 0 {
		var out []SubscriptionTarget
		for _, sub := range opts.Subscriptions {
			t, err := resolveSubscription(ctx, cred, sub)
			if err != nil {
				return nil, fmt.Errorf("subscription %s: %w", sub, err)
			}
			out = append(out, t)
		}
		return out, nil
	}

	if opts.Subscription != "" {
		t, err := resolveSubscription(ctx, cred, opts.Subscription)
		if err != nil {
			return nil, err
		}
		return []SubscriptionTarget{t}, nil
	}

	if opts.ManagementGroup != "" {
		return enumerateManagementGroup(ctx, cred, opts.ManagementGroup)
	}

	// Default: enumerate all accessible subscriptions. --all-subs is kept
	// for backwards compatibility (it's now the default behavior).
	subs, err := listSubscriptions(ctx, cred)
	if err != nil {
		return nil, fmt.Errorf("%w\n\nhint: authenticate with one of:\n  az login                                          (interactive)\n  export AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=...  (service principal)", err)
	}
	if len(subs) == 0 {
		return nil, fmt.Errorf("no accessible subscriptions found")
	}
	return subs, nil
}

func resolveSubscription(ctx context.Context, cred azcore.TokenCredential, subID string) (SubscriptionTarget, error) {
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return SubscriptionTarget{}, err
	}
	resp, err := client.Get(ctx, subID, nil)
	if err != nil {
		return SubscriptionTarget{}, fmt.Errorf("get subscription %s: %w", subID, err)
	}
	return SubscriptionTarget{
		SubscriptionID: ptrVal(resp.SubscriptionID),
		DisplayName:    ptrVal(resp.DisplayName),
		TenantID:       ptrVal(resp.TenantID),
		Credential:     cred,
	}, nil
}

func listSubscriptions(ctx context.Context, cred azcore.TokenCredential) ([]SubscriptionTarget, error) {
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(nil)
	var out []SubscriptionTarget
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list subscriptions: %w", err)
		}
		for _, s := range page.Value {
			if s.State != nil && *s.State != armsubscriptions.SubscriptionStateEnabled {
				continue
			}
			out = append(out, SubscriptionTarget{
				SubscriptionID: ptrVal(s.SubscriptionID),
				DisplayName:    ptrVal(s.DisplayName),
				TenantID:       ptrVal(s.TenantID),
				Credential:     cred,
			})
		}
	}
	return out, nil
}

func enumerateManagementGroup(ctx context.Context, cred azcore.TokenCredential, mgID string) ([]SubscriptionTarget, error) {
	client, err := armmanagementgroups.NewClient(cred, nil)
	if err != nil {
		return nil, err
	}
	pager := client.NewGetDescendantsPager(mgID, nil)
	subIDs := map[string]bool{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("management group %s descendants: %w", mgID, err)
		}
		for _, d := range page.Value {
			if d.Properties != nil && d.Type != nil && strings.Contains(*d.Type, "subscriptions") {
				if d.Properties.DisplayName != nil {
					subIDs[ptrVal(d.Name)] = true
				} else {
					subIDs[ptrVal(d.Name)] = true
				}
			}
		}
	}

	allSubs, err := listSubscriptions(ctx, cred)
	if err != nil {
		return nil, err
	}
	var out []SubscriptionTarget
	for _, s := range allSubs {
		if subIDs[s.SubscriptionID] {
			out = append(out, s)
		}
	}
	return out, nil
}

func ptrVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func IsExpired(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, sig := range []string{
		"AADSTS700024",
		"AADSTS50173",
		"AuthenticationFailed",
		"TokenExpired",
		"token has expired",
		"AADSTS70043",
	} {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

type ExpiryWatcher struct{ tripped atomic.Bool }

func (w *ExpiryWatcher) Trip()         { w.tripped.Store(true) }
func (w *ExpiryWatcher) Tripped() bool { return w.tripped.Load() }
