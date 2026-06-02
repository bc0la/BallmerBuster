package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/engagement"
	"github.com/you/ballmerbuster/internal/module"
	"github.com/you/ballmerbuster/internal/orchestrator"
	"github.com/you/ballmerbuster/internal/report"
	"github.com/you/ballmerbuster/internal/tui"

	// Side-effect imports to register modules.
	_ "github.com/you/ballmerbuster/internal/module/aci_env"
	_ "github.com/you/ballmerbuster/internal/module/acr_exposure"
	_ "github.com/you/ballmerbuster/internal/module/arm_deployments"
	_ "github.com/you/ballmerbuster/internal/module/automation_accounts"
	_ "github.com/you/ballmerbuster/internal/module/blob_anon"
	_ "github.com/you/ballmerbuster/internal/module/devops_secrets"
	_ "github.com/you/ballmerbuster/internal/module/entra_id"
	_ "github.com/you/ballmerbuster/internal/module/external_trust"
	_ "github.com/you/ballmerbuster/internal/module/function_app_env"
	_ "github.com/you/ballmerbuster/internal/module/iam_integrations"
	_ "github.com/you/ballmerbuster/internal/module/keyvault_exposure"
	_ "github.com/you/ballmerbuster/internal/module/logic_apps"
	_ "github.com/you/ballmerbuster/internal/module/nsg_exposure"
	_ "github.com/you/ballmerbuster/internal/module/public_sql"
	_ "github.com/you/ballmerbuster/internal/module/rbac_review"
	_ "github.com/you/ballmerbuster/internal/module/redirect_uris"
	_ "github.com/you/ballmerbuster/internal/module/subdomain_takeover"
	_ "github.com/you/ballmerbuster/internal/module/vm_userdata"
)

func main() {
	root := &cobra.Command{
		Use:   "ballmerbuster",
		Short: "Automated Azure whitebox pentest workflow",
	}
	root.AddCommand(
		runCmd("scan", "Run native Azure-SDK checks (fast, in-process)", "native"),
		reportCmd(), modulesCmd(), resumeCmd(),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCmd(use, short, kind string) *cobra.Command {
	var (
		subscription  string
		subscriptions []string
		allSubs       bool
		mgGroup       string
		outDir        string
		engDir        string
		moduleList    []string
		noTUI         bool
	)
	// One --no-<module> flag per registered module; set flags add their module
	// to the exclude list.
	noFlags := map[string]*bool{}
	c := &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			targets, err := creds.Detect(ctx, creds.Options{
				Subscription:    subscription,
				Subscriptions:   subscriptions,
				AllSubs:         allSubs,
				ManagementGroup: mgGroup,
			})
			if err != nil {
				return fmt.Errorf("detect creds: %w", err)
			}
			if len(targets) == 0 {
				return fmt.Errorf("no subscriptions detected")
			}

			var exclude []string
			for name, b := range noFlags {
				if *b {
					exclude = append(exclude, name)
				}
			}
			sort.Strings(exclude)

			modules := selectModules(kind, moduleList, exclude)
			if len(modules) == 0 {
				return fmt.Errorf("no %s modules to run", kind)
			}

			finalDir := engDir
			if finalDir == "" {
				if err := os.MkdirAll(outDir, 0o755); err != nil {
					return err
				}
				finalDir = filepath.Join(outDir, fmt.Sprintf("%s-%s", time.Now().UTC().Format("2006-01-02-150405"), targets[0].SubscriptionID))
			}
			eng, err := engagement.Open(finalDir)
			if err != nil {
				return err
			}
			defer eng.Close()
			_ = eng.SetMeta(ctx, "started_at", time.Now().UTC().Format(time.RFC3339))
			_ = eng.SetMeta(ctx, "targets", strings.Join(targetIDs(targets), ","))
			_ = eng.SetMeta(ctx, "opt.subscription", subscription)
			_ = eng.SetMeta(ctx, "opt.subscriptions", strings.Join(subscriptions, ","))
			_ = eng.SetMeta(ctx, "opt.all_subs", boolStr(allSubs))
			_ = eng.SetMeta(ctx, "opt.management_group", mgGroup)
			_ = eng.SetMeta(ctx, "opt.kind", kind)
			_ = eng.SetMeta(ctx, "opt.modules", strings.Join(moduleList, ","))
			_ = eng.SetMeta(ctx, "opt.exclude", strings.Join(exclude, ","))

			return runEngagement(ctx, eng, targets, modules, nil, noTUI)
		},
	}
	c.Flags().StringVar(&subscription, "subscription", "", "Azure subscription ID (single-subscription mode)")
	c.Flags().StringSliceVar(&subscriptions, "subscriptions", nil, "Comma-separated subscription IDs")
	c.Flags().BoolVar(&allSubs, "all-subs", false, "Auto-enumerate all accessible subscriptions")
	c.Flags().StringVar(&mgGroup, "management-group", "", "Enumerate subscriptions under a management group")
	c.Flags().StringVar(&outDir, "out", "engagements", "Parent dir for new engagements")
	c.Flags().StringVar(&engDir, "engagement", "", "Existing engagement dir to append to (default: create new)")
	c.Flags().StringSliceVar(&moduleList, "modules", nil, "Subset of modules to run (default: all of this kind)")
	c.Flags().BoolVar(&noTUI, "no-tui", false, "Disable TUI; stream events as text")
	for _, m := range module.All() {
		name := m.Name()
		b := new(bool)
		noFlags[name] = b
		c.Flags().BoolVar(b, "no-"+strings.ReplaceAll(name, "_", "-"), false, "Skip the "+name+" module")
	}
	return c
}

func selectModules(kind string, subset, exclude []string) []string {
	all := module.All()
	allowedKind := func(k module.Kind) bool {
		switch kind {
		case "native":
			return k == module.KindNative
		case "external":
			return k == module.KindExternal
		default:
			return true
		}
	}
	excluded := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		excluded[e] = true
	}

	var candidates []string
	if len(subset) > 0 {
		for _, name := range subset {
			if m, ok := module.Get(name); ok && allowedKind(m.Kind()) {
				candidates = append(candidates, name)
			}
		}
	} else {
		for _, m := range all {
			if allowedKind(m.Kind()) {
				candidates = append(candidates, m.Name())
			}
		}
	}

	out := make([]string, 0, len(candidates))
	for _, name := range candidates {
		if excluded[name] {
			continue
		}
		out = append(out, name)
	}
	return out
}

func targetIDs(ts []creds.SubscriptionTarget) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.SubscriptionID)
	}
	return out
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func runEngagement(ctx context.Context, eng *engagement.Engagement, targets []creds.SubscriptionTarget, moduleList []string, done map[string]bool, noTUI bool) error {
	watcher := &creds.ExpiryWatcher{}
	sched := orchestrator.New(eng, orchestrator.Options{Modules: moduleList, Done: done}, watcher)

	if noTUI {
		go func() {
			for ev := range sched.Events {
				fmt.Printf("[%s] %s/%s %s\n", ev.Status, ev.SubscriptionID, ev.Module, ev.Err)
			}
		}()
		if err := sched.Run(ctx, targets); err != nil {
			return err
		}
		fmt.Printf("engagement dir: %s\n", eng.Dir)
		if watcher.Tripped() {
			fmt.Fprintln(os.Stderr, "WARN: credentials expired mid-scan. Re-login with `az login` and run `ballmerbuster resume "+eng.Dir+"`.")
		}
		return nil
	}

	prog := tea.NewProgram(tui.New(sched.Events))
	errCh := make(chan error, 1)
	go func() { errCh <- sched.Run(ctx, targets) }()
	if _, err := prog.Run(); err != nil {
		return err
	}
	if err := <-errCh; err != nil {
		return err
	}
	fmt.Printf("engagement dir: %s\n", eng.Dir)
	if watcher.Tripped() {
		fmt.Fprintln(os.Stderr, "WARN: credentials expired mid-scan. Re-login with `az login` and run `ballmerbuster resume "+eng.Dir+"`.")
	}
	return nil
}

func reportCmd() *cobra.Command {
	var addr string
	c := &cobra.Command{
		Use:   "report <engagement-dir>",
		Short: "Serve a local web report for an engagement directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return report.Serve(addr, args[0])
		},
	}
	c.Flags().StringVar(&addr, "addr", "127.0.0.1:7979", "Listen address")
	return c
}

func modulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "modules",
		Short: "List registered modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, m := range module.All() {
				fmt.Printf("%-22s %s\n", m.Name(), m.Kind())
			}
			return nil
		},
	}
}

func resumeCmd() *cobra.Command {
	var noTUI bool
	c := &cobra.Command{
		Use:   "resume <engagement-dir>",
		Short: "Resume an engagement whose scan was paused or interrupted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			dbFile := filepath.Join(args[0], engagement.DBFileName)
			if _, err := os.Stat(dbFile); err != nil {
				return fmt.Errorf("engagement db not found at %s: %w", dbFile, err)
			}
			eng, err := engagement.Open(args[0])
			if err != nil {
				return err
			}
			defer eng.Close()

			opts, err := readScanOpts(ctx, eng)
			if err != nil {
				return err
			}

			targets, err := creds.Detect(ctx, opts.cred)
			if err != nil {
				return fmt.Errorf("detect creds: %w (hint: run `az login` then retry)", err)
			}
			if len(targets) == 0 {
				return fmt.Errorf("no subscriptions detected on resume")
			}

			done, err := eng.CompletedModules(ctx)
			if err != nil {
				return err
			}

			modules := selectModules(opts.kind, opts.modules, opts.exclude)
			remaining := 0
			for _, t := range targets {
				for _, name := range modules {
					if !done[t.SubscriptionID+"|"+name] {
						remaining++
					}
				}
			}
			fmt.Printf("resume (%s): %d targets x %d modules, %d pairs already complete, %d to run\n",
				orDefault(opts.kind, "all"), len(targets), len(modules), len(done), remaining)
			if remaining == 0 {
				fmt.Println("nothing to do.")
				return nil
			}

			return runEngagement(ctx, eng, targets, modules, done, noTUI)
		},
	}
	c.Flags().BoolVar(&noTUI, "no-tui", false, "Disable TUI; stream events as text")
	return c
}

type scanOpts struct {
	cred    creds.Options
	kind    string
	modules []string
	exclude []string
}

func readScanOpts(ctx context.Context, eng *engagement.Engagement) (scanOpts, error) {
	get := func(k string) string {
		v, _, _ := eng.GetMeta(ctx, k)
		return v
	}
	var out scanOpts
	out.cred.Subscription = get("opt.subscription")
	if v := get("opt.subscriptions"); v != "" {
		out.cred.Subscriptions = strings.Split(v, ",")
	}
	out.cred.AllSubs = get("opt.all_subs") == "true"
	out.cred.ManagementGroup = get("opt.management_group")
	out.kind = get("opt.kind")
	if v := get("opt.modules"); v != "" {
		out.modules = strings.Split(v, ",")
	}
	if v := get("opt.exclude"); v != "" {
		out.exclude = strings.Split(v, ",")
	}
	return out, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
