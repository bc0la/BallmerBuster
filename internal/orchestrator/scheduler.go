package orchestrator

import (
	"context"
	"fmt"
	"sync"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/engagement"
	"github.com/you/ballmerbuster/internal/module"
)

type Options struct {
	PerSubscriptionConcurrency int
	GlobalConcurrency          int
	Modules                    []string
	Done                       map[string]bool
}

type Event struct {
	SubscriptionID string
	Module         string
	Status         string
	Err            string
}

type Scheduler struct {
	eng     *engagement.Engagement
	opts    Options
	Events  chan Event
	watcher *creds.ExpiryWatcher
}

func New(eng *engagement.Engagement, opts Options, w *creds.ExpiryWatcher) *Scheduler {
	if opts.PerSubscriptionConcurrency <= 0 {
		opts.PerSubscriptionConcurrency = 4
	}
	if opts.GlobalConcurrency <= 0 {
		opts.GlobalConcurrency = 16
	}
	return &Scheduler{
		eng:     eng,
		opts:    opts,
		Events:  make(chan Event, 256),
		watcher: w,
	}
}

func (s *Scheduler) modulesToRun() []module.Module {
	if len(s.opts.Modules) == 0 {
		return module.All()
	}
	var out []module.Module
	for _, name := range s.opts.Modules {
		if m, ok := module.Get(name); ok {
			out = append(out, m)
		}
	}
	return out
}

func (s *Scheduler) Run(ctx context.Context, targets []creds.SubscriptionTarget) error {
	defer close(s.Events)

	s.eng.OnLog = func(mod, subscriptionID, level, msg string) {
		select {
		case s.Events <- Event{SubscriptionID: subscriptionID, Module: mod, Status: "progress", Err: msg}:
		default:
		}
	}

	modules := s.modulesToRun()
	if len(modules) == 0 {
		return fmt.Errorf("no modules registered")
	}

	global := make(chan struct{}, s.opts.GlobalConcurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		t := t
		_ = s.eng.UpsertSubscription(ctx, t.SubscriptionID, t.DisplayName)
		_ = s.eng.MarkSubscription(ctx, t.SubscriptionID, "running", "")

		perSub := make(chan struct{}, s.opts.PerSubscriptionConcurrency)
		var subWg sync.WaitGroup

		for _, m := range modules {
			m := m
			if s.opts.Done[t.SubscriptionID+"|"+m.Name()] {
				continue
			}
			subWg.Add(1)
			wg.Add(1)
			go func() {
				defer subWg.Done()
				defer wg.Done()
				select {
				case perSub <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-perSub }()
				select {
				case global <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-global }()

				if s.watcher != nil && s.watcher.Tripped() {
					s.emit(ctx, t.SubscriptionID, m.Name(), "skipped", "creds expired")
					return
				}

				s.emit(ctx, t.SubscriptionID, m.Name(), "running", "")
				err := m.Run(ctx, t, s.eng)
				if err != nil {
					if creds.IsExpired(err) && s.watcher != nil {
						s.watcher.Trip()
					}
					_ = s.eng.LogEvent(ctx, m.Name(), t.SubscriptionID, "error", err.Error())
					s.emit(ctx, t.SubscriptionID, m.Name(), "failed", err.Error())
					return
				}
				s.emit(ctx, t.SubscriptionID, m.Name(), "completed", "")
			}()
		}

		go func() {
			subWg.Wait()
			_ = s.eng.MarkSubscription(ctx, t.SubscriptionID, "completed", "")
		}()
	}

	wg.Wait()
	return nil
}

func (s *Scheduler) emit(ctx context.Context, subscriptionID, name, status, errMsg string) {
	_ = s.eng.MarkModule(ctx, subscriptionID, name, status, errMsg)
	select {
	case s.Events <- Event{SubscriptionID: subscriptionID, Module: name, Status: status, Err: errMsg}:
	default:
	}
}
