package module

import (
	"context"
	"sync"

	"github.com/you/ballmerbuster/internal/creds"
	"github.com/you/ballmerbuster/internal/findings"
)

type Kind string

const (
	KindNative   Kind = "native"
	KindExternal Kind = "external"
)

type Module interface {
	Name() string
	Kind() Kind
	Requires() []string
	Run(ctx context.Context, target creds.SubscriptionTarget, sink findings.Sink) error
}

var (
	regMu    sync.RWMutex
	registry = map[string]Module{}
)

func Register(m Module) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, ok := registry[m.Name()]; ok {
		panic("module already registered: " + m.Name())
	}
	registry[m.Name()] = m
}

func All() []Module {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Module, 0, len(registry))
	for _, m := range registry {
		out = append(out, m)
	}
	return out
}

func Get(name string) (Module, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	m, ok := registry[name]
	return m, ok
}
