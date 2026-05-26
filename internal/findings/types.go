package findings

import (
	"context"
	"encoding/json"
	"time"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type Finding struct {
	ID             int64
	SubscriptionID string
	Region         string
	Module         string
	Severity       Severity
	ResourceID     string
	Title          string
	Detail         any
	RawOutputPath  string
	CreatedAt      time.Time
}

func (f *Finding) DetailJSON() (string, error) {
	if f.Detail == nil {
		return "{}", nil
	}
	b, err := json.Marshal(f.Detail)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type Sink interface {
	Write(ctx context.Context, f Finding) error
	RawDir(module, subscriptionID string) (string, error)
	LogEvent(ctx context.Context, module, subscriptionID, level, msg string) error
}
