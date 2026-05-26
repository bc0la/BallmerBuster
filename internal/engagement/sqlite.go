package engagement

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/you/ballmerbuster/internal/findings"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriptions (
  subscription_id TEXT PRIMARY KEY,
  alias TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  started_at DATETIME,
  finished_at DATETIME
);
CREATE TABLE IF NOT EXISTS module_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subscription_id TEXT NOT NULL,
  module TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  started_at DATETIME,
  finished_at DATETIME,
  UNIQUE(subscription_id, module)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subscription_id TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  module TEXT NOT NULL,
  severity TEXT NOT NULL,
  resource_id TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  raw_output_path TEXT,
  created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module);
CREATE INDEX IF NOT EXISTS idx_findings_subscription ON findings(subscription_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subscription_id TEXT,
  module TEXT,
  level TEXT NOT NULL,
  msg TEXT NOT NULL,
  created_at DATETIME NOT NULL
);
`

const DBFileName = "engagement.db"

type Engagement struct {
	db  *sql.DB
	mu  sync.Mutex
	Dir string
	OnLog func(module, subscriptionID, level, msg string)
}

func Open(dir string) (*Engagement, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dir, DBFileName)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Engagement{db: db, Dir: dir}, nil
}

func (e *Engagement) Close() error { return e.db.Close() }

func (e *Engagement) DB() *sql.DB { return e.db }

func (e *Engagement) DBPath() string { return filepath.Join(e.Dir, DBFileName) }

func (e *Engagement) SetMeta(ctx context.Context, key, value string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}

func (e *Engagement) GetMeta(ctx context.Context, key string) (string, bool, error) {
	row := e.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key)
	var v string
	if err := row.Scan(&v); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

func (e *Engagement) CompletedModules(ctx context.Context) (map[string]bool, error) {
	rows, err := e.db.QueryContext(ctx,
		`SELECT subscription_id, module FROM module_runs WHERE status = 'completed'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var sub, mod string
		if err := rows.Scan(&sub, &mod); err != nil {
			return nil, err
		}
		out[sub+"|"+mod] = true
	}
	return out, rows.Err()
}

func (e *Engagement) UpsertSubscription(ctx context.Context, subscriptionID, alias string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO subscriptions(subscription_id, alias) VALUES(?,?)
		 ON CONFLICT(subscription_id) DO UPDATE SET alias=excluded.alias`,
		subscriptionID, alias)
	return err
}

func (e *Engagement) MarkSubscription(ctx context.Context, subscriptionID, status, errMsg string) error {
	_, err := e.db.ExecContext(ctx,
		`UPDATE subscriptions SET status=?, error=?, finished_at=CASE WHEN ?='running' THEN NULL ELSE CURRENT_TIMESTAMP END,
		 started_at=COALESCE(started_at, CASE WHEN ?='running' THEN CURRENT_TIMESTAMP END)
		 WHERE subscription_id=?`,
		status, nullIfEmpty(errMsg), status, status, subscriptionID)
	return err
}

func (e *Engagement) MarkModule(ctx context.Context, subscriptionID, module, status, errMsg string) error {
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO module_runs(subscription_id, module, status, error, started_at, finished_at)
		 VALUES(?, ?, ?, ?, CASE WHEN ?='running' THEN CURRENT_TIMESTAMP END,
		        CASE WHEN ? IN ('completed','failed','skipped') THEN CURRENT_TIMESTAMP END)
		 ON CONFLICT(subscription_id, module) DO UPDATE SET status=excluded.status, error=excluded.error,
		   finished_at=CASE WHEN excluded.status IN ('completed','failed','skipped') THEN CURRENT_TIMESTAMP ELSE module_runs.finished_at END`,
		subscriptionID, module, status, nullIfEmpty(errMsg), status, status)
	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Sink implementation

func (e *Engagement) Write(ctx context.Context, f findings.Finding) error {
	detail, err := f.DetailJSON()
	if err != nil {
		return err
	}
	created := f.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err = e.db.ExecContext(ctx,
		`INSERT INTO findings(subscription_id, region, module, severity, resource_id, title, detail_json, raw_output_path, created_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		f.SubscriptionID, f.Region, f.Module, string(f.Severity), f.ResourceID, f.Title, detail, nullIfEmpty(f.RawOutputPath), created)
	return err
}

func (e *Engagement) RawDir(module, subscriptionID string) (string, error) {
	if module == "" {
		return "", fmt.Errorf("module required")
	}
	parts := []string{e.Dir, module}
	if subscriptionID != "" {
		parts = append(parts, subscriptionID)
	}
	dir := filepath.Join(parts...)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func (e *Engagement) LogEvent(ctx context.Context, module, subscriptionID, level, msg string) error {
	if e.OnLog != nil {
		e.OnLog(module, subscriptionID, level, msg)
	}
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO logs(subscription_id, module, level, msg, created_at) VALUES(?,?,?,?,?)`,
		nullIfEmpty(subscriptionID), nullIfEmpty(module), level, msg, time.Now().UTC())
	return err
}
