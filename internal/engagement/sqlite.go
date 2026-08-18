package engagement

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
const LogFileName = "ballmerbuster.log"

type Engagement struct {
	db      *sql.DB
	mu      sync.Mutex
	Dir     string
	logFile *os.File
	logMu   sync.Mutex
	OnLog   func(module, subscriptionID, level, msg string)

	// Optional plaintext log sinks configured via SetLogFiles, independent of
	// the always-on ballmerbuster.log and the TUI's OnLog hook. logAll receives
	// every event; logErr receives only warn/error/fatal events. Either may be
	// nil. logClosers holds the underlying files to close on Close().
	logAll     io.Writer
	logErr     io.Writer
	logClosers []io.Closer
}

// SetLogFiles opens optional plaintext log files that mirror LogEvent output.
// allPath (if non-empty) receives every log line; errPath (if non-empty)
// receives only warn/error lines, so a run's failures land in one small,
// greppable file. Both are opened for append (so resume re-runs accumulate) and
// created if missing.
func (e *Engagement) SetLogFiles(allPath, errPath string) error {
	open := func(p string) (*os.File, error) {
		if p == "" {
			return nil, nil
		}
		if d := filepath.Dir(p); d != "" && d != "." {
			_ = os.MkdirAll(d, 0o755)
		}
		return os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	}
	f, err := open(allPath)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", allPath, err)
	}
	if f != nil {
		e.logAll = f
		e.logClosers = append(e.logClosers, f)
	}
	g, err := open(errPath)
	if err != nil {
		return fmt.Errorf("open error-log file %s: %w", errPath, err)
	}
	if g != nil {
		e.logErr = g
		e.logClosers = append(e.logClosers, g)
	}
	return nil
}

// isErrLevel reports whether a log level should land in the errors-only file.
// Module failures across the codebase are logged at "warn", so warn is included.
func isErrLevel(level string) bool {
	switch strings.ToLower(level) {
	case "warn", "warning", "error", "err", "fatal":
		return true
	}
	return false
}

func (e *Engagement) writeLogLine(module, subscriptionID, level, msg string) {
	if e.logAll == nil && e.logErr == nil {
		return
	}
	orDash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	line := fmt.Sprintf("%s [%-5s] %s %s: %s\n",
		time.Now().UTC().Format(time.RFC3339),
		strings.ToUpper(level), orDash(module), orDash(subscriptionID), msg)
	e.logMu.Lock()
	defer e.logMu.Unlock()
	if e.logAll != nil {
		_, _ = io.WriteString(e.logAll, line)
	}
	if e.logErr != nil && isErrLevel(level) {
		_, _ = io.WriteString(e.logErr, line)
	}
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
	logPath := filepath.Join(dir, LogFileName)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("open log file: %w", err)
	}
	return &Engagement{db: db, Dir: dir, logFile: logFile}, nil
}

func (e *Engagement) Close() error {
	if e.logFile != nil {
		_ = e.logFile.Close()
	}
	for _, c := range e.logClosers {
		_ = c.Close()
	}
	return e.db.Close()
}

func (e *Engagement) LogPath() string { return filepath.Join(e.Dir, LogFileName) }

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
	e.writeLogLine(module, subscriptionID, level, msg)
	now := time.Now().UTC()
	if e.logFile != nil {
		e.logMu.Lock()
		fmt.Fprintf(e.logFile, "%s [%s] %s sub=%s %s\n",
			now.Format(time.RFC3339), level, module, subscriptionID, msg)
		e.logMu.Unlock()
	}
	_, err := e.db.ExecContext(ctx,
		`INSERT INTO logs(subscription_id, module, level, msg, created_at) VALUES(?,?,?,?,?)`,
		nullIfEmpty(subscriptionID), nullIfEmpty(module), level, msg, now)
	return err
}
