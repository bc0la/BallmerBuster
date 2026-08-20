package report

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// This file powers the report UI's Utils → TREVORspray panel. TREVORspray
// (github.com/blacklanternsecurity/TREVORspray) is a modular O365/Entra ID
// password sprayer. The panel lets an operator, from the browser:
//
//  1. Install TREVORspray into a self-contained venv under the engagement dir
//     (no system-wide install; the report server stays self-hosting).
//  2. Build a target userlist by querying the DeHashed API for a tenant's
//     domain, or by pasting emails directly.
//  3. Run recon (`--recon`), a password spray, or a single test-user attempt
//     against O365/Entra, streaming TREVORspray's live output to the browser.
//
// Everything is scoped to <engagement>/trevorspray/: the venv, an isolated
// HOME (so TREVORspray's tried-credential state stays per-engagement), the
// generated userlists, and per-run logs. To protect real accounts from
// lockout, the run handler caps the number of passwords sprayed per user to
// MaxAttempts (default 2, configurable) — since TREVORspray tries one password
// per user per pass, that ceiling *is* the per-user attempt limit.
//
// The server binds to localhost by default; the run handler executes the venv
// binary with an argument slice (never a shell), and all user/password values
// are written to files rather than interpolated into a command line.

// tsPaths holds the per-engagement filesystem layout for TREVORspray.
type tsPaths struct {
	root      string // <dir>/trevorspray
	venv      string // <root>/venv
	bin       string // <root>/venv/bin/trevorspray
	pip       string // <root>/venv/bin/pip
	python    string // <root>/venv/bin/python
	home      string // <root>/home  (HOME for runs → isolates ~/.trevorspray state)
	userlists string // <root>/userlists
	runs      string // <root>/runs
}

func tsPathsFor(dir string) tsPaths {
	root := filepath.Join(dir, "trevorspray")
	venv := filepath.Join(root, "venv")
	return tsPaths{
		root:      root,
		venv:      venv,
		bin:       filepath.Join(venv, "bin", "trevorspray"),
		pip:       filepath.Join(venv, "bin", "pip"),
		python:    filepath.Join(venv, "bin", "python"),
		home:      filepath.Join(root, "home"),
		userlists: filepath.Join(root, "userlists"),
		runs:      filepath.Join(root, "runs"),
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// rawURLFor maps an absolute path under the engagement dir to the /raw/ URL the
// browser fetches; falls back to the absolute path if it isn't under dir.
func rawURLFor(dir, abs string) string {
	if rel, err := filepath.Rel(dir, abs); err == nil && !strings.HasPrefix(rel, "..") {
		return "/raw/" + filepath.ToSlash(rel)
	}
	return abs
}

// --- Status -----------------------------------------------------------------

func handleTSStatus(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := tsPathsFor(dir)
		installed := fileExists(p.bin)
		version := ""
		if installed {
			ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, p.pip, "show", "trevorspray").Output()
			if err == nil {
				for _, line := range strings.Split(string(out), "\n") {
					if strings.HasPrefix(line, "Version:") {
						version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
					}
				}
			}
		}
		_, python3 := exec.LookPath("python3")
		writeJSON(w, map[string]any{
			"installed":       installed,
			"version":         version,
			"venv":            p.venv,
			"bin":             p.bin,
			"python3_on_path": python3 == nil,
		})
	}
}

// --- SSE helper -------------------------------------------------------------

func tsSSEHead(w http.ResponseWriter) (http.Flusher, bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	return flusher, true
}

func tsSend(w http.ResponseWriter, f http.Flusher, event, data string) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, strings.ReplaceAll(data, "\n", "\\n"))
	f.Flush()
}

func tsSendJSON(w http.ResponseWriter, f http.Flusher, event string, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
	f.Flush()
}

// streamCmd runs cmd, tees its combined stdout+stderr line-by-line to the SSE
// stream and (if non-nil) to logw, and returns the process exit code. The
// command must have been built with exec.CommandContext(r.Context(), ...) so a
// browser disconnect cancels it; SysProcAttr/Cancel below SIGKILL the whole
// process group so TREVORspray's worker threads/children never linger.
//
// The raw line (ANSI colour codes and all) is forwarded to the browser, which
// renders the colours; the log file gets the same bytes so it's a faithful
// transcript.
func streamCmd(w http.ResponseWriter, f http.Flusher, cmd *exec.Cmd, logw io.Writer) int {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 10 * time.Second

	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		tsSend(w, f, "line", "[error] failed to start: "+err.Error())
		return -1
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
		_ = pw.Close()
	}()

	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if logw != nil {
			_, _ = io.WriteString(logw, line+"\n")
		}
		tsSend(w, f, "line", line)
	}

	err := <-waitCh
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// --- Install ----------------------------------------------------------------

func handleTSInstall(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := tsPathsFor(dir)
		flusher, ok := tsSSEHead(w)
		if !ok {
			return
		}

		if _, err := exec.LookPath("python3"); err != nil {
			tsSend(w, flusher, "line", "[error] python3 not found on PATH — install Python 3.9+ first")
			tsSendJSON(w, flusher, "done", map[string]any{"ok": false, "exit": -1})
			return
		}
		if err := os.MkdirAll(p.root, 0o755); err != nil {
			tsSend(w, flusher, "line", "[error] "+err.Error())
			tsSendJSON(w, flusher, "done", map[string]any{"ok": false, "exit": -1})
			return
		}

		logPath := filepath.Join(p.root, "install.log")
		logw, _ := os.Create(logPath)
		if logw != nil {
			defer logw.Close()
		}

		if !fileExists(p.python) {
			tsSend(w, flusher, "line", "[*] creating virtualenv at "+p.venv)
			if code := streamCmd(w, flusher, exec.CommandContext(r.Context(), "python3", "-m", "venv", p.venv), logw); code != 0 {
				tsSendJSON(w, flusher, "done", map[string]any{"ok": false, "exit": code})
				return
			}
		} else {
			tsSend(w, flusher, "line", "[*] reusing existing virtualenv at "+p.venv)
		}

		// pip install steps. TREVORspray and its trevorproxy dependency are
		// installed straight from git per the project's README.
		steps := [][]string{
			{p.python, "-m", "pip", "install", "--upgrade", "pip"},
			{p.pip, "install", "git+https://github.com/blacklanternsecurity/trevorproxy"},
			{p.pip, "install", "git+https://github.com/blacklanternsecurity/TREVORspray"},
		}
		for _, step := range steps {
			tsSend(w, flusher, "line", "\n[*] $ "+strings.Join(step, " "))
			cmd := exec.CommandContext(r.Context(), step[0], step[1:]...)
			// Keep pip's cache/config under the isolated HOME so installs are
			// reproducible and don't touch the operator's home directory.
			cmd.Env = append(os.Environ(), "PIP_DISABLE_PIP_VERSION_CHECK=1")
			if code := streamCmd(w, flusher, cmd, logw); code != 0 {
				tsSend(w, flusher, "line", fmt.Sprintf("[error] step failed (exit %d)", code))
				tsSendJSON(w, flusher, "done", map[string]any{"ok": false, "exit": code})
				return
			}
		}

		if fileExists(p.bin) {
			tsSend(w, flusher, "line", "\n[+] TREVORspray installed: "+p.bin)
			tsSendJSON(w, flusher, "done", map[string]any{"ok": true, "exit": 0})
		} else {
			tsSend(w, flusher, "line", "\n[error] install finished but trevorspray binary not found")
			tsSendJSON(w, flusher, "done", map[string]any{"ok": false, "exit": -1})
		}
	}
}

// --- DeHashed userlist ------------------------------------------------------

type dehashedReq struct {
	Endpoint string `json:"endpoint"`
	APIKey   string `json:"api_key"`
	Email    string `json:"email"`  // set → v1 GET + HTTP basic auth; empty → v2 POST + header
	Domain   string `json:"domain"` // one or more domains (newline/comma/space separated)
	Query    string `json:"query"`  // optional; used verbatim when no domains are given
	Size     int    `json:"size"`
}

var reSafe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// asStrings flattens a DeHashed field that may be a bare string (v1 API) or an
// array of strings (v2 API) into a slice.
func asStrings(v any) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{t}
		}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// joinField renders a possibly-multi-valued DeHashed field as one cell.
func joinField(e map[string]any, key string) string {
	return strings.Join(asStrings(e[key]), "; ")
}

// splitList parses a free-form list (newline/comma/semicolon/whitespace
// separated) into a deduped, lowercased slice — used for the domain box so an
// operator can paste many tenants at once.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '\t' || r == ',' || r == ';' || r == ' '
	})
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// toInt coerces a JSON number/string (DeHashed's `total`) to an int.
func toInt(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n, true
		}
	}
	return 0, false
}

// dhRecord is one exportable credential row surfaced to the browser and CSV.
type dhRecord struct {
	Domain         string `json:"domain"`
	Email          string `json:"email"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	HashedPassword string `json:"hashed_password"`
	Name           string `json:"name"`
	Database       string `json:"database_name"`
	IPAddress      string `json:"ip_address"`
	Phone          string `json:"phone"`
}

var dhCSVHeader = []string{"domain", "email", "username", "password", "hashed_password", "name", "database_name", "ip_address", "phone"}

func (r dhRecord) row() []string {
	return []string{r.Domain, r.Email, r.Username, r.Password, r.HashedPassword, r.Name, r.Database, r.IPAddress, r.Phone}
}

// DeHashed serves at most this many records per query (the API's pagination
// depth cap) and at most this many per page.
const dehashedMaxPerPage = 10000
const dehashedHardCap = 10000

// dehashedPage fetches one page of a DeHashed search (v1 or v2 depending on
// whether an email is set) and returns that page's entries plus the reported
// total match count. page is 1-indexed.
func dehashedPage(ctx context.Context, req dehashedReq, query string, page, size int) ([]map[string]any, any, error) {
	endpoint := strings.TrimSpace(req.Endpoint)
	var httpReq *http.Request
	var err error
	if req.Email != "" {
		// DeHashed v1: GET with HTTP basic auth (email:apikey).
		if endpoint == "" {
			endpoint = "https://api.dehashed.com/search"
		}
		httpReq, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err == nil {
			q := httpReq.URL.Query()
			q.Set("query", query)
			q.Set("size", fmt.Sprintf("%d", size))
			q.Set("page", fmt.Sprintf("%d", page))
			httpReq.URL.RawQuery = q.Encode()
			httpReq.SetBasicAuth(req.Email, req.APIKey)
		}
	} else {
		// DeHashed v2: POST JSON with the Dehashed-Api-Key header.
		if endpoint == "" {
			endpoint = "https://api.dehashed.com/v2/search"
		}
		body, _ := json.Marshal(map[string]any{"query": query, "size": size, "page": page})
		httpReq, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
		if err == nil {
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("Dehashed-Api-Key", req.APIKey)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 45 * time.Second}).Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var parsed struct {
		Entries []map[string]any `json:"entries"`
		Total   any              `json:"total"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, nil, fmt.Errorf("could not parse response: %w", err)
	}
	return parsed.Entries, parsed.Total, nil
}

// dehashedCollect pages through a DeHashed search, accumulating entries until it
// has gathered `budget` records, exhausted the result set, or hit the API's
// pagination depth cap. It returns the collected entries and the total match
// count the API reports (which may exceed len(entries) when the budget or cap
// limits how many were fetched).
func dehashedCollect(ctx context.Context, req dehashedReq, query string, budget int) ([]map[string]any, any, error) {
	if budget <= 0 {
		budget = 100
	}
	if budget > dehashedHardCap {
		budget = dehashedHardCap
	}
	pageSize := budget
	if pageSize > dehashedMaxPerPage {
		pageSize = dehashedMaxPerPage
	}

	var all []map[string]any
	var total any
	// The page size stays constant across pages: DeHashed's pagination is
	// offset-based (offset = (page-1)*size), so varying it would overlap or skip
	// records.
	for page := 1; page <= 100; page++ {
		entries, tot, err := dehashedPage(ctx, req, query, page, pageSize)
		if err != nil {
			// A first-page failure is fatal (bad key/endpoint/query); a later
			// page failing is best-effort — keep what we already gathered.
			if page == 1 {
				return nil, nil, err
			}
			break
		}
		if page == 1 {
			total = tot
		}
		all = append(all, entries...)

		if len(all) >= budget { // hit the caller's budget
			all = all[:budget]
			break
		}
		if len(entries) == 0 { // nothing more to fetch
			break
		}
		if n, ok := toInt(total); ok {
			if len(all) >= n { // gathered every match the API reports
				break
			}
		} else if len(entries) < pageSize {
			// No trustworthy total: a short page is our best last-page signal.
			break
		}
		if page*pageSize >= dehashedHardCap { // API won't paginate past this
			break
		}
		if ctx.Err() != nil { // client gone / deadline
			break
		}
		// Respect DeHashed's rate limit between pages.
		select {
		case <-ctx.Done():
			return all, total, nil
		case <-time.After(150 * time.Millisecond):
		}
	}
	return all, total, nil
}

// perDomainResult summarizes what one domain's search yielded.
type perDomainResult struct {
	Domain  string `json:"domain"`
	Users   int    `json:"users"`
	Records int    `json:"records"`
	Total   any    `json:"total,omitempty"`
	Error   string `json:"error,omitempty"`
}

func handleTSDehashed(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req dehashedReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.APIKey == "" {
			http.Error(w, "api_key is required", http.StatusBadRequest)
			return
		}
		if req.Size <= 0 {
			req.Size = 100
		}
		if req.Size > dehashedHardCap {
			req.Size = dehashedHardCap
		}

		// Build the searches to run. A pasted list of domains → one
		// `domain:<d>` search each; otherwise a single verbatim query.
		type search struct{ domain, query string }
		var searches []search
		domains := splitList(req.Domain)
		customQuery := strings.TrimSpace(req.Query)
		switch {
		case len(domains) > 0:
			for _, d := range domains {
				searches = append(searches, search{domain: d, query: "domain:" + d})
			}
		case customQuery != "":
			searches = append(searches, search{query: customQuery})
		default:
			http.Error(w, "domain(s) or query is required", http.StatusBadRequest)
			return
		}

		// A generous overall budget across all domains and their pages;
		// per-request client timeout is 45s each.
		ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
		defer cancel()

		emailSet := map[string]bool{}
		userSet := map[string]bool{}
		var emails, users []string
		var records []dhRecord
		var per []perDomainResult
		totalSum, haveTotal := 0, true

		ulDir := tsPathsFor(dir).userlists
		_ = os.MkdirAll(ulDir, 0o755)

		for _, s := range searches {
			entries, total, err := dehashedCollect(ctx, req, s.query, req.Size)
			if err != nil {
				// One search of many: record the error and keep going so a
				// single bad domain doesn't sink the whole batch. A lone
				// search fails outright so the operator sees why.
				if len(searches) == 1 {
					http.Error(w, "dehashed "+err.Error(), http.StatusBadGateway)
					return
				}
				per = append(per, perDomainResult{Domain: s.domain, Error: err.Error()})
				haveTotal = false
				continue
			}

			var domEmails, domUsers []string
			domESeen, domUSeen := map[string]bool{}, map[string]bool{}
			for _, e := range entries {
				records = append(records, dhRecord{
					Domain:         s.domain,
					Email:          joinField(e, "email"),
					Username:       joinField(e, "username"),
					Password:       joinField(e, "password"),
					HashedPassword: joinField(e, "hashed_password"),
					Name:           joinField(e, "name"),
					Database:       joinField(e, "database_name"),
					IPAddress:      joinField(e, "ip_address"),
					Phone:          joinField(e, "phone"),
				})
				for _, v := range asStrings(e["email"]) {
					v = strings.ToLower(strings.TrimSpace(v))
					if v == "" {
						continue
					}
					if !emailSet[v] {
						emailSet[v] = true
						emails = append(emails, v)
					}
					if !domESeen[v] {
						domESeen[v] = true
						domEmails = append(domEmails, v)
					}
				}
				for _, v := range asStrings(e["username"]) {
					v = strings.TrimSpace(v)
					if v == "" {
						continue
					}
					if !userSet[v] {
						userSet[v] = true
						users = append(users, v)
					}
					if !domUSeen[v] {
						domUSeen[v] = true
						domUsers = append(domUsers, v)
					}
				}
			}

			// Per-domain userlist file (emails preferred as UPNs).
			domList := domEmails
			if len(domList) == 0 {
				domList = domUsers
			}
			if len(domList) > 0 && s.domain != "" {
				base := reSafe.ReplaceAllString(s.domain, "_")
				_ = os.WriteFile(filepath.Join(ulDir, base+"-dehashed.txt"), []byte(strings.Join(domList, "\n")+"\n"), 0o644)
			}

			if n, ok := toInt(total); ok {
				totalSum += n
			} else {
				haveTotal = false
			}
			per = append(per, perDomainResult{Domain: s.domain, Users: len(domList), Records: len(entries), Total: total})
		}

		// Prefer emails (usable as O365 UPNs); fall back to usernames.
		list := emails
		kind := "email"
		if len(list) == 0 {
			list = users
			kind = "username"
		}

		// Name the combined artifacts after the single domain, else "combined".
		base := "dehashed"
		switch {
		case len(domains) == 1:
			base = reSafe.ReplaceAllString(domains[0], "_")
		case len(domains) > 1:
			base = "combined"
		}

		savedPath, savedURL := "", ""
		if len(list) > 0 {
			savedPath = filepath.Join(ulDir, base+"-dehashed.txt")
			_ = os.WriteFile(savedPath, []byte(strings.Join(list, "\n")+"\n"), 0o644)
			savedURL = rawURLFor(dir, savedPath)
		}

		// Persist the full credential table as CSV so it survives the session
		// and can be fed to other tools.
		csvPath, csvURL := "", ""
		if len(records) > 0 {
			csvPath = filepath.Join(ulDir, base+"-dehashed.csv")
			if f, err := os.Create(csvPath); err == nil {
				cw := csv.NewWriter(f)
				_ = cw.Write(dhCSVHeader)
				for _, rec := range records {
					_ = cw.Write(rec.row())
				}
				cw.Flush()
				_ = f.Close()
				csvURL = rawURLFor(dir, csvPath)
			} else {
				csvPath = ""
			}
		}

		var totalOut any
		if haveTotal {
			totalOut = totalSum
		}

		writeJSON(w, map[string]any{
			"kind":         kind,
			"users":        list,
			"count":        len(list),
			"emails":       len(emails),
			"usernames":    len(users),
			"records":      records,
			"record_count": len(records),
			"total":        totalOut,
			"domains":      domains,
			"per_domain":   per,
			"saved_path":   savedPath,
			"saved_url":    savedURL,
			"csv_path":     csvPath,
			"csv_url":      csvURL,
		})
	}
}

// --- Run (recon / spray / test-user) ---------------------------------------

type tsRunReq struct {
	Mode          string   `json:"mode"` // "recon" | "spray" | "test"
	Module        string   `json:"module"`
	Domain        string   `json:"domain"`
	URL           string   `json:"url"`
	Users         []string `json:"users"`
	Passwords     []string `json:"passwords"`
	MaxAttempts   int      `json:"max_attempts"`
	Delay         float64  `json:"delay"`
	LockoutDelay  float64  `json:"lockout_delay"`
	Jitter        float64  `json:"jitter"`
	Threads       int      `json:"threads"`
	Timeout       float64  `json:"timeout"`
	UserEnum      string   `json:"user_enum"`
	ExitOnSuccess bool     `json:"exit_on_success"`
	IgnoreLock    bool     `json:"ignore_lockouts"`
	Force         bool     `json:"force"`
	Verbose       bool     `json:"verbose"`
}

// The valid TREVORspray sprayer modules and user-enumeration methods, mirrored
// here so the server rejects anything the browser sends that isn't a real
// choice (defence-in-depth even though args never touch a shell).
var tsSprayModules = map[string]bool{
	"msol": true, "adfs": true, "owa": true, "okta": true,
	"auth0": true, "anyconnect": true, "jumpcloud": true, "officehome": true,
}
var tsUserEnumMethods = map[string]bool{
	"onedrive": true, "seamless_sso": true, "teams_photo": true,
}

func cleanLines(in []string) []string {
	var out []string
	for _, s := range in {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
	}
	return out
}

func handleTSRun(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := tsPathsFor(dir)
		if !fileExists(p.bin) {
			http.Error(w, "TREVORspray is not installed — install it first", http.StatusPreconditionFailed)
			return
		}
		var req tsRunReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Module == "" {
			req.Module = "msol"
		}
		if !tsSprayModules[req.Module] {
			http.Error(w, "unknown module: "+req.Module, http.StatusBadRequest)
			return
		}
		if req.UserEnum != "" && !tsUserEnumMethods[req.UserEnum] {
			http.Error(w, "unknown user-enum method: "+req.UserEnum, http.StatusBadRequest)
			return
		}
		if req.MaxAttempts <= 0 {
			req.MaxAttempts = 2
		}

		users := cleanLines(req.Users)
		passwords := cleanLines(req.Passwords)

		flusher, ok := tsSSEHead(w)
		if !ok {
			return
		}

		// Enforce the per-user attempt ceiling: TREVORspray tries one password
		// per user per pass, so capping the password list caps attempts/user.
		attemptNote := ""
		if req.Mode != "recon" && len(passwords) > req.MaxAttempts {
			attemptNote = fmt.Sprintf("[!] capping to %d password(s) per user (max_attempts=%d) to avoid lockouts; %d supplied",
				req.MaxAttempts, req.MaxAttempts, len(passwords))
			passwords = passwords[:req.MaxAttempts]
		}

		// Validate mode requirements. Recon accepts a pasted list of domains
		// (one tenant per line) and enumerates each in turn.
		var reconDomains []string
		switch req.Mode {
		case "recon":
			reconDomains = splitList(req.Domain)
			if len(reconDomains) == 0 {
				tsSend(w, flusher, "line", "[error] recon requires a tenant/domain")
				tsSendJSON(w, flusher, "done", map[string]any{"ok": false, "exit": 2})
				return
			}
		case "spray", "test":
			if len(users) == 0 || len(passwords) == 0 {
				tsSend(w, flusher, "line", "[error] spray/test requires at least one user and one password")
				tsSendJSON(w, flusher, "done", map[string]any{"ok": false, "exit": 2})
				return
			}
			if req.Mode == "test" && len(users) != 1 {
				tsSend(w, flusher, "line", fmt.Sprintf("[!] test mode expects a single user; using the first of %d", len(users)))
				users = users[:1]
			}
		default:
			tsSend(w, flusher, "line", "[error] unknown mode: "+req.Mode)
			tsSendJSON(w, flusher, "done", map[string]any{"ok": false, "exit": 2})
			return
		}

		// Per-run artifact directory: <runs>/<mode>-<timestamp>/.
		ts := time.Now().Format("20060102-150405")
		runDir := filepath.Join(p.runs, req.Mode+"-"+ts)
		if err := os.MkdirAll(runDir, 0o755); err != nil {
			tsSend(w, flusher, "line", "[error] "+err.Error())
			tsSendJSON(w, flusher, "done", map[string]any{"ok": false, "exit": -1})
			return
		}
		_ = os.MkdirAll(p.home, 0o755)

		usersFile := ""
		if len(users) > 0 {
			usersFile = filepath.Join(runDir, "users.txt")
			_ = os.WriteFile(usersFile, []byte(strings.Join(users, "\n")+"\n"), 0o644)
		}

		// Flags shared by every invocation this run makes.
		common := []string{}
		if req.URL != "" {
			common = append(common, "--url", req.URL)
		}
		if req.Threads > 0 {
			common = append(common, "-t", fmt.Sprintf("%d", req.Threads))
		}
		if req.Delay > 0 {
			common = append(common, "-d", trimFloat(req.Delay))
		}
		if req.LockoutDelay > 0 {
			common = append(common, "-ld", trimFloat(req.LockoutDelay))
		}
		if req.Jitter > 0 {
			common = append(common, "-j", trimFloat(req.Jitter))
		}
		if req.Timeout > 0 {
			common = append(common, "--timeout", trimFloat(req.Timeout))
		}
		if req.IgnoreLock {
			common = append(common, "--ignore-lockouts")
		}
		if req.Force {
			common = append(common, "-f")
		}
		if req.Verbose {
			common = append(common, "-v")
		}

		// Build the list of invocations. Recon runs once per domain; spray/test
		// is a single invocation over the full userlist.
		type invocation struct {
			label string
			args  []string
		}
		var invs []invocation
		switch req.Mode {
		case "recon":
			for _, d := range reconDomains {
				a := []string{"-m", req.Module, "--recon", d}
				if usersFile != "" {
					a = append(a, "-u", usersFile)
					if req.UserEnum != "" {
						a = append(a, "-ue", req.UserEnum)
					}
				}
				invs = append(invs, invocation{label: d, args: append(a, common...)})
			}
		case "spray", "test":
			passFile := filepath.Join(runDir, "passwords.txt")
			_ = os.WriteFile(passFile, []byte(strings.Join(passwords, "\n")+"\n"), 0o644)
			a := []string{"-m", req.Module, "-u", usersFile, "-p", passFile}
			if req.ExitOnSuccess || req.Mode == "test" {
				a = append(a, "-e")
			}
			invs = append(invs, invocation{label: req.Mode, args: append(a, common...)})
		}

		if attemptNote != "" {
			tsSend(w, flusher, "line", attemptNote)
		}
		if len(invs) > 1 {
			tsSend(w, flusher, "line", fmt.Sprintf("[*] running recon against %d domains", len(invs)))
		}
		tsSend(w, flusher, "line", "[*] output dir: "+runDir+"\n")

		logPath := filepath.Join(runDir, "trevorspray.log")
		logw, _ := os.Create(logPath)
		if logw != nil {
			defer logw.Close()
		}

		// Run each invocation sequentially, streaming into the same terminal and
		// log. The overall exit code is the first non-zero one seen.
		code := 0
		for i, inv := range invs {
			if len(invs) > 1 {
				tsSend(w, flusher, "line", fmt.Sprintf("\n[*] === recon %d/%d: %s ===", i+1, len(invs), inv.label))
				if logw != nil {
					_, _ = io.WriteString(logw, fmt.Sprintf("\n=== recon %d/%d: %s ===\n", i+1, len(invs), inv.label))
				}
			}
			tsSend(w, flusher, "line", "[*] $ trevorspray "+strings.Join(inv.args, " "))
			cmd := exec.CommandContext(r.Context(), p.bin, inv.args...)
			// Isolate TREVORspray's ~/.trevorspray state per engagement; force
			// unbuffered Python so lines reach the browser as they happen.
			cmd.Env = append(os.Environ(), "HOME="+p.home, "PYTHONUNBUFFERED=1")
			cmd.Dir = runDir
			if c := streamCmd(w, flusher, cmd, logw); c != 0 && code == 0 {
				code = c
			}
		}

		tsSend(w, flusher, "line", fmt.Sprintf("\n[+] finished (exit %d)", code))
		tsSendJSON(w, flusher, "done", map[string]any{
			"ok":       code == 0,
			"exit":     code,
			"run_dir":  rawURLFor(dir, runDir) + "/",
			"log":      rawURLFor(dir, logPath),
			"tool_log": rawURLFor(dir, filepath.Join(p.home, ".trevorspray", "trevorspray.log")),
		})
	}
}

// trimFloat renders a float without a trailing ".0" so integer-valued delays
// pass to TREVORspray as clean integers.
func trimFloat(f float64) string {
	s := fmt.Sprintf("%g", f)
	return s
}

// handleTSUserlists lists the userlist files already generated under the
// engagement so the operator can reload one into the run form without
// re-querying DeHashed. Each entry carries a /raw/ URL the browser fetches to
// repopulate the users box.
func handleTSUserlists(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := tsPathsFor(dir)
		entries, _ := os.ReadDir(p.userlists)
		type ul struct {
			Name   string `json:"name"`
			Count  int    `json:"count"`
			RawURL string `json:"raw_url"`
		}
		out := []ul{}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			abs := filepath.Join(p.userlists, e.Name())
			b, err := os.ReadFile(abs)
			if err != nil {
				continue
			}
			count := 0
			for _, line := range strings.Split(string(b), "\n") {
				if strings.TrimSpace(line) != "" {
					count++
				}
			}
			rawURL := abs
			if rel, err := filepath.Rel(dir, abs); err == nil {
				rawURL = "/raw/" + filepath.ToSlash(rel)
			}
			out = append(out, ul{Name: e.Name(), Count: count, RawURL: rawURL})
		}
		writeJSON(w, out)
	}
}
