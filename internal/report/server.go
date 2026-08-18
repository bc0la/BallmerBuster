package report

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/you/ballmerbuster/internal/engagement"
	"github.com/you/ballmerbuster/internal/module"

	_ "modernc.org/sqlite"
)

//go:embed index.html
var indexHTML []byte

func Serve(addr, dir string) error {
	dbPath := filepath.Join(dir, engagement.DBFileName)
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("engagement db not found at %s: %w", dbPath, err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.Handle("/raw/", http.StripPrefix("/raw/", http.FileServer(http.Dir(dir))))
	mux.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		mod := r.URL.Query().Get("module")
		rows, err := queryFindings(db, dir, mod)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, rows)
	})
	mux.HandleFunc("/api/summary", func(w http.ResponseWriter, r *http.Request) {
		s, err := summary(db)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, s)
	})
	fmt.Printf("report listening on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

type findingRow struct {
	ID             int64  `json:"id"`
	SubscriptionID string `json:"subscription_id"`
	Region         string `json:"region"`
	Module         string `json:"module"`
	Severity       string `json:"severity"`
	ResourceID     string `json:"resource_id"`
	Title          string `json:"title"`
	Detail         any    `json:"detail"`
	RawOutputPath  string `json:"raw_output_path,omitempty"`
	CreatedAt      string `json:"created_at"`
}

func queryFindings(db *sql.DB, dir, mod string) ([]findingRow, error) {
	query := `SELECT id, subscription_id, region, module, severity, resource_id, title, detail_json, raw_output_path, created_at FROM findings`
	var args []any
	if mod != "" {
		query += " WHERE module = ?"
		args = append(args, mod)
	}
	query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id DESC LIMIT 1000000"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []findingRow
	for rows.Next() {
		var r findingRow
		var detailJSON string
		var rawPath sql.NullString
		if err := rows.Scan(&r.ID, &r.SubscriptionID, &r.Region, &r.Module, &r.Severity, &r.ResourceID, &r.Title, &detailJSON, &rawPath, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(detailJSON), &r.Detail)
		if rawPath.Valid && rawPath.String != "" {
			if rel, err := filepath.Rel(dir, rawPath.String); err == nil {
				r.RawOutputPath = "/raw/" + filepath.ToSlash(rel) + "/"
			}
		}
		out = append(out, r)
	}
	return out, nil
}

type summaryRow struct {
	Module   string `json:"module"`
	Count    int    `json:"count"`
	Category string `json:"category"`
	Rating   string `json:"rating"`
}

func summary(db *sql.DB) (map[string]any, error) {
	dbCounts := map[string]int{}
	rows, err := db.Query(`SELECT module, count(*) FROM findings GROUP BY module ORDER BY module`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var mod string
		var count int
		if err := rows.Scan(&mod, &count); err != nil {
			return nil, err
		}
		dbCounts[mod] = count
	}

	seen := map[string]bool{}
	var byMod []summaryRow
	for name, count := range dbCounts {
		byMod = append(byMod, summaryRow{Module: name, Count: count, Category: module.CategoryOf(name), Rating: module.RatingOf(name)})
		seen[name] = true
	}
	for _, m := range module.All() {
		if !seen[m.Name()] {
			byMod = append(byMod, summaryRow{Module: m.Name(), Count: 0, Category: module.CategoryOf(m.Name()), Rating: module.RatingOf(m.Name())})
		}
	}
	sort.Slice(byMod, func(i, j int) bool { return byMod[i].Module < byMod[j].Module })

	sevRows, err := db.Query(`SELECT severity, count(*) FROM findings GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer sevRows.Close()
	bySev := map[string]int{}
	for sevRows.Next() {
		var k string
		var v int
		if err := sevRows.Scan(&k, &v); err != nil {
			return nil, err
		}
		bySev[k] = v
	}
	return map[string]any{"modules": byMod, "severity": bySev, "categories": module.Categories()}, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
