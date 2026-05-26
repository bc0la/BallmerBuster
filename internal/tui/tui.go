package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/you/ballmerbuster/internal/orchestrator"
)

type tab int

const (
	tabProgress tab = iota
	tabSubscriptions
	tabModules
	tabLogs
	numTabs
)

var tabNames = []string{"Progress", "Subscriptions", "Modules", "Logs"}

type moduleKey struct{ subscription, module string }

type moduleProgress struct {
	status    string
	startedAt time.Time
	elapsed   time.Duration
	err       string
	lastLog   string
}

type Model struct {
	tab           tab
	subscriptions map[string]string
	modules       map[moduleKey]string
	progress      map[moduleKey]*moduleProgress
	subOrder      []string
	modOrder      []string
	logs          []string
	events        <-chan orchestrator.Event
	done          bool
	err           error
	started       time.Time

	totalModules   int
	runningCount   int
	completedCount int
	failedCount    int
	skippedCount   int
}

type eventMsg orchestrator.Event
type doneMsg struct{ err error }
type tickMsg struct{}

func New(events <-chan orchestrator.Event) Model {
	return Model{
		tab:           tabProgress,
		subscriptions: map[string]string{},
		modules:       map[moduleKey]string{},
		progress:      map[moduleKey]*moduleProgress{},
		events:        events,
		started:       time.Now(),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(waitForEvent(m.events), tickEvery())
}

func waitForEvent(events <-chan orchestrator.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-events
		if !ok {
			return doneMsg{}
		}
		return eventMsg(ev)
	}
}

func tickEvery() tea.Cmd {
	return tea.Tick(time.Second, func(_ time.Time) tea.Msg {
		return tickMsg{}
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab", "right":
			m.tab = (m.tab + 1) % numTabs
		case "shift+tab", "left":
			m.tab = (m.tab + numTabs - 1) % numTabs
		}
	case tickMsg:
		for _, p := range m.progress {
			if p.status == "running" {
				p.elapsed = time.Since(p.startedAt)
			}
		}
		return m, tickEvery()
	case eventMsg:
		ev := orchestrator.Event(msg)
		if _, ok := m.subscriptions[ev.SubscriptionID]; !ok {
			m.subOrder = append(m.subOrder, ev.SubscriptionID)
		}
		m.subscriptions[ev.SubscriptionID] = ev.Status
		k := moduleKey{ev.SubscriptionID, ev.Module}
		if _, ok := m.modules[k]; !ok {
			m.modOrder = appendUnique(m.modOrder, ev.Module)
		}

		prev := m.modules[k]
		m.modules[k] = ev.Status

		p, exists := m.progress[k]
		if !exists {
			p = &moduleProgress{}
			m.progress[k] = p
			m.totalModules++
		}

		switch ev.Status {
		case "progress":
			p.lastLog = ev.Err
		case "running":
			if prev == "running" {
				m.runningCount--
			}
			p.startedAt = time.Now()
			p.status = "running"
			m.runningCount++
		case "completed":
			if prev == "running" {
				m.runningCount--
			}
			p.elapsed = time.Since(p.startedAt)
			p.status = "completed"
			p.lastLog = ""
			m.completedCount++
		case "failed":
			if prev == "running" {
				m.runningCount--
			}
			p.elapsed = time.Since(p.startedAt)
			p.status = "failed"
			p.err = ev.Err
			m.failedCount++
		case "skipped":
			p.status = "skipped"
			p.err = ev.Err
			m.skippedCount++
		}

		line := fmt.Sprintf("[%s] %s/%s → %s", ev.Status, ev.SubscriptionID, ev.Module, ev.Err)
		m.logs = append(m.logs, line)
		if len(m.logs) > 500 {
			m.logs = m.logs[len(m.logs)-500:]
		}
		return m, waitForEvent(m.events)
	case doneMsg:
		m.done = true
		return m, tea.Quit
	}
	return m, nil
}

func appendUnique(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

var (
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Padding(0, 1)
	activeTab   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Underline(true).Padding(0, 1)
	dim         = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	green       = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	red         = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	yellow      = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	cyan        = lipgloss.NewStyle().Foreground(lipgloss.Color("87"))
	bold        = lipgloss.NewStyle().Bold(true)
)

func (m Model) View() string {
	var tabs []string
	for i, name := range tabNames {
		if tab(i) == m.tab {
			tabs = append(tabs, activeTab.Render(name))
		} else {
			tabs = append(tabs, headerStyle.Render(name))
		}
	}
	var body string
	switch m.tab {
	case tabProgress:
		body = m.renderProgress()
	case tabSubscriptions:
		body = m.renderSubscriptions()
	case tabModules:
		body = m.renderModules()
	case tabLogs:
		body = m.renderLogs()
	}
	footer := dim.Render("tab/shift-tab: switch • q: quit")
	return strings.Join([]string{
		headerStyle.Render("BallmerBuster"),
		strings.Join(tabs, "  "),
		"",
		body,
		"",
		footer,
	}, "\n")
}

func (m Model) renderProgress() string {
	if m.totalModules == 0 {
		return dim.Render("waiting for modules to start…")
	}

	var b strings.Builder
	elapsed := time.Since(m.started).Truncate(time.Second)

	finished := m.completedCount + m.failedCount + m.skippedCount
	pct := 0
	if m.totalModules > 0 {
		pct = finished * 100 / m.totalModules
	}
	b.WriteString(bold.Render(fmt.Sprintf("  Progress: %d%% (%d/%d)  Elapsed: %s\n",
		pct, finished, m.totalModules, elapsed)))
	b.WriteString(fmt.Sprintf("  %s  %s  %s  %s\n\n",
		green.Render(fmt.Sprintf("completed:%d", m.completedCount)),
		cyan.Render(fmt.Sprintf("running:%d", m.runningCount)),
		red.Render(fmt.Sprintf("failed:%d", m.failedCount)),
		dim.Render(fmt.Sprintf("skipped:%d", m.skippedCount)),
	))

	barWidth := 50
	filled := 0
	if m.totalModules > 0 {
		filled = finished * barWidth / m.totalModules
	}
	bar := green.Render(strings.Repeat("█", filled)) + dim.Render(strings.Repeat("░", barWidth-filled))
	b.WriteString("  " + bar + "\n\n")

	var running []string
	for k, p := range m.progress {
		if p.status == "running" {
			line := fmt.Sprintf("  %s  %s/%s  %s",
				yellow.Render("▸"),
				dim.Render(k.subscription),
				bold.Render(k.module),
				dim.Render(p.elapsed.Truncate(time.Second).String()))
			if p.lastLog != "" {
				logMsg := p.lastLog
				if len(logMsg) > 70 {
					logMsg = logMsg[:70] + "…"
				}
				line += "  " + cyan.Render(logMsg)
			}
			running = append(running, line)
		}
	}
	if len(running) > 0 {
		sort.Strings(running)
		b.WriteString(bold.Render("  Running:\n"))
		for _, r := range running {
			b.WriteString(r + "\n")
		}
		b.WriteString("\n")
	}

	type completedEntry struct {
		key     moduleKey
		elapsed time.Duration
		status  string
		err     string
	}
	var recent []completedEntry
	for k, p := range m.progress {
		if p.status == "completed" || p.status == "failed" {
			recent = append(recent, completedEntry{k, p.elapsed, p.status, p.err})
		}
	}
	sort.Slice(recent, func(i, j int) bool {
		return recent[i].elapsed > recent[j].elapsed
	})
	if len(recent) > 10 {
		recent = recent[:10]
	}
	if len(recent) > 0 {
		b.WriteString(bold.Render("  Recent:\n"))
		for _, r := range recent {
			icon := green.Render("✓")
			if r.status == "failed" {
				icon = red.Render("✗")
			}
			line := fmt.Sprintf("  %s  %s/%s  %s",
				icon,
				dim.Render(r.key.subscription),
				r.key.module,
				dim.Render(r.elapsed.Truncate(time.Second).String()))
			if r.err != "" {
				errShort := r.err
				if len(errShort) > 60 {
					errShort = errShort[:60] + "…"
				}
				line += "  " + red.Render(errShort)
			}
			b.WriteString(line + "\n")
		}
	}

	return b.String()
}

func (m Model) renderSubscriptions() string {
	if len(m.subOrder) == 0 {
		return dim.Render("waiting…")
	}
	var b strings.Builder
	subs := append([]string(nil), m.subOrder...)
	sort.Strings(subs)
	for _, s := range subs {
		fmt.Fprintf(&b, "%-40s %s\n", s, m.subscriptions[s])
	}
	return b.String()
}

func (m Model) renderModules() string {
	if len(m.modOrder) == 0 {
		return dim.Render("waiting…")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-22s", "module")
	subs := append([]string(nil), m.subOrder...)
	sort.Strings(subs)
	for _, s := range subs {
		short := s
		if len(short) > 14 {
			short = short[:14]
		}
		fmt.Fprintf(&b, " %-14s", short)
	}
	b.WriteString("\n")
	mods := append([]string(nil), m.modOrder...)
	sort.Strings(mods)
	for _, mod := range mods {
		fmt.Fprintf(&b, "%-22s", mod)
		for _, s := range subs {
			status := m.modules[moduleKey{s, mod}]
			if status == "" {
				status = "-"
			}
			fmt.Fprintf(&b, " %-14s", status)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (m Model) renderLogs() string {
	if len(m.logs) == 0 {
		return dim.Render("no events yet")
	}
	start := 0
	if len(m.logs) > 30 {
		start = len(m.logs) - 30
	}
	return strings.Join(m.logs[start:], "\n")
}
