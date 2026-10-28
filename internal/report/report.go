// Package report collects findings from a scan run and writes them to the results directory.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	return [...]string{"info", "low", "medium", "high"}[s]
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Finding is one thing worth a human looking at.
type Finding struct {
	Severity Severity `json:"severity"`
	Check    string   `json:"check"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	// Key identifies the finding for allowlisting (usually a path or label).
	Key string `json:"key,omitempty"`
}

// CheckStatus records whether a check ran.
type CheckStatus struct {
	Name     string        `json:"name"`
	Status   string        `json:"status"` // ok | skipped | error
	Note     string        `json:"note,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

// Report is a single scan run.
type Report struct {
	Mode     string            `json:"mode"`
	Started  time.Time         `json:"started"`
	Finished time.Time         `json:"finished"`
	Host     string            `json:"host"`
	Root     bool              `json:"root"`
	Versions map[string]string `json:"tool_versions"`
	Checks   []CheckStatus     `json:"checks"`
	Findings []Finding         `json:"findings"`
	Dir      string            `json:"-"`

	mu        sync.Mutex
	allowlist map[string]bool
}

// New creates the run directory results/<timestamp>-<mode>.
func New(resultsDir, mode string, allow []string) (*Report, error) {
	now := time.Now()
	dir := filepath.Join(resultsDir, now.Format("20060102-150405")+"-"+mode)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	r := &Report{
		Mode:      mode,
		Started:   now,
		Host:      host,
		Root:      os.Geteuid() == 0,
		Versions:  map[string]string{},
		Dir:       dir,
		allowlist: map[string]bool{},
	}
	for _, a := range allow {
		r.allowlist[a] = true
	}
	return r, nil
}

// Add records a finding unless its key is allowlisted.
func (r *Report) Add(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f.Key != "" && r.allowlist[f.Key] {
		return
	}
	r.Findings = append(r.Findings, f)
}

func (r *Report) Status(s CheckStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Checks = append(r.Checks, s)
}

func (r *Report) Version(tool, v string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Versions[tool] = strings.TrimSpace(v)
}

// Raw saves tool output to the run directory and returns its path.
func (r *Report) Raw(name string, data []byte) string {
	p := filepath.Join(r.Dir, name)
	_ = os.WriteFile(p, data, 0o600)
	return p
}

// Counts returns the number of findings per severity.
func (r *Report) Counts() map[Severity]int {
	c := map[Severity]int{}
	for _, f := range r.Findings {
		c[f.Severity]++
	}
	return c
}

// Write writes findings.json and summary.md, then hands the run dir to the
// invoking user when running under sudo so it stays readable without root.
func (r *Report) Write() error {
	r.Finished = time.Now()
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Severity > r.Findings[j].Severity
	})

	js, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	r.Raw("findings.json", js)
	r.Raw("summary.md", []byte(r.markdown()))
	return ChownToSudoUser(filepath.Dir(r.Dir), r.Dir)
}

func (r *Report) markdown() string {
	var b strings.Builder
	c := r.Counts()
	fmt.Fprintf(&b, "# osxscan %s scan — %s\n\n", r.Mode, r.Started.Format(time.RFC1123))
	fmt.Fprintf(&b, "- Host: `%s`\n- Ran as root: %v\n- Duration: %s\n", r.Host, r.Root, r.Finished.Sub(r.Started).Round(time.Second))
	fmt.Fprintf(&b, "- Findings: **%d high**, **%d medium**, %d low, %d info\n\n", c[High], c[Medium], c[Low], c[Info])

	b.WriteString("## Checks\n\n| Check | Status | Time | Note |\n|---|---|---|---|\n")
	for _, s := range r.Checks {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", s.Name, s.Status, s.Duration.Round(time.Second), esc(s.Note))
	}

	b.WriteString("\n## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("None.\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "### [%s] %s — %s\n\n", strings.ToUpper(f.Severity.String()), f.Check, f.Title)
		if f.Key != "" {
			fmt.Fprintf(&b, "Allowlist key: `%s`\n\n", f.Key)
		}
		if f.Detail != "" {
			fmt.Fprintf(&b, "```\n%s\n```\n\n", strings.TrimSpace(f.Detail))
		}
	}

	b.WriteString("\n## Tool versions\n\n")
	tools := make([]string, 0, len(r.Versions))
	for t := range r.Versions {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	for _, t := range tools {
		fmt.Fprintf(&b, "- %s: `%s`\n", t, r.Versions[t])
	}
	return b.String()
}

func esc(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

// ChownToSudoUser gives ownership of paths (recursively) back to $SUDO_UID.
func ChownToSudoUser(paths ...string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil {
		return nil
	}
	for _, p := range paths {
		err := filepath.Walk(p, func(path string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(path, uid, gid)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
