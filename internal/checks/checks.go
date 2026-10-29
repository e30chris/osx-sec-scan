// Package checks implements the individual scans. Each check records findings on
// the report and returns a status; a missing tool is "skipped", never fatal.
package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/config"
	"github.com/e30chris/osx-sec-scan/internal/report"
	"github.com/e30chris/osx-sec-scan/internal/runner"
)

// Env is shared state for one run.
type Env struct {
	Report     *report.Report
	Config     config.Config
	RepoDir    string
	ResultsDir string
	StateDir   string
	Root       bool
}

// Check is one named scan step.
type Check struct {
	Name string
	Run  func(e *Env) (status, note string)
}

// Quick checks are cheap: posture, persistence, osquery, KnockKnock.
func Quick() []Check {
	return []Check{
		{"posture", Posture},
		{"xprotect", XProtect},
		{"persistence", Persistence},
		{"osquery", Osquery},
		{"knockknock", KnockKnock},
	}
}

// Full adds the slow, file-content scans.
func Full() []Check {
	return append(Quick(),
		Check{"codesign", Codesign},
		Check{"lynis", Lynis},
		Check{"clamav", ClamAV},
		Check{"yara", Yara},
	)
}

// RunAll executes checks in order, printing progress to stderr.
func RunAll(e *Env, list []Check) {
	for _, c := range list {
		if runner.Interrupted() {
			e.Report.Status(report.CheckStatus{Name: c.Name, Status: "skipped", Note: "interrupted"})
			continue
		}
		fmt.Fprintf(os.Stderr, "==> %s\n", c.Name)
		start := time.Now()
		status, note := safeRun(e, c)
		if runner.Interrupted() {
			status, note = "interrupted", "partial: "+note
		}
		d := time.Since(start)
		e.Report.Status(report.CheckStatus{Name: c.Name, Status: status, Note: note, Duration: d})
		fmt.Fprintf(os.Stderr, "    %s (%s) %s\n", status, d.Round(time.Second), note)
	}
}

func safeRun(e *Env, c Check) (status, note string) {
	defer func() {
		if r := recover(); r != nil {
			status, note = "error", fmt.Sprintf("panic: %v", r)
		}
	}()
	return c.Run(e)
}

func skipped(note string) (string, string) { return "skipped", note }
func failed(err error) (string, string)    { return "error", err.Error() }
func ok(format string, a ...any) (string, string) {
	return "ok", fmt.Sprintf(format, a...)
}

// userHomes lists home directories this process can read.
func userHomes() []string {
	dirs, _ := filepath.Glob("/Users/*")
	var homes []string
	for _, d := range dirs {
		base := filepath.Base(d)
		if base == "Shared" || base == "Guest" || base[0] == '.' {
			continue
		}
		if _, err := os.ReadDir(d); err == nil {
			homes = append(homes, d)
		}
	}
	return homes
}
