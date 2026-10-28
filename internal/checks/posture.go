package checks

import (
	"strings"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/harden"
	"github.com/e30chris/osx-sec-scan/internal/report"
	"github.com/e30chris/osx-sec-scan/internal/runner"
)

// Posture reports every hardening baseline item that is not in its desired state.
func Posture(e *Env) (string, string) {
	results := harden.Evaluate()
	bad := 0
	for _, r := range results {
		if r.OK {
			continue
		}
		bad++
		sev := report.Medium
		if r.Item.Critical {
			sev = report.High
		}
		e.Report.Add(report.Finding{
			Severity: sev,
			Check:    "posture",
			Title:    r.Item.Name + " is not set as expected",
			Detail:   r.Detail + "\nFix: osxscan harden apply",
			Key:      "posture:" + r.Item.ID,
		})
	}
	return ok("%d/%d baseline items OK", len(results)-bad, len(results))
}

// XProtect records Apple's built-in malware definition versions.
func XProtect(e *Env) (string, string) {
	plists := map[string]string{
		"xprotect":     "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
		"xprotect-mrt": "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist",
	}
	var notes []string
	for name, p := range plists {
		r := runner.Run(10*time.Second, "/usr/bin/defaults", "read", strings.TrimSuffix(p, ".plist"), "CFBundleShortVersionString")
		if r.ExitCode == 0 {
			e.Report.Version(name, string(r.Stdout))
			notes = append(notes, name+" "+strings.TrimSpace(string(r.Stdout)))
		}
	}
	if len(notes) == 0 {
		return skipped("XProtect bundle not found")
	}
	return ok("%s", strings.Join(notes, ", "))
}
