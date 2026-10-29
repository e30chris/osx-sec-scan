package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/report"
	"github.com/e30chris/osx-sec-scan/internal/runner"
)

const knockKnockBin = "/Applications/KnockKnock.app/Contents/MacOS/KnockKnock"

// KnockKnock gives an independent second opinion on persistence. VirusTotal
// lookups are skipped so no file hashes leave the machine.
func KnockKnock(e *Env) (string, string) {
	if runner.Find(knockKnockBin) == "" {
		return skipped("KnockKnock not installed (brew bundle)")
	}
	r := runner.Run(10*time.Minute, knockKnockBin, "-whosthere", "-pretty", "-skipVT")
	path := e.Report.Raw("knockknock.json", r.Stdout)
	if len(r.Stderr) > 0 {
		e.Report.Raw("knockknock.stderr.txt", r.Stderr)
	}
	if strings.Contains(r.Combined(), "requires Full Disk Access") {
		return skipped("KnockKnock needs Full Disk Access for the app running osxscan (see README)")
	}
	if r.Err != nil || r.ExitCode != 0 {
		return "error", fmt.Sprintf("exit %d %v (see %s)", r.ExitCode, r.Err, filepath.Base(path))
	}
	return ok("raw output in %s", filepath.Base(path))
}

// Codesign verifies every app bundle's signature and Gatekeeper assessment.
func Codesign(e *Env) (string, string) {
	var apps []string
	for _, d := range append([]string{"/Applications", "/Applications/Utilities"}, homeApps()...) {
		found, _ := filepath.Glob(filepath.Join(d, "*.app"))
		apps = append(apps, found...)
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for app := range jobs {
				checkApp(e, app)
			}
		}()
	}
	for _, a := range apps {
		jobs <- a
	}
	close(jobs)
	wg.Wait()
	return ok("%d apps checked", len(apps))
}

func homeApps() []string {
	var dirs []string
	for _, h := range userHomes() {
		dirs = append(dirs, filepath.Join(h, "Applications"))
	}
	return dirs
}

func checkApp(e *Env, app string) {
	v := runner.Run(10*time.Minute, "/usr/bin/codesign", "--verify", "--deep", "--strict", app)
	if v.ExitCode != 0 && strings.Contains(v.Combined(), "detritus not allowed") &&
		runner.Run(10*time.Minute, "/usr/bin/codesign", "--verify", "--deep", app).ExitCode == 0 {
		// Code is intact; only Finder metadata xattrs (common in Chromium helpers) trip --strict.
		e.Report.Add(report.Finding{
			Severity: report.Low, Check: "codesign",
			Title:  "Extra Finder metadata inside " + filepath.Base(app) + " (code intact)",
			Detail: app + "\n" + strings.TrimSpace(v.Combined()),
			Key:    "detritus:" + app,
		})
		return
	}
	if v.ExitCode != 0 {
		e.Report.Add(report.Finding{
			Severity: report.Medium, Check: "codesign",
			Title:  "App signature does not verify: " + filepath.Base(app),
			Detail: app + "\n" + strings.TrimSpace(v.Combined()) + "\nCould be tampering, or just a sloppy/self-updating app. Reinstall it from the vendor.",
			Key:    "codesign:" + app,
		})
		return
	}
	s := runner.Run(2*time.Minute, "/usr/sbin/spctl", "--assess", "--type", "execute", "-v", app)
	if s.ExitCode != 0 {
		e.Report.Add(report.Finding{
			Severity: report.Low, Check: "gatekeeper",
			Title:  "Gatekeeper rejects " + filepath.Base(app),
			Detail: app + "\n" + strings.TrimSpace(s.Combined()),
			Key:    "spctl:" + app,
		})
	}
}

// Lynis runs a general host audit; warnings become findings.
func Lynis(e *Env) (string, string) {
	bin := runner.Find("lynis")
	if bin == "" {
		return skipped("lynis not installed (brew bundle)")
	}
	e.Report.Version("lynis", runner.Run(30*time.Second, bin, "show", "version").Combined())
	reportFile := filepath.Join(e.Report.Dir, "lynis-report.dat")
	args := []string{"audit", "system", "--quick", "--no-colors",
		"--report-file", reportFile, "--logfile", filepath.Join(e.Report.Dir, "lynis.log")}
	if !e.Root {
		args = append(args, "--pentest") // non-privileged mode
	}
	r := runner.Run(30*time.Minute, bin, args...)
	e.Report.Raw("lynis.txt", []byte(r.Combined()))
	if r.Err != nil {
		return failed(r.Err)
	}

	f, err := os.Open(reportFile)
	if err != nil {
		return failed(err)
	}
	defer f.Close()
	var warnings, suggestions []string
	index := "?"
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "warning[]="):
			warnings = append(warnings, strings.TrimPrefix(line, "warning[]="))
		case strings.HasPrefix(line, "suggestion[]="):
			suggestions = append(suggestions, strings.TrimPrefix(line, "suggestion[]="))
		case strings.HasPrefix(line, "hardening_index="):
			index = strings.TrimPrefix(line, "hardening_index=")
		}
	}
	for _, w := range warnings {
		id, _, _ := strings.Cut(w, "|")
		e.Report.Add(report.Finding{Severity: report.Medium, Check: "lynis", Title: "Lynis warning " + id, Detail: strings.ReplaceAll(w, "|", "\n"), Key: "lynis:" + id})
	}
	if len(suggestions) > 0 {
		e.Report.Add(report.Finding{Severity: report.Info, Check: "lynis", Title: fmt.Sprintf("%d Lynis suggestions", len(suggestions)), Detail: strings.Join(suggestions, "\n"), Key: "lynis:suggestions"})
	}
	if !e.Root {
		return ok("hardening index %s (non-root: partial audit)", index)
	}
	return ok("hardening index %s, %d warnings", index, len(warnings))
}
