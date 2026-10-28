package checks

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
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

// clamavPkgBin is where the official Cisco-Talos macOS .pkg installs. It is
// preferred over Homebrew, whose OpenSSL 4 build cannot verify signature DBs
// (Cisco-Talos/clamav#1873). See docs/clamav.md.
const clamavPkgBin = "/usr/local/clamav/bin"

func clamTool(name string) string {
	if p := runner.Find(filepath.Join(clamavPkgBin, name)); p != "" {
		return p
	}
	return runner.Find(name)
}

// clamCerts finds the CA cert dir shipped with the install: etc/certs for the
// official pkg, etc/clamav/certs for Homebrew.
func clamCerts(clamscan string) string {
	prefix := filepath.Join(filepath.Dir(clamscan), "..")
	for _, rel := range []string{"etc/certs", "etc/clamav/certs"} {
		if p, err := filepath.EvalSymlinks(filepath.Join(prefix, rel)); err == nil {
			return p
		}
	}
	return ""
}

// ClamAV updates signatures into state/clamav (repo-local, gitignored) and scans ScanPaths.
func ClamAV(e *Env) (string, string) {
	clamscan, freshclam := clamTool("clamscan"), clamTool("freshclam")
	if clamscan == "" || freshclam == "" {
		return skipped("clamav not installed (see docs/clamav.md)")
	}
	e.Report.Version("clamav", runner.Run(10*time.Second, clamscan, "--version").Combined())

	dbDir := filepath.Join(e.StateDir, "clamav")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return failed(err)
	}
	// ClamAV 1.5+ verifies signature DBs against the CA cert shipped with the
	// install; a custom config must point at it.
	certs := clamCerts(clamscan)
	if certs == "" {
		return "error", "ClamAV CA cert dir not found next to " + clamscan
	}
	conf := filepath.Join(e.StateDir, "freshclam.conf")
	confBody := fmt.Sprintf("DatabaseDirectory %s\nDatabaseMirror database.clamav.net\nDatabaseOwner %s\nUpdateLogFile %s\nCVDCertsDirectory %s\n",
		dbDir, dbOwner(), filepath.Join(e.StateDir, "freshclam.log"), certs)
	if err := os.WriteFile(conf, []byte(confBody), 0o644); err != nil {
		return failed(err)
	}
	_ = report.ChownToSudoUser(e.StateDir)

	fc := runner.Run(30*time.Minute, freshclam, "--config-file="+conf)
	e.Report.Raw("freshclam.txt", []byte(fc.Combined()))
	if fc.ExitCode != 0 {
		// Rate limiting or a mirror hiccup should not block a scan if we already have a DB.
		if dbs, _ := filepath.Glob(filepath.Join(dbDir, "*.c[lv]d")); len(dbs) == 0 {
			return "error", "freshclam failed and no signature DB present (see freshclam.txt)"
		}
	}

	logFile := filepath.Join(e.Report.Dir, "clamscan.log")
	args := []string{"--database=" + dbDir, "--cvdcertsdir=" + certs, "-r", "-i", "--cross-fs=no",
		"--max-filesize=200M", "--max-scansize=400M", "--log=" + logFile}
	for _, x := range e.Config.ExcludeDirs {
		args = append(args, "--exclude-dir="+x)
	}
	args = append(args, e.Config.ScanPaths...)

	r := runner.Run(8*time.Hour, clamscan, args...)
	if r.Err != nil {
		return failed(r.Err)
	}
	// exit 0 = clean, 1 = infections found, 2 = some errors (usually permission denied)
	hits := 0
	for _, line := range strings.Split(string(r.Stdout), "\n") {
		path, sig, found := strings.Cut(line, ": ")
		if !found || !strings.HasSuffix(sig, " FOUND") {
			continue
		}
		hits++
		e.Report.Add(report.Finding{Severity: report.High, Check: "clamav", Title: strings.TrimSuffix(sig, " FOUND"), Detail: path, Key: "clamav:" + path})
	}
	note := fmt.Sprintf("%d detections, log in clamscan.log", hits)
	if r.ExitCode == 2 {
		note += " (some files unreadable; grant Full Disk Access or run with sudo)"
	}
	return ok("%s", note)
}

func dbOwner() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "root"
}

// Yara scans ScanPaths with the rule file in config. No rules = skipped.
func Yara(e *Env) (string, string) {
	bin := runner.Find("yara")
	if bin == "" {
		return skipped("yara not installed (brew bundle)")
	}
	e.Report.Version("yara", runner.Run(10*time.Second, bin, "--version").Combined())
	rules := e.Config.YaraRules
	if rules == "" {
		return skipped("no yara_rules set in config/local.json (see docs/yara-rules.md)")
	}
	if _, err := os.Stat(rules); err != nil {
		return failed(err)
	}

	base := []string{"-r", "-w", "-f", "-N", "--skip-larger=209715200"}
	if strings.HasSuffix(rules, ".yarc") {
		base = append(base, "-C")
	}
	var out strings.Builder
	hits := 0
	for _, p := range e.Config.ScanPaths {
		r := runner.Run(4*time.Hour, bin, append(base, rules, p)...)
		out.Write(r.Stdout)
		for _, line := range strings.Split(string(r.Stdout), "\n") {
			rule, path, found := strings.Cut(line, " ")
			if !found {
				continue
			}
			hits++
			e.Report.Add(report.Finding{Severity: report.High, Check: "yara", Title: "YARA rule " + rule, Detail: path, Key: "yara:" + rule + ":" + path})
		}
		if r.Err != nil {
			e.Report.Raw("yara.txt", []byte(out.String()))
			return failed(r.Err)
		}
	}
	e.Report.Raw("yara.txt", []byte(out.String()))
	return ok("%d matches", hits)
}
