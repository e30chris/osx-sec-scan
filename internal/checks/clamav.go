package checks

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/report"
	"github.com/e30chris/osx-sec-scan/internal/runner"
)

// clamavPkgPrefix is where the official Cisco-Talos macOS .pkg installs. It is
// preferred over Homebrew, whose OpenSSL 4 build cannot verify signature DBs
// (Cisco-Talos/clamav#1873). See docs/clamav.md.
const clamavPkgPrefix = "/usr/local/clamav"

const clamTimeout = 12 * time.Hour

func clamTool(dir, name string) string {
	if p := runner.Find(filepath.Join(clamavPkgPrefix, dir, name)); p != "" {
		return p
	}
	return runner.Find(name)
}

// clamCerts finds the CA cert dir shipped with the install: etc/certs for the
// official pkg, etc/clamav/certs for Homebrew.
func clamCerts(bin string) string {
	prefix := filepath.Join(filepath.Dir(bin), "..")
	for _, rel := range []string{"etc/certs", "etc/clamav/certs"} {
		if p, err := filepath.EvalSymlinks(filepath.Join(prefix, rel)); err == nil {
			return p
		}
	}
	return ""
}

// ClamAV updates signatures into state/clamav (repo-local, gitignored), starts
// a private clamd for the duration of the scan, and multiscans ScanPaths on
// all cores with clamdscan. clamd is always stopped before returning.
func ClamAV(e *Env) (string, string) {
	freshclam, clamd, clamdscan := clamTool("bin", "freshclam"), clamTool("sbin", "clamd"), clamTool("bin", "clamdscan")
	if freshclam == "" || clamd == "" || clamdscan == "" {
		return skipped("clamav not installed (see docs/clamav.md)")
	}
	e.Report.Version("clamav", runner.Run(10*time.Second, clamdscan, "--version").Combined())
	certs := clamCerts(freshclam)
	if certs == "" {
		return "error", "ClamAV CA cert dir not found next to " + freshclam
	}

	dbDir := filepath.Join(e.StateDir, "clamav")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return failed(err)
	}
	if status, note := e.freshclam(freshclam, dbDir, certs); status != "" {
		return status, note
	}

	sock := filepath.Join(e.StateDir, "clamd.sock")
	conf := filepath.Join(e.StateDir, "clamd.conf")
	if err := os.WriteFile(conf, []byte(e.clamdConf(dbDir, certs, sock)), 0o600); err != nil {
		return failed(err)
	}
	_ = os.Remove(sock)

	// clamd runs in the foreground as our child so it dies with the scan.
	d := exec.Command(clamd, "--config-file="+conf)
	clamdOut, _ := os.Create(filepath.Join(e.Report.Dir, "clamd.out"))
	defer clamdOut.Close()
	d.Stdout, d.Stderr = clamdOut, clamdOut
	if err := d.Start(); err != nil {
		return failed(err)
	}
	defer func() {
		_ = d.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = d.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			_ = d.Process.Kill()
		}
		_ = os.Remove(sock)
	}()

	// Loading ~3.6M signatures takes a little while.
	if r := runner.Run(5*time.Minute, clamdscan, "--config-file="+conf, "--ping", "120:2"); r.ExitCode != 0 {
		return "error", "clamd did not start (see clamd.out): " + strings.TrimSpace(r.Combined())
	}

	logFile := filepath.Join(e.Report.Dir, "clamscan.log")
	args := append([]string{"--config-file=" + conf, "--multiscan", "--infected", "--log=" + logFile}, e.Config.ScanPaths...)
	r := runner.Run(clamTimeout, clamdscan, args...)

	// Parse the log, not stdout: it is written as the scan goes, so detections
	// survive a timeout.
	hits := e.clamHits(logFile)
	note := fmt.Sprintf("%d detections on %d threads, log in clamscan.log", hits, runtime.NumCPU())
	switch {
	case r.Err != nil:
		return "error", fmt.Sprintf("%v after %s; partial results: %s", r.Err, clamTimeout, note)
	case r.ExitCode == 2:
		note += " (some files unreadable; grant Full Disk Access or run with sudo)"
	}
	return ok("%s", note)
}

func (e *Env) freshclam(bin, dbDir, certs string) (string, string) {
	conf := filepath.Join(e.StateDir, "freshclam.conf")
	body := fmt.Sprintf("DatabaseDirectory %s\nDatabaseMirror database.clamav.net\nDatabaseOwner %s\nUpdateLogFile %s\nCVDCertsDirectory %s\n",
		dbDir, dbOwner(), filepath.Join(e.StateDir, "freshclam.log"), certs)
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		return failed(err)
	}
	_ = report.ChownToSudoUser(e.StateDir)

	fc := runner.Run(30*time.Minute, bin, "--config-file="+conf)
	e.Report.Raw("freshclam.txt", []byte(fc.Combined()))
	if fc.ExitCode != 0 {
		// Rate limiting or a mirror hiccup should not block a scan if we already have a DB.
		if dbs, _ := filepath.Glob(filepath.Join(dbDir, "*.c[lv]d")); len(dbs) == 0 {
			return "error", "freshclam failed and no signature DB present (see freshclam.txt)"
		}
	}
	return "", ""
}

func (e *Env) clamdConf(dbDir, certs, sock string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Foreground yes\nLocalSocket %s\nLocalSocketMode 600\n", sock)
	fmt.Fprintf(&b, "DatabaseDirectory %s\nCVDCertsDirectory %s\n", dbDir, certs)
	fmt.Fprintf(&b, "LogFile %s\nLogTime yes\n", filepath.Join(e.Report.Dir, "clamd.log"))
	fmt.Fprintf(&b, "MaxThreads %d\nMaxQueue %d\n", runtime.NumCPU(), runtime.NumCPU()*20)
	b.WriteString("MaxFileSize 200M\nMaxScanSize 400M\nMaxDirectoryRecursion 64\n")
	b.WriteString("CrossFilesystems no\nFollowDirectorySymlinks no\nFollowFileSymlinks no\n")
	// Generous timeouts: a single huge archive can take minutes.
	b.WriteString("ReadTimeout 600\nCommandReadTimeout 60\nIdleTimeout 600\n")
	for _, x := range e.Config.ExcludeDirs {
		fmt.Fprintf(&b, "ExcludePath %s\n", x)
	}
	return b.String()
}

func (e *Env) clamHits(logFile string) int {
	f, err := os.Open(logFile)
	if err != nil {
		return 0
	}
	defer f.Close()
	hits := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		path, sig, found := strings.Cut(sc.Text(), ": ")
		if !found || !strings.HasSuffix(sig, " FOUND") {
			continue
		}
		hits++
		sig = strings.TrimSuffix(sig, " FOUND")
		sev := report.High
		// Heuristics.* are structural oddities (malformed archives, etc.), not known malware.
		if strings.HasPrefix(sig, "Heuristics.") {
			sev = report.Medium
		}
		e.Report.Add(report.Finding{Severity: sev, Check: "clamav", Title: sig, Detail: path, Key: "clamav:" + path})
	}
	return hits
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
