package checks

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/report"
	"github.com/e30chris/osx-sec-scan/internal/runner"
)

// sfDataless marks cloud placeholder files (iCloud, File Provider); reading
// them triggers a download.
const sfDataless = 0x40000000

const yaraMaxFile = 200 << 20

// Yara scans ScanPaths with the rule file in config. No rules = skipped.
// YARA has no exclude option, so we build the file list ourselves.
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

	listFile := filepath.Join(e.Report.Dir, "yara-files.txt")
	n, err := e.scanList(listFile)
	if err != nil {
		return failed(err)
	}

	args := []string{"-w", "-f", fmt.Sprintf("--threads=%d", runtime.NumCPU())}
	if strings.HasSuffix(rules, ".yarc") {
		args = append(args, "-C")
	}
	args = append(args, "--scan-list", rules, listFile)
	r := runner.Run(clamTimeout, bin, args...)
	e.Report.Raw("yara.txt", r.Stdout)
	_ = os.Remove(listFile)

	hits := 0
	for _, line := range strings.Split(string(r.Stdout), "\n") {
		rule, path, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		hits++
		e.Report.Add(report.Finding{Severity: report.High, Check: "yara", Title: "YARA rule " + rule, Detail: path, Key: "yara:" + rule + ":" + path})
	}
	if r.Err != nil {
		return "error", fmt.Sprintf("%v; partial results: %d matches in %d files", r.Err, hits, n)
	}
	return ok("%d matches in %d files", hits, n)
}

// scanList writes every regular file under ScanPaths, minus excluded dirs,
// cloud placeholders and files over yaraMaxFile, one per line.
func (e *Env) scanList(out string) (int, error) {
	var excl []*regexp.Regexp
	for _, x := range e.Config.ExcludeDirs {
		re, err := regexp.Compile(x)
		if err != nil {
			return 0, fmt.Errorf("exclude_dirs %q: %w", x, err)
		}
		excl = append(excl, re)
	}
	excluded := func(p string) bool {
		for _, re := range excl {
			if re.MatchString(p) {
				return true
			}
		}
		return false
	}

	f, err := os.Create(out)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	n := 0
	for _, root := range e.Config.ScanPaths {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if runner.Interrupted() {
				return filepath.SkipAll
			}
			if err != nil {
				return nil // unreadable: skip, keep walking
			}
			if excluded(p) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil // symlinks, sockets, devices
			}
			fi, err := d.Info()
			if err != nil || fi.Size() == 0 || fi.Size() > yaraMaxFile {
				return nil
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Flags&sfDataless != 0 {
				return nil
			}
			fmt.Fprintln(w, p)
			n++
			return nil
		})
	}
	return n, w.Flush()
}
