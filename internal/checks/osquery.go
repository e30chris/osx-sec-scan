package checks

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/report"
	"github.com/e30chris/osx-sec-scan/internal/runner"
)

type row map[string]string

type osq struct {
	bin string
	e   *Env
}

func (q osq) query(name, sql string) ([]row, error) {
	r := runner.Run(2*time.Minute, q.bin, "--json", sql)
	q.e.Report.Raw("osquery-"+name+".json", r.Stdout)
	if r.Err != nil || r.ExitCode != 0 {
		return nil, fmt.Errorf("%s: %v %s", name, r.Err, strings.TrimSpace(string(r.Stderr)))
	}
	var rows []row
	if err := json.Unmarshal(r.Stdout, &rows); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return rows, nil
}

// Osquery looks at live OS state: keyboard event taps, kernel/system
// extensions, network listeners, cron and browser extensions.
func Osquery(e *Env) (string, string) {
	bin := runner.Find("osqueryi")
	if bin == "" {
		return skipped("osqueryi not installed (brew bundle)")
	}
	e.Report.Version("osquery", runner.Run(10*time.Second, bin, "--version").Combined())
	q := osq{bin, e}
	var errs []string
	note := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	note(q.eventTaps())
	note(q.kexts())
	note(q.sysExts())
	note(q.listeners())
	note(q.cron())
	note(q.browserExts())

	if len(errs) > 0 {
		return "error", strings.Join(errs, "; ")
	}
	return ok("6 query groups")
}

// eventTaps is the main keylogger signal: a process tapping key events.
func (q osq) eventTaps() error {
	rows, err := q.query("event_taps", `
		SELECT et.event_tapped, et.tapping_process, et.process_being_tapped,
		       p.name, p.path
		FROM event_taps et LEFT JOIN processes p ON p.pid = et.tapping_process
		WHERE et.enabled = 1`)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, a := range q.e.Config.KeyboardTapAllowlist {
		allowed[a] = true
	}
	for _, r := range rows {
		if !strings.Contains(r["event_tapped"], "Key") {
			continue
		}
		path := r["path"]
		if allowed[path] || strings.HasPrefix(path, "/System/") || strings.HasPrefix(path, "/usr/libexec/") {
			continue
		}
		sev := report.Medium
		sig := codesignInfo(path)
		if path == "" || !sig.valid || sig.adhoc {
			sev = report.High
		}
		q.e.Report.Add(report.Finding{
			Severity: sev,
			Check:    "keyboard-tap",
			Title:    fmt.Sprintf("%s is reading keyboard events", orUnknown(r["name"])),
			Detail: fmt.Sprintf("path: %s\npid: %s\nevents: %s\nsigner: %s\n"+
				"Legitimate for launchers, window managers, remappers and text expanders. "+
				"If you recognize it, add the path to keyboard_tap_allowlist.", path, r["tapping_process"], r["event_tapped"], sig.authority),
			Key: "tap:" + path,
		})
	}
	return nil
}

func (q osq) kexts() error {
	rows, err := q.query("kernel_extensions", `SELECT name, version, path FROM kernel_extensions WHERE name NOT LIKE 'com.apple.%' AND name != '__kernel__'`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		q.e.Report.Add(report.Finding{Severity: report.Medium, Check: "kext", Title: "Third-party kernel extension loaded: " + r["name"], Detail: r["path"], Key: "kext:" + r["name"]})
	}
	return nil
}

func (q osq) sysExts() error {
	rows, err := q.query("system_extensions", `SELECT identifier, version, state, team, bundle_path, category FROM system_extensions`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		q.e.Report.Add(report.Finding{
			Severity: report.Info, Check: "system-extension",
			Title:  fmt.Sprintf("System extension %s (%s)", r["identifier"], r["state"]),
			Detail: fmt.Sprintf("team: %s\ncategory: %s\nbundle: %s", r["team"], r["category"], r["bundle_path"]),
			Key:    "sysext:" + r["identifier"],
		})
	}
	return nil
}

func (q osq) listeners() error {
	rows, err := q.query("listening_ports", `
		SELECT DISTINCT p.name, p.path, lp.port, lp.address, lp.protocol
		FROM listening_ports lp JOIN processes p USING (pid)
		WHERE lp.port > 0 AND lp.address NOT IN ('127.0.0.1', '::1')
		  AND lp.address NOT LIKE 'fe80%'`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		proto := map[string]string{"6": "tcp", "17": "udp"}[r["protocol"]]
		q.e.Report.Add(report.Finding{
			Severity: report.Low, Check: "network",
			Title:  fmt.Sprintf("%s listens on %s %s:%s", orUnknown(r["name"]), proto, r["address"], r["port"]),
			Detail: r["path"],
			Key:    fmt.Sprintf("listen:%s:%s/%s", r["path"], proto, r["port"]),
		})
	}
	return nil
}

func (q osq) cron() error {
	rows, err := q.query("crontab", `SELECT path, minute, hour, day_of_month, month, day_of_week, command FROM crontab`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		q.e.Report.Add(report.Finding{Severity: report.Medium, Check: "persistence", Title: "cron job present", Detail: r["path"] + "\n" + r["command"], Key: "cron:" + r["command"]})
	}
	return nil
}

func (q osq) browserExts() error {
	queries := map[string]string{
		"chrome_extensions": `SELECT c.browser_type AS browser, c.name, c.identifier, c.version, c.permissions, c.path
			FROM users u CROSS JOIN chrome_extensions c USING (uid)`,
		"safari_extensions": `SELECT 'safari' AS browser, s.name, s.identifier, s.version, '' AS permissions, s.path
			FROM users u CROSS JOIN safari_extensions s USING (uid)`,
		"firefox_addons": `SELECT 'firefox' AS browser, f.name, f.identifier, f.version, '' AS permissions, f.path
			FROM users u CROSS JOIN firefox_addons f USING (uid) WHERE f.type = 'extension'`,
	}
	for name, sql := range queries {
		rows, err := q.query(name, sql)
		if err != nil {
			return err
		}
		for _, r := range rows {
			q.e.Report.Add(report.Finding{
				Severity: report.Info, Check: "browser-extension",
				Title:  fmt.Sprintf("%s extension: %s %s", r["browser"], r["name"], r["version"]),
				Detail: fmt.Sprintf("id: %s\npermissions: %s\npath: %s", r["identifier"], r["permissions"], r["path"]),
				Key:    "ext:" + r["browser"] + ":" + r["identifier"],
			})
		}
	}
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown process"
	}
	return s
}
