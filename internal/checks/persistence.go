package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/report"
	"github.com/e30chris/osx-sec-scan/internal/runner"
)

// PersistItem is one thing that can make code run automatically.
type PersistItem struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Program string `json:"program,omitempty"`
	Args    string `json:"args,omitempty"`
	Signer  string `json:"signer,omitempty"`
	TeamID  string `json:"team_id,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

func (p PersistItem) key() string {
	return strings.Join([]string{p.Kind, p.Path, p.Program, p.Signer, p.SHA256}, "|")
}

var interpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "osascript": true, "python": true,
	"python3": true, "perl": true, "ruby": true, "node": true, "curl": true,
}

// Persistence inventories launchd jobs, login/logout hooks, auth plugins, sudoers
// drop-ins, profiles and shell startup files, then diffs against the previous run.
func Persistence(e *Env) (string, string) {
	var items []PersistItem

	launchDirs := []string{"/Library/LaunchAgents", "/Library/LaunchDaemons"}
	for _, h := range userHomes() {
		launchDirs = append(launchDirs, filepath.Join(h, "Library/LaunchAgents"))
	}
	for _, d := range launchDirs {
		plists, _ := filepath.Glob(filepath.Join(d, "*.plist"))
		for _, p := range plists {
			items = append(items, e.launchItem(p))
		}
	}

	items = append(items, e.loginHooks()...)
	items = append(items, e.dirEntries("auth-plugin", "/Library/Security/SecurityAgentPlugins", report.Medium)...)
	items = append(items, e.dirEntries("sudoers.d", "/private/etc/sudoers.d", report.Medium)...)
	items = append(items, e.dirEntries("periodic", "/usr/local/etc/periodic", report.Medium)...)
	items = append(items, shellFiles()...)

	e.profiles()
	e.backgroundTasks()

	sort.Slice(items, func(i, j int) bool { return items[i].key() < items[j].key() })
	js, _ := json.MarshalIndent(items, "", "  ")
	e.Report.Raw("persistence.json", js)

	prev, prevDir := e.previousPersistence()
	if prev == nil {
		return ok("%d items inventoried (first run, no drift baseline)", len(items))
	}
	added := 0
	for _, it := range items {
		if !prev[it.key()] {
			added++
			e.Report.Add(report.Finding{
				Severity: report.Medium,
				Check:    "persistence-drift",
				Title:    fmt.Sprintf("New or changed %s since %s", it.Kind, filepath.Base(prevDir)),
				Detail:   fmt.Sprintf("path: %s\nprogram: %s %s\nsigner: %s", it.Path, it.Program, it.Args, it.Signer),
				Key:      "drift:" + it.key(),
			})
		}
	}
	return ok("%d items, %d new/changed since %s", len(items), added, filepath.Base(prevDir))
}

func (e *Env) launchItem(plist string) PersistItem {
	it := PersistItem{Kind: "launchd", Path: plist}
	r := runner.Run(10*time.Second, "/usr/bin/plutil", "-convert", "json", "-o", "-", plist)
	var job struct {
		Label            string   `json:"Label"`
		Program          string   `json:"Program"`
		ProgramArguments []string `json:"ProgramArguments"`
	}
	if r.ExitCode != 0 || json.Unmarshal(r.Stdout, &job) != nil {
		e.Report.Add(report.Finding{Severity: report.Medium, Check: "persistence", Title: "Unreadable launchd plist", Detail: plist + "\n" + r.Combined(), Key: plist})
		return it
	}
	it.Program = job.Program
	args := job.ProgramArguments
	if it.Program == "" && len(args) > 0 {
		it.Program, args = args[0], args[1:]
	} else if len(args) > 0 {
		args = args[1:]
	}
	it.Args = strings.Join(args, " ")

	f := report.Finding{Check: "persistence"}
	detail := fmt.Sprintf("plist: %s\nlabel: %s\nprogram: %s %s", plist, job.Label, it.Program, it.Args)

	system := strings.HasPrefix(plist, "/Library/")
	if system && !rootOwned(plist) {
		e.Report.Add(report.Finding{
			Severity: report.Medium, Check: "persistence",
			Title:  "System launchd plist is not root-owned or is group/world-writable",
			Detail: plist + "\n" + ownerString(plist) + "\nlaunchd refuses to load these; a non-root user can also rewrite it.",
			Key:    "owner:" + plist,
		})
	}

	switch {
	case it.Program == "":
		f.Severity, f.Title = report.Low, "Inert launchd plist (no program) — leftover, or a deliberate updater blocker?"
	case interpreters[filepath.Base(it.Program)]:
		f.Severity, f.Title = report.Medium, "launchd job runs a script interpreter ("+filepath.Base(it.Program)+")"
	case suspiciousPath(it.Program):
		f.Severity, f.Title = report.High, "launchd job runs from a temp, shared or hidden location"
	}
	if it.Program != "" && filepath.IsAbs(it.Program) {
		if _, err := os.Stat(it.Program); err != nil {
			if f.Title == "" {
				f.Severity, f.Title = report.Low, "launchd job points at a missing program (stale leftover?)"
			}
		} else if isScript(it.Program) {
			// Scripts cannot be code-signed; what matters is who can modify them.
			it.SHA256 = fileHash(it.Program)
			detail += "\n" + ownerString(it.Program)
			switch {
			case system && !rootOwned(it.Program):
				f.Severity, f.Title = report.High, "System launchd job runs a script a non-root user can modify"
			case f.Title == "":
				f.Severity, f.Title = report.Low, "launchd job runs a shell script (unsigned by nature): "+job.Label
			}
		} else {
			sig := codesignInfo(it.Program)
			it.Signer, it.TeamID = sig.authority, sig.teamID
			detail += fmt.Sprintf("\nsigner: %s\nteam: %s", sig.authority, sig.teamID)
			switch {
			case system && !rootOwned(it.Program):
				f.Severity, f.Title = report.High, "System launchd job runs a binary a non-root user can modify"
			case !sig.valid && f.Severity < report.High:
				f.Severity, f.Title = report.High, "launchd job program is unsigned or has an invalid signature"
			case sig.adhoc && f.Severity < report.Medium:
				f.Severity, f.Title = report.Medium, "launchd job program is only ad-hoc signed"
			case f.Title == "" && sig.authority != "Software Signing":
				f.Severity, f.Title = report.Info, "Third-party launchd job: "+job.Label
			}
		}
	}
	if f.Title != "" {
		// Severity is part of the key so allowlisting a benign job does not
		// hide it if it later turns unsigned.
		f.Detail, f.Key = detail, f.Severity.String()+":"+plist
		e.Report.Add(f)
	}
	return it
}

// rootOwned reports whether p is owned by root and not writable by group or others.
func rootOwned(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && fi.Mode().Perm()&0o022 == 0
}

func ownerString(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return err.Error()
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("owner uid %d gid %d, mode %s", st.Uid, st.Gid, fi.Mode().Perm())
	}
	return fi.Mode().String()
}

func isScript(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 2)
	n, _ := f.Read(b)
	return n == 2 && string(b) == "#!"
}

func suspiciousPath(p string) bool {
	for _, pre := range []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return strings.Contains(p, "/.")
}

type sigInfo struct {
	valid, adhoc      bool
	authority, teamID string
}

func codesignInfo(path string) sigInfo {
	var s sigInfo
	v := runner.Run(30*time.Second, "/usr/bin/codesign", "--verify", "--strict", path)
	s.valid = v.ExitCode == 0
	d := runner.Run(30*time.Second, "/usr/bin/codesign", "-dv", "--verbose=2", path)
	for _, line := range strings.Split(d.Combined(), "\n") {
		switch {
		case strings.HasPrefix(line, "Authority=") && s.authority == "":
			s.authority = strings.TrimPrefix(line, "Authority=")
		case strings.HasPrefix(line, "TeamIdentifier="):
			s.teamID = strings.TrimPrefix(line, "TeamIdentifier=")
		case strings.HasPrefix(line, "Signature=adhoc"):
			s.adhoc = true
		}
	}
	return s
}

func (e *Env) loginHooks() []PersistItem {
	var items []PersistItem
	for _, key := range []string{"LoginHook", "LogoutHook"} {
		r := runner.Run(10*time.Second, "/usr/bin/defaults", "read", "com.apple.loginwindow", key)
		if r.ExitCode == 0 {
			v := strings.TrimSpace(string(r.Stdout))
			items = append(items, PersistItem{Kind: "login-hook", Path: key, Program: v})
			e.Report.Add(report.Finding{Severity: report.High, Check: "persistence", Title: key + " is set (legacy persistence, rarely legitimate)", Detail: v, Key: "hook:" + key})
		}
	}
	return items
}

func (e *Env) dirEntries(kind, dir string, sev report.Severity) []PersistItem {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var items []PersistItem
	for _, ent := range entries {
		p := filepath.Join(dir, ent.Name())
		items = append(items, PersistItem{Kind: kind, Path: p, SHA256: fileHash(p)})
		e.Report.Add(report.Finding{Severity: sev, Check: "persistence", Title: "Entry in " + dir + " — confirm you installed it", Detail: p, Key: p})
	}
	return items
}

// shellFiles hashes shell startup files so changes show up as drift.
func shellFiles() []PersistItem {
	names := []string{".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile"}
	var items []PersistItem
	for _, h := range userHomes() {
		for _, n := range names {
			p := filepath.Join(h, n)
			if hsum := fileHash(p); hsum != "" {
				items = append(items, PersistItem{Kind: "shell-rc", Path: p, SHA256: hsum})
			}
		}
	}
	for _, p := range []string{"/etc/zshrc", "/etc/zprofile", "/etc/profile", "/etc/bashrc", "/etc/hosts"} {
		if hsum := fileHash(p); hsum != "" {
			items = append(items, PersistItem{Kind: "system-rc", Path: p, SHA256: hsum})
		}
	}
	return items
}

func fileHash(p string) string {
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (e *Env) profiles() {
	r := runner.Run(30*time.Second, "/usr/bin/profiles", "list")
	out := r.Combined()
	e.Report.Raw("profiles.txt", []byte(out))
	if r.ExitCode == 0 && !strings.Contains(out, "no configuration profiles") && strings.TrimSpace(out) != "" {
		e.Report.Add(report.Finding{Severity: report.Medium, Check: "persistence", Title: "Configuration profiles are installed — confirm each one is yours", Detail: out, Key: "profiles:" + fileHashBytes([]byte(out))})
	}
}

// backgroundTasks dumps the Background Task Management DB (login items, SMAppService). Needs root.
func (e *Env) backgroundTasks() {
	if !e.Root {
		return
	}
	r := runner.Run(2*time.Minute, "/usr/bin/sfltool", "dumpbtm")
	e.Report.Raw("btm.txt", []byte(r.Combined()))
}

func fileHashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func (e *Env) previousPersistence() (map[string]bool, string) {
	dirs, _ := filepath.Glob(filepath.Join(e.ResultsDir, "*", "persistence.json"))
	sort.Strings(dirs)
	for i := len(dirs) - 1; i >= 0; i-- {
		if filepath.Dir(dirs[i]) == e.Report.Dir {
			continue
		}
		data, err := os.ReadFile(dirs[i])
		if err != nil {
			continue
		}
		var prev []PersistItem
		if json.Unmarshal(data, &prev) != nil {
			continue
		}
		set := map[string]bool{}
		for _, p := range prev {
			set[p.key()] = true
		}
		return set, filepath.Dir(dirs[i])
	}
	return nil, ""
}
