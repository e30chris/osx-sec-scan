// Package schedule installs per-user LaunchAgents for the daily quick and weekly
// full scans. They run as you, not root: a root job executing a binary and
// Homebrew tools from user-writable paths would let any process you run
// escalate to root by replacing them.
package schedule

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/runner"
)

const prefix = "com.osxsecscan."

// Job is one scheduled scan. Weekday -1 means every day.
type Job struct {
	Mode    string
	Weekday int
	Hour    int
	Minute  int
}

var plistTmpl = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Bin}}</string>
		<string>{{.Mode}}</string>
		<string>--notify</string>
	</array>
	<key>WorkingDirectory</key>
	<string>{{.Repo}}</string>
	<key>StartCalendarInterval</key>
	<dict>
{{- if ge .Weekday 0}}
		<key>Weekday</key>
		<integer>{{.Weekday}}</integer>
{{- end}}
		<key>Hour</key>
		<integer>{{.Hour}}</integer>
		<key>Minute</key>
		<integer>{{.Minute}}</integer>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
	<key>LowPriorityIO</key>
	<true/>
	<key>Nice</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>{{.Log}}</string>
	<key>StandardErrorPath</key>
	<string>{{.Log}}</string>
</dict>
</plist>
`))

func agentDir() (string, error) {
	h, err := os.UserHomeDir()
	return filepath.Join(h, "Library", "LaunchAgents"), err
}

func label(mode string) string { return prefix + mode }

// Install writes and loads the LaunchAgents. bin must be an absolute path.
func Install(bin, repo, stateDir string, jobs []Job) error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("run schedule install as yourself, not with sudo")
	}
	dir, err := agentDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	uid := fmt.Sprint(os.Getuid())
	for _, j := range jobs {
		var buf bytes.Buffer
		err := plistTmpl.Execute(&buf, map[string]any{
			"Label": label(j.Mode), "Bin": bin, "Mode": j.Mode, "Repo": repo,
			"Weekday": j.Weekday, "Hour": j.Hour, "Minute": j.Minute,
			"Log": filepath.Join(stateDir, "launchd-"+j.Mode+".log"),
		})
		if err != nil {
			return err
		}
		p := filepath.Join(dir, label(j.Mode)+".plist")
		// Unload any previous version so the new schedule takes effect.
		runner.Run(30*time.Second, "/bin/launchctl", "bootout", "gui/"+uid, p)
		if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
			return err
		}
		if r := runner.Run(30*time.Second, "/bin/launchctl", "bootstrap", "gui/"+uid, p); r.ExitCode != 0 {
			return fmt.Errorf("launchctl bootstrap %s: %s", p, r.Combined())
		}
		fmt.Printf("installed %s\n", p)
	}
	return nil
}

// Uninstall unloads and removes the LaunchAgents.
func Uninstall(modes []string) error {
	dir, err := agentDir()
	if err != nil {
		return err
	}
	uid := fmt.Sprint(os.Getuid())
	for _, m := range modes {
		p := filepath.Join(dir, label(m)+".plist")
		runner.Run(30*time.Second, "/bin/launchctl", "bootout", "gui/"+uid, p)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Printf("removed %s\n", p)
	}
	return nil
}

// Status prints launchd's view of each job.
func Status(modes []string) {
	uid := fmt.Sprint(os.Getuid())
	for _, m := range modes {
		r := runner.Run(30*time.Second, "/bin/launchctl", "print", "gui/"+uid+"/"+label(m))
		if r.ExitCode != 0 {
			fmt.Printf("%s: not loaded\n", label(m))
			continue
		}
		fmt.Printf("%s: loaded\n", label(m))
		for _, line := range bytes.Split(r.Stdout, []byte("\n")) {
			t := bytes.TrimSpace(line)
			if bytes.HasPrefix(t, []byte("state =")) || bytes.HasPrefix(t, []byte("last exit code =")) || bytes.HasPrefix(t, []byte("runs =")) {
				fmt.Printf("    %s\n", t)
			}
		}
	}
}
