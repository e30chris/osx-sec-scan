// Command osxscan scans a Mac for malware, persistence and keyloggers using
// open-source tools, and checks/applies a security baseline.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/e30chris/osx-sec-scan/internal/checks"
	"github.com/e30chris/osx-sec-scan/internal/config"
	"github.com/e30chris/osx-sec-scan/internal/harden"
	"github.com/e30chris/osx-sec-scan/internal/report"
	"github.com/e30chris/osx-sec-scan/internal/runner"
	"github.com/e30chris/osx-sec-scan/internal/schedule"
)

const usage = `osxscan — open-source macOS security scanner

Usage:
  osxscan quick                 posture, persistence, keyboard taps, osquery, KnockKnock
  osxscan full                  quick + app signatures, Lynis, ClamAV, YARA
  osxscan harden check          show baseline PASS/FAIL (no changes)
  sudo osxscan harden apply     fix failing items, asking before each one
  osxscan schedule install      daily quick + weekly full LaunchAgents (run as yourself)
  osxscan schedule uninstall
  osxscan schedule status

Flags (before the subcommand's own flags):
  -repo DIR     repo root (default: found from the current directory or binary)
  -notify       show a macOS notification when medium/high findings exist

Run full scans with sudo for complete coverage. Results go to <repo>/results/.
`

func main() {
	fs := flag.NewFlagSet("osxscan", flag.ExitOnError)
	repoFlag := fs.String("repo", "", "repo root")
	notify := fs.Bool("notify", false, "notify on findings")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	if len(os.Args) < 2 {
		fs.Usage()
		os.Exit(2)
	}
	cmd, rest := os.Args[1], os.Args[2:]
	_ = fs.Parse(rest)
	args := fs.Args()

	repo := *repoFlag
	if repo == "" {
		repo = findRepo()
	}
	if repo == "" {
		fatal(fmt.Errorf("cannot find repo root; pass -repo"))
	}

	switch cmd {
	case "quick", "full":
		os.Exit(scan(repo, cmd, *notify))
	case "harden":
		switch sub(args) {
		case "check":
			if harden.PrintCheck() > 0 {
				os.Exit(1)
			}
		case "apply":
			yes := len(args) > 1 && args[1] == "-y"
			if err := harden.Apply(yes); err != nil {
				fatal(err)
			}
		default:
			fs.Usage()
			os.Exit(2)
		}
	case "schedule":
		modes := []string{"quick", "full"}
		switch sub(args) {
		case "install":
			bin, err := os.Executable()
			if err != nil {
				fatal(err)
			}
			bin, _ = filepath.EvalSymlinks(bin)
			jobs := []schedule.Job{
				{Mode: "quick", Weekday: -1, Hour: 10, Minute: 0},
				{Mode: "full", Weekday: 0, Hour: 12, Minute: 0}, // Sunday noon; runs on wake if asleep
			}
			if err := schedule.Install(bin, repo, filepath.Join(repo, "state"), jobs); err != nil {
				fatal(err)
			}
		case "uninstall":
			if err := schedule.Uninstall(modes); err != nil {
				fatal(err)
			}
		case "status":
			schedule.Status(modes)
		default:
			fs.Usage()
			os.Exit(2)
		}
	case "-h", "--help", "help":
		fs.Usage()
	default:
		fs.Usage()
		os.Exit(2)
	}
}

func scan(repo, mode string, notify bool) int {
	cfg, err := config.Load(filepath.Join(repo, "config", "local.json"))
	if err != nil {
		fatal(fmt.Errorf("config/local.json: %w", err))
	}
	resultsDir := filepath.Join(repo, "results")
	rep, err := report.New(resultsDir, mode, cfg.Allowlist)
	if err != nil {
		fatal(err)
	}
	env := &checks.Env{
		Report: rep, Config: cfg, RepoDir: repo, ResultsDir: resultsDir,
		StateDir: filepath.Join(repo, "state"), Root: os.Geteuid() == 0,
	}
	if !env.Root {
		fmt.Fprintln(os.Stderr, "note: not running as root; some checks will be partial")
	}

	list := checks.Quick()
	if mode == "full" {
		list = checks.Full()
	}
	checks.RunAll(env, list)

	if err := rep.Write(); err != nil {
		fatal(err)
	}
	c := rep.Counts()
	fmt.Printf("\n%d high, %d medium, %d low, %d info\nreport: %s\n",
		c[report.High], c[report.Medium], c[report.Low], c[report.Info],
		filepath.Join(rep.Dir, "summary.md"))

	if notify && c[report.High]+c[report.Medium] > 0 {
		msg := fmt.Sprintf("%d high, %d medium findings. See results/%s", c[report.High], c[report.Medium], filepath.Base(rep.Dir))
		runner.Run(10*time.Second, "/usr/bin/osascript", "-e",
			fmt.Sprintf("display notification %q with title %q", msg, "osxscan "+mode))
	}
	if c[report.High] > 0 {
		return 3
	}
	return 0
}

func sub(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// findRepo walks up from the working directory, then from the binary, looking for Brewfile + go.mod.
func findRepo() string {
	var starts []string
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			starts = append(starts, filepath.Dir(exe))
		}
	}
	for _, d := range starts {
		for {
			if exists(filepath.Join(d, "Brewfile")) && exists(filepath.Join(d, "go.mod")) {
				return d
			}
			parent := filepath.Dir(d)
			if parent == d {
				break
			}
			d = parent
		}
	}
	return ""
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "osxscan:", err)
	os.Exit(1)
}
