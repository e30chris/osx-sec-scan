// Package runner executes external tools with timeouts and captures their output.
package runner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Brew prefixes searched before $PATH so scheduled jobs (minimal PATH) still find tools.
var searchDirs = []string{
	"/opt/homebrew/bin",
	"/opt/homebrew/sbin",
	"/usr/local/bin",
	"/usr/local/sbin",
}

// Result is the outcome of a single command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error // non-nil only when the command could not run or timed out
}

// Combined returns stdout followed by stderr.
func (r Result) Combined() string {
	return string(r.Stdout) + string(r.Stderr)
}

// Find resolves a tool name to an absolute path, or "" if not installed.
func Find(name string) string {
	if filepath.IsAbs(name) {
		if _, err := os.Stat(name); err == nil {
			return name
		}
		return ""
	}
	for _, d := range searchDirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// base is the parent of every Run; cancelling it (Ctrl-C) kills the running tool.
var base = context.Background()

// SetContext makes every later Run stop when ctx is cancelled.
func SetContext(ctx context.Context) { base = ctx }

// Interrupted reports whether the run was cancelled (e.g. by Ctrl-C).
func Interrupted() bool { return base.Err() != nil }

// Run executes name with args, killing it after timeout or on interrupt.
func Run(timeout time.Duration, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(base, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	res := Result{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	default:
		res.Err = err
		res.ExitCode = -1
	}
	if ctx.Err() != nil {
		res.Err = ctx.Err()
	}
	return res
}

// Interactive runs a command attached to the current terminal.
func Interactive(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
