// Package config loads scanner settings. Defaults live in code; machine-specific
// overrides (allowlists, extra paths) go in config/local.json, which is gitignored.
package config

import (
	"encoding/json"
	"errors"
	"os"
)

type Config struct {
	// ScanPaths are scanned by ClamAV and YARA in full mode.
	ScanPaths []string `json:"scan_paths"`
	// ExcludeDirs are regexes passed to clamscan --exclude-dir.
	ExcludeDirs []string `json:"exclude_dirs"`
	// YaraRules is a compiled or source rule file. Empty skips YARA.
	YaraRules string `json:"yara_rules"`
	// Allowlist holds finding keys (paths, labels) you have reviewed and accept.
	Allowlist []string `json:"allowlist"`
	// KeyboardTapAllowlist holds processes allowed to tap keyboard events.
	KeyboardTapAllowlist []string `json:"keyboard_tap_allowlist"`
}

func Default() Config {
	return Config{
		ScanPaths: []string{
			"/Users",
			"/Applications",
			"/Library",
			"/private/tmp",
			"/private/var/tmp",
			"/usr/local",
			"/opt",
		},
		ExcludeDirs: []string{
			`^/Users/[^/]+/Library/Containers/com\.docker\.docker/Data`,
			`^/Users/[^/]+/\.Trash`,
			`/\.git/objects`,
			`/node_modules/\.cache`,
		},
	}
}

// Load returns defaults overlaid with any fields set in path. A missing file is fine.
func Load(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	var local Config
	if err := json.Unmarshal(data, &local); err != nil {
		return c, err
	}
	if len(local.ScanPaths) > 0 {
		c.ScanPaths = local.ScanPaths
	}
	if len(local.ExcludeDirs) > 0 {
		c.ExcludeDirs = local.ExcludeDirs
	}
	if local.YaraRules != "" {
		c.YaraRules = local.YaraRules
	}
	c.Allowlist = local.Allowlist
	c.KeyboardTapAllowlist = local.KeyboardTapAllowlist
	return c, nil
}
