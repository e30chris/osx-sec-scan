# osx-sec-scan

Open-source macOS security scanning suite. A single Go binary, `osxscan`, drives
open-source scanners, checks a hardening baseline, and tracks what changed
between runs. Results stay on the machine in `results/` (gitignored).

## What it checks

| Mode | Check | Tool | Looks for |
|---|---|---|---|
| quick | posture | built-in | Baseline settings (firewall, updates, sharing, Objective-See tools…) |
| quick | xprotect | built-in | Records Apple XProtect definition versions |
| quick | persistence | built-in + `codesign` | launchd jobs (signature, ownership, odd paths), login hooks, auth plugins, sudoers.d, profiles, shell rc files; **drift vs. previous run** |
| quick | osquery | osquery | **Keyboard event taps (keyloggers)**, kexts, system extensions, network listeners, cron, browser extensions |
| quick | knockknock | KnockKnock | Second opinion on persistence (VirusTotal disabled) |
| full | codesign | `codesign`/`spctl` | Every app bundle's signature and Gatekeeper verdict |
| full | lynis | Lynis | General host audit |
| full | clamav | ClamAV (clamd, all cores) | Known-malware signatures across user-writable areas |
| full | yara | YARA | Malware-family rules (bring your own, see [docs/yara-rules.md](docs/yara-rules.md)) |

Always-on protection between scans: LuLu, BlockBlock, ReiKey, OverSight (see `Brewfile`).

## Requirements

- macOS 26 on Apple Silicon (what it's built and tested on)
- [Homebrew](https://brew.sh) and Go 1.26+
- An admin account, for `sudo` scans and hardening

## Setup

```bash
git clone https://github.com/e30chris/osx-sec-scan.git && cd osx-sec-scan
```

```bash
brew bundle --file Brewfile
```

Install ClamAV from the official Cisco-Talos package, not Homebrew. See [docs/clamav.md](docs/clamav.md).

```bash
go build -o bin/osxscan ./cmd/osxscan
```

Then open LuLu, BlockBlock Helper, ReiKey and OverSight once each and approve
their system extensions and permissions.

By default, ClamAV and YARA skip cloud-only folders (Dropbox/iCloud: reading
them forces downloads), `~/Movies`, rebuildable caches and VM/container
disks (Docker, OrbStack, UTM, Claude). See `exclude_dirs` in
`internal/config/config.go`.

The default scope is every home folder. That's thorough but slow, since it
reads all your code and documents. To speed it up, set `scan_paths` in
`config/local.json` to where malware actually lands or persists: `~/Downloads`,
`~/Desktop`, `~/Library`, `~/.local`, `~/.config`, `/Users/Shared`,
`/Applications`, `/Library`, the temp folders, `/usr/local` and `/opt`. Use
full paths (`/Users/<you>/Downloads`): `~` isn't expanded.

### Local config

Optional: `cp config/local.example.json config/local.json` and edit. That file
is gitignored, so machine-specific paths and allowlists stay out of git.

| Field | Meaning |
|---|---|
| `scan_paths` | Folders ClamAV and YARA scan |
| `exclude_dirs` | Regexes of folders they skip |
| `yara_rules` | Rule file for YARA; empty skips YARA |
| `allowlist` | Finding keys you've reviewed (see Triage) |
| `keyboard_tap_allowlist` | Program paths allowed to watch the keyboard |

`scan_paths` and `exclude_dirs` **replace** the defaults; they aren't added to
them. When you override `exclude_dirs`, copy the full list from
`local.example.json` and add to it.

### Full Disk Access

macOS privacy protection (TCC) hides Mail, Messages, Safari data, other
apps' containers and so on, even from root. Without Full Disk Access (FDA),
ClamAV gets "permission denied" there and KnockKnock refuses to run.

- Manual runs: add your terminal app under System Settings > Privacy & Security > Full Disk Access.
- Scheduled runs: add `bin/osxscan` itself. FDA is tied to the binary's code hash, so **re-add it after every rebuild**.

## Usage

```bash
./bin/osxscan harden check
```

```bash
sudo ./bin/osxscan harden apply
```

`harden apply` shows the exact command for each failing item and asks `y/N`
before running it (`harden apply -y` skips the questions). Items it can't
script (FileVault, SIP, screen lock password) are listed as manual steps at
the end. `harden check` exits `1` if any item fails.

```bash
./bin/osxscan quick
```

```bash
sudo ./bin/osxscan full
```

Running as root gives full coverage (Background Task Management dump, other
processes' listeners, the full Lynis audit). Files under sudo are handed back
to you, so reports stay readable without root.

Every run writes `results/<timestamp>-<mode>/`:

- `summary.md`: start here
- `findings.json`: same data, machine-readable
- raw tool output (`clamscan.log`, `osquery-*.json`, `persistence.json`, `lynis-report.dat`, …)

A full scan takes about an hour with a narrowed `scan_paths` (around 60 GB),
nearly all of it ClamAV. Press **Ctrl-C** to stop early: the running tool and
clamd are stopped, the remaining checks are skipped, and a partial report is
still written. Press Ctrl-C again to quit immediately.

Flags go after the subcommand, e.g. `./bin/osxscan quick -notify`:

- `-repo DIR`: repo root, if you run the binary from somewhere else
- `-notify`: show a macOS notification when there are medium or high findings

Exit codes: `0` no high findings, `3` high findings, `1` tool error, `130`
interrupted.

### Scheduling

```bash
./bin/osxscan schedule install
```

This installs two **per-user** LaunchAgents: a daily quick scan at 10:00 and a
weekly full scan on Sunday at 12:00. If the Mac is asleep, a missed run happens
on wake. Each sends a macOS notification when there are medium or high findings.

They deliberately run as you, not root. A root job that runs `bin/osxscan` and
Homebrew tools from user-writable paths would let anything running as you
replace those files and get root. For root-level coverage, run
`sudo ./bin/osxscan full` yourself now and then.

`schedule status` / `schedule uninstall` manage them. Each job's output goes
to `state/launchd-quick.log` or `state/launchd-full.log`. BlockBlock will alert
when you install them. That's expected, and a good test that it works.

## Triage

- **Allowlist** a reviewed finding by adding its `Allowlist key` (shown in
  `summary.md`) to `allowlist` in `config/local.json`. For launchd jobs, the key
  includes the severity, so a job you allowlisted still alerts if it later
  becomes unsigned.
- Keyboard taps you recognize (Raycast, Karabiner, BetterTouchTool, …) go in
  `keyboard_tap_allowlist` by path.
- **Drift** findings mean something new appeared or changed since the previous
  run. Review it, and it becomes part of the next baseline automatically.

## Limits

A scan from inside the running OS can lower the risk but cannot *prove* the
machine is clean: a kernel- or firmware-level implant can hide from everything
here. If anything high-severity can't be explained, the honest remedy is to
erase and reinstall macOS (see [docs/runbook.md](docs/runbook.md)).

## Docs

- [docs/runbook.md](docs/runbook.md): first clean-up, when to reinstall, lockdown, ongoing routine
- [docs/clamav.md](docs/clamav.md): installing and verifying the official ClamAV package
- [docs/yara-rules.md](docs/yara-rules.md): choosing a YARA rule set and its license

## License

Public domain ([The Unlicense](LICENSE)). The bundled tools keep their own
licenses, listed in the `Brewfile`.
