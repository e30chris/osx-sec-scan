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
| full | clamav | ClamAV | Known-malware signatures across user-writable areas |
| full | yara | YARA | Malware-family rules (bring your own, see [docs/yara-rules.md](docs/yara-rules.md)) |

Always-on protection between scans: LuLu, BlockBlock, ReiKey, OverSight (see `Brewfile`).

## Setup

```bash
brew bundle --file Brewfile
```

Install ClamAV from the official Cisco-Talos package, not Homebrew. See [docs/clamav.md](docs/clamav.md).

```bash
go build -o bin/osxscan ./cmd/osxscan
```

Then open LuLu, BlockBlock Helper, ReiKey and OverSight once each and approve
their system extensions and permissions.

Optional: `cp config/local.example.json config/local.json` and edit. That file
is gitignored. Use it for allowlists of findings you've reviewed.

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
before running it. Items it can't script (FileVault, SIP, screen lock
password) are listed as manual steps at the end.

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

Exit codes: `0` no high findings, `3` high findings, `1` tool error.

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

`schedule status` / `schedule uninstall` manage them. BlockBlock will alert
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
