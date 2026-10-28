# Runbook

## 1. First clean-up pass

1. `brew bundle --file Brewfile`, install ClamAV per [clamav.md](clamav.md), and `go build -o bin/osxscan ./cmd/osxscan`
2. Give your terminal app Full Disk Access (README > Full Disk Access).
3. `sudo ./bin/osxscan full`. This takes 1–3 hours and keeps the Mac awake (`caffeinate -i sudo ./bin/osxscan full`).
4. Read `results/<latest>/summary.md` from the top. For each finding:
   - **Recognize it and want it** → add its key to the allowlist.
   - **Recognize it, don't need it** → uninstall the app properly, then remove leftovers.
   - **Don't recognize it** → don't delete it yet. Copy the path, the program and its signer, and investigate (vendor, team ID, when the file appeared).
5. Re-run `quick` until only allowlisted or understood items remain.

## 2. When to reinstall instead

Erase and reinstall macOS (Recovery > Erase Mac, then reinstall from Apple) if any of these:

- ClamAV/YARA detection in something that ran (not just a downloaded archive in ~/Downloads)
- An unsigned or ad-hoc-signed launchd job, keyboard tap or kext you can't attribute
- Configuration profiles, auth plugins, or sudoers entries you didn't install
- SIP or Gatekeeper was found disabled and you didn't do it

After a reinstall, restore **data only** (documents, not apps or `~/Library`),
reinstall apps from vendors, then start again at step 1.

## 3. Lock down

1. `./bin/osxscan harden check`
2. `sudo ./bin/osxscan harden apply`, then do the manual steps it prints.
3. Open LuLu, BlockBlock Helper, ReiKey, OverSight; approve extensions; enable each as a login item.
4. `./bin/osxscan schedule install`, then grant `bin/osxscan` Full Disk Access.

## 4. Ongoing

- Daily quick and weekly full scans notify you on medium/high findings.
- Monthly: `sudo ./bin/osxscan full` for root-level coverage.
- After `brew upgrade`: rebuild, re-grant FDA to `bin/osxscan`.
- Treat every BlockBlock/ReiKey/LuLu prompt you didn't expect as a finding.
