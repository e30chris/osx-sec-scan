# ClamAV

Homebrew's `clamav` 1.5.4 links OpenSSL 4.1, and with that combination freshclam
cannot install signature databases ("NULL X509 store" / "Incorrect digital
signature", [Cisco-Talos/clamav#1873](https://github.com/Cisco-Talos/clamav/pull/1873)).
Until that is fixed, use the official Cisco-Talos macOS installer. It
statically links its own dependencies and installs to `/usr/local/clamav`.
`osxscan` prefers `/usr/local/clamav/bin` over Homebrew when both exist.

## Install

Download into an empty directory outside the repo:

```bash
mkdir -p ~/Downloads/clamav-pkg && cd ~/Downloads/clamav-pkg
```

```bash
gh release download clamav-1.5.4 -R Cisco-Talos/clamav -p 'clamav-1.5.4.macos.universal.pkg*'
```

Check the Apple signature. It should say "Developer ID Installer: Cisco (DE8Y96K9QP)" and "trusted by the Apple notary service":

```bash
pkgutil --check-signature clamav-1.5.4.macos.universal.pkg
```

Check the GPG signature against the Talos key published in ClamAV's documentation repo.
Use a throwaway keyring so your own isn't changed:

```bash
export GNUPGHOME=$(mktemp -d)
```

```bash
curl -fsSLO https://raw.githubusercontent.com/Cisco-Talos/clamav-documentation/main/src/manual/cisco-talos.gpg && gpg --import cisco-talos.gpg
```

```bash
gpg --verify clamav-1.5.4.macos.universal.pkg.sig clamav-1.5.4.macos.universal.pkg
```

Expect `Good signature from "Talos (Talos, Cisco Systems Inc.)"`, made with key
fingerprint `5BAD CA26 65EF 59DC F8A2 3D8B 707F 0DB4 8083 6771` (rotates every
couple of years). The `[unknown]` trust warning is normal.

Verified 2026-10-28: SHA-256 `df7fa753e2f9f67f3bc99b2a40a3be7ef559088c68ad6bdf66b4b5764e965bd6`.
The package has no pre/post-install scripts.

Install:

```bash
sudo installer -pkg clamav-1.5.4.macos.universal.pkg -target /
```

Optionally remove the broken Homebrew copy so there's only one ClamAV on PATH:

```bash
brew uninstall clamav
```

## Updating

The pkg does not auto-update. Watch
[ClamAV releases](https://github.com/Cisco-Talos/clamav/releases), repeat the
steps above for new versions, and switch back to Homebrew once
`brew info clamav` no longer depends on `openssl@4` or the fix ships.

## Uninstall

```bash
sudo rm -rf /usr/local/clamav && sudo pkgutil --forget com.cisco.ClamAV.programs && sudo pkgutil --forget com.cisco.ClamAV.libraries && sudo pkgutil --forget com.cisco.ClamAV.documentation
```
