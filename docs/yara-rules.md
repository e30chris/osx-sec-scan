# YARA rules

`osxscan full` runs YARA only when `yara_rules` in `config/local.json` points
at a rule file. No rules are bundled. The most useful macOS rule sets come with
different licenses, and choosing one is your call.

| Source | macOS coverage | License | Open source? |
|---|---|---|---|
| [YARA-Forge](https://github.com/YARAHQ/yara-forge) packages (core/extended/full) | Mixed, aggregated from many repos | Per-rule; includes DRL 1.1, CC-BY-NC, GPL, MIT… | Mixed: check `yara-rules-*.yar` headers |
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | Some macOS | Detection Rule License 1.1 | Source-available, not OSI |
| [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) `yara/rules/MacOS_*` | Strong macOS coverage | Elastic License 2.0 | Source-available, not OSI |
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | Little macOS, unmaintained | GPL-2.0 | Yes |

Download into `state/` (gitignored), read what you downloaded, then point
the config at it:

```json
{ "yara_rules": "/Users/<you>/Codestuff/OSXstuff/osx-sec-scan/state/yara/rules.yar" }
```

A `.yarc` file (precompiled with `yarac`) is loaded with `-C` automatically.
