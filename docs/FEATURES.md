# Features – PortShield 0.0.4

## Rules

| Feature | Details |
| --- | --- |
| Outbound / inbound lists | PortShield rules; switch *Also other program rules* shows Windows and third-party program rules too |
| Columns | action, name (+ origin), program (+ folder, *missing* badge), addresses, profiles, enabled, publisher – sortable, resizable, movable |
| Filters | search (name, path, publisher), all / blocked / allowed / disabled / program missing |
| Multi-selection | Shift/Ctrl, Ctrl+A, invert (Ctrl+I); right click selects the row |
| Allow temporarily | blocked PortShield rules for 15 / 30 / 60 / 120 min, badge “allowed until …”, block again now; restored by the app, at start and by a one-shot SYSTEM task (also at boot) |
| Actions | block, allow, enable, disable, delete (confirmation, snapshot), rename (F2), addresses all / internet only, profiles all / public / private+domain, copy path, open location, file properties, run program, export selection |
| Add | files (multi), folder (recursive, without installers), running programs, Explorer context menu, tray (no drag & drop: Windows blocks it from Explorer into elevated apps) |
| Review dialog | direction out / in / both, block / allow, all addresses / internet only, profiles, enabled; status per program; summary; nothing written before *Create rules* |
| Duplicates | existing PortShield rule for the same program and direction is updated instead of duplicated |
| Protection | core Windows processes, PortShield, own list – never blocked |

## Firewall

| Feature | Details |
| --- | --- |
| Overview | protection state, active network profile, profiles with defaults, group policy badges |
| Notices | no admin rights, service stopped, local rules ignored by GPO, profile off, third-party firewall, GPO-managed, rules changed outside PortShield, temporarily allowed rules, watched rule sets with new programs |
| Integrity check | record of PortShield's rules after every own change (`baseline.json`); missing / changed rules (name, program, service, direction, action, state, profiles, addresses) → restore (same id, snapshot) or accept |
| Kill switch | block rules without program (out + in), internet only or complete; sidebar, overview, tray, CLI |
| Whitelist mode | outbound default *Block* on all profiles (snapshot first) |
| Profiles | turn the firewall of a profile on/off (confirmation) |
| Reset | `netsh advfirewall reset` (snapshot first) |
| wf.msc | opens *Windows Defender Firewall with Advanced Security* |

## Scan

| Feature | Details |
| --- | --- |
| Origins | PortShield · other tools (Firewall App Blocker, wf.msc, installers) · Windows · group policy (registry, read only) |
| Findings | program missing, duplicates (same program, service, direction, action), conflicts (allow and block), disabled |
| Adopt | marker `[ps:id]` in the description, optionally rename to the PortShield scheme; snapshot first; Windows and GPO rules excluded |
| Merge duplicates | one rule per program, direction and action stays (PortShield's preferred); snapshot first |
| Further actions | enable, disable, delete, export (CSV, JSON, HTML, PowerShell) |

## Connections

| Feature | Details |
| --- | --- |
| Source | Security log, event 5157 (Windows Filtering Platform blocked a connection), via `wevtutil`; device paths mapped to drive letters |
| Recording | audit policy *Filtering Platform Connection – Failure* on/off (audit API with subcategory GUID `{0CCE9226-69AE-11D9-BED3-505054503030}`); state pill; success auditing stays as it is |
| List | grouped by program, direction, remote address, remote port, protocol – count, first/last seen; newest 5,000 events |
| Filters | 1 h / 24 h / 7 days, out / in / both, internet only (hides LAN, loopback, link-local, multicast/broadcast), search |
| Actions | block or allow program (review), copy address, open location |

## Service rules

Rules for one Windows service inside `svchost.exe` (e.g. `DiagTrack`) – in rule sets, imports and all exports. svchost.exe without a service stays protected.

## Rules (rule sets)

Presets (Adobe, TechSmith Snagit, Maxon Cinema 4D, Windows telemetry with service rules) and own sets in `%ProgramData%\PortShield\rulesets`; `%Variables%`, `*` and `**` (any sub folder depth) wildcards; editor for own sets (programs, folders, patterns, services, direction out/in/both, action, scope, *check paths*), copy of presets; *programs on this PC* counter; apply with review and snapshot; save current rules, import, export, delete (presets are hidden, a reset shows them again); **watch** applied sets for new programs (ignore list per set).

## Import & export

See [EXPORT-FORMATS.md](EXPORT-FORMATS.md). Sources: PortShield rules (all / outbound / inbound) or all program rules. Options: portable paths, SHA-256, CSV delimiter. Clipboard or file. Complete policy as `.wfw`. Transfer of all own rule sets (optionally plus the current rules) as one `portshield.rulesets` bundle for another PC.

## Snapshots

Automatic before delete, import, rule set, whitelist, reset, restore, policy import (configurable, retention); manual with note; restore PortShield rules only or complete policy; open, delete.

## Command line

```text
PortShield.exe --status
PortShield.exe --list [--all] [--json]
PortShield.exe --block "C:\Program Files\App\app.exe" [--inbound|--both] [--internet] [--profiles public]
PortShield.exe --allow <program> …   |   --unblock <program> …
PortShield.exe --apply ruleset.json [--confirm]
PortShield.exe --import list.csv [--confirm]
PortShield.exe --export rules.ps1 [--format ps1] [--all] [--literal-paths] [--hashes]
PortShield.exe --snapshot [--note "before update"]
PortShield.exe --kill-switch on|off [--full]
PortShield.exe --remove-all --confirm
PortShield.exe --restore-temporary [--all]
PortShield.exe --register-shell | --unregister-shell
```

Exit codes: 0 success, 1 errors or nothing done, 2 invalid arguments.

## Reset

*Settings › Data*: **Reset PortShield** – settings and hidden presets, restart. **Factory reset** – PortShield rules, kill switch, whitelist mode, own rule sets, watch list, integrity record, temporary rules, settings, autostart, Explorer context menu (setup: on, portable: off); snapshots optionally; snapshot first; restart. Rules of Windows, other programs and group policy stay.

## Interface

Avalonia, dark (default) / light / system, palette Royal Blue · Bay of Many · Shark, collapsible sidebar, icons on every button, toasts, system tray (kill switch, add, pages, language), English and German (first start: German if Windows uses German), Windows 10/11 and Windows Server 2016–2025.
