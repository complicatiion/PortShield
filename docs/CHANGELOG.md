# Changelog

All changes to PortShield in one file, newest version first.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [0.0.4] – 2026-10-31

### Added

- **Connections** (new page under *Firewall*, also in the tray): blocked connections from the Security log (event 5157) – program, direction, remote address and port, protocol, count, last seen; time range (1 h / 24 h / 7 days), direction, *internet only*, search; *Block program* / *Allow program* with review, copy address, open location. *Start recording* turns on the audit policy “Filtering Platform Connection – Failure” (via GUID, works in every Windows language).
- **Allow temporarily**: blocked PortShield rules for 15 / 30 / 60 / 120 minutes (command bar *Temporarily* and context menu); PortShield blocks them again on time. Safety net when PortShield is not running: one-shot task `\PortShield\Restore temporary rules` (SYSTEM, also at boot) runs `PortShield.exe --restore-temporary`. Overview notice with *Block again now*; badge “allowed until …” in the list.
- **Integrity check**: after every own change PortShield records its rules (`baseline.json`); rules deleted or changed outside PortShield (Windows update, installer, other tool, group policy, wf.msc) are reported on the overview – *Restore* (same id, snapshot first) or *Accept*. Changes made by PortShield never hide other changes.
- **Watched rule sets**: applied sets are watched (eye button on the card, *Watched* pill); at start, on refresh and every 30 minutes the overview reports new programs without a rule (e.g. a new version folder) – *Apply* (review with the missing programs only) or *Ignore*.
- **Remove presets**: trash button on every rule set card (left of *Show file*); presets are hidden (an update does not bring them back), own sets deleted.
- **Settings › Data**: *Reset PortShield* (settings, hidden presets) and *Factory reset* (PortShield rules, kill switch, whitelist mode, own rule sets, watch list, temporary rules, settings, autostart, Explorer context menu as after installation; snapshots optionally) – PortShield restarts.
- Command line: `--restore-temporary [--all]`; changes from the command line are recorded for the integrity check.

### Changed

- Overview: *Activate kill switch* as wide as *Turn on whitelist mode*, *Scan* as wide as *Refresh*; button *Windows Firewall* renamed to *Open Windows Firewall*.
- Scan: start text without “and lets PortShield adopt them”.
- Snapshots: info text removed.

## [0.0.3] – 2026-10-31

### Added

- **Rule set editor** (*Rules › New rule set*, *Edit* on own sets, *Copy* on every set): name, description and any number of lines – program, folder or pattern, optional service, direction (out / in / both), action, scope. *Add folder* writes `Folder\**\*.exe` (with sub folders) or `Folder\*.exe`; *Check paths* counts the programs every line finds on this PC. Paths are stored portable (`%ProgramFiles%` …).
- **`**`** in patterns: any sub folder depth (`%ProgramFiles%\Vendor\**\*.exe`).
- **Transfer rule sets** (card in *Import & export*, also on the *Rules* page): all own sets – optionally plus the current PortShield rules as their own set – in one file (`portshield.rulesets`); importing it on another PC restores them without reconfiguring. Single rule sets are still accepted.

### Changed

- Sidebar: *Snapshots* above *Import & export* (also in the tray).
- Overview and scan: the counter labels take the colour of their number.
- Kill switch card: state as a pill on the right of the header – *Off* green, *Active* red.
- Quick actions centered.
- “Note:” in front of the whitelist hint, the trademark notice and the hint for other security products.
- About: license permissions without “Commercial use”.

### Fixed

- Snapshots: the reason was not level with date and content when a snapshot had no note.
- Select all (Add rules): single check mark instead of a double one.

## [0.0.2] – 2026-10-31

### Added

- **Scan** (new page under *Manage*, also in the tray): sorts all program rules by origin – PortShield, other tools (e.g. Firewall App Blocker, wf.msc, installers), Windows, group policy – and finds missing programs, duplicates, allow/block conflicts and disabled rules. Counters work as filters.
- **Adopt** rules of other tools: only the PortShield marker is added to the description (optionally renamed to “PortShield · Program · Out”); group, program and action stay; snapshot first. Windows and group policy rules are never adopted; group policy rules are read from the registry (read only).
- **Merge duplicates**: one rule per program, direction and action stays (a PortShield rule is preferred).
- Overview notice when program rules of other tools exist, with a *Scan* button.
- **Service rules**: rules for a single Windows service inside `svchost.exe` (`"service": "DiagTrack"` in rule sets, *Service* column in CSV, `-Service` in PowerShell, `service=` in netsh). svchost itself stays protected.
- Presets: **Maxon Cinema 4D – offline** (all versions under `Program Files\Maxon Cinema 4D *`, `…\Maxon\Cinema 4D *`, `…\Maxon\Maxon Cinema 4D *`, `…\Cinema 4D *`), **Windows – telemetry** now with the services *DiagTrack* and *dmwappushservice*.
- Command line: rule sets and imports understand services.

### Changed

- Sidebar: group **FIREWALL** (Outbound, Inbound, **Rules** – formerly *Rule sets*), group *Manage* with Scan, Import & export, Snapshots.
- First start in a **normal window** (about 80 % of the screen, centered) instead of maximized; settings of 0.0.1 are migrated once.
- Overview: the logo takes the **status colour** (green active, orange warning, red alert); counters coloured – PortShield rules accent blue, blocked red, allowed green, internet only orange.
- Kill switch in the sidebar in accent colour, completely red while active.
- Rules page: cards in a grid – three side by side in a normal window, more when maximized, fewer only on very small displays.
- Snapshots: *Restore complete policy* button in accent colour.
- Quick actions: *Rules*, *Reset*, *Running*.
- Texts: info texts on export, import, policy, rule sets, kill switch, quick actions and the empty rule list removed; “Note:” in front of the snapshot, profile and running-program hints.
- Overlapping wildcard patterns of a rule set find each program only once.

## [0.0.1] – 2026-10-31

First version.

### Fixed (build)

- Styles.axaml: badge styles split per control type (AVLN2000 – a combined selector `TextBlock, PathIcon` has no common `Foreground`).

### Added

- **Rule lists** *Outbound* and *Inbound*: all PortShield rules (optionally also the program rules of Windows and other apps) with action, name, program, address scope, profiles, state and publisher; search, filters (blocked, allowed, disabled, program missing), sortable and movable columns, multi-selection.
- **Command bar and context menu** (no classic menu bar): add application(s), folder, running program; block, allow, enable, disable, delete; addresses (all / internet only), profiles, rename, copy path, open file location, file properties, run program, select all, invert selection, export of the selection. Keyboard: Del, F2, F5, Ctrl+A, Ctrl+B, Ctrl+E, Ctrl+I.
- **Review dialog** before every change: direction (outbound, inbound, both), action, scope, profiles, state; per program *new*, *will be changed*, *already exists*, *protected*, *not found*, *duplicate*; warning when another rule blocks a program that should be allowed.
- **Internet only** scope: computed address ranges (everything except RFC 1918, loopback, link-local, multicast) – LAN devices stay reachable.
- **Folder scan** with sub folders and without installers/uninstallers; **running programs** with full image path.
- **Overview**: protection state, firewall profiles (on/off, defaults, active network, group policy), notices for missing administrator rights, stopped firewall service, *local rules ignored by group policy*, third-party firewalls (Security Center), turned-off profiles; rule counts; quick actions.
- **Kill switch** (sidebar, overview, tray): block rules without a program that beat every allow rule – internet only (default) or complete, with a warning in remote sessions.
- **Whitelist mode**: default outbound action *Block* on all profiles (inbound defaults are kept).
- **Rule sets**: presets (Adobe, TechSmith Snagit, Windows telemetry helpers) and own sets; portable paths with `%Variables%` and `*` wildcards; *Save current rules as rule set*, import, export, apply with review.
- **Import & export**: PortShield JSON, CSV (`;` `,` tab, Excel-safe), path list, SHA-256 hash list, PowerShell (idempotent, `-PolicyStore` for GPOs, `-Remove`), netsh batch, HTML and Markdown report, XML; import of JSON, CSV (also German headers) and TXT lists; complete policy as `.wfw` (export/import).
- **Snapshots** before deleting, imports, rule sets, whitelist mode, reset and restore: complete policy (`policy.wfw`) plus PortShield rules (`rules.json`); restore only PortShield's rules or the complete policy; retention setting.
- **Group policy and domain detection** (registry, `NetGetJoinInformation`), Windows Server support.
- **Explorer context menu** “Block with PortShield” for .exe files and folders (settings, installer task); a running instance takes the paths over.
- **Command line** (`--status`, `--list`, `--block`, `--allow`, `--unblock`, `--apply`, `--import`, `--export`, `--snapshot`, `--kill-switch`, `--remove-all`, `--register-shell`).
- **Protected programs**: core Windows processes, PortShield itself and an own list are never blocked.
- **Interface**: Avalonia, dark (default) and light theme in the PortShield palette, collapsible sidebar, icons on every button, English and German (automatic on the first start), system tray, toasts.
- Installer (Inno Setup), portable ZIP, GitHub Actions workflow, MIT license.
