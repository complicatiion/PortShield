# Privacy

PortShield is **local-first**:

- **No telemetry, no account, no cloud.** PortShield sends no usage data anywhere and has no online features.
- **No network connections by PortShield.** It only reads and changes the Windows Firewall of this computer. Links (project page, license pages, sksdesign.de) open in your browser only when you click them.
- **No external resources in the app.** Fonts and icons are embedded.

## Data read on this computer

- Firewall rules, profiles and group policy settings of the Windows Firewall (registry, COM interface, netsh).
- Version information, signature and – only for exports that ask for it – the SHA-256 hash of the programs in the rules.
- The list of running processes (only when you open *Running program*).
- Firewall products registered in the Windows Security Center (client editions).
- Display language, region and keyboard layouts for the first-start language.

Nothing of this is stored or sent, except as described below.

## Data stored by PortShield

| Location | Content |
| --- | --- |
| `%AppData%\PortShield\settings.json` (portable: `data\settings.json`) | interface settings per user (language, theme, window size, defaults for new rules, protected programs, export options) |
| `%ProgramData%\PortShield\snapshots\` (portable: `data\snapshots`) | snapshots: the complete firewall policy (`policy.wfw`, contains all rules of this PC incl. program paths with user names) and PortShield's rules (`rules.json`) |
| `%ProgramData%\PortShield\rulesets\` | your own rule sets (program paths, preferably with variables) |
| `%ProgramData%\PortShield\baseline.json` | integrity check: PortShield's rules as PortShield last wrote them (names, program paths, settings) |
| `%ProgramData%\PortShield\temporary.json`, `watch.json` | temporarily allowed rules (until when) and watched rule sets (file names, ignored programs) |
| `%ProgramData%\PortShield\pending-add.txt` | short-lived hand-over of paths from the Explorer context menu to the running app (deleted when read) |
| Windows Firewall | the rules you create (group "PortShield", marker `[ps:…]` in the description) |
| Task Scheduler `\PortShield\Tray <user>` | only if you enable *Start in the system tray at sign-in* |
| Task Scheduler `\PortShield\Restore temporary rules` | only while rules are allowed temporarily (blocks them again, runs as SYSTEM) |
| Windows Security log (event 5157) | only if you start recording on *Connections*: Windows itself logs blocked connections (program, addresses, ports); PortShield only reads them. *Stop recording* turns the audit policy off again |
| `HKLM\SOFTWARE\Classes\exefile\shell\PortShield.Block`, `…\Directory\shell\PortShield.Block` | only if you enable the Explorer context menu |

Exports are written only where you save them. They may contain program paths with user names, machine names and hashes – check them before passing them on. Snapshots can be deleted at any time in *Snapshots*; uninstalling PortShield offers to remove its rules and all of its data.
