# Export and import formats

All machine formats are written in English and UTF-8 (CSV and PowerShell with BOM for Excel and Windows PowerShell 5.1). *Portable paths* replace known folders with variables (`%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%`, `%LOCALAPPDATA%`, `%APPDATA%`, `%USERPROFILE%`, `%SystemRoot%`).

| Format | Extension | Import | Content |
| --- | --- | --- | --- |
| PortShield rule set | `.json` | yes | `format`, `version`, `name`, `description`, `author`, `created`, `generator`, `rules[]` with `name`, `program`, `service`, `direction`, `action`, `scope`, `remoteAddresses`, `profiles`, `enabled`, `description`, `sha256`, `publisher` |
| PortShield rule set bundle | `.json` | yes | `format: "portshield.rulesets"`, `version`, `created`, `generator`, `machine`, `sets[]` – complete rule sets as above; transfers all own sets to another PC |
| CSV | `.csv` | yes | `Name;Program;Service;Direction;Action;Scope;RemoteAddresses;Profiles;Enabled;Publisher;SHA256;FileExists` – values starting with `= + - @` get a leading `'` (Excel formula injection) |
| Path list | `.txt` | yes | one path per line, distinct |
| SHA-256 list | `.txt` | – (hashes cannot become rules) | one lower-case hash per line, only existing files |
| PowerShell | `.ps1` | – | `New-NetFirewallRule` / `Set-NetFirewallRule`, group `PortShield`; `-PolicyStore 'domain\GPO'`, `-Remove` |
| netsh | `.cmd` | – | `netsh advfirewall firewall delete/add rule …`, admin check |
| Markdown | `.md` | – | summary and table |
| HTML | `.html` | – | standalone report, dark/light via `prefers-color-scheme` |
| XML | `.xml` | – | `<PortShieldRules><Rule name direction action scope profiles enabled><Program/>…</Rule></PortShieldRules>` |
| Windows Firewall policy | `.wfw` | yes (replaces everything) | `netsh advfirewall export/import` |

## Rule set example

```json
{
  "format": "portshield.ruleset",
  "version": 1,
  "name": "TechSmith Snagit – offline",
  "rules": [
    { "program": "%ProgramFiles%\\TechSmith\\Snagit *\\*.exe", "direction": "Outbound", "action": "Block" },
    { "program": "%SystemRoot%\\System32\\CompatTelRunner.exe", "direction": "Outbound", "action": "Block", "scope": "Internet" }
  ]
}
```

`service` limits a rule to one Windows service inside svchost.exe (e.g. `"service": "DiagTrack"`). Defaults when a field is missing: `direction` Outbound, `action` Block, `scope` All, `profiles` All, `enabled` true. `*` and `?` work in every path segment, `**` as a whole segment matches any sub folder depth (including none, e.g. `%ProgramFiles%\Vendor\**\*.exe`); only existing files become rules.

## CSV import

The header decides the columns (case-insensitive, spaces ignored): program `Program`, `Path`, `Application`, `Dateipfad`, `Pfad`, `Programm`, `Anwendung` · name `Name`, `DisplayName`, `Regel` · direction `Direction`, `Richtung` (`Out`, `Outbound`, `Ausgehend`, `In`, `Inbound`, `Eingehend`) · action `Action`, `Aktion`, `Status` (`Block`, `Blockieren`, `Deny`, `Allow`, `Zulassen`) · `Scope` (`All`, `Internet`, `Custom`) · `RemoteAddresses` · `Profiles` (`All`, `Domain|Private|Public`, `Domäne`, `Privat`, `Öffentlich`) · `Enabled`, `Aktiviert` (`true`, `ja`, `1`). Delimiter `;`, `,`, tab or `|` is detected. Without a header the first column holding a path is used.

## Text import

One path per line; `#`, `;`, `//` and `rem` start comments; `sha256sum` lines (`<hash>  <path>`) are read as paths; quotes are removed. Direction, action and scope are chosen in the review dialog.

## Other security products

Most antivirus suites have no import for Windows Firewall rules. Use the path list or the SHA-256 list for block lists / application control (e.g. Bitdefender GravityZone, ESET, Microsoft Defender indicators), the PowerShell script for group policy or Intune scripts, and CSV/XML as a neutral source. Check the product documentation for the exact import format.
