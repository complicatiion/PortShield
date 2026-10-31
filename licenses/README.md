# Licenses

## PortShield

PortShield is released under the **MIT License** – see [LICENSE.md](LICENSE.md).
Copyright © 2026 Sven Klocke (*sksdesign | complicatiion*).

| Document | Content |
| --- | --- |
| [LICENSE.md](LICENSE.md) | MIT License of PortShield |
| [COPYRIGHT.md](COPYRIGHT.md) | Copyright and trademark notes |
| [LEGAL-NOTICE.md](LEGAL-NOTICE.md) | Disclaimer, limitation of liability, notes on firewall changes |
| [PRIVACY.md](PRIVACY.md) | Privacy notes (local-first, no telemetry) |

## Third-party components

Components shipped with PortShield keep their own copyrights and licenses. Full license texts are in [third-party/](third-party/).

| Component | Version | License | Shipped as | File |
| --- | --- | --- | --- | --- |
| .NET Runtime | 10.0 | MIT | self-contained runtime | [third-party/DOTNET.md](third-party/DOTNET.md) |
| Avalonia UI (incl. Fluent theme, Inter font package) | 11.3.14 | MIT | library | [third-party/AVALONIA.md](third-party/AVALONIA.md) |
| Avalonia.Controls.DataGrid | 11.3.13 | MIT | library | [third-party/AVALONIA-DATAGRID.md](third-party/AVALONIA-DATAGRID.md) |
| SkiaSharp / HarfBuzzSharp (via Avalonia) | – | MIT (+ Skia BSD-3-Clause, HarfBuzz MIT-style) | native libraries | [third-party/SKIASHARP.md](third-party/SKIASHARP.md) |
| CommunityToolkit.Mvvm | 8.4.0 | MIT | library | [third-party/COMMUNITYTOOLKIT-MVVM.md](third-party/COMMUNITYTOOLKIT-MVVM.md) |
| Material Design Icons (Pictogrammers) | 7.4.47 | Apache-2.0 | vector icons in the UI | [third-party/MATERIAL-DESIGN-ICONS.md](third-party/MATERIAL-DESIGN-ICONS.md) |
| Inter (font) | 4.x | SIL OFL 1.1 | embedded font | [third-party/INTER-FONT.md](third-party/INTER-FONT.md) |

Shared license texts: [Apache License 2.0](third-party/LICENSE-APACHE-2.0.md) · [SIL Open Font License 1.1](third-party/LICENSE-OFL-1.1.md) · [MIT](third-party/LICENSE-MIT.md) · [BSD 3-Clause](third-party/LICENSE-BSD-3-CLAUSE.md)

Build-time only (not shipped): xUnit (Apache-2.0), Microsoft.NET.Test.Sdk (MIT), Inno Setup (own license, installer only).

**Used, not shipped:** the Windows Firewall (Windows Defender Firewall with Advanced Security), its COM interface `HNetCfg.FwPolicy2` and `netsh.exe` are part of Windows. The PortShield logo and the small glyphs `IconWall`, `IconArrowOut`, `IconArrowIn`, `IconLan`, `IconBothWays` are PortShield's own work (MIT).
