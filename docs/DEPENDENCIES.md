# Dependencies

| Component | Version | License | Use |
| --- | --- | --- | --- |
| .NET | 10.0 (SDK per `global.json`) | MIT | runtime, self-contained |
| Avalonia, Avalonia.Desktop, Avalonia.Themes.Fluent, Avalonia.Fonts.Inter | 11.3.14 | MIT | user interface |
| Avalonia.Controls.DataGrid | 11.3.13 | MIT | sortable, reorderable rule tables |
| Avalonia.Diagnostics | 11.3.14 | MIT | Debug builds only |
| SkiaSharp (transitive through Avalonia) | as shipped with Avalonia | MIT (+ Skia BSD-3-Clause) | rendering |
| CommunityToolkit.Mvvm | 8.4.0 | MIT | MVVM source generators |
| Material Design Icons (`@mdi/js`) | 7.4.47 | Apache-2.0 | icon paths (copied into Icons.axaml) |
| xUnit, xunit.runner.visualstudio, Microsoft.NET.Test.Sdk | 2.9.3 / 3.0.2 / 17.12.0 | Apache-2.0 / MIT | tests only |
| Inno Setup | 6.x | Inno Setup License | installer build only |

Central versions: `Directory.Packages.props`. PortShield.Core and PortShield.Platform.Windows use no NuGet packages.

## Windows components used at runtime (part of Windows, not shipped)

`HNetCfg.FwPolicy2` / `HNetCfg.FWRule` (Windows Firewall COM API), `netsh.exe advfirewall` (profile state and defaults, policy export/import, reset), `sc.exe` (firewall service state), `powershell.exe` (`Get-CimInstance root/SecurityCenter2 FirewallProduct`), `schtasks.exe` (tray at sign-in), `mmc.exe wf.msc`, registry via the .NET API (firewall policy, group policy, Explorer context menu), `netapi32.dll` `NetGetJoinInformation`, `kernel32.dll` `QueryFullProcessImageName`, `wintrust.dll` `WinVerifyTrust`, `shell32.dll` `ShellExecuteEx` (file properties), `dwmapi.dll` (title bar colours), `user32.dll` (`GetKeyboardLayoutList`, `GetSystemMetrics`).
