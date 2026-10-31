using System.Text.Json.Serialization;
using PortShield.Core.Models;
using PortShield.Core.Storage;

namespace PortShield.App.Services;

/// <summary>Per-user settings (%AppData%\PortShield\settings.json, portable: data\settings.json). Saved on every change.</summary>
public sealed class UiSettings
{
    public string? Language { get; set; }

    /// <summary>dark (default), light or system.</summary>
    public string Theme { get; set; } = "dark";

    public bool SidebarCollapsed { get; set; }

    /// <summary>Window state when PortShield was closed (first start: normal window).</summary>
    public bool WindowMaximized { get; set; }

    /// <summary>Last normal window size; 0 = first start (about 80 % of the screen's work area, centered).</summary>
    public double WindowWidth { get; set; }

    public double WindowHeight { get; set; }

    /// <summary>Settings format version (one-time adjustments of old defaults, see <see cref="Load"/>).</summary>
    public int SettingsVersion { get; set; }

    private const int CurrentVersion = 2;

    /// <summary>Closing the window keeps PortShield in the tray.</summary>
    public bool CloseToTray { get; set; }

    public bool NotificationsEnabled { get; set; } = true;

    public double ToastSeconds { get; set; } = 4;

    public double ErrorToastSeconds { get; set; } = 8;

    // ------------------------------------------------------------------ New rules

    public DirectionChoice DefaultDirection { get; set; } = DirectionChoice.Outbound;

    public RuleAction DefaultAction { get; set; } = RuleAction.Block;

    public RuleScope DefaultScope { get; set; } = RuleScope.All;

    public FirewallProfiles DefaultProfiles { get; set; } = FirewallProfiles.All;

    /// <summary>First part of the rule names ("PortShield · Snagit · Out").</summary>
    public string NamePrefix { get; set; } = "PortShield";

    /// <summary>Folder scan: include sub folders.</summary>
    public bool ScanRecursive { get; set; } = true;

    /// <summary>Folder scan: leave out installers, uninstallers and runtime setups.</summary>
    public bool ScanSkipInstallers { get; set; } = true;

    /// <summary>Rule pages: also list program rules of Windows and other apps (default: only PortShield's rules).</summary>
    public bool ShowAllRules { get; set; }

    /// <summary>Programs PortShield never blocks (in addition to core Windows processes).</summary>
    public List<string> ProtectedPaths { get; set; } = [];

    /// <summary>Scan: rename adopted rules to the PortShield scheme ("PortShield · Program · Out").</summary>
    public bool ScanRenameOnAdopt { get; set; }

    // ------------------------------------------------------------------ Safety

    /// <summary>Snapshot (policy + PortShield rules) before deleting, importing, rule sets, whitelist mode and reset.</summary>
    public bool SnapshotBeforeChanges { get; set; } = true;

    /// <summary>Automatic snapshots kept (manual ones are never removed).</summary>
    public int SnapshotKeep { get; set; } = 30;

    /// <summary>Kill switch blocks internet only – LAN, printers and remote desktop from the LAN keep working.</summary>
    public bool KillSwitchLanAllowed { get; set; } = true;

    // ------------------------------------------------------------------ Export

    public bool ExportPortablePaths { get; set; } = true;

    /// <summary>";" (Excel in German), "," or "\t".</summary>
    public string CsvDelimiter { get; set; } = ";";

    public bool ExportIncludeHashes { get; set; }

    // ------------------------------------------------------------------ Rule sets

    /// <summary>File names of shipped presets the user removed (an update brings them back otherwise).</summary>
    public List<string> HiddenPresets { get; set; } = [];

    /// <summary>After a reset nothing is written any more until the restart (the window would save its size again).</summary>
    [JsonIgnore]
    public bool Frozen { get; set; }

    /// <summary>Deletes the settings file and stops saving (reset, then restart).</summary>
    public void DeleteAndFreeze()
    {
        Frozen = true;
        try
        {
            File.Delete(AppPaths.SettingsFile);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    public static UiSettings Load()
    {
        try
        {
            var settings = JsonFile.Read<UiSettings>(AppPaths.SettingsFile) ?? new UiSettings { SettingsVersion = CurrentVersion };
            if (settings.SettingsVersion < 2)
            {
                // v0.0.2: start in a normal window instead of maximized.
                settings.WindowMaximized = false;
                settings.WindowWidth = 0;
                settings.WindowHeight = 0;
                settings.SettingsVersion = CurrentVersion;
            }

            return settings;
        }
        catch
        {
            return new UiSettings();
        }
    }

    public void Save()
    {
        if (Frozen)
        {
            return;
        }

        try
        {
            JsonFile.Write(AppPaths.SettingsFile, this);
        }
        catch
        {
            // Not critical.
        }
    }
}
