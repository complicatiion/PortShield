namespace PortShield.Core.Storage;

/// <summary>Data folders: %ProgramData%\PortShield (setup) or .\data next to the app (portable).</summary>
public static class AppPaths
{
    public const string PortableMarker = "PortShield.portable";

    public static string BaseDirectory => AppContext.BaseDirectory;

    public static bool IsPortable => File.Exists(Path.Combine(BaseDirectory, PortableMarker));

    public static string DataDirectory => IsPortable
        ? Path.Combine(BaseDirectory, "data")
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PortShield");

    /// <summary>Snapshots of the firewall (policy .wfw + PortShield rules as JSON) before bigger changes.</summary>
    public static string SnapshotsDirectory => Path.Combine(DataDirectory, "snapshots");

    /// <summary>The user's own rule sets.</summary>
    public static string RuleSetsDirectory => Path.Combine(DataDirectory, "rulesets");

    public static string LogsDirectory => Path.Combine(DataDirectory, "logs");

    /// <summary>Rule sets shipped with PortShield (read only).</summary>
    public static string PresetsDirectory => Path.Combine(BaseDirectory, "presets");

    /// <summary>Paths handed over by a second start (Explorer context menu) to the running instance.</summary>
    public static string PendingAddFile => Path.Combine(DataDirectory, "pending-add.txt");

    /// <summary>Last known state of PortShield's rules (integrity check: changes made outside PortShield).</summary>
    public static string BaselineFile => Path.Combine(DataDirectory, "baseline.json");

    /// <summary>Rules allowed for a limited time (blocked again when the time is up).</summary>
    public static string TemporaryFile => Path.Combine(DataDirectory, "temporary.json");

    /// <summary>Applied rule sets PortShield watches for new programs.</summary>
    public static string WatchFile => Path.Combine(DataDirectory, "watch.json");

    /// <summary>Marker: PortShield turned on the audit policy for blocked connections (a factory reset turns it off again).</summary>
    public static string AuditMarkerFile => Path.Combine(DataDirectory, "recording.flag");

    /// <summary>Per-user interface settings.</summary>
    public static string SettingsFile => IsPortable
        ? Path.Combine(DataDirectory, "settings.json")
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PortShield", "settings.json");
}
