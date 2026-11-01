namespace PortShield.Core.Storage;

/// <summary>Why a snapshot was taken.</summary>
public enum SnapshotReason
{
    Manual,
    BeforeDelete,
    BeforeImport,
    BeforeRuleSet,
    BeforeWhitelist,
    BeforeReset,
    BeforeRestore,
    BeforePolicyImport,
    BeforeAdopt
}

/// <summary>
/// Metadata of one snapshot folder (snapshot.json). Each snapshot holds the complete firewall policy (policy.wfw, written
/// by netsh) and the PortShield rules as rule set (rules.json) – the latter can be restored without touching other rules.
/// </summary>
public sealed record SnapshotInfo
{
    public const string MetaFile = "snapshot.json";

    public const string PolicyFile = "policy.wfw";

    public const string RulesFile = "rules.json";

    public DateTime Created { get; init; }

    public SnapshotReason Reason { get; init; }

    public string? Note { get; init; }

    public int PortShieldRules { get; init; }

    public int TotalRules { get; init; }

    public string? Machine { get; init; }

    public string? AppVersion { get; init; }

    /// <summary>Folder of the snapshot (not stored in the file).</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string Directory { get; init; } = "";

    [System.Text.Json.Serialization.JsonIgnore]
    public bool HasPolicy => File.Exists(Path.Combine(Directory, PolicyFile));

    [System.Text.Json.Serialization.JsonIgnore]
    public bool HasRules => File.Exists(Path.Combine(Directory, RulesFile));

    /// <summary>Folder name: 20261031-142355-before-delete.</summary>
    public static string FolderName(DateTime created, SnapshotReason reason) =>
        created.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture) + "-" + Slug(reason);

    private static string Slug(SnapshotReason reason) => string.Concat(reason.ToString().Select((c, i) =>
        char.IsUpper(c) && i > 0 ? "-" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
}
