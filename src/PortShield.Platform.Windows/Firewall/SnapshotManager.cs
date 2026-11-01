using PortShield.Core.Models;
using PortShield.Core.RuleSets;
using PortShield.Core.Storage;

namespace PortShield.Platform.Windows;

/// <summary>
/// Snapshots before bigger changes: the complete policy (policy.wfw via netsh) plus PortShield's own rules as rule set
/// (rules.json). Restoring the rule set touches only PortShield rules; restoring the policy replaces everything.
/// </summary>
public static class SnapshotManager
{
    public static string Root => AppPaths.SnapshotsDirectory;

    public static SnapshotInfo Create(SnapshotReason reason, IReadOnlyList<FirewallRuleInfo> rules, string appVersion, string? note = null)
    {
        var created = DateTime.Now;
        var folder = Path.Combine(Root, SnapshotInfo.FolderName(created, reason));
        var suffix = 1;
        while (Directory.Exists(folder))
        {
            folder = Path.Combine(Root, SnapshotInfo.FolderName(created, reason) + "-" + suffix++);
        }

        Directory.CreateDirectory(folder);
        var own = rules.Where(r => r.IsPortShield).ToList();
        var set = new RuleSet
        {
            Name = "Snapshot " + created.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture),
            Description = note,
            Created = created,
            Generator = "PortShield " + appVersion,
            Rules = own.Select(RuleDefinition.FromRule).ToList()
        };
        set.Save(Path.Combine(folder, SnapshotInfo.RulesFile));

        // The policy export is best effort: without it the PortShield rules can still be restored.
        Netsh.Export(Path.Combine(folder, SnapshotInfo.PolicyFile));

        var info = new SnapshotInfo
        {
            Created = created,
            Reason = reason,
            Note = note,
            PortShieldRules = own.Count,
            TotalRules = rules.Count,
            Machine = Environment.MachineName,
            AppVersion = appVersion,
            Directory = folder
        };
        JsonFile.Write(Path.Combine(folder, SnapshotInfo.MetaFile), info);
        return info;
    }

    public static IReadOnlyList<SnapshotInfo> List()
    {
        if (!Directory.Exists(Root))
        {
            return [];
        }

        var result = new List<SnapshotInfo>();
        foreach (var folder in Directory.EnumerateDirectories(Root))
        {
            try
            {
                var info = JsonFile.Read<SnapshotInfo>(Path.Combine(folder, SnapshotInfo.MetaFile));
                if (info is not null)
                {
                    result.Add(info with { Directory = folder });
                }
            }
            catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or UnauthorizedAccessException)
            {
                // Damaged snapshot: not listed.
            }
        }

        return result.OrderByDescending(s => s.Created).ToList();
    }

    public static RuleSet LoadRules(SnapshotInfo snapshot) => RuleSet.Load(Path.Combine(snapshot.Directory, SnapshotInfo.RulesFile));

    public static Core.Diagnostics.ProcessRunner.Result RestorePolicy(SnapshotInfo snapshot) =>
        Netsh.Import(Path.Combine(snapshot.Directory, SnapshotInfo.PolicyFile));

    public static void Delete(SnapshotInfo snapshot)
    {
        if (Directory.Exists(snapshot.Directory) && snapshot.Directory.StartsWith(Root, StringComparison.OrdinalIgnoreCase))
        {
            Directory.Delete(snapshot.Directory, recursive: true);
        }
    }

    /// <summary>Keeps the newest <paramref name="keep"/> snapshots (manual snapshots are never pruned).</summary>
    public static int Prune(int keep)
    {
        var removed = 0;
        foreach (var old in List().Where(s => s.Reason != SnapshotReason.Manual).Skip(Math.Max(1, keep)))
        {
            try
            {
                Delete(old);
                removed++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Still in use: next time.
            }
        }

        return removed;
    }
}
