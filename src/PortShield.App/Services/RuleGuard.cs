using PortShield.Core.Integrity;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.Storage;
using PortShield.Platform.Windows;

namespace PortShield.App.Services;

/// <summary>
/// Shared by the app and the command line: records PortShield's rules after own changes (integrity check) and blocks
/// temporarily allowed rules again.
/// </summary>
public static class RuleGuard
{
    // ------------------------------------------------------------------ Integrity

    /// <summary>
    /// Records the current PortShield rules as "written by PortShield" and returns what is still drifted.
    /// <paramref name="touched"/> = rules the change just wrote (null = all, e.g. restore, reset, accept): changes made
    /// outside PortShield to other rules stay reported instead of being accepted silently.
    /// </summary>
    public static IReadOnlyList<RuleDrift> Commit(IReadOnlyList<FirewallRuleInfo> rules, IEnumerable<FirewallRuleInfo>? touched = null)
    {
        var baseline = RuleIntegrity.Capture(rules);
        if (touched is not null && RuleBaseline.Load(AppPaths.BaselineFile) is { } old)
        {
            var ids = touched.Select(r => r.PortShieldId).OfType<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var drift in RuleIntegrity.Compare(old, rules).Where(d => !ids.Contains(d.Expected.Id)))
            {
                baseline.Rules.RemoveAll(b => string.Equals(b.Id, drift.Expected.Id, StringComparison.OrdinalIgnoreCase));
                baseline.Rules.Add(drift.Expected);
            }
        }

        try
        {
            baseline.Save(AppPaths.BaselineFile);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Without a record the check stays silent – never block a change because of it.
        }

        return RuleIntegrity.Compare(baseline, rules);
    }

    /// <summary>Rules removed or changed outside PortShield. The first call (no record yet) records the current state.</summary>
    public static IReadOnlyList<RuleDrift> Check(IReadOnlyList<FirewallRuleInfo> rules)
    {
        var baseline = RuleBaseline.Load(AppPaths.BaselineFile);
        if (baseline is null)
        {
            Commit(rules);
            return [];
        }

        return RuleIntegrity.Compare(baseline, rules);
    }

    // ------------------------------------------------------------------ Temporarily allowed

    public static TemporaryList LoadTemporary() => TemporaryList.Load(AppPaths.TemporaryFile);

    /// <summary>
    /// Blocks the due (or all) temporarily allowed rules again, removes them from the list and plans the safety task
    /// for the next one.
    /// </summary>
    public static WriteResult RestoreTemporary(FirewallStore store, IReadOnlyList<FirewallRuleInfo> rules, bool all, IReadOnlyCollection<string>? ids = null)
    {
        var list = LoadTemporary();
        var due = ids is not null
            ? list.Entries.Where(e => ids.Contains(e.Id, StringComparer.OrdinalIgnoreCase)).ToList()
            : all ? list.Entries : list.Due(DateTime.Now);
        if (due.Count == 0)
        {
            return WriteResult.Empty;
        }

        var dueIds = due.Select(e => e.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var live = rules.Where(r => r.PortShieldId is { } id && dueIds.Contains(id) && r.Action == RuleAction.Allow).ToList();
        var result = live.Count > 0 ? store.SetAction(live, RuleAction.Block) : WriteResult.Empty;

        // Entries of rules that failed stay (next try); deleted rules are dropped.
        var failed = result.Errors.Select(e => e.Rule).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var done = due.Where(e => !live.Any(r => string.Equals(r.PortShieldId, e.Id, StringComparison.OrdinalIgnoreCase) && failed.Contains(r.Name)))
            .Select(e => e.Id);
        SaveTemporary(list.Without(done));
        return result;
    }

    public static void SaveTemporary(TemporaryList list)
    {
        try
        {
            if (list.Entries.Count == 0)
            {
                File.Delete(AppPaths.TemporaryFile);
            }
            else
            {
                list.Save(AppPaths.TemporaryFile);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }

        ScheduleTask(list.Next);
    }

    /// <summary>Safety net for the time PortShield is not running: a one-shot task as SYSTEM.</summary>
    private static void ScheduleTask(DateTime? next)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            if (next is { } time)
            {
                TemporaryTask.Schedule(time < DateTime.Now ? DateTime.Now.AddMinutes(1) : time, AppEnvironment.ExecutablePath);
            }
            else
            {
                TemporaryTask.Remove();
            }
        }
        catch (Exception)
        {
            // schtasks missing or blocked: the running app still restores on its own.
        }
    }
}
