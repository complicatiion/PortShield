using PortShield.Core.Integrity;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.RuleSets;
using PortShield.Core.Storage;
using PortShield.Platform.Windows;

namespace PortShield.App.Services;

/// <summary>Outcome of a change for the toast: counts and the first errors.</summary>
public sealed record ChangeResult(int Changed, IReadOnlyList<RuleError> Errors, SnapshotInfo? Snapshot = null)
{
    public static readonly ChangeResult None = new(0, []);

    public bool HasErrors => Errors.Count > 0;

    public static ChangeResult From(WriteResult result, SnapshotInfo? snapshot = null) => new(result.Succeeded, result.Errors, snapshot);
}

/// <summary>
/// The app's single entry to the Windows Firewall. All work runs on a background thread, one operation at a time
/// (the COM objects of the last load stay valid for the following changes). After every change the rule list is
/// reloaded and <see cref="RulesChanged"/> fires.
/// </summary>
public sealed class FirewallService : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly UiSettings _ui;
    private FirewallStore? _store;

    public FirewallService(UiSettings ui)
    {
        _ui = ui;
    }

    public static bool IsSupported => OperatingSystem.IsWindows();

    private FirewallStore Store => _store ??= new FirewallStore();

    /// <summary>All rules of the last load (system, third-party and PortShield).</summary>
    public IReadOnlyList<FirewallRuleInfo> Rules { get; private set; } = [];

    public FirewallStatus? Status { get; private set; }

    public FirewallProfiles ActiveProfiles { get; private set; }

    public bool KillSwitchOn => Rules.Any(r => r.IsKillSwitch && r.Enabled);

    /// <summary>PortShield rules removed or changed outside PortShield since its last own change.</summary>
    public IReadOnlyList<RuleDrift> Drifts { get; private set; } = [];

    /// <summary>Rules allowed for a limited time.</summary>
    public TemporaryList Temporary { get; private set; } = new();

    public event Action? RulesChanged;

    public event Action? StatusChanged;

    // ------------------------------------------------------------------ Read

    public Task<IReadOnlyList<FirewallRuleInfo>> RefreshAsync() => RunAsync(() =>
    {
        LoadLocked();
        return Rules;
    }, notify: true);

    public Task<FirewallStatus?> RefreshStatusAsync() => RunAsync<FirewallStatus?>(() =>
    {
        ActiveProfiles = Store.CurrentProfiles();
        Status = FirewallPolicy.Read(ActiveProfiles);
        return Status;
    }, notify: false, status: true);

    private void LoadLocked()
    {
        Rules = Store.Load();
        Drifts = RuleGuard.Check(Rules);
        Temporary = RuleGuard.LoadTemporary();
    }

    /// <summary>
    /// After an own change: reload and record the rules as written by PortShield (integrity check).
    /// <paramref name="touched"/> = ids of the rules this change wrote (null = all, e.g. restore or reset): changes made
    /// outside PortShield to other rules stay reported instead of being accepted silently.
    /// </summary>
    private void CommitLocked(IEnumerable<FirewallRuleInfo>? touched = null)
    {
        Rules = Store.Load();
        Drifts = RuleGuard.Commit(Rules, touched);
        Temporary = RuleGuard.LoadTemporary();
    }

    /// <summary>A rule that is permanently allowed, blocked again or deleted is no longer "temporary".</summary>
    private static void EndTemporary(IEnumerable<FirewallRuleInfo> rules)
    {
        var ids = rules.Select(r => r.PortShieldId).OfType<string>().ToList();
        var list = RuleGuard.LoadTemporary();
        if (ids.Count > 0 && ids.Any(id => list.Find(id) is not null))
        {
            RuleGuard.SaveTemporary(list.Without(ids));
        }
    }

    // ------------------------------------------------------------------ Plan & apply

    /// <summary>Expands wildcards and variables of rule set entries into one definition per existing program.</summary>
    public static IReadOnlyList<RuleDefinition> Resolve(IEnumerable<RuleDefinition> definitions)
    {
        var result = new List<RuleDefinition>();
        var seen = new HashSet<(string, string, RuleDirection)>();
        void Add(RuleDefinition d)
        {
            // Overlapping patterns (Maxon\Cinema 4D * and MAXON\CINEMA 4D *) find the same file only once.
            if (seen.Add((ProgramPaths.Key(d.Program), RulePlanner.ServiceKey(d.Service), d.Direction)))
            {
                result.Add(d);
            }
        }

        foreach (var definition in definitions)
        {
            if (ProgramPaths.HasWildcard(definition.Program))
            {
                foreach (var path in ProgramPaths.Resolve(definition.Program))
                {
                    Add(definition with { Program = path, Name = "" });
                }
            }
            else
            {
                Add(definition with { Program = ProgramPaths.Expand(definition.Program) });
            }
        }

        return result;
    }

    /// <summary>Rule name for a new rule: "PortShield · Snagit Editor · Out" or "PortShield · DiagTrack · Out" for a service rule.</summary>
    public static string NameFor(RuleDefinition definition, string prefix) =>
        !string.IsNullOrWhiteSpace(definition.Name) ? definition.Name
        : definition.HasService ? RuleNaming.BuildName(prefix, definition.Service!.Trim(), definition.Direction)
        : RuleNaming.BuildName(prefix, RuleNaming.DisplayNameFor(definition.Program, FileInspector.Read(ProgramPaths.Expand(definition.Program)).Description), definition.Direction);

    public IReadOnlyList<PlanItem> Plan(IReadOnlyList<RuleDefinition> definitions) =>
        RulePlanner.Plan(Rules, definitions, new RulePlanner.Options
        {
            OwnExecutable = AppEnvironment.ExecutablePath,
            ProtectedPaths = _ui.ProtectedPaths,
            FileExists = FileInspector.Exists
        });

    /// <summary>Creates and updates the planned rules (skipped items are ignored).</summary>
    public Task<ChangeResult> ApplyAsync(IReadOnlyList<PlanItem> plan, SnapshotReason? snapshotReason = null) => RunAsync(() =>
    {
        var snapshot = TakeSnapshotLocked(snapshotReason);
        var errors = new List<RuleError>();
        var changed = 0;
        var create = new List<FirewallStore.NewRule>();
        foreach (var item in plan)
        {
            if (item.Action == PlanAction.Create)
            {
                var definition = item.Definition;
                create.Add(FirewallStore.Prepare(definition, NameFor(definition, _ui.NamePrefix), RuleNaming.NewId()));
            }
            else if (item.Action == PlanAction.Update && item.Existing is not null)
            {
                var result = Store.Update(item.Existing, item.Definition);
                changed += result.Succeeded;
                errors.AddRange(result.Errors);
            }
        }

        if (create.Count > 0)
        {
            var result = Store.Add(create);
            changed += result.Succeeded;
            errors.AddRange(result.Errors);
        }

        var updated = plan.Where(i => i.Action == PlanAction.Update && i.Existing is not null).Select(i => i.Existing!).ToList();
        EndTemporary(updated);
        CommitLocked(updated);
        return new ChangeResult(changed, errors, snapshot);
    }, notify: true);

    // ------------------------------------------------------------------ Change selected rules

    public Task<ChangeResult> SetEnabledAsync(IReadOnlyList<FirewallRuleInfo> rules, bool enabled) =>
        ChangeAsync(rules, () => Store.SetEnabled(rules, enabled));

    public Task<ChangeResult> SetActionAsync(IReadOnlyList<FirewallRuleInfo> rules, RuleAction action) =>
        ChangeAsync(rules, () =>
        {
            var result = Store.SetAction(rules, action);
            EndTemporary(rules);
            return result;
        });

    public Task<ChangeResult> SetScopeAsync(IReadOnlyList<FirewallRuleInfo> rules, RuleScope scope) =>
        ChangeAsync(rules, () => Store.SetRemoteAddresses(rules, scope == RuleScope.Internet ? InternetRanges.All : "*"));

    public Task<ChangeResult> SetProfilesAsync(IReadOnlyList<FirewallRuleInfo> rules, FirewallProfiles profiles) =>
        ChangeAsync(rules, () => Store.SetProfiles(rules, profiles));

    public Task<ChangeResult> RenameAsync(FirewallRuleInfo rule, string name) =>
        ChangeAsync([rule], () => Store.Rename(rule, name));

    public Task<ChangeResult> DeleteAsync(IReadOnlyList<FirewallRuleInfo> rules) => RunAsync(() =>
    {
        var snapshot = TakeSnapshotLocked(SnapshotReason.BeforeDelete);
        var result = Store.Delete(rules);
        EndTemporary(rules);
        CommitLocked(rules);
        return ChangeResult.From(result, snapshot);
    }, notify: true);

    /// <summary>Removes every PortShield rule (Settings, uninstall).</summary>
    public Task<ChangeResult> DeleteAllOwnAsync() => RunAsync(() =>
    {
        LoadLocked();
        var snapshot = TakeSnapshotLocked(SnapshotReason.BeforeDelete);
        var result = Store.Delete(Rules.Where(r => r.IsPortShield).ToList());
        CommitLocked();
        return ChangeResult.From(result, snapshot);
    }, notify: true);

    /// <summary>Scan: rules of this machine plus group policy rules, sorted by origin and findings.</summary>
    public Task<ScanResult> ScanAsync() => RunAsync(() =>
    {
        LoadLocked();
        return RuleScanner.Scan(Rules, FirewallPolicy.ReadPolicyRules(), FileInspector.Exists);
    }, notify: true);

    /// <summary>Adopts rules of other tools (marker only, optionally renamed to the PortShield scheme); snapshot first.</summary>
    public Task<ChangeResult> AdoptAsync(IReadOnlyList<FirewallRuleInfo> rules, bool rename) => RunAsync(() =>
    {
        var snapshot = TakeSnapshotLocked(SnapshotReason.BeforeAdopt);
        var prefix = _ui.NamePrefix;
        var result = Store.Adopt(rules, rename
            ? info => NameFor(new RuleDefinition { Program = info.Program, Service = info.HasService ? info.Service : null, Direction = info.Direction }, prefix)
            : null);
        CommitLocked(rules);
        return ChangeResult.From(result, snapshot);
    }, notify: true);

    private Task<ChangeResult> ChangeAsync(IReadOnlyList<FirewallRuleInfo> rules, Func<WriteResult> change) => RunAsync(() =>
    {
        var result = change();
        CommitLocked(rules);
        return ChangeResult.From(result);
    }, notify: true);

    // ------------------------------------------------------------------ Integrity check

    /// <summary>Creates missing rules again and puts changed rules back the way PortShield wrote them (same id).</summary>
    public Task<ChangeResult> RestoreDriftsAsync() => RunAsync(() =>
    {
        LoadLocked();
        IReadOnlyList<RuleDrift> drifts = Drifts;
        if (drifts.Count == 0)
        {
            return ChangeResult.None;
        }

        // A missing rule whose program already has a PortShield rule again (e.g. rule set re-applied) is not created twice.
        var live = RuleIntegrity.Tracked(Rules)
            .Select(r => (ProgramPaths.Key(r.Program), RulePlanner.ServiceKey(r.HasService ? r.Service : null), r.Direction)).ToHashSet();
        drifts = drifts.Where(d => d.Kind == DriftKind.Changed
            || !live.Contains((ProgramPaths.Key(d.Expected.Definition.Program), RulePlanner.ServiceKey(d.Expected.Definition.Service), d.Expected.Definition.Direction))).ToList();
        var snapshot = TakeSnapshotLocked(SnapshotReason.BeforeRestore, force: true);
        var ids = drifts.Select(d => d.Expected.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var deleted = Store.Delete(Rules.Where(r => r.PortShieldId is { } id && ids.Contains(id) && !r.IsKillSwitch).ToList());
        var create = drifts.Select(d => FirewallStore.Prepare(d.Expected.Definition with { Program = ProgramPaths.Expand(d.Expected.Definition.Program) },
            d.Expected.Name, d.Expected.Id)).ToList();
        var added = Store.Add(create);
        // Superseded missing rules (program has a rule again) are dropped from the record as well.
        CommitLocked();
        return new ChangeResult(added.Succeeded, deleted.Errors.Concat(added.Errors).ToList(), snapshot);
    }, notify: true);

    /// <summary>Accepts the current state as the new reference.</summary>
    public Task AcceptDriftsAsync() => RunAsync(() =>
    {
        CommitLocked();
        return true;
    }, notify: true);

    // ------------------------------------------------------------------ Temporarily allowed

    /// <summary>Allows blocked PortShield rules for <paramref name="duration"/>; afterwards they are blocked again.</summary>
    public Task<ChangeResult> AllowTemporarilyAsync(IReadOnlyList<FirewallRuleInfo> rules, TimeSpan duration) => RunAsync(() =>
    {
        var targets = rules.Where(r => r.PortShieldId is not null && !r.IsKillSwitch && (r.Action == RuleAction.Block || Temporary.Find(r.PortShieldId) is not null)).ToList();
        if (targets.Count == 0)
        {
            return ChangeResult.None;
        }

        var until = DateTime.Now.Add(duration);
        var result = Store.SetAction(targets.Where(r => r.Action == RuleAction.Block), RuleAction.Allow);
        var failed = result.Errors.Select(e => e.Rule).ToHashSet(StringComparer.OrdinalIgnoreCase);
        RuleGuard.SaveTemporary(RuleGuard.LoadTemporary().With(targets.Where(r => !failed.Contains(r.Name))
            .Select(r => new TemporaryEntry(r.PortShieldId!, r.Name, until))));
        CommitLocked(targets);
        return new ChangeResult(targets.Count - failed.Count, result.Errors);
    }, notify: true);

    /// <summary>Blocks temporarily allowed rules again: the due ones, the given ones or all.</summary>
    public Task<ChangeResult> RestoreTemporaryAsync(bool all, IReadOnlyCollection<string>? ids = null) => RunAsync(() =>
    {
        LoadLocked();
        var before = Temporary.Entries.Select(e => e.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var result = RuleGuard.RestoreTemporary(Store, Rules, all, ids);
        CommitLocked(Rules.Where(r => r.PortShieldId is { } id && before.Contains(id)));
        return ChangeResult.From(result);
    }, notify: true);

    // ------------------------------------------------------------------ Factory reset

    /// <summary>
    /// Back to the state after installation: kill switch and whitelist mode off, all PortShield rules removed, own rule
    /// sets, watch list, integrity record and temporary rules deleted, snapshots optionally. A snapshot is taken first.
    /// Rules of Windows, other tools and group policy stay untouched.
    /// </summary>
    public Task<ChangeResult> FactoryResetAsync(bool deleteSnapshots) => RunAsync(() =>
    {
        LoadLocked();
        var snapshot = deleteSnapshots ? null : TakeSnapshotLocked(SnapshotReason.BeforeReset, force: true);
        var errors = new List<RuleError>();
        var killSwitch = Store.SetKillSwitch(Rules, false, true);
        errors.AddRange(killSwitch.Errors);
        Rules = Store.Load();
        if (Status?.WhitelistMode == true)
        {
            var run = FirewallPolicy.SetOutboundDefault(false);
            if (!run.Success)
            {
                errors.Add(new RuleError("Whitelist", run.Output.Trim()));
            }
        }

        var deleted = Store.Delete(Rules.Where(r => r.IsPortShield).ToList());
        errors.AddRange(deleted.Errors);

        RuleGuard.SaveTemporary(new TemporaryList());
        if (File.Exists(AppPaths.AuditMarkerFile))
        {
            // Recording of blocked connections was turned on by PortShield.
            try
            {
                ConnectionAudit.SetEnabled(false);
            }
            catch (Exception ex)
            {
                errors.Add(new RuleError("Audit", ex.Message));
            }

            TryDelete(() => File.Delete(AppPaths.AuditMarkerFile));
        }
        foreach (var file in new[] { AppPaths.BaselineFile, AppPaths.WatchFile, AppPaths.PendingAddFile })
        {
            TryDelete(() => File.Delete(file));
        }

        TryDelete(() => Directory.Delete(AppPaths.RuleSetsDirectory, recursive: true));
        if (deleteSnapshots)
        {
            TryDelete(() => Directory.Delete(AppPaths.SnapshotsDirectory, recursive: true));
        }

        Rules = Store.Load();
        Drifts = [];
        Temporary = new TemporaryList();
        RefreshStatusLocked();
        return new ChangeResult(deleted.Succeeded, errors, snapshot);
    }, notify: true, status: true);

    private static void TryDelete(Action delete)
    {
        try
        {
            delete();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    // ------------------------------------------------------------------ Kill switch, whitelist, profiles

    public Task<ChangeResult> SetKillSwitchAsync(bool on, bool lanAllowed) => RunAsync(() =>
    {
        LoadLocked();
        var result = Store.SetKillSwitch(Rules, on, lanAllowed);
        CommitLocked([]);
        return ChangeResult.From(result);
    }, notify: true);

    public Task<string?> SetWhitelistModeAsync(bool on) => RunAsync<string?>(() =>
    {
        if (on)
        {
            TakeSnapshotLocked(SnapshotReason.BeforeWhitelist);
        }

        var run = FirewallPolicy.SetOutboundDefault(on);
        RefreshStatusLocked();
        return run.Success ? null : run.Output.Trim();
    }, notify: false, status: true);

    public Task<string?> SetFirewallEnabledAsync(FirewallProfiles profiles, bool on) => RunAsync<string?>(() =>
    {
        var run = FirewallPolicy.SetEnabled(profiles, on);
        RefreshStatusLocked();
        return run.Success ? null : run.Output.Trim();
    }, notify: false, status: true);

    /// <summary>netsh advfirewall reset – Windows defaults, all own rules removed (snapshot first).</summary>
    public Task<string?> ResetFirewallAsync() => RunAsync<string?>(() =>
    {
        LoadLocked();
        TakeSnapshotLocked(SnapshotReason.BeforeReset, force: true);
        var run = Netsh.Reset();
        CommitLocked();
        RefreshStatusLocked();
        return run.Success ? null : run.Output.Trim();
    }, notify: true, status: true);

    private void RefreshStatusLocked()
    {
        ActiveProfiles = Store.CurrentProfiles();
        Status = FirewallPolicy.Read(ActiveProfiles);
    }

    // ------------------------------------------------------------------ Snapshots & policy files

    public Task<SnapshotInfo> SnapshotAsync(SnapshotReason reason, string? note = null) => RunAsync(() =>
    {
        LoadLocked();
        return SnapshotManager.Create(reason, Rules, AppEnvironment.Version, note);
    }, notify: false);

    /// <summary>Deletes the current PortShield rules and creates those of the snapshot again (other rules stay untouched).</summary>
    public Task<ChangeResult> RestoreRulesAsync(SnapshotInfo snapshot) => RunAsync(() =>
    {
        var set = SnapshotManager.LoadRules(snapshot);
        LoadLocked();
        var before = TakeSnapshotLocked(SnapshotReason.BeforeRestore, force: true);
        var deleted = Store.Delete(Rules.Where(r => r.IsPortShield).ToList());
        var create = set.Rules.Select(d => FirewallStore.Prepare(d with { Program = ProgramPaths.Expand(d.Program) },
            NameFor(d, _ui.NamePrefix), RuleNaming.NewId())).ToList();
        var added = Store.Add(create);
        CommitLocked();
        return new ChangeResult(added.Succeeded, deleted.Errors.Concat(added.Errors).ToList(), before);
    }, notify: true);

    public Task<string?> RestorePolicyAsync(SnapshotInfo snapshot) => RunAsync<string?>(() =>
    {
        LoadLocked();
        TakeSnapshotLocked(SnapshotReason.BeforeRestore, force: true);
        var run = SnapshotManager.RestorePolicy(snapshot);
        CommitLocked();
        RefreshStatusLocked();
        return run.Success ? null : run.Output.Trim();
    }, notify: true, status: true);

    public Task<string?> ExportPolicyAsync(string path) => RunAsync<string?>(() =>
    {
        var run = Netsh.Export(path);
        return run.Success ? null : run.Output.Trim();
    }, notify: false);

    public Task<string?> ImportPolicyAsync(string path) => RunAsync<string?>(() =>
    {
        LoadLocked();
        TakeSnapshotLocked(SnapshotReason.BeforePolicyImport, force: true);
        var run = Netsh.Import(path);
        CommitLocked();
        RefreshStatusLocked();
        return run.Success ? null : run.Output.Trim();
    }, notify: true, status: true);

    private SnapshotInfo? TakeSnapshotLocked(SnapshotReason? reason, bool force = false)
    {
        if (reason is null || (!force && !_ui.SnapshotBeforeChanges))
        {
            return null;
        }

        try
        {
            var snapshot = SnapshotManager.Create(reason.Value, Rules, AppEnvironment.Version);
            SnapshotManager.Prune(_ui.SnapshotKeep);
            return snapshot;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A missing snapshot must not block the change; the user sees no snapshot in the list.
            return null;
        }
    }

    // ------------------------------------------------------------------ Worker

    private async Task<T> RunAsync<T>(Func<T> work, bool notify, bool status = false)
    {
        if (!IsSupported)
        {
            throw new PlatformNotSupportedException("PortShield needs Windows.");
        }

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await Task.Run(work).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
            if (notify)
            {
                RulesChanged?.Invoke();
            }

            if (status)
            {
                StatusChanged?.Invoke();
            }
        }
    }

    public void Dispose()
    {
        _store?.Dispose();
        _gate.Dispose();
    }
}
