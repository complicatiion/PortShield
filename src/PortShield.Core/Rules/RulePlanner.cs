using PortShield.Core.Models;

namespace PortShield.Core.Rules;

/// <summary>Programs PortShield never blocks: without them Windows loses its network, sign-in or the firewall itself.</summary>
public static class ProtectedPrograms
{
    private static readonly HashSet<string> SystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "csrss.exe", "smss.exe", "winlogon.exe",
        "lsaiso.exe", "dashost.exe", "spoolsv.exe"
    };

    /// <summary>
    /// True for core Windows processes in the system folder, PortShield itself and the user's own protected list.
    /// A rule limited to one service of svchost.exe is not protected – it does not touch the other services.
    /// </summary>
    public static bool IsProtected(string? path, string? ownExecutable = null, IEnumerable<string>? extra = null, string? systemRoot = null)
    {
        var key = ProgramPaths.Key(path);
        if (string.IsNullOrEmpty(key))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(ownExecutable) && key == ProgramPaths.Key(ownExecutable))
        {
            return true;
        }

        if (extra is not null && extra.Any(e => !string.IsNullOrWhiteSpace(e) && key == ProgramPaths.Key(e)))
        {
            return true;
        }

        var root = systemRoot ?? Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        var system32 = ProgramPaths.Key(root + @"\System32");
        var sysWow = ProgramPaths.Key(root + @"\SysWOW64");
        var folder = ProgramPaths.Key(ProgramPaths.Directory(key));
        return SystemNames.Contains(ProgramPaths.FileName(key)) && (folder == system32 || folder == sysWow);
    }
}

/// <summary>What happens with one requested rule.</summary>
public enum PlanAction
{
    /// <summary>New rule.</summary>
    Create,

    /// <summary>A PortShield rule for the program and direction exists with a different action, scope, profiles or state – it is changed.</summary>
    Update,

    /// <summary>An identical rule already exists.</summary>
    Unchanged,

    /// <summary>Core Windows process, PortShield itself or on the protected list.</summary>
    Protected,

    /// <summary>The program does not exist on this machine.</summary>
    Missing,

    /// <summary>Same program and direction twice in the request.</summary>
    Duplicate
}

public sealed record PlanItem(RuleDefinition Definition, PlanAction Action, FirewallRuleInfo? Existing)
{
    /// <summary>Allow requested, but another (non-PortShield) rule blocks the program – block always wins in the Windows Firewall.</summary>
    public bool BlockedByOtherRule { get; init; }

    public bool WillChange => Action is PlanAction.Create or PlanAction.Update;
}

/// <summary>Plans rule changes before anything is written: duplicates, existing rules, protected and missing programs.</summary>
public static class RulePlanner
{
    public sealed record Options
    {
        public string? OwnExecutable { get; init; }

        public IReadOnlyList<string> ProtectedPaths { get; init; } = [];

        /// <summary>Checks whether a program exists; null = do not check (e.g. rules for another machine).</summary>
        public Func<string, bool>? FileExists { get; init; } = File.Exists;

        public string? SystemRoot { get; init; }
    }

    public static IReadOnlyList<PlanItem> Plan(IReadOnlyList<FirewallRuleInfo> existing, IReadOnlyList<RuleDefinition> requested, Options? options = null)
    {
        options ??= new Options();
        var byProgram = existing
            .Where(r => r.HasProgram)
            .ToLookup(r => (ProgramPaths.Key(r.Program), ServiceKey(r.HasService ? r.Service : null), r.Direction));

        var seen = new HashSet<(string, string, RuleDirection)>();
        var result = new List<PlanItem>(requested.Count);
        foreach (var definition in requested)
        {
            var key = (ProgramPaths.Key(definition.Program), ServiceKey(definition.Service), definition.Direction);
            if (!seen.Add(key))
            {
                result.Add(new PlanItem(definition, PlanAction.Duplicate, null));
                continue;
            }

            if (!definition.HasService && ProtectedPrograms.IsProtected(definition.Program, options.OwnExecutable, options.ProtectedPaths, options.SystemRoot))
            {
                result.Add(new PlanItem(definition, PlanAction.Protected, null));
                continue;
            }

            var matches = byProgram[key].ToList();
            var own = matches.FirstOrDefault(r => r.IsPortShield && !r.IsKillSwitch);
            var blockedByOther = definition.Action == RuleAction.Allow
                && matches.Any(r => !r.IsPortShield && r.Enabled && r.Action == RuleAction.Block);

            if (own is not null)
            {
                var same = own.Action == definition.Action
                    && own.Enabled == definition.Enabled
                    && own.Scope == definition.Scope
                    && (definition.Scope != RuleScope.Custom || string.Equals(own.RemoteAddresses, definition.EffectiveRemoteAddresses, StringComparison.OrdinalIgnoreCase))
                    && Normalize(own.Profiles) == Normalize(definition.Profiles);
                result.Add(new PlanItem(definition, same ? PlanAction.Unchanged : PlanAction.Update, own) { BlockedByOtherRule = blockedByOther });
                continue;
            }

            if (options.FileExists is { } exists && !exists(ProgramPaths.Expand(definition.Program)))
            {
                result.Add(new PlanItem(definition, PlanAction.Missing, null));
                continue;
            }

            result.Add(new PlanItem(definition, PlanAction.Create, null) { BlockedByOtherRule = blockedByOther });
        }

        return result;
    }

    /// <summary>One definition per direction for the choice "both directions".</summary>
    public static IEnumerable<RuleDirection> Directions(DirectionChoice choice) => choice switch
    {
        DirectionChoice.Inbound => [RuleDirection.Inbound],
        DirectionChoice.Both => [RuleDirection.Outbound, RuleDirection.Inbound],
        _ => [RuleDirection.Outbound]
    };

    public static string ServiceKey(string? service) => string.IsNullOrWhiteSpace(service) ? "" : service.Trim().ToUpperInvariant();

    private static FirewallProfiles Normalize(FirewallProfiles profiles) =>
        (profiles & FirewallProfiles.All) == FirewallProfiles.None ? FirewallProfiles.All : profiles & FirewallProfiles.All;
}
