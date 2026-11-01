using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.Storage;

namespace PortShield.Core.Integrity;

/// <summary>One PortShield rule as PortShield last wrote it.</summary>
public sealed record BaselineRule(string Id, string Name, string Fingerprint, RuleDefinition Definition);

/// <summary>State of all PortShield rules after PortShield's last own change.</summary>
public sealed record RuleBaseline
{
    public int Version { get; init; } = 1;

    public DateTime Saved { get; init; } = DateTime.Now;

    public List<BaselineRule> Rules { get; init; } = [];

    public static RuleBaseline? Load(string path)
    {
        try
        {
            return JsonFile.Read<RuleBaseline>(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            return null;
        }
    }

    public void Save(string path) => JsonFile.Write(path, this);
}

public enum DriftKind
{
    /// <summary>The rule no longer exists.</summary>
    Missing,

    /// <summary>Name, program, direction, action, state, profiles or addresses differ.</summary>
    Changed
}

/// <summary>A PortShield rule that was removed or changed outside PortShield.</summary>
public sealed record RuleDrift(BaselineRule Expected, FirewallRuleInfo? Current, DriftKind Kind);

/// <summary>
/// Integrity check: after every own change PortShield records its rules; at start and on refresh the live rules are
/// compared with that record. Rules removed or changed by Windows updates, installers, other tools or group policy show up.
/// </summary>
public static class RuleIntegrity
{
    /// <summary>Everything that makes a rule behave the way PortShield wrote it.</summary>
    public static string Fingerprint(FirewallRuleInfo rule) => string.Join('|',
        rule.Name.Trim(),
        ProgramPaths.Key(rule.Program),
        RulePlanner.ServiceKey(rule.HasService ? rule.Service : null),
        rule.Direction,
        rule.Action,
        rule.Enabled,
        rule.Profiles is FirewallProfiles.None ? FirewallProfiles.All : rule.Profiles,
        rule.Scope,
        rule.Scope == RuleScope.Custom ? rule.RemoteAddresses.Replace(" ", "").ToUpperInvariant() : "");

    /// <summary>Rules the check covers: PortShield rules with an id (the kill switch comes and goes on purpose).</summary>
    public static IEnumerable<FirewallRuleInfo> Tracked(IEnumerable<FirewallRuleInfo> rules) =>
        rules.Where(r => r.PortShieldId is not null && !r.IsKillSwitch);

    public static RuleBaseline Capture(IEnumerable<FirewallRuleInfo> rules) => new()
    {
        Saved = DateTime.Now,
        Rules = Tracked(rules)
            .GroupBy(r => r.PortShieldId!, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Select(r => new BaselineRule(r.PortShieldId!, r.Name, Fingerprint(r), RuleDefinition.FromRule(r)))
            .ToList()
    };

    public static IReadOnlyList<RuleDrift> Compare(RuleBaseline baseline, IEnumerable<FirewallRuleInfo> rules)
    {
        var current = Tracked(rules).ToLookup(r => r.PortShieldId!, StringComparer.OrdinalIgnoreCase);
        var drifts = new List<RuleDrift>();
        foreach (var expected in baseline.Rules)
        {
            var live = current[expected.Id].ToList();
            if (live.Count == 0)
            {
                drifts.Add(new RuleDrift(expected, null, DriftKind.Missing));
            }
            else if (!live.Any(r => Fingerprint(r) == expected.Fingerprint))
            {
                drifts.Add(new RuleDrift(expected, live[0], DriftKind.Changed));
            }
        }

        return drifts;
    }
}
