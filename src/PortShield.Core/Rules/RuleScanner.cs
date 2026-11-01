using PortShield.Core.Models;

namespace PortShield.Core.Rules;

/// <summary>Where a rule comes from.</summary>
public enum RuleOrigin
{
    /// <summary>Created or adopted by PortShield.</summary>
    PortShield,

    /// <summary>Program rule of another tool, an installer or created by hand (wf.msc, Sordum …) – can be adopted.</summary>
    Other,

    /// <summary>Windows' own rule (resource-named group) – shown, never adopted.</summary>
    System,

    /// <summary>Delivered by group policy – read only.</summary>
    Policy
}

/// <summary>Things worth a look.</summary>
[Flags]
public enum ScanFinding
{
    None = 0,

    /// <summary>The program does not exist (any more).</summary>
    Orphan = 1,

    /// <summary>Several rules for the same program, service and direction.</summary>
    Duplicate = 2,

    /// <summary>Allow and block rules for the same program, service and direction (block wins).</summary>
    Conflict = 4,

    /// <summary>Disabled program rule.</summary>
    Disabled = 8
}

public sealed record ScanEntry(FirewallRuleInfo Rule, RuleOrigin Origin, ScanFinding Findings)
{
    public bool CanAdopt => Origin == RuleOrigin.Other;

    public bool Has(ScanFinding finding) => (Findings & finding) != 0;
}

/// <summary>A rule delivered by group policy (registry value under Policies\Microsoft\WindowsFirewall\FirewallRules).</summary>
public sealed record PolicyRule(string Name, string Program, string Service, RuleDirection Direction, RuleAction Action, bool Enabled);

public sealed record ScanResult(IReadOnlyList<ScanEntry> Entries, IReadOnlyList<PolicyRule> PolicyRules)
{
    public int Count(RuleOrigin origin) => Entries.Count(e => e.Origin == origin);

    public int Count(ScanFinding finding) => Entries.Count(e => e.Has(finding));

    public int Adoptable => Entries.Count(e => e.CanAdopt);
}

/// <summary>
/// Scan of existing program rules: origin (PortShield, other, Windows, group policy) and findings (missing program,
/// duplicates, allow/block conflicts, disabled rules). Rules of other tools can then be adopted by PortShield (marker only).
/// </summary>
public static class RuleScanner
{
    public static ScanResult Scan(IReadOnlyList<FirewallRuleInfo> rules, IReadOnlyList<PolicyRule> policyRules, Func<string, bool>? fileExists = null)
    {
        fileExists ??= File.Exists;
        var policyKeys = policyRules
            .Select(p => (p.Name.ToUpperInvariant(), ProgramPaths.Key(p.Program), p.Direction))
            .ToHashSet();

        var programRules = rules.Where(r => r.HasProgram && !r.IsKillSwitch).ToList();
        var groups = programRules
            .GroupBy(r => (ProgramPaths.Key(r.Program), RulePlanner.ServiceKey(r.HasService ? r.Service : null), r.Direction))
            .ToDictionary(g => g.Key, g => g.ToList());

        var exists = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var entries = new List<ScanEntry>(programRules.Count);
        foreach (var rule in programRules)
        {
            var origin = rule.IsPortShield ? RuleOrigin.PortShield
                : policyKeys.Contains((rule.Name.ToUpperInvariant(), ProgramPaths.Key(rule.Program), rule.Direction)) ? RuleOrigin.Policy
                : rule.IsSystem ? RuleOrigin.System
                : RuleOrigin.Other;

            var findings = ScanFinding.None;
            var path = rule.ExpandedProgram;
            if (!exists.TryGetValue(path, out var present))
            {
                present = fileExists(path);
                exists[path] = present;
            }

            if (!present)
            {
                findings |= ScanFinding.Orphan;
            }

            var group = groups[(ProgramPaths.Key(rule.Program), RulePlanner.ServiceKey(rule.HasService ? rule.Service : null), rule.Direction)];
            var enabled = group.Where(r => r.Enabled).ToList();
            if (enabled.Count > 1 && rule.Enabled && enabled.Count(r => r.Action == rule.Action) > 1)
            {
                findings |= ScanFinding.Duplicate;
            }

            if (rule.Enabled && enabled.Any(r => r.Action != rule.Action))
            {
                findings |= ScanFinding.Conflict;
            }

            if (!rule.Enabled)
            {
                findings |= ScanFinding.Disabled;
            }

            entries.Add(new ScanEntry(rule, origin, findings));
        }

        return new ScanResult(entries, policyRules);
    }

    /// <summary>
    /// Duplicates to remove when merging: per program, service, direction and action the first rule stays
    /// (a PortShield rule is preferred), all other enabled rules with the same action are returned.
    /// </summary>
    public static IReadOnlyList<FirewallRuleInfo> MergeExtras(IEnumerable<ScanEntry> entries) =>
        entries
            .Where(e => e.Has(ScanFinding.Duplicate) && e.Origin is RuleOrigin.PortShield or RuleOrigin.Other)
            .GroupBy(e => (ProgramPaths.Key(e.Rule.Program), RulePlanner.ServiceKey(e.Rule.HasService ? e.Rule.Service : null), e.Rule.Direction, e.Rule.Action))
            .SelectMany(g => g.OrderByDescending(e => e.Origin == RuleOrigin.PortShield).Skip(1).Select(e => e.Rule))
            .ToList();

    /// <summary>Parses a group policy rule value: "v2.31|Action=Block|Active=TRUE|Dir=Out|App=…|Svc=…|Name=…|".</summary>
    public static PolicyRule? ParsePolicyRule(string value)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in value.Split('|'))
        {
            var eq = part.IndexOf('=');
            if (eq > 0)
            {
                fields[part[..eq]] = part[(eq + 1)..];
            }
        }

        if (!fields.TryGetValue("Name", out var name))
        {
            return null;
        }

        return new PolicyRule(
            name,
            fields.GetValueOrDefault("App") ?? "",
            fields.GetValueOrDefault("Svc") ?? "",
            string.Equals(fields.GetValueOrDefault("Dir"), "In", StringComparison.OrdinalIgnoreCase) ? RuleDirection.Inbound : RuleDirection.Outbound,
            string.Equals(fields.GetValueOrDefault("Action"), "Allow", StringComparison.OrdinalIgnoreCase) ? RuleAction.Allow : RuleAction.Block,
            !string.Equals(fields.GetValueOrDefault("Active"), "FALSE", StringComparison.OrdinalIgnoreCase));
    }
}
