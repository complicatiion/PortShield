using System.Text.RegularExpressions;
using PortShield.Core.Models;

namespace PortShield.Core.Rules;

/// <summary>
/// Names, group and marker of PortShield rules. Every rule PortShield creates carries the group "PortShield" and a marker
/// "[ps:1a2b3c4d]" at the end of its description, so PortShield finds its own rules again – also after renaming – and never
/// touches system or third-party rules unless the user selects them explicitly.
/// </summary>
public static partial class RuleNaming
{
    /// <summary>Rule group (Grouping) of all PortShield rules – visible as "Group" in wf.msc.</summary>
    public const string Group = "PortShield";

    public const string DefaultPrefix = "PortShield";

    /// <summary>Name of the kill switch rules (followed by " · Out" / " · In").</summary>
    public const string KillSwitchName = "PortShield · Kill switch";

    private const string Separator = " · ";

    [GeneratedRegex(@"\[ps:([0-9a-f]{8})\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MarkerRegex();

    public static string NewId() => Guid.NewGuid().ToString("N")[..8];

    public static string DirectionSuffix(RuleDirection direction) => direction == RuleDirection.Outbound ? "Out" : "In";

    /// <summary>"PortShield · Snagit Editor · Out".</summary>
    public static string BuildName(string? prefix, string displayName, RuleDirection direction)
    {
        var p = string.IsNullOrWhiteSpace(prefix) ? DefaultPrefix : prefix.Trim();
        var name = string.IsNullOrWhiteSpace(displayName) ? "?" : displayName.Trim();
        return p + Separator + name + Separator + DirectionSuffix(direction);
    }

    /// <summary>
    /// Readable name of a program: the file description from its version info when it says more than the file name
    /// (e.g. "Adobe Photoshop 2021"), otherwise the file name without extension.
    /// </summary>
    public static string DisplayNameFor(string programPath, string? fileDescription)
    {
        var fileName = Path.GetFileNameWithoutExtension(ProgramPaths.FileName(programPath));
        var description = fileDescription?.Trim();
        if (string.IsNullOrEmpty(description) || description.Length > 80 || description.Contains('\\'))
        {
            return string.IsNullOrEmpty(fileName) ? programPath : fileName;
        }

        return description;
    }

    public static string? ParseId(string? description)
    {
        if (string.IsNullOrEmpty(description))
        {
            return null;
        }

        var match = MarkerRegex().Match(description);
        return match.Success ? match.Groups[1].Value.ToLowerInvariant() : null;
    }

    public static string Marker(string id) => $"[ps:{id}]";

    /// <summary>Description text plus marker: "Blocks Snagit (internet only). [ps:1a2b3c4d]".</summary>
    public static string WithMarker(string? description, string id)
    {
        var text = StripMarker(description);
        return string.IsNullOrEmpty(text) ? Marker(id) : text + " " + Marker(id);
    }

    public static string StripMarker(string? description) =>
        string.IsNullOrEmpty(description) ? "" : MarkerRegex().Replace(description, "").Trim();

    /// <summary>Default description of a new rule (English, as all texts stored in the firewall).</summary>
    public static string DefaultDescription(RuleDefinition definition)
    {
        var verb = definition.Action == RuleAction.Block ? "Blocks" : "Allows";
        var service = definition.HasService ? $" of the service {definition.Service}" : "";
        var direction = definition.Direction == RuleDirection.Outbound ? "outbound" : "inbound";
        var scope = definition.Scope switch
        {
            RuleScope.Internet => "internet only, LAN stays reachable",
            RuleScope.Custom => "custom addresses",
            _ => "all addresses"
        };
        return $"{verb} {direction} traffic{service} ({scope}). Created by PortShield.";
    }
}
