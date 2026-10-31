using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.RuleSets;

namespace PortShield.Core.Import;

/// <summary>Defaults for imported entries that do not say direction, action or scope (plain path lists).</summary>
public sealed record ImportDefaults
{
    public DirectionChoice Direction { get; init; } = DirectionChoice.Outbound;

    public RuleAction Action { get; init; } = RuleAction.Block;

    public RuleScope Scope { get; init; } = RuleScope.All;

    public FirewallProfiles Profiles { get; init; } = FirewallProfiles.All;
}

public sealed record ImportResult(string Format, string? Name, IReadOnlyList<RuleDefinition> Rules, IReadOnlyList<string> Warnings);

/// <summary>
/// Reads PortShield rule sets (JSON), CSV tables (own export or any table with a program/path column, also German
/// headers) and plain text lists (one path per line, "hash  path" lines of sha256sum).
/// </summary>
public static partial class RuleImporter
{
    [GeneratedRegex(@"^[0-9a-fA-F]{64}\s+\*?(.+)$")]
    private static partial Regex HashLineRegex();

    public static ImportResult ImportFile(string path, ImportDefaults? defaults = null) =>
        Import(File.ReadAllText(path), Path.GetFileName(path), defaults);

    public static ImportResult Import(string content, string fileName, ImportDefaults? defaults = null)
    {
        defaults ??= new ImportDefaults();
        var text = content.TrimStart('﻿');
        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        var trimmed = text.TrimStart();

        if (extension == ".json" || trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            var set = RuleSet.Parse(text, Path.GetFileNameWithoutExtension(fileName));
            var warnings = new List<string>();
            var rules = set.Rules.Where(r =>
            {
                if (!string.IsNullOrWhiteSpace(r.Program))
                {
                    return true;
                }

                warnings.Add($"Rule \"{r.Name}\" has no program – skipped.");
                return false;
            }).ToList();
            return new ImportResult("JSON", set.Name, rules, warnings);
        }

        if (extension == ".csv" || LooksLikeCsv(text))
        {
            return Csv(text, defaults);
        }

        return PlainText(text, defaults);
    }

    // ------------------------------------------------------------------ Text

    private static ImportResult PlainText(string text, ImportDefaults defaults)
    {
        var rules = new List<RuleDefinition>();
        var warnings = new List<string>();
        var lineNumber = 0;
        foreach (var raw in text.Split('\n'))
        {
            lineNumber++;
            var line = raw.Trim().Trim('\r');
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';') || line.StartsWith("//", StringComparison.Ordinal) || line.StartsWith("rem ", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var hash = HashLineRegex().Match(line);
            var path = (hash.Success ? hash.Groups[1].Value : line).Trim().Trim('"');
            if (!LooksLikePath(path))
            {
                warnings.Add($"Line {lineNumber}: \"{Shorten(line)}\" is not a program path – skipped.");
                continue;
            }

            rules.AddRange(Expand(path, defaults));
        }

        return new ImportResult("TXT", null, rules, warnings);
    }

    // ------------------------------------------------------------------ CSV

    private static readonly string[] ProgramColumns = ["program", "path", "programpath", "application", "applicationname", "app", "file", "dateipfad", "pfad", "programm", "anwendung", "datei"];
    private static readonly string[] NameColumns = ["name", "displayname", "rule", "regel", "bezeichnung"];
    private static readonly string[] DirectionColumns = ["direction", "dir", "richtung"];
    private static readonly string[] ActionColumns = ["action", "aktion", "status"];
    private static readonly string[] ScopeColumns = ["scope", "bereich"];
    private static readonly string[] RemoteColumns = ["remoteaddresses", "remoteaddress", "remoteip", "remote"];
    private static readonly string[] ProfileColumns = ["profiles", "profile", "profil", "profile(s)"];
    private static readonly string[] ServiceColumns = ["service", "servicename", "dienst"];
    private static readonly string[] EnabledColumns = ["enabled", "enable", "aktiviert", "active", "aktiv"];

    private static ImportResult Csv(string text, ImportDefaults defaults)
    {
        var lines = text.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Trim().Length > 0).ToList();
        var warnings = new List<string>();
        var rules = new List<RuleDefinition>();
        if (lines.Count == 0)
        {
            return new ImportResult("CSV", null, rules, warnings);
        }

        var delimiter = DetectDelimiter(lines[0]);
        var header = SplitCsv(lines[0], delimiter).Select(h => h.Trim().Replace(" ", "").Replace("-", "").ToLowerInvariant()).ToList();
        int Col(string[] names) => header.FindIndex(h => names.Contains(h));

        var program = Col(ProgramColumns);
        var start = 1;
        if (program < 0)
        {
            // No header: first column holding a path.
            var first = SplitCsv(lines[0], delimiter);
            program = first.FindIndex(LooksLikePath);
            start = 0;
            if (program < 0)
            {
                warnings.Add("No program/path column found.");
                return new ImportResult("CSV", null, rules, warnings);
            }
        }

        var name = start == 1 ? Col(NameColumns) : -1;
        var direction = start == 1 ? Col(DirectionColumns) : -1;
        var action = start == 1 ? Col(ActionColumns) : -1;
        var scope = start == 1 ? Col(ScopeColumns) : -1;
        var remote = start == 1 ? Col(RemoteColumns) : -1;
        var profiles = start == 1 ? Col(ProfileColumns) : -1;
        var enabled = start == 1 ? Col(EnabledColumns) : -1;
        var service = start == 1 ? Col(ServiceColumns) : -1;

        for (var i = start; i < lines.Count; i++)
        {
            var fields = SplitCsv(lines[i], delimiter);
            string? Field(int index) => index >= 0 && index < fields.Count ? fields[index].Trim() : null;

            var path = Field(program)?.Trim('"');
            if (string.IsNullOrWhiteSpace(path) || !LooksLikePath(path))
            {
                warnings.Add($"Row {i + 1}: no program path – skipped.");
                continue;
            }

            var scopeValue = ParseScope(Field(scope), Field(remote), out var customAddresses) ?? defaults.Scope;
            var directionValue = ParseDirection(Field(direction));
            var directions = directionValue is null ? RulePlanner.Directions(defaults.Direction) : [directionValue.Value];
            foreach (var dir in directions)
            {
                rules.Add(new RuleDefinition
                {
                    Name = Field(name) ?? "",
                    Program = path,
                    Service = string.IsNullOrWhiteSpace(Field(service)) ? null : Field(service),
                    Direction = dir,
                    Action = ParseAction(Field(action)) ?? defaults.Action,
                    Scope = scopeValue,
                    RemoteAddresses = scopeValue == RuleScope.Custom ? customAddresses : null,
                    Profiles = ParseProfiles(Field(profiles)) ?? defaults.Profiles,
                    Enabled = ParseBool(Field(enabled)) ?? true
                });
            }
        }

        return new ImportResult("CSV", null, rules, warnings);
    }

    internal static char DetectDelimiter(string headerLine)
    {
        char[] candidates = [';', ',', '\t', '|'];
        return candidates.OrderByDescending(c => SplitCsv(headerLine, c).Count).First();
    }

    /// <summary>RFC 4180 field split for one line (quoted fields, doubled quotes).</summary>
    internal static List<string> SplitCsv(string line, char delimiter)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        quoted = false;
                    }
                }
                else
                {
                    current.Append(c);
                }
            }
            else if (c == '"')
            {
                quoted = true;
            }
            else if (c == delimiter)
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        fields.Add(current.ToString());

        // Values protected against formula injection on export ("'=…") come back without the apostrophe.
        return fields.Select(f => f.Length > 1 && f[0] == '\'' && f[1] is '=' or '+' or '-' or '@' ? f[1..] : f).ToList();
    }

    private static bool LooksLikeCsv(string text)
    {
        var first = text.Split('\n').FirstOrDefault(l => l.Trim().Length > 0) ?? "";
        return (first.Contains(';') || first.Contains('\t') || first.Count(c => c == ',') >= 2)
               && ProgramColumns.Any(c => first.Replace(" ", "").Contains(c, StringComparison.OrdinalIgnoreCase));
    }

    // ------------------------------------------------------------------ Values

    internal static RuleDirection? ParseDirection(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "out" or "outbound" or "ausgehend" or "2" or "egress" => RuleDirection.Outbound,
        "in" or "inbound" or "eingehend" or "1" or "ingress" => RuleDirection.Inbound,
        _ => null
    };

    internal static RuleAction? ParseAction(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "block" or "blocked" or "blockieren" or "blockiert" or "deny" or "drop" or "0" => RuleAction.Block,
        "allow" or "allowed" or "zulassen" or "erlauben" or "erlaubt" or "permit" or "1" => RuleAction.Allow,
        _ => null
    };

    internal static bool? ParseBool(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "true" or "yes" or "ja" or "1" or "on" or "enabled" or "aktiv" => true,
        "false" or "no" or "nein" or "0" or "off" or "disabled" or "inaktiv" => false,
        _ => null
    };

    public static FirewallProfiles? ParseProfiles(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim().ToLowerInvariant();
        if (text is "all" or "any" or "alle" or "*")
        {
            return FirewallProfiles.All;
        }

        var result = FirewallProfiles.None;
        foreach (var part in text.Split(new[] { '|', ',', ' ', '+', '/' }, StringSplitOptions.RemoveEmptyEntries))
        {
            result |= part switch
            {
                "domain" or "domäne" => FirewallProfiles.Domain,
                "private" or "privat" => FirewallProfiles.Private,
                "public" or "öffentlich" => FirewallProfiles.Public,
                _ => FirewallProfiles.None
            };
        }

        return result == FirewallProfiles.None ? null : result;
    }

    private static RuleScope? ParseScope(string? scope, string? remote, out string? custom)
    {
        custom = null;
        var s = scope?.Trim().ToLowerInvariant();
        switch (s)
        {
            case "internet" or "internetonly" or "nur internet":
                return RuleScope.Internet;
            case "all" or "any" or "alle" or "*":
                return RuleScope.All;
            case "custom":
                custom = string.IsNullOrWhiteSpace(remote) ? null : remote;
                return custom is null ? RuleScope.All : RuleScope.Custom;
        }

        if (!string.IsNullOrWhiteSpace(remote))
        {
            var r = remote.Trim();
            if (r.Equals("internet", StringComparison.OrdinalIgnoreCase))
            {
                return RuleScope.Internet;
            }

            var detected = InternetRanges.DetectScope(r);
            if (detected == RuleScope.Custom)
            {
                custom = r;
            }

            return detected;
        }

        return null;
    }

    private static IEnumerable<RuleDefinition> Expand(string path, ImportDefaults defaults) =>
        RulePlanner.Directions(defaults.Direction).Select(direction => new RuleDefinition
        {
            Program = path,
            Direction = direction,
            Action = defaults.Action,
            Scope = defaults.Scope,
            Profiles = defaults.Profiles
        });

    /// <summary>Drive path, UNC path or a path starting with an environment variable.</summary>
    internal static bool LooksLikePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var v = value.Trim().Trim('"');
        return (v.Length > 3 && char.IsLetter(v[0]) && v[1] == ':' && v[2] is '\\' or '/')
               || v.StartsWith(@"\\", StringComparison.Ordinal)
               || (v.StartsWith('%') && v.IndexOf('%', 1) > 1);
    }

    private static string Shorten(string value) => value.Length > 60 ? value[..57] + "…" : value;
}
