using System.Text.Json;
using PortShield.Core.Models;
using PortShield.Core.Storage;

namespace PortShield.Core.RuleSets;

/// <summary>
/// A named list of rule definitions – the native PortShield exchange format (JSON). Program paths may use environment
/// variables and * wildcards, so one rule set works on many machines ("%ProgramFiles%\Adobe\Adobe Photoshop *\Photoshop.exe").
/// </summary>
public sealed record RuleSet
{
    public const string FormatName = "portshield.ruleset";

    public const int CurrentVersion = 1;

    public string Format { get; init; } = FormatName;

    public int Version { get; init; } = CurrentVersion;

    public string Name { get; init; } = "";

    public string? Description { get; init; }

    public string? Author { get; init; }

    public DateTime? Created { get; init; }

    /// <summary>App and version that wrote the file ("PortShield 0.0.1").</summary>
    public string? Generator { get; init; }

    public List<RuleDefinition> Rules { get; init; } = [];

    public static RuleSet Load(string path)
    {
        var text = File.ReadAllText(path);
        return Parse(text, Path.GetFileNameWithoutExtension(path));
    }

    /// <summary>Reads a rule set or a plain JSON array of rules.</summary>
    public static RuleSet Parse(string json, string fallbackName)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
        if (document.RootElement.ValueKind == JsonValueKind.Array)
        {
            var rules = document.RootElement.Deserialize<List<RuleDefinition>>(PortShieldJson.Options) ?? [];
            return new RuleSet { Name = fallbackName, Rules = rules };
        }

        var set = document.RootElement.Deserialize<RuleSet>(PortShieldJson.Options)
                  ?? throw new InvalidDataException("Empty rule set.");
        if (!string.Equals(set.Format, FormatName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"Not a PortShield rule set (format \"{set.Format}\").");
        }

        if (set.Version > CurrentVersion)
        {
            throw new InvalidDataException($"Rule set version {set.Version} is newer than this PortShield supports ({CurrentVersion}).");
        }

        return string.IsNullOrWhiteSpace(set.Name) ? set with { Name = fallbackName } : set;
    }

    public string ToJson() => JsonSerializer.Serialize(this, PortShieldJson.Options);

    public void Save(string path) => JsonFile.Write(path, this);
}

/// <summary>
/// Several rule sets in one file ("portshield.rulesets") – to move all own rule sets to another PC at once.
/// </summary>
public sealed record RuleSetBundle
{
    public const string FormatName = "portshield.rulesets";

    public string Format { get; init; } = FormatName;

    public int Version { get; init; } = RuleSet.CurrentVersion;

    public DateTime? Created { get; init; }

    public string? Generator { get; init; }

    public string? Machine { get; init; }

    public List<RuleSet> Sets { get; init; } = [];

    public string ToJson() => JsonSerializer.Serialize(this, PortShieldJson.Options);

    /// <summary>Reads a bundle, a single rule set or a plain array of rules (always returns a list of sets).</summary>
    public static IReadOnlyList<RuleSet> ParseAny(string json, string fallbackName)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
        if (document.RootElement.ValueKind == JsonValueKind.Object
            && document.RootElement.TryGetProperty("format", out var format)
            && string.Equals(format.GetString(), FormatName, StringComparison.OrdinalIgnoreCase))
        {
            var bundle = document.RootElement.Deserialize<RuleSetBundle>(PortShieldJson.Options) ?? throw new InvalidDataException("Empty bundle.");
            if (bundle.Version > RuleSet.CurrentVersion)
            {
                throw new InvalidDataException($"Bundle version {bundle.Version} is newer than this PortShield supports ({RuleSet.CurrentVersion}).");
            }

            return bundle.Sets.Select((s, i) => string.IsNullOrWhiteSpace(s.Name) ? s with { Name = $"{fallbackName} {i + 1}" } : s).ToList();
        }

        return [RuleSet.Parse(json, fallbackName)];
    }
}

/// <summary>A rule set file with its origin (shipped preset or own).</summary>
public sealed record RuleSetFile(string Path, RuleSet Set, bool IsPreset)
{
    public static IReadOnlyList<RuleSetFile> LoadFolder(string folder, bool isPreset, ICollection<string>? errors = null)
    {
        if (!Directory.Exists(folder))
        {
            return [];
        }

        var result = new List<RuleSetFile>();
        foreach (var file in Directory.EnumerateFiles(folder, "*.json").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                result.Add(new RuleSetFile(file, RuleSet.Load(file), isPreset));
            }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException or UnauthorizedAccessException)
            {
                errors?.Add($"{System.IO.Path.GetFileName(file)}: {ex.Message}");
            }
        }

        return result;
    }
}
