using PortShield.Core.Storage;

namespace PortShield.Core.RuleSets;

/// <summary>An applied rule set PortShield checks for new programs (e.g. a new Adobe or Cinema 4D version folder).</summary>
public sealed record WatchEntry
{
    /// <summary>File name of the rule set (preset or own set).</summary>
    public required string File { get; init; }

    public bool IsPreset { get; init; }

    public string Name { get; init; } = "";

    public DateTime Applied { get; init; } = DateTime.Now;

    /// <summary>Programs the user does not want a rule for ("Ignore" on the overview): program key + direction.</summary>
    public List<string> Ignored { get; init; } = [];

    public static string IgnoreKey(string program, string? service, Models.RuleDirection direction) =>
        Rules.ProgramPaths.Key(program) + "|" + Rules.RulePlanner.ServiceKey(service) + "|" + direction;
}

/// <summary>%ProgramData%\PortShield\watch.json.</summary>
public sealed record WatchList
{
    public List<WatchEntry> Sets { get; init; } = [];

    public static WatchList Load(string path)
    {
        try
        {
            return JsonFile.Read<WatchList>(path) ?? new WatchList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            return new WatchList();
        }
    }

    public void Save(string path) => JsonFile.Write(path, this);

    public bool Contains(string file, bool isPreset) =>
        Sets.Any(s => s.IsPreset == isPreset && string.Equals(s.File, file, StringComparison.OrdinalIgnoreCase));

    public WatchList With(WatchEntry entry) => new()
    {
        Sets = Sets.Where(s => !(s.IsPreset == entry.IsPreset && string.Equals(s.File, entry.File, StringComparison.OrdinalIgnoreCase)))
            .Append(entry).ToList()
    };

    public WatchEntry? Find(string file, bool isPreset) =>
        Sets.FirstOrDefault(s => s.IsPreset == isPreset && string.Equals(s.File, file, StringComparison.OrdinalIgnoreCase));

    public WatchList Without(string file, bool isPreset) => new()
    {
        Sets = Sets.Where(s => !(s.IsPreset == isPreset && string.Equals(s.File, file, StringComparison.OrdinalIgnoreCase))).ToList()
    };
}
