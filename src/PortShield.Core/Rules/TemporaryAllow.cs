using PortShield.Core.Storage;

namespace PortShield.Core.Rules;

/// <summary>A block rule that is allowed until <see cref="Until"/> (local time) and then blocked again.</summary>
public sealed record TemporaryEntry(string Id, string Name, DateTime Until);

/// <summary>Rules allowed for a limited time (%ProgramData%\PortShield\temporary.json).</summary>
public sealed record TemporaryList
{
    public List<TemporaryEntry> Entries { get; init; } = [];

    public static TemporaryList Load(string path)
    {
        try
        {
            return JsonFile.Read<TemporaryList>(path) ?? new TemporaryList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            return new TemporaryList();
        }
    }

    public void Save(string path) => JsonFile.Write(path, this);

    /// <summary>Adds or extends entries (one per rule id).</summary>
    public TemporaryList With(IEnumerable<TemporaryEntry> entries)
    {
        var map = Entries.ToDictionary(e => e.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            map[entry.Id] = entry;
        }

        return new TemporaryList { Entries = map.Values.OrderBy(e => e.Until).ToList() };
    }

    public TemporaryList Without(IEnumerable<string> ids)
    {
        var remove = ids.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return new TemporaryList { Entries = Entries.Where(e => !remove.Contains(e.Id)).ToList() };
    }

    public IReadOnlyList<TemporaryEntry> Due(DateTime now) => Entries.Where(e => e.Until <= now).ToList();

    public DateTime? Next => Entries.Count == 0 ? null : Entries.Min(e => e.Until);

    public TemporaryEntry? Find(string? id) =>
        id is null ? null : Entries.FirstOrDefault(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase));
}
