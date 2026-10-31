using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.RuleSets;

namespace PortShield.App.ViewModels;

/// <summary>One line of the rule set editor: program path or pattern, optional service, direction, action, scope.</summary>
public sealed partial class RuleSetEntry : ObservableObject
{
    [ObservableProperty]
    private string _program = "";

    [ObservableProperty]
    private string _service = "";

    /// <summary>0 outbound · 1 inbound · 2 both.</summary>
    [ObservableProperty]
    private int _directionIndex;

    /// <summary>0 block · 1 allow.</summary>
    [ObservableProperty]
    private int _actionIndex;

    /// <summary>0 all addresses · 1 internet only.</summary>
    [ObservableProperty]
    private int _scopeIndex;

    /// <summary>"3 found" – programs this line matches on this PC.</summary>
    [ObservableProperty]
    private string _foundText = "";

    [ObservableProperty]
    private bool _found;

    partial void OnProgramChanged(string value) => FoundText = "";

    /// <summary>Programs the line matches on this PC (file system only – may run in the background).</summary>
    public static int Count(string program) =>
        string.IsNullOrWhiteSpace(program) ? 0
        : ProgramPaths.HasWildcard(program) ? ProgramPaths.Resolve(program).Count
        : File.Exists(ProgramPaths.Expand(program)) ? 1 : 0;

    /// <summary>Shows the result (UI thread).</summary>
    public void SetCount(int count)
    {
        Found = count > 0;
        FoundText = Loc.F("EditorFound", count);
    }

    public void Check() => SetCount(Count(Program));

    public IEnumerable<RuleDefinition> ToDefinitions()
    {
        var directions = DirectionIndex switch
        {
            1 => new[] { RuleDirection.Inbound },
            2 => new[] { RuleDirection.Outbound, RuleDirection.Inbound },
            _ => new[] { RuleDirection.Outbound }
        };
        return directions.Select(d => new RuleDefinition
        {
            Program = Program.Trim().Trim('"'),
            Service = string.IsNullOrWhiteSpace(Service) ? null : Service.Trim(),
            Direction = d,
            Action = ActionIndex == 1 ? RuleAction.Allow : RuleAction.Block,
            Scope = ScopeIndex == 1 ? RuleScope.Internet : RuleScope.All
        });
    }
}

/// <summary>
/// Editor for own rule sets: name, description and lines of programs, folders or patterns (%ProgramFiles%, *, **).
/// Opened for a new set, to edit an own set or to copy a preset.
/// </summary>
public sealed partial class RuleSetEditorModel : ObservableObject
{
    private readonly MainViewModel _main;

    public RuleSetEditorModel(MainViewModel main, RuleSet? source, string title)
    {
        _main = main;
        Title = title;
        _name = source?.Name ?? "";
        _description = source?.Description ?? "";
        if (source is not null)
        {
            foreach (var entry in FromDefinitions(source.Rules))
            {
                Entries.Add(entry);
            }
        }

        Original = source;
    }

    public string Title { get; }

    /// <summary>The set that was opened (null for a new one) – unknown fields are kept when saving.</summary>
    public RuleSet? Original { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    private string _name;

    [ObservableProperty]
    private string _description;

    /// <summary>"Add folder" also covers its sub folders (pattern folder\**\*.exe).</summary>
    [ObservableProperty]
    private bool _includeSubfolders = true;

    public ObservableCollection<RuleSetEntry> Entries { get; } = [];

    public bool CanSave => !string.IsNullOrWhiteSpace(Name);

    public IReadOnlyList<string> Directions => [Loc.T("DirOut"), Loc.T("DirIn"), Loc.T("DirBoth")];

    public IReadOnlyList<string> Actions => [Loc.T("ActionBlock"), Loc.T("ActionAllow")];

    public IReadOnlyList<string> Scopes => [Loc.T("ScopeAll"), Loc.T("ScopeInternet")];

    public bool HasEntries => Entries.Count > 0;

    // ------------------------------------------------------------------ Lines

    [RelayCommand]
    private async Task AddFilesAsync()
    {
        var files = await _main.Host.PickFilesAsync(Loc.T("PickApplications"), Loc.T("FileTypePrograms"), MainViewModel.ExePatterns, multiple: true);
        foreach (var file in files)
        {
            Add(ProgramPaths.ToPortable(file));
        }
    }

    [RelayCommand]
    private async Task AddFolderAsync()
    {
        var folder = await _main.Host.PickFolderAsync(Loc.T("PickFolder"));
        if (!string.IsNullOrEmpty(folder))
        {
            var portable = ProgramPaths.ToPortable(folder).TrimEnd('\\');
            Add(portable + (IncludeSubfolders ? @"\**\*.exe" : @"\*.exe"));
        }
    }

    [RelayCommand]
    private void AddLine() => Add("");

    [RelayCommand]
    private void Remove(RuleSetEntry? entry)
    {
        if (entry is not null)
        {
            Entries.Remove(entry);
            OnPropertyChanged(nameof(HasEntries));
        }
    }

    /// <summary>Counts the programs every line finds on this PC.</summary>
    [RelayCommand]
    private async Task CheckAsync()
    {
        var entries = Entries.ToList();
        var programs = entries.Select(e => e.Program).ToList();
        var counts = await Task.Run(() => programs.Select(RuleSetEntry.Count).ToList());
        for (var i = 0; i < entries.Count; i++)
        {
            entries[i].SetCount(counts[i]);
        }
    }

    private void Add(string program)
    {
        var entry = new RuleSetEntry
        {
            Program = program,
            DirectionIndex = _main.Ui.DefaultDirection switch { DirectionChoice.Inbound => 1, DirectionChoice.Both => 2, _ => 0 },
            ActionIndex = _main.Ui.DefaultAction == RuleAction.Allow ? 1 : 0,
            ScopeIndex = _main.Ui.DefaultScope == RuleScope.Internet ? 1 : 0
        };
        if (program.Length > 0)
        {
            entry.Check();
        }

        Entries.Add(entry);
        OnPropertyChanged(nameof(HasEntries));
    }

    // ------------------------------------------------------------------ Result

    public RuleSet Build() => new()
    {
        Name = Name.Trim(),
        Description = string.IsNullOrWhiteSpace(Description) ? null : Description.Trim(),
        Author = Original?.Author ?? Environment.UserName,
        Created = Original?.Created ?? DateTime.Now,
        Generator = AppEnvironment.Generator,
        Rules = Entries.Where(e => !string.IsNullOrWhiteSpace(e.Program)).SelectMany(e => e.ToDefinitions()).ToList()
    };

    /// <summary>Lines from definitions: an outbound and an inbound rule with the same settings become one line "both".</summary>
    private static IEnumerable<RuleSetEntry> FromDefinitions(IReadOnlyList<RuleDefinition> rules)
    {
        var used = new HashSet<int>();
        for (var i = 0; i < rules.Count; i++)
        {
            if (used.Contains(i))
            {
                continue;
            }

            var r = rules[i];
            var pair = -1;
            for (var j = i + 1; j < rules.Count && pair < 0; j++)
            {
                var o = rules[j];
                if (!used.Contains(j) && o.Direction != r.Direction && string.Equals(o.Program, r.Program, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(o.Service ?? "", r.Service ?? "", StringComparison.OrdinalIgnoreCase) && o.Action == r.Action && o.Scope == r.Scope)
                {
                    pair = j;
                }
            }

            if (pair >= 0)
            {
                used.Add(pair);
            }

            yield return new RuleSetEntry
            {
                Program = r.Program,
                Service = r.Service ?? "",
                DirectionIndex = pair >= 0 ? 2 : r.Direction == RuleDirection.Inbound ? 1 : 0,
                ActionIndex = r.Action == RuleAction.Allow ? 1 : 0,
                ScopeIndex = r.Scope == RuleScope.Internet ? 1 : 0
            };
        }
    }
}
