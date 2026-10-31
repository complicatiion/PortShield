using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Platform.Windows;

namespace PortShield.App.ViewModels;

/// <summary>One program (or one rule of a rule set) in the review dialog.</summary>
public sealed partial class AddItem : ObservableObject
{
    public required string Path { get; init; }

    public string FileName => Definition?.HasService == true ? Loc.F("ServiceName", Definition.Service) : ProgramPaths.FileName(Path);

    public string Folder => ProgramPaths.Directory(Path);

    public string? Description { get; init; }

    public string? Company { get; init; }

    public string Details => string.Join(" · ", new[] { Description, Company }.Where(s => !string.IsNullOrWhiteSpace(s)));

    public bool HasDetails => Details.Length > 0;

    /// <summary>Rule set / import mode: the fixed rule of this row.</summary>
    public RuleDefinition? Definition { get; init; }

    public bool HasDefinition => Definition is not null;

    public string DirectionText => Definition is null ? "" : Loc.T(Definition.Direction == RuleDirection.Outbound ? "DirOut" : "DirIn");

    public string ActionText => Definition is null ? "" : Loc.T(Definition.Action == RuleAction.Block ? "ActionBlock" : "ActionAllow");

    public bool IsBlock => Definition?.Action == RuleAction.Block;

    public bool IsAllow => Definition?.Action == RuleAction.Allow;

    internal Action? CheckedChanged { get; set; }

    [ObservableProperty]
    private bool _isChecked = true;

    partial void OnIsCheckedChanged(bool value) => CheckedChanged?.Invoke();

    [ObservableProperty]
    private string _statusText = "";

    [ObservableProperty]
    private string? _warning;

    [ObservableProperty]
    private bool _isNew;

    [ObservableProperty]
    private bool _isUpdate;

    [ObservableProperty]
    private bool _isSame;

    [ObservableProperty]
    private bool _isSkipped;

    public bool HasWarning => !string.IsNullOrEmpty(Warning);

    partial void OnWarningChanged(string? value) => OnPropertyChanged(nameof(HasWarning));
}

/// <summary>
/// Review dialog for new rules: from files, a folder, running programs, an import or a rule set. Shows per program
/// whether a rule is created, updated, already exists or is skipped (protected, missing, duplicate) – nothing is written
/// before the user confirms.
/// </summary>
public sealed partial class AddRulesModel : ObservableObject
{
    private readonly MainViewModel _main;
    private readonly IReadOnlyList<string> _files;
    private readonly string? _folder;
    private readonly IReadOnlyList<RuleDefinition>? _definitions;
    private IReadOnlyList<PlanItem> _plan = [];
    private bool _ready;

    private AddRulesModel(MainViewModel main, string title, string? subtitle, IReadOnlyList<string> files, string? folder,
        IReadOnlyList<RuleDefinition>? definitions, DirectionChoice direction)
    {
        _main = main;
        _files = files;
        _folder = folder;
        _definitions = definitions;
        Title = title;
        Subtitle = subtitle;

        var ui = main.Ui;
        _directionOut = direction == DirectionChoice.Outbound;
        _directionIn = direction == DirectionChoice.Inbound;
        _directionBoth = direction == DirectionChoice.Both;
        _actionBlock = ui.DefaultAction == RuleAction.Block;
        _actionAllow = ui.DefaultAction == RuleAction.Allow;
        _scopeAll = ui.DefaultScope != RuleScope.Internet;
        _scopeInternet = ui.DefaultScope == RuleScope.Internet;
        _profileDomain = ui.DefaultProfiles.HasFlag(FirewallProfiles.Domain);
        _profilePrivate = ui.DefaultProfiles.HasFlag(FirewallProfiles.Private);
        _profilePublic = ui.DefaultProfiles.HasFlag(FirewallProfiles.Public);
        _recursive = ui.ScanRecursive;
        _skipInstallers = ui.ScanSkipInstallers;
    }

    public static AddRulesModel ForPaths(MainViewModel main, IReadOnlyList<string> files, string? folder, DirectionChoice direction) =>
        new(main, Loc.T(folder is null ? "AddTitle" : "AddFolderTitle"), folder, files, folder, null, direction);

    /// <summary>A plain path list (TXT import): direction, action and scope are chosen in the dialog.</summary>
    public static AddRulesModel ForPathsFromImport(MainViewModel main, IReadOnlyList<string> paths, string fileName) =>
        new(main, Loc.F("ImportReviewTitle", fileName), null, paths, null, null, main.Ui.DefaultDirection);

    public static AddRulesModel ForDefinitions(MainViewModel main, string title, string? subtitle, IReadOnlyList<RuleDefinition> definitions) =>
        new(main, title, subtitle, [], null, definitions, DirectionChoice.Outbound);

    public string Title { get; }

    public string? Subtitle { get; }

    public bool HasSubtitle => !string.IsNullOrEmpty(Subtitle);

    /// <summary>Plain paths: direction, action, scope and profiles are chosen here. Rule sets and imports bring their own.</summary>
    public bool UsesOptions => _definitions is null;

    public bool IsFolder => _folder is not null;

    public ObservableCollection<AddItem> Items { get; } = [];

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _summary = "";

    [ObservableProperty]
    private bool _canConfirm;

    [ObservableProperty]
    private string _search = "";

    partial void OnSearchChanged(string value) => OnPropertyChanged(nameof(VisibleItems));

    public IEnumerable<AddItem> VisibleItems => string.IsNullOrWhiteSpace(Search)
        ? Items
        : Items.Where(i => i.Path.Contains(Search.Trim(), StringComparison.OrdinalIgnoreCase)
                           || (i.Description?.Contains(Search.Trim(), StringComparison.OrdinalIgnoreCase) ?? false));

    // ------------------------------------------------------------------ Options

    [ObservableProperty]
    private bool _directionOut;

    [ObservableProperty]
    private bool _directionIn;

    [ObservableProperty]
    private bool _directionBoth;

    [ObservableProperty]
    private bool _actionBlock;

    [ObservableProperty]
    private bool _actionAllow;

    [ObservableProperty]
    private bool _scopeAll;

    [ObservableProperty]
    private bool _scopeInternet;

    [ObservableProperty]
    private bool _profileDomain;

    [ObservableProperty]
    private bool _profilePrivate;

    [ObservableProperty]
    private bool _profilePublic;

    [ObservableProperty]
    private bool _enableRules = true;

    [ObservableProperty]
    private bool _recursive;

    [ObservableProperty]
    private bool _skipInstallers;

    partial void OnDirectionOutChanged(bool value) => Recompute();

    partial void OnDirectionInChanged(bool value) => Recompute();

    partial void OnDirectionBothChanged(bool value) => Recompute();

    partial void OnActionBlockChanged(bool value) => Recompute();

    partial void OnActionAllowChanged(bool value) => Recompute();

    partial void OnScopeAllChanged(bool value) => Recompute();

    partial void OnScopeInternetChanged(bool value) => Recompute();

    partial void OnProfileDomainChanged(bool value) => Recompute();

    partial void OnProfilePrivateChanged(bool value) => Recompute();

    partial void OnProfilePublicChanged(bool value) => Recompute();

    partial void OnEnableRulesChanged(bool value) => Recompute();

    partial void OnRecursiveChanged(bool value) => _ = RescanAsync();

    partial void OnSkipInstallersChanged(bool value) => _ = RescanAsync();

    private DirectionChoice Direction => DirectionBoth ? DirectionChoice.Both : DirectionIn ? DirectionChoice.Inbound : DirectionChoice.Outbound;

    private RuleAction Action => ActionAllow ? RuleAction.Allow : RuleAction.Block;

    private RuleScope Scope => ScopeInternet ? RuleScope.Internet : RuleScope.All;

    private FirewallProfiles Profiles
    {
        get
        {
            var p = FirewallProfiles.None;
            if (ProfileDomain)
            {
                p |= FirewallProfiles.Domain;
            }

            if (ProfilePrivate)
            {
                p |= FirewallProfiles.Private;
            }

            if (ProfilePublic)
            {
                p |= FirewallProfiles.Public;
            }

            return p;
        }
    }

    // ------------------------------------------------------------------ Loading

    /// <summary>Scans the folder / reads the version info of every program (background thread).</summary>
    public async Task PrepareAsync()
    {
        IsLoading = true;
        try
        {
            var folder = _folder;
            var files = _files;
            var definitions = _definitions;
            var recursive = Recursive;
            var skipInstallers = SkipInstallers;
            var items = await Task.Run(() => Load(files, folder, definitions, recursive, skipInstallers));
            Items.Clear();
            foreach (var item in items)
            {
                item.CheckedChanged = Recompute;
                Items.Add(item);
            }

            _ready = true;
            Recompute();
            OnPropertyChanged(nameof(VisibleItems));
        }
        finally
        {
            IsLoading = false;
        }
    }

    private static List<AddItem> Load(IReadOnlyList<string> files, string? folder, IReadOnlyList<RuleDefinition>? definitions, bool recursive, bool skipInstallers)
    {
        if (definitions is not null)
        {
            return definitions.Select(d =>
            {
                var facts = FileInspector.Read(ProgramPaths.Expand(d.Program));
                return new AddItem { Path = ProgramPaths.Expand(d.Program), Definition = d, Description = facts.Description, Company = facts.Company };
            }).ToList();
        }

        var paths = folder is null ? files : ProgramPaths.FindExecutables(folder, recursive);
        return paths
            .Where(p => !(skipInstallers && folder is not null && ProgramPaths.IsInstaller(p)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(p =>
            {
                var facts = FileInspector.Read(p);
                return new AddItem { Path = p, Description = facts.Description, Company = facts.Company };
            })
            .ToList();
    }

    private async Task RescanAsync()
    {
        if (_ready && IsFolder)
        {
            await PrepareAsync();
        }
    }

    // ------------------------------------------------------------------ Plan

    private IReadOnlyList<RuleDefinition> Definitions(IEnumerable<AddItem> items)
    {
        if (!UsesOptions)
        {
            return items.Where(i => i.Definition is not null).Select(i => i.Definition! with { Program = i.Path }).ToList();
        }

        var profiles = Profiles == FirewallProfiles.None ? FirewallProfiles.All : Profiles;
        return items.SelectMany(i => RulePlanner.Directions(Direction).Select(direction => new RuleDefinition
        {
            Program = i.Path,
            Direction = direction,
            Action = Action,
            Scope = Scope,
            Profiles = profiles,
            Enabled = EnableRules
        })).ToList();
    }

    private void Recompute()
    {
        if (!_ready)
        {
            return;
        }

        var selected = Items.Where(i => i.IsChecked).ToList();
        _plan = _main.Firewall.Plan(Definitions(selected));
        var byProgram = _plan.ToLookup(p => ProgramPaths.Key(p.Definition.Program));

        foreach (var item in Items)
        {
            var entries = byProgram[ProgramPaths.Key(item.Path)].ToList();
            if (!UsesOptions && item.Definition is not null)
            {
                entries = entries.Where(e => e.Definition.Direction == item.Definition.Direction
                                             && RulePlanner.ServiceKey(e.Definition.Service) == RulePlanner.ServiceKey(item.Definition.Service)).ToList();
            }

            item.IsNew = item.IsUpdate = item.IsSame = item.IsSkipped = false;
            item.Warning = null;
            if (!item.IsChecked || entries.Count == 0)
            {
                item.StatusText = Loc.T("AddStatusNotSelected");
                item.IsSkipped = true;
                continue;
            }

            if (entries.Any(e => e.Action == PlanAction.Create))
            {
                item.StatusText = Loc.T("AddStatusNew");
                item.IsNew = true;
            }
            else if (entries.Any(e => e.Action == PlanAction.Update))
            {
                item.StatusText = Loc.T("AddStatusUpdate");
                item.IsUpdate = true;
            }
            else if (entries.All(e => e.Action == PlanAction.Unchanged))
            {
                item.StatusText = Loc.T("AddStatusExists");
                item.IsSame = true;
            }
            else
            {
                var reason = entries.First(e => !e.WillChange && e.Action != PlanAction.Unchanged).Action;
                item.StatusText = Loc.T(reason switch
                {
                    PlanAction.Protected => "AddStatusProtected",
                    PlanAction.Missing => "AddStatusMissing",
                    _ => "AddStatusDuplicate"
                });
                item.IsSkipped = true;
            }

            if (entries.Any(e => e.BlockedByOtherRule))
            {
                item.Warning = Loc.T("AddWarnBlockedByOther");
            }
        }

        var create = _plan.Count(p => p.Action == PlanAction.Create);
        var update = _plan.Count(p => p.Action == PlanAction.Update);
        var same = _plan.Count(p => p.Action == PlanAction.Unchanged);
        var skipped = _plan.Count(p => !p.WillChange && p.Action != PlanAction.Unchanged);
        Summary = Loc.F("AddSummary", create, update, same, skipped);
        CanConfirm = create + update > 0;
    }

    /// <summary>Changes to write (create and update); remembers the chosen action and scope as new defaults.</summary>
    public IReadOnlyList<PlanItem> BuildPlan()
    {
        if (UsesOptions)
        {
            _main.Ui.DefaultAction = Action;
            _main.Ui.DefaultScope = Scope;
            _main.Ui.Save();
        }

        return _plan.Where(p => p.WillChange).ToList();
    }

    [RelayCommand]
    private void CheckAll()
    {
        foreach (var item in Items)
        {
            item.CheckedChanged = null;
            item.IsChecked = true;
            item.CheckedChanged = Recompute;
        }

        Recompute();
    }

    [RelayCommand]
    private void CheckNone()
    {
        foreach (var item in Items)
        {
            item.CheckedChanged = null;
            item.IsChecked = false;
            item.CheckedChanged = Recompute;
        }

        Recompute();
    }
}
