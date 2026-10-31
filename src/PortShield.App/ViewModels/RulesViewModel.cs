using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Export;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Platform.Windows;

namespace PortShield.App.ViewModels;

/// <summary>One firewall rule in the list.</summary>
public sealed partial class RuleRow : ObservableObject
{
    public RuleRow(FirewallRuleInfo info)
    {
        Info = info;
    }

    public FirewallRuleInfo Info { get; }

    /// <summary>Allowed temporarily until this time (then blocked again).</summary>
    public DateTime? TemporaryUntil { get; init; }

    public bool IsTemporary => TemporaryUntil is not null;

    public string TemporaryText => TemporaryUntil is { } until ? Loc.F("BadgeTemporary", until.ToString("t")) : "";

    public string Name => Info.Name;

    public string Program => Info.Program;

    public string ExpandedProgram => Info.ExpandedProgram;

    public bool HasProgram => Info.HasProgram;

    public string FileName => Info.HasService ? Loc.F("ServiceName", Info.Service) : HasProgram ? ProgramPaths.FileName(Info.Program) : Loc.T("NoProgram");

    public string Folder => HasProgram ? (Info.HasService ? Info.ExpandedProgram : ProgramPaths.Directory(Info.ExpandedProgram)) : "";

    public bool IsBlock => Info.Action == RuleAction.Block;

    public bool IsAllow => !IsBlock;

    public string ActionText => Loc.T(IsBlock ? "ActionBlock" : "ActionAllow");

    public bool Enabled => Info.Enabled;

    public string EnabledText => Loc.T(Info.Enabled ? "Yes" : "No");

    public bool IsInternetScope => Info.Scope == RuleScope.Internet;

    public string ScopeText => Loc.T(Info.Scope switch
    {
        RuleScope.Internet => "ScopeInternet",
        RuleScope.Custom => "ScopeCustom",
        _ => "ScopeAll"
    });

    public string ScopeTip => Info.Scope == RuleScope.Custom ? Info.RemoteAddresses : ScopeText;

    public string ProfilesText => Info.Profiles is FirewallProfiles.All or FirewallProfiles.None
        ? Loc.T("ProfilesAll")
        : string.Join(", ", new[]
            {
                Info.Profiles.HasFlag(FirewallProfiles.Domain) ? Loc.T("ProfileDomain") : null,
                Info.Profiles.HasFlag(FirewallProfiles.Private) ? Loc.T("ProfilePrivate") : null,
                Info.Profiles.HasFlag(FirewallProfiles.Public) ? Loc.T("ProfilePublic") : null
            }.Where(s => s is not null));

    public bool IsPortShield => Info.IsPortShield;

    public string OriginText => IsPortShield ? "PortShield" : string.IsNullOrEmpty(Info.Grouping) ? Loc.T("OriginOther") : Loc.T("OriginWindows");

    public string Tooltip => Info.Name + Environment.NewLine + Info.ExpandedProgram + (string.IsNullOrEmpty(Info.Description) ? "" : Environment.NewLine + RuleNaming.StripMarker(Info.Description));

    /// <summary>Company from the version info (loaded in the background).</summary>
    [ObservableProperty]
    private string? _publisher;

    /// <summary>The program file exists (false: rule points to a deleted or moved program).</summary>
    [ObservableProperty]
    private bool _fileExists = true;

    public bool IsMissing => HasProgram && !FileExists;

    partial void OnFileExistsChanged(bool value) => OnPropertyChanged(nameof(IsMissing));

    public void RefreshText()
    {
        OnPropertyChanged(nameof(ActionText));
        OnPropertyChanged(nameof(EnabledText));
        OnPropertyChanged(nameof(ScopeText));
        OnPropertyChanged(nameof(ProfilesText));
        OnPropertyChanged(nameof(OriginText));
        OnPropertyChanged(nameof(TemporaryText));
        OnPropertyChanged(nameof(FileName));
        OnPropertyChanged(nameof(Folder));
    }
}

public enum SelectionRequest
{
    All,
    None,
    Invert
}

/// <summary>Outbound or inbound rules: list, filters, command bar and context menu actions on the selection.</summary>
public sealed partial class RulesViewModel : PageViewModel
{
    private readonly RuleDirection _direction;
    private List<RuleRow> _all = [];
    private IReadOnlyList<RuleRow> _selected = [];
    private CancellationTokenSource? _factsCts;

    public RulesViewModel(MainViewModel main, RuleDirection direction) : base(main)
    {
        _direction = direction;
        _showAll = main.Ui.ShowAllRules;
    }

    public override string TitleKey => _direction == RuleDirection.Outbound ? "NavOutbound" : "NavInbound";

    public bool IsOutbound => _direction == RuleDirection.Outbound;

    private DirectionChoice Choice => IsOutbound ? DirectionChoice.Outbound : DirectionChoice.Inbound;

    public ObservableCollection<RuleRow> Rows { get; } = [];

    /// <summary>The view selects rows (select all, none, invert) – DataGrid selection is not bindable.</summary>
    public event Action<SelectionRequest>? SelectionRequested;

    /// <summary>After a reload: rows the view should select again (same rule as before the change).</summary>
    public event Action<IReadOnlyList<RuleRow>>? SelectionRestoreRequested;

    public void NotifyBusy() => OnPropertyChanged(nameof(IsEmpty));

    private static string Identity(FirewallRuleInfo r) => r.PortShieldId is { } id
        ? id + "|" + r.Direction
        : r.Name + "|" + ProgramPaths.Key(r.Program) + "|" + r.Direction + "|" + r.Action;

    // ------------------------------------------------------------------ Filters

    [ObservableProperty]
    private string _search = "";

    /// <summary>0 all · 1 blocked · 2 allowed · 3 disabled · 4 program missing.</summary>
    [ObservableProperty]
    private int _filterIndex;

    /// <summary>Also show program rules of Windows and other apps.</summary>
    [ObservableProperty]
    private bool _showAll;

    public IReadOnlyList<string> Filters =>
    [
        Loc.T("FilterAll"),
        Loc.T("FilterBlocked"),
        Loc.T("FilterAllowed"),
        Loc.T("FilterDisabled"),
        Loc.T("FilterMissing")
    ];

    partial void OnSearchChanged(string value) => ApplyFilter();

    partial void OnFilterIndexChanged(int value) => ApplyFilter();

    partial void OnShowAllChanged(bool value)
    {
        Ui.ShowAllRules = value;
        Ui.Save();
        Rebuild();
        var other = IsOutbound ? Main.Inbound : Main.Outbound;
        if (other.ShowAll != value)
        {
            other.ShowAll = value;
        }
    }

    public string CountText => Loc.F("RulesCount", Rows.Count, _all.Count);

    public string SelectionText => _selected.Count == 0 ? "" : Loc.F("RulesSelected", _selected.Count);

    public bool HasSelection => _selected.Count > 0;

    public bool HasSingleSelection => _selected.Count == 1;

    public bool HasRows => Rows.Count > 0;

    public bool IsEmpty => !Main.IsBusy && Rows.Count == 0;

    // ------------------------------------------------------------------ Lifecycle

    public override void OnActivated()
    {
        if (_all.Count == 0)
        {
            Rebuild();
        }
    }

    public override void OnRulesChanged() => Rebuild();

    public override void OnLanguageChanged()
    {
        base.OnLanguageChanged();
        OnPropertyChanged(nameof(Filters));
        OnPropertyChanged(nameof(FilterIndex));
        foreach (var row in _all)
        {
            row.RefreshText();
        }

        OnPropertyChanged(nameof(CountText));
        OnPropertyChanged(nameof(SelectionText));
    }

    private void Rebuild()
    {
        var keepPublisher = _all.Where(r => r.Publisher is not null).GroupBy(r => r.ExpandedProgram, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Publisher, StringComparer.OrdinalIgnoreCase);
        _all = Firewall.Rules
            .Where(r => r.Direction == _direction && !r.IsKillSwitch && (r.IsPortShield || (ShowAll && r.HasProgram)))
            .OrderByDescending(r => r.IsPortShield)
            .ThenBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(r => new RuleRow(r)
            {
                Publisher = keepPublisher.GetValueOrDefault(r.ExpandedProgram),
                TemporaryUntil = Firewall.Temporary.Find(r.PortShieldId)?.Until
            })
            .ToList();
        ApplyFilter();
        LoadFactsInBackground();
    }

    private void ApplyFilter()
    {
        var previous = _selected.Select(r => Identity(r.Info)).ToHashSet();
        var text = Search.Trim();
        Rows.Clear();
        foreach (var row in _all.Where(r =>
                     (text.Length == 0
                      || r.Name.Contains(text, StringComparison.OrdinalIgnoreCase)
                      || r.ExpandedProgram.Contains(text, StringComparison.OrdinalIgnoreCase)
                      || (r.Publisher?.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false))
                     && FilterIndex switch
                     {
                         1 => r.IsBlock,
                         2 => r.IsAllow,
                         3 => !r.Enabled,
                         4 => r.IsMissing,
                         _ => true
                     }))
        {
            Rows.Add(row);
        }

        var restore = previous.Count == 0 ? [] : Rows.Where(r => previous.Contains(Identity(r.Info))).ToList();
        SetSelection(restore);
        if (restore.Count > 0)
        {
            SelectionRestoreRequested?.Invoke(restore);
        }

        OnPropertyChanged(nameof(CountText));
        OnPropertyChanged(nameof(HasRows));
        OnPropertyChanged(nameof(IsEmpty));
    }

    /// <summary>Publisher and "file exists" for every row, read in the background.</summary>
    private void LoadFactsInBackground()
    {
        _factsCts?.Cancel();
        var cts = new CancellationTokenSource();
        _factsCts = cts;
        var rows = _all.Where(r => r.HasProgram).ToList();
        _ = Task.Run(() =>
        {
            var results = new List<(RuleRow Row, bool Exists, string? Company)>();
            foreach (var row in rows)
            {
                if (cts.IsCancellationRequested)
                {
                    return;
                }

                var facts = FileInspector.Read(row.ExpandedProgram);
                results.Add((row, facts.Exists, facts.Company));
            }

            Dispatcher.UIThread.Post(() =>
            {
                if (cts.IsCancellationRequested)
                {
                    return;
                }

                foreach (var (row, exists, company) in results)
                {
                    row.FileExists = exists;
                    row.Publisher = company;
                }

                if (FilterIndex == 4)
                {
                    ApplyFilter();
                }
            });
        });
    }

    /// <summary>Called by the view when the grid selection changes.</summary>
    public void SetSelection(IReadOnlyList<RuleRow> rows)
    {
        _selected = rows;
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(HasSingleSelection));
        OnPropertyChanged(nameof(SelectionText));
    }

    private IReadOnlyList<FirewallRuleInfo> SelectedRules => _selected.Select(r => r.Info).ToList();

    // ------------------------------------------------------------------ Add

    [RelayCommand]
    private Task AddApplicationAsync() => Main.AddApplicationsAsync(Choice);

    [RelayCommand]
    private Task AddFolderAsync() => Main.AddFolderAsync(Choice);

    [RelayCommand]
    private Task AddProcessAsync() => Main.AddProcessAsync(Choice);

    [RelayCommand]
    private Task RefreshAsync() => Main.ReloadAsync();

    // ------------------------------------------------------------------ Change selection

    [RelayCommand]
    private Task BlockAsync() => RunAsync(rules => Firewall.SetActionAsync(rules, RuleAction.Block), "ToastBlocked");

    [RelayCommand]
    private Task AllowAsync() => RunAsync(rules => Firewall.SetActionAsync(rules, RuleAction.Allow), "ToastAllowed");

    /// <summary>Allow the selected blocked rules for 15/30/60/120 minutes; then PortShield blocks them again.</summary>
    [RelayCommand]
    private Task AllowTemporarilyAsync(string? minutes) =>
        int.TryParse(minutes, out var m) && _selected.Count > 0 ? Main.AllowTemporarilyAsync(SelectedRules, m) : Task.CompletedTask;

    [RelayCommand]
    private Task BlockAgainAsync() =>
        Main.RestoreTemporaryAsync(all: false, SelectedRules.Select(r => r.PortShieldId).OfType<string>().ToList());

    [RelayCommand]
    private Task EnableAsync() => RunAsync(rules => Firewall.SetEnabledAsync(rules, true), "ToastEnabled");

    [RelayCommand]
    private Task DisableAsync() => RunAsync(rules => Firewall.SetEnabledAsync(rules, false), "ToastDisabled");

    [RelayCommand]
    private Task ScopeAllAsync() => RunAsync(rules => Firewall.SetScopeAsync(rules, RuleScope.All), "ToastScopeChanged");

    [RelayCommand]
    private Task ScopeInternetAsync() => RunAsync(rules => Firewall.SetScopeAsync(rules, RuleScope.Internet), "ToastScopeChanged");

    [RelayCommand]
    private Task ProfilesAllAsync() => RunAsync(rules => Firewall.SetProfilesAsync(rules, FirewallProfiles.All), "ToastProfilesChanged");

    [RelayCommand]
    private Task ProfilesPublicAsync() => RunAsync(rules => Firewall.SetProfilesAsync(rules, FirewallProfiles.Public), "ToastProfilesChanged");

    [RelayCommand]
    private Task ProfilesPrivateDomainAsync() => RunAsync(rules => Firewall.SetProfilesAsync(rules, FirewallProfiles.Private | FirewallProfiles.Domain), "ToastProfilesChanged");

    [RelayCommand]
    private async Task DeleteAsync()
    {
        var rules = SelectedRules;
        if (rules.Count == 0)
        {
            return;
        }

        var foreign = rules.Count(r => !r.IsPortShield);
        var message = Loc.F("ConfirmDeleteText", rules.Count) + (foreign > 0 ? Environment.NewLine + Environment.NewLine + Loc.F("ConfirmDeleteForeign", foreign) : "");
        var confirm = await Host.ConfirmAsync(Loc.T("ConfirmDeleteTitle"), message, Loc.T("BtnDelete"), danger: true);
        if (!confirm.Confirmed)
        {
            return;
        }

        await RunAsync(Firewall.DeleteAsync, "ToastDeleted", rules);
    }

    private async Task RunAsync(Func<IReadOnlyList<FirewallRuleInfo>, Task<ChangeResult>> action, string successKey, IReadOnlyList<FirewallRuleInfo>? rules = null)
    {
        rules ??= SelectedRules;
        if (rules.Count == 0)
        {
            return;
        }

        try
        {
            Main.IsBusy = true;
            var result = await action(rules);
            Main.ShowResult(result, successKey);
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
        finally
        {
            Main.IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task RenameAsync()
    {
        if (_selected.Count != 1)
        {
            return;
        }

        var row = _selected[0];
        var name = await Host.PromptAsync(Loc.T("RenameTitle"), Loc.T("RenameText"), Loc.T("BtnRename"), Loc.T("RenameWatermark"), row.Name);
        if (string.IsNullOrWhiteSpace(name) || name == row.Name)
        {
            return;
        }

        await RunAsync(rules => Firewall.RenameAsync(rules[0], name), "ToastRenamed", [row.Info]);
    }

    // ------------------------------------------------------------------ File actions (first selected row)

    private RuleRow? First => _selected.FirstOrDefault(r => r.HasProgram);

    [RelayCommand]
    private async Task CopyPathAsync()
    {
        var text = string.Join(Environment.NewLine, _selected.Where(r => r.HasProgram).Select(r => r.ExpandedProgram).Distinct(StringComparer.OrdinalIgnoreCase));
        if (text.Length > 0)
        {
            await Host.CopyAsync(text);
            Main.ShowToast(Loc.T("ToastCopied"));
        }
    }

    [RelayCommand]
    private void OpenLocation()
    {
        if (First is { } row)
        {
            AppEnvironment.OpenFolder(File.Exists(row.ExpandedProgram) ? row.ExpandedProgram : ProgramPaths.Directory(row.ExpandedProgram));
        }
    }

    [RelayCommand]
    private void Properties()
    {
        if (First is { } row && OperatingSystem.IsWindows() && File.Exists(row.ExpandedProgram))
        {
            ShellIntegration.ShowProperties(row.ExpandedProgram);
        }
    }

    [RelayCommand]
    private void RunProgram()
    {
        if (First is { } row && File.Exists(row.ExpandedProgram) && !AppEnvironment.Run(row.ExpandedProgram))
        {
            Main.ShowToast(Loc.T("ToastRunFailed"), isError: true);
        }
    }

    // ------------------------------------------------------------------ Selection and export

    [RelayCommand]
    private void SelectAll() => SelectionRequested?.Invoke(SelectionRequest.All);

    [RelayCommand]
    private void SelectNone() => SelectionRequested?.Invoke(SelectionRequest.None);

    [RelayCommand]
    private void InvertSelection() => SelectionRequested?.Invoke(SelectionRequest.Invert);

    /// <summary>Export the selection (or the whole list when nothing is selected).</summary>
    [RelayCommand]
    private Task ExportAsync(ExportFormat format)
    {
        var rules = _selected.Count > 0 ? SelectedRules : Rows.Select(r => r.Info).ToList();
        return Main.ImportExport.ExportRulesAsync(rules, format);
    }
}
