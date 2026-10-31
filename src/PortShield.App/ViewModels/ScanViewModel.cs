using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Export;
using PortShield.Core.Models;
using PortShield.Core.Rules;

namespace PortShield.App.ViewModels;

/// <summary>One rule in the scan result.</summary>
public sealed class ScanRow(ScanEntry entry)
{
    public ScanEntry Entry { get; } = entry;

    public FirewallRuleInfo Info => Entry.Rule;

    public string Name => Info.Name;

    public string FileName => Info.HasService ? Loc.F("ServiceName", Info.Service) : ProgramPaths.FileName(Info.Program);

    public string Folder => Info.HasService ? Info.ExpandedProgram : ProgramPaths.Directory(Info.ExpandedProgram);

    public bool IsBlock => Info.Action == RuleAction.Block;

    public bool IsAllow => !IsBlock;

    public string ActionText => Loc.T(IsBlock ? "ActionBlock" : "ActionAllow");

    public string DirectionText => Loc.T(Info.Direction == RuleDirection.Outbound ? "DirOut" : "DirIn");

    public bool Enabled => Info.Enabled;

    public string OriginText => Loc.T("Origin" + Entry.Origin);

    public bool IsOther => Entry.Origin == RuleOrigin.Other;

    public bool IsPortShield => Entry.Origin == RuleOrigin.PortShield;

    public bool IsSystemOrPolicy => Entry.Origin is RuleOrigin.System or RuleOrigin.Policy;

    public string Group => Info.Grouping.StartsWith('@') ? "Windows" : Info.Grouping;

    public bool HasFindings => Entry.Findings != ScanFinding.None;

    public string FindingsText => string.Join(" · ", Enum.GetValues<ScanFinding>()
        .Where(f => f != ScanFinding.None && Entry.Has(f))
        .Select(f => Loc.T("Finding" + f)));

    public string Tooltip => Info.Name + Environment.NewLine + Info.ExpandedProgram + (Info.HasService ? " (" + Info.Service + ")" : "");
}

/// <summary>
/// Scan of existing program rules: shows where they come from, finds missing programs, duplicates and conflicts, and
/// adopts rules of other tools (e.g. Sordum Firewall App Blocker, wf.msc) – only the PortShield marker is added.
/// </summary>
public sealed partial class ScanViewModel(MainViewModel main) : PageViewModel(main)
{
    private ScanResult? _result;
    private IReadOnlyList<ScanRow> _selected = [];

    public override string TitleKey => "NavScan";

    public ObservableCollection<ScanRow> Rows { get; } = [];

    public event Action<SelectionRequest>? SelectionRequested;

    [ObservableProperty]
    private bool _isScanning;

    public bool HasScanned => _result is not null;

    public bool NotScanned => _result is null && !IsScanning;

    partial void OnIsScanningChanged(bool value) => OnPropertyChanged(nameof(NotScanned));

    /// <summary>0 adoptable · 1 all · 2 program missing · 3 duplicates · 4 conflicts · 5 disabled · 6 Windows · 7 group policy · 8 PortShield.</summary>
    [ObservableProperty]
    private int _filterIndex;

    [ObservableProperty]
    private string _search = "";

    partial void OnFilterIndexChanged(int value) => ApplyFilter();

    partial void OnSearchChanged(string value) => ApplyFilter();

    public IReadOnlyList<string> Filters =>
    [
        Loc.T("ScanFilterAdoptable"),
        Loc.T("ScanFilterAll"),
        Loc.T("FilterMissing"),
        Loc.T("FindingDuplicate"),
        Loc.T("FindingConflict"),
        Loc.T("FilterDisabled"),
        Loc.T("OriginSystem"),
        Loc.T("OriginPolicy"),
        Loc.T("OriginPortShield")
    ];

    /// <summary>Rename adopted rules to "PortShield · Program · Out".</summary>
    public bool RenameOnAdopt
    {
        get => Ui.ScanRenameOnAdopt;
        set
        {
            Ui.ScanRenameOnAdopt = value;
            Ui.Save();
            OnPropertyChanged();
        }
    }

    // ------------------------------------------------------------------ Counters

    public int Adoptable => _result?.Adoptable ?? 0;

    public int Orphans => _result?.Entries.Count(e => e.Has(ScanFinding.Orphan) && e.Origin != RuleOrigin.System) ?? 0;

    public int Duplicates => _result?.Count(ScanFinding.Duplicate) ?? 0;

    public int Conflicts => _result?.Count(ScanFinding.Conflict) ?? 0;

    public int SystemRules => _result?.Count(RuleOrigin.System) ?? 0;

    public int PolicyRules => _result?.PolicyRules.Count ?? 0;

    public int OwnRules => _result?.Count(RuleOrigin.PortShield) ?? 0;

    public string CountText => Loc.F("RulesCount", Rows.Count, _result?.Entries.Count ?? 0);

    public bool HasSelection => _selected.Count > 0;

    public string SelectionText => _selected.Count == 0 ? "" : Loc.F("RulesSelected", _selected.Count);

    public bool HasRows => Rows.Count > 0;

    public bool IsEmptyResult => HasScanned && Rows.Count == 0;

    public override void OnLanguageChanged()
    {
        base.OnLanguageChanged();
        OnPropertyChanged(nameof(Filters));
        OnPropertyChanged(nameof(FilterIndex));
        ApplyFilter();
    }

    // ------------------------------------------------------------------ Scan

    [RelayCommand]
    public async Task ScanAsync()
    {
        if (IsScanning)
        {
            return;
        }

        try
        {
            IsScanning = true;
            Main.IsBusy = true;
            _result = await Firewall.ScanAsync();
            OnPropertyChanged(string.Empty);
            ApplyFilter();
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
        finally
        {
            IsScanning = false;
            Main.IsBusy = false;
        }
    }

    private void ApplyFilter()
    {
        Rows.Clear();
        if (_result is not null)
        {
            var text = Search.Trim();
            foreach (var entry in _result.Entries.Where(e =>
                         (text.Length == 0 || e.Rule.Name.Contains(text, StringComparison.OrdinalIgnoreCase)
                                           || e.Rule.ExpandedProgram.Contains(text, StringComparison.OrdinalIgnoreCase)
                                           || e.Rule.Grouping.Contains(text, StringComparison.OrdinalIgnoreCase))
                         && FilterIndex switch
                         {
                             0 => e.CanAdopt,
                             2 => e.Has(ScanFinding.Orphan) && e.Origin != RuleOrigin.System,
                             3 => e.Has(ScanFinding.Duplicate),
                             4 => e.Has(ScanFinding.Conflict),
                             5 => e.Has(ScanFinding.Disabled),
                             6 => e.Origin == RuleOrigin.System,
                             7 => e.Origin == RuleOrigin.Policy,
                             8 => e.Origin == RuleOrigin.PortShield,
                             _ => true
                         })
                         .OrderBy(e => e.Origin)
                         .ThenBy(e => e.Rule.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                Rows.Add(new ScanRow(entry));
            }
        }

        SetSelection([]);
        OnPropertyChanged(nameof(CountText));
        OnPropertyChanged(nameof(HasRows));
        OnPropertyChanged(nameof(IsEmptyResult));
    }

    public void SetSelection(IReadOnlyList<ScanRow> rows)
    {
        _selected = rows;
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(SelectionText));
    }

    [RelayCommand]
    private void ShowFilter(string? index)
    {
        if (int.TryParse(index, out var i))
        {
            FilterIndex = i;
        }
    }

    [RelayCommand]
    private void SelectAll() => SelectionRequested?.Invoke(SelectionRequest.All);

    [RelayCommand]
    private void InvertSelection() => SelectionRequested?.Invoke(SelectionRequest.Invert);

    // ------------------------------------------------------------------ Actions

    /// <summary>Adopt the selected rules of other tools (or all adoptable rules when nothing is selected).</summary>
    [RelayCommand]
    private async Task AdoptAsync()
    {
        var rules = (_selected.Count > 0 ? _selected.Select(r => r.Entry) : _result?.Entries ?? [])
            .Where(e => e.CanAdopt).Select(e => e.Rule).ToList();
        if (rules.Count == 0)
        {
            Main.ShowToast(Loc.T("ToastNothingToAdopt"));
            return;
        }

        var confirm = await Host.ConfirmAsync(Loc.T("AdoptTitle"), Loc.F(RenameOnAdopt ? "AdoptTextRename" : "AdoptText", rules.Count),
            Loc.T("BtnAdopt"), danger: false, confirmIcon: "IconShieldCheck");
        if (confirm.Confirmed)
        {
            await RunAsync(() => Firewall.AdoptAsync(rules, RenameOnAdopt), "ToastAdopted");
        }
    }

    /// <summary>Removes duplicate rules (one rule per program, direction and action stays; PortShield's preferred).</summary>
    [RelayCommand]
    private async Task MergeAsync()
    {
        var extras = RuleScanner.MergeExtras(_result?.Entries ?? []);
        if (extras.Count == 0)
        {
            Main.ShowToast(Loc.T("ToastNoDuplicates"));
            return;
        }

        var confirm = await Host.ConfirmAsync(Loc.T("MergeTitle"), Loc.F("MergeText", extras.Count), Loc.T("BtnMerge"), danger: true,
            confirmIcon: "IconDeleteSweep");
        if (confirm.Confirmed)
        {
            await RunAsync(() => Firewall.DeleteAsync(extras), "ToastDeleted");
        }
    }

    [RelayCommand]
    private Task EnableAsync() => RunAsync(() => Firewall.SetEnabledAsync(Changeable(), true), "ToastEnabled");

    [RelayCommand]
    private Task DisableAsync() => RunAsync(() => Firewall.SetEnabledAsync(Changeable(), false), "ToastDisabled");

    [RelayCommand]
    private async Task DeleteAsync()
    {
        var rules = Changeable();
        if (rules.Count == 0)
        {
            return;
        }

        var system = _selected.Count(r => r.Entry.Origin == RuleOrigin.System);
        var message = Loc.F("ConfirmDeleteText", rules.Count) + (system > 0 ? Environment.NewLine + Environment.NewLine + Loc.F("ConfirmDeleteForeign", system) : "");
        var confirm = await Host.ConfirmAsync(Loc.T("ConfirmDeleteTitle"), message, Loc.T("BtnDelete"), danger: true);
        if (confirm.Confirmed)
        {
            await RunAsync(() => Firewall.DeleteAsync(rules), "ToastDeleted");
        }
    }

    [RelayCommand]
    private Task ExportAsync(ExportFormat format) =>
        Main.ImportExport.ExportRulesAsync((_selected.Count > 0 ? _selected : Rows).Select(r => r.Info).ToList(), format);

    /// <summary>Selected rules that may be changed (group policy rules are read only).</summary>
    private IReadOnlyList<FirewallRuleInfo> Changeable() =>
        _selected.Where(r => r.Entry.Origin != RuleOrigin.Policy).Select(r => r.Info).ToList();

    private async Task RunAsync(Func<Task<ChangeResult>> action, string successKey)
    {
        try
        {
            Main.IsBusy = true;
            var result = await action();
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

        await ScanAsync();
    }
}
