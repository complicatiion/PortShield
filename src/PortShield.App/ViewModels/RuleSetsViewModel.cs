using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.RuleSets;
using PortShield.Core.Storage;

namespace PortShield.App.ViewModels;

/// <summary>A rule set in the list (shipped preset or own file).</summary>
public sealed partial class RuleSetRow(RuleSetFile file) : ObservableObject
{
    public RuleSetFile File { get; } = file;

    public string Name => File.Set.Name;

    public string Description => File.Set.Description ?? "";

    public bool HasDescription => Description.Length > 0;

    public bool IsPreset => File.IsPreset;

    public bool IsOwn => !File.IsPreset;

    public int RuleCount => File.Set.Rules.Count;

    public string OriginText => Loc.T(IsPreset ? "RuleSetPreset" : "RuleSetOwn");

    public string CountText => Loc.F("RuleSetCount", RuleCount);

    /// <summary>"8 programs found on this PC" – resolved in the background.</summary>
    [ObservableProperty]
    private string _availableText = "";

    [ObservableProperty]
    private bool _hasMatches;

    /// <summary>PortShield checks this applied set for new programs (new version folders).</summary>
    [ObservableProperty]
    private bool _isWatched;

    public string FileName => Path.GetFileName(File.Path);

    public void RefreshText()
    {
        OnPropertyChanged(nameof(OriginText));
        OnPropertyChanged(nameof(CountText));
    }
}

/// <summary>Rule sets: presets shipped with PortShield and own sets – apply, save from the current rules, import, export.</summary>
public sealed partial class RuleSetsViewModel(MainViewModel main) : PageViewModel(main)
{
    public override string TitleKey => "NavRuleSets";

    public ObservableCollection<RuleSetRow> Items { get; } = [];

    /// <summary>Cards per row: three in a normal window, more on wide screens, fewer only on very small displays.</summary>
    [ObservableProperty]
    private int _columns = 3;

    public void UpdateColumns(double width)
    {
        var columns = width switch
        {
            >= 1750 => 5,
            >= 1350 => 4,
            >= 820 => 3,
            >= 560 => 2,
            _ => 1
        };
        if (columns != Columns)
        {
            Columns = columns;
        }
    }

    public bool HasItems => Items.Count > 0;

    public override void OnActivated()
    {
        if (Items.Count == 0)
        {
            Reload();
        }
    }

    public override void OnLanguageChanged()
    {
        base.OnLanguageChanged();
        foreach (var item in Items)
        {
            item.RefreshText();
        }

        _ = ResolveAvailabilityAsync();
    }

    [RelayCommand]
    public void Reload()
    {
        var errors = new List<string>();
        Items.Clear();
        var hidden = Ui.HiddenPresets.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var watch = WatchList.Load(AppPaths.WatchFile);
        foreach (var file in RuleSetFile.LoadFolder(AppPaths.PresetsDirectory, isPreset: true, errors)
                     .Where(f => !hidden.Contains(Path.GetFileName(f.Path)))
                     .Concat(RuleSetFile.LoadFolder(AppPaths.RuleSetsDirectory, isPreset: false, errors)))
        {
            var row = new RuleSetRow(file);
            row.IsWatched = watch.Contains(row.FileName, file.IsPreset);
            Items.Add(row);
        }

        OnPropertyChanged(nameof(HasItems));
        foreach (var error in errors)
        {
            Main.ShowToast(error, isError: true);
        }

        _ = ResolveAvailabilityAsync();
    }

    private async Task ResolveAvailabilityAsync()
    {
        var rows = Items.ToList();
        var counts = await Task.Run(() => rows.Select(r => FirewallService.Resolve(r.File.Set.Rules)
            .Select(d => ProgramPaths.Key(d.Program))
            .Where(p => !string.IsNullOrEmpty(p) && System.IO.File.Exists(ProgramPaths.Expand(p)))
            .Distinct()
            .Count()).ToList());
        for (var i = 0; i < rows.Count; i++)
        {
            rows[i].HasMatches = counts[i] > 0;
            rows[i].AvailableText = Loc.F("RuleSetAvailable", counts[i]);
        }
    }

    // ------------------------------------------------------------------ Apply

    [RelayCommand]
    private async Task ApplyAsync(RuleSetRow? row)
    {
        if (row is null)
        {
            return;
        }

        var resolved = await Task.Run(() => FirewallService.Resolve(row.File.Set.Rules));
        if (resolved.Count == 0)
        {
            Main.ShowToast(Loc.T("ToastRuleSetNothingFound"));
            return;
        }

        var model = AddRulesModel.ForDefinitions(Main, Loc.F("ApplyRuleSetTitle", row.Name), row.Description, resolved);
        if (await Main.ReviewAsync(model, SnapshotReason.BeforeRuleSet) > 0 && !row.IsWatched)
        {
            // Applied sets are watched: new programs (e.g. a new version folder) are reported on the overview.
            SetWatched(row, true);
        }
    }

    // ------------------------------------------------------------------ Watch

    [RelayCommand]
    private void ToggleWatch(RuleSetRow? row)
    {
        if (row is not null)
        {
            SetWatched(row, !row.IsWatched);
            Main.ShowToast(Loc.F(row.IsWatched ? "ToastWatchOn" : "ToastWatchOff", row.Name));
            _ = Main.Overview.CheckWatchedAsync();
        }
    }

    private static void SetWatched(RuleSetRow row, bool watched)
    {
        try
        {
            var list = WatchList.Load(AppPaths.WatchFile);
            list = watched
                ? list.With(new WatchEntry { File = row.FileName, IsPreset = row.IsPreset, Name = row.Name, Applied = DateTime.Now })
                : list.Without(row.FileName, row.IsPreset);
            list.Save(AppPaths.WatchFile);
            row.IsWatched = watched;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    /// <summary>"Ignore": these programs of the set are not reported again.</summary>
    public static void Ignore(RuleSetFile file, IEnumerable<RuleDefinition> definitions)
    {
        try
        {
            var list = WatchList.Load(AppPaths.WatchFile);
            var name = Path.GetFileName(file.Path);
            if (list.Find(name, file.IsPreset) is { } entry)
            {
                list.With(entry with { Ignored = entry.Ignored.Concat(definitions.Select(d => WatchEntry.IgnoreKey(d.Program, d.Service, d.Direction)))
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToList() }).Save(AppPaths.WatchFile);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    /// <summary>Watched sets that find programs without a rule: set and the definitions still missing.</summary>
    public static IReadOnlyList<(RuleSetFile File, IReadOnlyList<RuleDefinition> Missing)> FindNewPrograms(FirewallService firewall, UiSettings ui)
    {
        var watch = WatchList.Load(AppPaths.WatchFile);
        if (watch.Sets.Count == 0)
        {
            return [];
        }

        var hidden = ui.HiddenPresets.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var files = RuleSetFile.LoadFolder(AppPaths.PresetsDirectory, isPreset: true)
            .Where(f => !hidden.Contains(Path.GetFileName(f.Path)))
            .Concat(RuleSetFile.LoadFolder(AppPaths.RuleSetsDirectory, isPreset: false))
            .Where(f => watch.Contains(Path.GetFileName(f.Path), f.IsPreset));
        var result = new List<(RuleSetFile, IReadOnlyList<RuleDefinition>)>();
        foreach (var file in files)
        {
            var ignored = (watch.Find(Path.GetFileName(file.Path), file.IsPreset)?.Ignored ?? []).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var resolved = FirewallService.Resolve(file.Set.Rules);
            var missing = firewall.Plan(resolved).Where(p => p.Action == PlanAction.Create).Select(p => p.Definition)
                .Where(d => !ignored.Contains(WatchEntry.IgnoreKey(d.Program, d.Service, d.Direction)))
                .ToList();
            if (missing.Count > 0)
            {
                result.Add((file, missing));
            }
        }

        return result;
    }

    // ------------------------------------------------------------------ Create, import, export, delete

    [RelayCommand]
    private async Task CreateFromRulesAsync()
    {
        var own = Firewall.Rules.Where(r => r.IsPortShield && !r.IsKillSwitch && r.HasProgram).ToList();
        if (own.Count == 0)
        {
            Main.ShowToast(Loc.T("ToastNoOwnRules"));
            return;
        }

        var name = await Host.PromptAsync(Loc.T("NewRuleSetTitle"), Loc.F("NewRuleSetText", own.Count), Loc.T("BtnSave"), Loc.T("NewRuleSetWatermark"));
        if (string.IsNullOrWhiteSpace(name))
        {
            return;
        }

        var set = new RuleSet
        {
            Name = name,
            Description = Loc.F("NewRuleSetDescription", Environment.MachineName, DateTime.Now.ToString("d")),
            Author = Environment.UserName,
            Created = DateTime.Now,
            Generator = AppEnvironment.Generator,
            // Portable paths: the set works on other PCs as well.
            Rules = own.Select(r => RuleDefinition.FromRule(r) with { Program = ProgramPaths.ToPortable(r.Program) }).ToList()
        };

        try
        {
            var path = UniquePath(AppPaths.RuleSetsDirectory, FileName(name));
            set.Save(path);
            Main.ShowToast(Loc.F("ToastRuleSetSaved", name));
            Reload();
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
    }

    [RelayCommand]
    private async Task ImportAsync()
    {
        var files = await Host.PickFilesAsync(Loc.T("PickRuleSet"), Loc.T("FileTypeRuleSet"), ["*.json"], multiple: true);
        await ImportFilesAsync(files);
    }

    /// <summary>Imports single rule sets and bundles (several sets in one file) into the own rule set folder.</summary>
    public async Task ImportFilesAsync(IReadOnlyList<string> files)
    {
        var imported = 0;
        foreach (var file in files)
        {
            try
            {
                var text = await File.ReadAllTextAsync(file);
                foreach (var set in RuleSetBundle.ParseAny(text, Path.GetFileNameWithoutExtension(file)))
                {
                    set.Save(UniquePath(AppPaths.RuleSetsDirectory, FileName(set.Name)));
                    imported++;
                }
            }
            catch (Exception ex)
            {
                Main.ShowToast(Loc.F("ToastImportFailed", Path.GetFileName(file), ex.Message), isError: true);
            }
        }

        if (imported > 0)
        {
            Main.ShowToast(Loc.F("ToastRuleSetsImported", imported));
            Reload();
        }
    }

    /// <summary>All own rule sets in one file – optionally plus the current PortShield rules as an extra set.</summary>
    public async Task ExportAllAsync(bool includeCurrentRules)
    {
        var sets = RuleSetFile.LoadFolder(AppPaths.RuleSetsDirectory, isPreset: false).Select(f => f.Set).ToList();
        if (includeCurrentRules)
        {
            var own = Firewall.Rules.Where(r => r.IsPortShield && !r.IsKillSwitch && r.HasProgram).ToList();
            if (own.Count > 0)
            {
                sets.Add(new RuleSet
                {
                    Name = Loc.F("CurrentRulesSetName", Environment.MachineName),
                    Created = DateTime.Now,
                    Generator = AppEnvironment.Generator,
                    Rules = own.Select(r => RuleDefinition.FromRule(r) with { Program = ProgramPaths.ToPortable(r.Program) }).ToList()
                });
            }
        }

        if (sets.Count == 0)
        {
            Main.ShowToast(Loc.T("ToastNoRuleSets"));
            return;
        }

        var path = await Host.PickSavePathAsync(Loc.T("ExportRuleSetsTitle"), $"portshield-rulesets-{DateTime.Now:yyyyMMdd}.json", "json", Loc.T("FileTypeRuleSet"));
        if (path is null)
        {
            return;
        }

        try
        {
            var bundle = new RuleSetBundle { Created = DateTime.Now, Generator = AppEnvironment.Generator, Machine = Environment.MachineName, Sets = sets };
            await File.WriteAllTextAsync(path, bundle.ToJson(), PortShieldJson.Utf8NoBom);
            Main.ShowToast(Loc.F("ToastRuleSetsExported", sets.Count, Path.GetFileName(path)));
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
    }

    // ------------------------------------------------------------------ Editor

    [RelayCommand]
    private Task NewAsync() => OpenEditorAsync(new RuleSetEditorModel(Main, null, Loc.T("EditorNewTitle")), null);

    /// <summary>Own sets are edited in place; presets are opened as a copy.</summary>
    [RelayCommand]
    private Task EditAsync(RuleSetRow? row) =>
        row is null ? Task.CompletedTask
        : row.IsPreset ? CopyAsync(row)
        : OpenEditorAsync(new RuleSetEditorModel(Main, row.File.Set, Loc.F("EditorEditTitle", row.Name)), row.File.Path);

    [RelayCommand]
    private Task CopyAsync(RuleSetRow? row) =>
        row is null ? Task.CompletedTask
        : OpenEditorAsync(new RuleSetEditorModel(Main, row.File.Set with { Name = Loc.F("CopyName", row.Name) }, Loc.F("EditorCopyTitle", row.Name)), null);

    private async Task OpenEditorAsync(RuleSetEditorModel model, string? existingPath)
    {
        if (!await Host.EditRuleSetAsync(model))
        {
            return;
        }

        try
        {
            var set = model.Build();
            set.Save(existingPath ?? UniquePath(AppPaths.RuleSetsDirectory, FileName(set.Name)));
            Main.ShowToast(Loc.F("ToastRuleSetSaved", set.Name));
            Reload();
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
    }

    [RelayCommand]
    private async Task ExportAsync(RuleSetRow? row)
    {
        if (row is null)
        {
            return;
        }

        var path = await Host.PickSavePathAsync(Loc.T("ExportRuleSetTitle"), FileName(row.Name), "json", Loc.T("FileTypeRuleSet"));
        if (path is null)
        {
            return;
        }

        try
        {
            row.File.Set.Save(path);
            Main.ShowToast(Loc.F("ToastExported", Path.GetFileName(path)));
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
    }

    /// <summary>Own sets: the file is deleted. Presets: hidden (an update would bring the file back); a reset shows them again.</summary>
    [RelayCommand]
    private async Task DeleteAsync(RuleSetRow? row)
    {
        if (row is null)
        {
            return;
        }

        var confirm = row.IsPreset
            ? await Host.ConfirmAsync(Loc.T("RemovePresetTitle"), Loc.F("RemovePresetText", row.Name), Loc.T("BtnRemove"), danger: true, confirmIcon: "IconDelete")
            : await Host.ConfirmAsync(Loc.T("DeleteRuleSetTitle"), Loc.F("DeleteRuleSetText", row.Name), Loc.T("BtnDelete"), danger: true);
        if (!confirm.Confirmed)
        {
            return;
        }

        try
        {
            SetWatched(row, false);
            if (row.IsPreset)
            {
                Ui.HiddenPresets = Ui.HiddenPresets.Append(row.FileName).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                Ui.Save();
            }
            else
            {
                System.IO.File.Delete(row.File.Path);
            }

            Main.ShowToast(Loc.F("ToastRuleSetRemoved", row.Name));
            Reload();
            _ = Main.Overview.CheckWatchedAsync();
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
    }

    [RelayCommand]
    private void OpenFile(RuleSetRow? row)
    {
        if (row is not null)
        {
            AppEnvironment.OpenFolder(row.File.Path);
        }
    }

    [RelayCommand]
    private void OpenFolder() => AppEnvironment.OpenFolder(AppPaths.RuleSetsDirectory, create: true);

    private static string FileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var clean = new string(name.Select(c => invalid.Contains(c) ? '_' : c).ToArray()).Trim();
        return (clean.Length == 0 ? "ruleset" : clean) + ".json";
    }

    private static string UniquePath(string folder, string fileName)
    {
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, fileName);
        var stem = Path.GetFileNameWithoutExtension(fileName);
        var counter = 2;
        while (System.IO.File.Exists(path))
        {
            path = Path.Combine(folder, $"{stem} ({counter++}).json");
        }

        return path;
    }
}
