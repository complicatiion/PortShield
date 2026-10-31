using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Export;
using PortShield.Core.Import;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.Storage;
using PortShield.Platform.Windows;

namespace PortShield.App.ViewModels;

/// <summary>An export format as selectable card.</summary>
public sealed partial class FormatOption(ExportFormat format, string iconKey) : ObservableObject
{
    public ExportFormat Format { get; } = format;

    public Avalonia.Media.Geometry? Icon { get; } = Res.Icon(iconKey);

    public string Name => Loc.T("Format" + Format);

    public string Description => Loc.T("Format" + Format + "Text");

    public string Extension => "." + RuleExporter.Extension(Format);

    [ObservableProperty]
    private bool _isSelected;

    public void RefreshText()
    {
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Description));
    }
}

public sealed record ChoiceOption(string Code, string Name)
{
    public override string ToString() => Name;
}

/// <summary>Export in many formats (also for other security products), import of lists, firewall policy files.</summary>
public sealed partial class ImportExportViewModel : PageViewModel
{
    public ImportExportViewModel(MainViewModel main) : base(main)
    {
        Formats =
        [
            new FormatOption(ExportFormat.PortShieldJson, "IconBundle"),
            new FormatOption(ExportFormat.Csv, "IconCsv"),
            new FormatOption(ExportFormat.TextPaths, "IconFormatList"),
            new FormatOption(ExportFormat.TextHashes, "IconKey"),
            new FormatOption(ExportFormat.PowerShell, "IconConsole"),
            new FormatOption(ExportFormat.Netsh, "IconConsole"),
            new FormatOption(ExportFormat.Html, "IconReport"),
            new FormatOption(ExportFormat.Markdown, "IconDocument"),
            new FormatOption(ExportFormat.Xml, "IconFileType")
        ];
        Formats[0].IsSelected = true;
        _portablePaths = main.Ui.ExportPortablePaths;
        _includeHashes = main.Ui.ExportIncludeHashes;
        _delimiterIndex = main.Ui.CsvDelimiter switch { "," => 1, "\t" => 2, _ => 0 };
    }

    public override string TitleKey => "NavImportExport";

    public IReadOnlyList<FormatOption> Formats { get; }

    private ExportFormat SelectedFormat => Formats.FirstOrDefault(f => f.IsSelected)?.Format ?? ExportFormat.PortShieldJson;

    /// <summary>0 PortShield rules · 1 outbound PortShield rules · 2 inbound PortShield rules · 3 all program rules (incl. Windows and other apps).</summary>
    [ObservableProperty]
    private int _sourceIndex;

    public IReadOnlyList<string> Sources =>
    [
        Loc.T("SourceOwn"),
        Loc.T("SourceOwnOutbound"),
        Loc.T("SourceOwnInbound"),
        Loc.T("SourceAllPrograms")
    ];

    [ObservableProperty]
    private bool _portablePaths;

    [ObservableProperty]
    private bool _includeHashes;

    /// <summary>0 ";" · 1 "," · 2 tab.</summary>
    [ObservableProperty]
    private int _delimiterIndex;

    public IReadOnlyList<string> Delimiters => [Loc.T("DelimiterSemicolon"), Loc.T("DelimiterComma"), Loc.T("DelimiterTab")];

    partial void OnPortablePathsChanged(bool value)
    {
        Ui.ExportPortablePaths = value;
        Ui.Save();
    }

    partial void OnIncludeHashesChanged(bool value)
    {
        Ui.ExportIncludeHashes = value;
        Ui.Save();
    }

    partial void OnDelimiterIndexChanged(int value)
    {
        Ui.CsvDelimiter = value switch { 1 => ",", 2 => "\t", _ => ";" };
        Ui.Save();
    }

    public string SourceCountText => Loc.F("ExportSourceCount", SourceRules().Count);

    partial void OnSourceIndexChanged(int value) => OnPropertyChanged(nameof(SourceCountText));

    public override void OnRulesChanged() => OnPropertyChanged(nameof(SourceCountText));

    public override void OnLanguageChanged()
    {
        base.OnLanguageChanged();
        foreach (var format in Formats)
        {
            format.RefreshText();
        }

        OnPropertyChanged(nameof(Sources));
        OnPropertyChanged(nameof(SourceIndex));
        OnPropertyChanged(nameof(Delimiters));
        OnPropertyChanged(nameof(DelimiterIndex));
        OnPropertyChanged(nameof(SourceCountText));
    }

    private IReadOnlyList<FirewallRuleInfo> SourceRules() => Firewall.Rules.Where(r => !r.IsKillSwitch && SourceIndex switch
    {
        1 => r.IsPortShield && r.Direction == RuleDirection.Outbound,
        2 => r.IsPortShield && r.Direction == RuleDirection.Inbound,
        3 => r.HasProgram,
        _ => r.IsPortShield
    }).ToList();

    [RelayCommand]
    private void SelectFormat(FormatOption? option)
    {
        if (option is null)
        {
            return;
        }

        foreach (var format in Formats)
        {
            format.IsSelected = ReferenceEquals(format, option);
        }
    }

    // ------------------------------------------------------------------ Export

    [RelayCommand]
    private Task ExportAsync() => ExportRulesAsync(SourceRules(), SelectedFormat);

    [RelayCommand]
    private async Task CopyAsync()
    {
        var rules = SourceRules();
        if (rules.Count == 0)
        {
            Main.ShowToast(Loc.T("ToastNothingToExport"));
            return;
        }

        try
        {
            Main.IsBusy = true;
            var text = await BuildAsync(rules, SelectedFormat);
            await Host.CopyAsync(text);
            Main.ShowToast(Loc.T("ToastCopied"));
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

    /// <summary>Asks for the file and writes the rules in the format (also used by the rule pages for their selection).</summary>
    public async Task ExportRulesAsync(IReadOnlyList<FirewallRuleInfo> rules, ExportFormat format)
    {
        if (rules.Count == 0)
        {
            Main.ShowToast(Loc.T("ToastNothingToExport"));
            return;
        }

        var path = await Host.PickSavePathAsync(Loc.T("ExportTitle"), RuleExporter.SuggestedFileName(format, DateTime.Now),
            RuleExporter.Extension(format), Loc.T("Format" + format));
        if (path is null)
        {
            return;
        }

        try
        {
            Main.IsBusy = true;
            var text = await BuildAsync(rules, format);
            await File.WriteAllTextAsync(path, text, RuleExporter.EncodingFor(format));
            Main.ShowToast(Loc.F("ToastExportedRules", rules.Count, Path.GetFileName(path)));
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

    private Task<string> BuildAsync(IReadOnlyList<FirewallRuleInfo> rules, ExportFormat format)
    {
        var hashes = RuleExporter.NeedsHashes(format) || (IncludeHashes && RuleExporter.CanIncludeHashes(format));
        var options = new ExportOptions
        {
            PortablePaths = PortablePaths,
            CsvDelimiter = Ui.CsvDelimiter == "\t" ? '\t' : Ui.CsvDelimiter.FirstOrDefault(';'),
            Title = Loc.T("ExportDocumentTitle"),
            Generator = AppEnvironment.Generator,
            Machine = Environment.MachineName,
            Created = DateTime.Now
        };

        return Task.Run(() =>
        {
            var items = rules.Select(rule =>
            {
                var path = rule.ExpandedProgram;
                var facts = rule.HasProgram && OperatingSystem.IsWindows() ? FileInspector.Read(path) : FileFacts.Missing;
                var hash = hashes && facts.Exists ? FileInspector.Sha256(path) : null;
                return new ExportItem(RuleDefinition.FromRule(rule), rule.Name, facts.Exists, hash, facts.Company);
            }).ToList();
            return RuleExporter.Export(format, items, options);
        });
    }

    // ------------------------------------------------------------------ Import

    [RelayCommand]
    private async Task ImportAsync()
    {
        var files = await Host.PickFilesAsync(Loc.T("ImportTitle"), Loc.T("FileTypeImport"), ["*.json", "*.csv", "*.txt"], multiple: false);
        if (files.Count == 0)
        {
            return;
        }

        try
        {
            var file = files[0];
            var result = await Task.Run(() => RuleImporter.ImportFile(file));
            foreach (var warning in result.Warnings.Take(3))
            {
                Main.ShowToast(warning, isError: true);
            }

            if (result.Rules.Count == 0)
            {
                Main.ShowToast(Loc.T("ToastImportEmpty"));
                return;
            }

            // Plain path lists: direction, action and scope are chosen in the dialog.
            if (result.Format == "TXT")
            {
                var paths = result.Rules.Select(r => ProgramPaths.Expand(r.Program)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                await Main.ReviewAsync(AddRulesModel.ForPathsFromImport(Main, paths, Path.GetFileName(file)), SnapshotReason.BeforeImport);
                return;
            }

            var resolved = FirewallService.Resolve(result.Rules);
            var model = AddRulesModel.ForDefinitions(Main, Loc.F("ImportReviewTitle", Path.GetFileName(file)), result.Name, resolved);
            await Main.ReviewAsync(model, SnapshotReason.BeforeImport);
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
    }

    // ------------------------------------------------------------------ Rule sets (move PortShield to another PC)

    /// <summary>Also write the current PortShield rules as an extra rule set into the file.</summary>
    [ObservableProperty]
    private bool _includeCurrentRules = true;

    [RelayCommand]
    private Task ExportRuleSetsAsync() => Main.RuleSets.ExportAllAsync(IncludeCurrentRules);

    [RelayCommand]
    private async Task ImportRuleSetsAsync()
    {
        var files = await Host.PickFilesAsync(Loc.T("PickRuleSet"), Loc.T("FileTypeRuleSet"), ["*.json"], multiple: true);
        await Main.RuleSets.ImportFilesAsync(files);
    }

    // ------------------------------------------------------------------ Windows Firewall policy (.wfw)

    [RelayCommand]
    private async Task ExportPolicyAsync()
    {
        var path = await Host.PickSavePathAsync(Loc.T("ExportPolicyTitle"), $"firewall-policy-{Environment.MachineName}-{DateTime.Now:yyyyMMdd}.wfw", "wfw", Loc.T("FileTypePolicy"));
        if (path is null)
        {
            return;
        }

        try
        {
            Main.IsBusy = true;
            var error = await Firewall.ExportPolicyAsync(path);
            Main.ShowToast(error is null ? Loc.F("ToastExported", Path.GetFileName(path)) : Loc.F("ToastError", error), isError: error is not null);
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
    private async Task ImportPolicyAsync()
    {
        var files = await Host.PickFilesAsync(Loc.T("ImportPolicyTitle"), Loc.T("FileTypePolicy"), ["*.wfw"], multiple: false);
        if (files.Count == 0)
        {
            return;
        }

        var confirm = await Host.ConfirmAsync(Loc.T("ImportPolicyTitle"), Loc.F("ImportPolicyConfirm", Path.GetFileName(files[0])), Loc.T("BtnImport"),
            danger: true, confirmIcon: "IconImport");
        if (!confirm.Confirmed)
        {
            return;
        }

        try
        {
            Main.IsBusy = true;
            var error = await Firewall.ImportPolicyAsync(files[0]);
            Main.ShowToast(error is null ? Loc.T("ToastPolicyImported") : Loc.F("ToastError", error), isError: error is not null);
            Main.Snapshots.Reload();
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
}
