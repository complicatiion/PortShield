using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Storage;
using PortShield.Platform.Windows;

namespace PortShield.App.ViewModels;

public sealed class SnapshotRow(SnapshotInfo info)
{
    public SnapshotInfo Info { get; } = info;

    public string DateText => Info.Created.ToString("g");

    public string ReasonText => Loc.T("Reason" + Info.Reason);

    public string RulesText => Loc.F("SnapshotRules", Info.PortShieldRules, Info.TotalRules);

    public bool HasPolicy => Info.HasPolicy;

    public bool HasRules => Info.HasRules;

    public bool IsManual => Info.Reason == SnapshotReason.Manual;

    public string Note => Info.Note ?? "";

    /// <summary>The note line only takes space when there is a note (keeps the reason level with the other columns).</summary>
    public bool HasNote => !string.IsNullOrWhiteSpace(Info.Note);
}

/// <summary>Snapshots of the firewall before changes: restore PortShield's rules or the complete policy.</summary>
public sealed partial class SnapshotsViewModel(MainViewModel main) : PageViewModel(main)
{
    public override string TitleKey => "NavSnapshots";

    public ObservableCollection<SnapshotRow> Items { get; } = [];

    public bool HasItems => Items.Count > 0;

    public bool IsEmpty => Items.Count == 0;

    public string FolderText => SnapshotManager.Root;

    public override void OnActivated() => Reload();

    public override void OnLanguageChanged()
    {
        base.OnLanguageChanged();
        Reload();
    }

    public void Reload()
    {
        Items.Clear();
        if (OperatingSystem.IsWindows())
        {
            foreach (var info in SnapshotManager.List())
            {
                Items.Add(new SnapshotRow(info));
            }
        }

        OnPropertyChanged(nameof(HasItems));
        OnPropertyChanged(nameof(IsEmpty));
    }

    [RelayCommand]
    private void Refresh() => Reload();

    [RelayCommand]
    private async Task CreateAsync()
    {
        var note = await Host.PromptAsync(Loc.T("SnapshotNoteTitle"), Loc.T("SnapshotNoteText"), Loc.T("BtnCreate"), Loc.T("SnapshotNoteWatermark"));
        if (note is null)
        {
            return;
        }

        try
        {
            Main.IsBusy = true;
            var snapshot = await Firewall.SnapshotAsync(SnapshotReason.Manual, string.IsNullOrWhiteSpace(note) ? null : note);
            Main.ShowToast(Loc.F("ToastSnapshotCreated", snapshot.PortShieldRules));
            Reload();
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
    private async Task RestoreRulesAsync(SnapshotRow? row)
    {
        if (row is null || !row.HasRules)
        {
            return;
        }

        var confirm = await Host.ConfirmAsync(Loc.T("RestoreRulesTitle"), Loc.F("RestoreRulesText", row.DateText, row.Info.PortShieldRules),
            Loc.T("BtnRestore"), danger: false, confirmIcon: "IconRestore");
        if (!confirm.Confirmed)
        {
            return;
        }

        try
        {
            Main.IsBusy = true;
            var result = await Firewall.RestoreRulesAsync(row.Info);
            Main.ShowResult(result, "ToastRestored");
            Reload();
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
    private async Task RestorePolicyAsync(SnapshotRow? row)
    {
        if (row is null || !row.HasPolicy)
        {
            return;
        }

        var confirm = await Host.ConfirmAsync(Loc.T("RestorePolicyTitle"), Loc.F("RestorePolicyText", row.DateText),
            Loc.T("BtnRestorePolicy"), danger: true, confirmIcon: "IconBackupRestore");
        if (!confirm.Confirmed)
        {
            return;
        }

        try
        {
            Main.IsBusy = true;
            var error = await Firewall.RestorePolicyAsync(row.Info);
            Main.ShowToast(error is null ? Loc.T("ToastPolicyRestored") : Loc.F("ToastError", error), isError: error is not null);
            Reload();
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
    private async Task DeleteAsync(SnapshotRow? row)
    {
        if (row is null)
        {
            return;
        }

        var confirm = await Host.ConfirmAsync(Loc.T("DeleteSnapshotTitle"), Loc.F("DeleteSnapshotText", row.DateText), Loc.T("BtnDelete"), danger: true);
        if (!confirm.Confirmed)
        {
            return;
        }

        try
        {
            SnapshotManager.Delete(row.Info);
            Reload();
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
    }

    [RelayCommand]
    private void OpenSnapshot(SnapshotRow? row) => AppEnvironment.OpenFolder(row?.Info.Directory);

    [RelayCommand]
    private void OpenFolder() => AppEnvironment.OpenFolder(SnapshotManager.Root, create: true);
}
