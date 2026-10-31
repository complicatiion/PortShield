using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Integrity;
using PortShield.Core.Models;
using PortShield.Core.RuleSets;
using PortShield.Core.Storage;
using PortShield.Platform.Windows;

namespace PortShield.App.ViewModels;

/// <summary>One firewall profile on the overview.</summary>
public sealed class ProfileRow(ProfileState state)
{
    public ProfileState State { get; } = state;

    public string Name => Loc.T(State.Profile switch
    {
        FirewallProfiles.Domain => "ProfileDomain",
        FirewallProfiles.Private => "ProfilePrivate",
        _ => "ProfilePublic"
    });

    public bool Enabled => State.Enabled;

    public bool Disabled => !State.Enabled;

    public bool IsActive => State.IsActive;

    public string StateText => Loc.T(State.Enabled ? "ProfileOn" : "ProfileOff");

    public string OutboundText => Loc.T(State.BlockOutboundByDefault ? "OutboundBlocked" : "OutboundAllowed");

    public string InboundText => Loc.T(State.BlockInboundByDefault ? "InboundBlocked" : "InboundAllowed");

    public bool ByPolicy => State.EnabledByPolicy || State.OutboundByPolicy;

    public bool LocalRulesIgnored => State.LocalRulesIgnored;
}

/// <summary>A watched rule set found programs without a rule (e.g. a new version folder).</summary>
public sealed class WatchNotice(RuleSetFile file, IReadOnlyList<RuleDefinition> missing)
{
    public RuleSetFile File { get; } = file;

    public IReadOnlyList<RuleDefinition> Missing { get; } = missing;

    public int Programs => Missing.Select(d => d.Program).Distinct(StringComparer.OrdinalIgnoreCase).Count();

    public string Text => Loc.F("NoticeWatchText", File.Set.Name, Programs);
}

/// <summary>Overview: protection state, profiles, kill switch, whitelist mode, rule counts and quick actions.</summary>
public sealed partial class OverviewViewModel(MainViewModel main) : PageViewModel(main)
{
    public override string TitleKey => "NavOverview";

    private FirewallStatus? Status => Firewall.Status;

    public override void OnRulesChanged() => Refresh();

    public override void OnStatusChanged() => Refresh();

    public override void OnLanguageChanged()
    {
        base.OnLanguageChanged();
        Refresh();
        var notices = WatchNotices.ToList();
        WatchNotices.Clear();
        foreach (var notice in notices)
        {
            WatchNotices.Add(notice);
        }
    }

    private List<FirewallRuleInfo> _own = [];

    public void Refresh()
    {
        _own = Firewall.Rules.Where(r => r.IsPortShield && !r.IsKillSwitch).ToList();
        OnPropertyChanged(string.Empty);
    }

    // ------------------------------------------------------------------ Hero

    public bool HasStatus => Status is not null;

    public bool IsProtected => Status is { AllProfilesEnabled: true, ServiceRunning: true, LocalRulesIgnored: false, ThirdPartyActive: false };

    public bool HasProblems => HasStatus && !IsProtected;

    public bool HasAlert => Status is { } s && (!s.AllProfilesEnabled || !s.ServiceRunning || s.LocalRulesIgnored);

    public bool HasWarningOnly => HasProblems && !HasAlert;

    public string HeroTitle => !HasStatus ? Loc.T("HeroLoading")
        : IsProtected ? Loc.T("HeroProtected")
        : HasAlert ? Loc.T("HeroAlert")
        : Loc.T("HeroWarning");

    public string HeroText
    {
        get
        {
            if (Status is not { } s)
            {
                return Loc.T("HeroLoadingText");
            }

            var active = s.Profiles.Where(p => p.IsActive).Select(p => new ProfileRow(p).Name).ToList();
            var network = active.Count == 0 ? Loc.T("NetworkNone") : string.Join(", ", active);
            return Loc.F("HeroText", network, OwnRules.Count, s.IsServer ? SystemInfo.ProductName() : Environment.MachineName);
        }
    }

    public IReadOnlyList<ProfileRow> Profiles => Status?.Profiles.Select(p => new ProfileRow(p)).ToList() ?? [];

    // ------------------------------------------------------------------ Notices

    public bool ShowNotElevated => !Main.IsElevated;

    public bool ShowServiceStopped => Status is { ServiceRunning: false };

    public bool ShowLocalRulesIgnored => Status is { LocalRulesIgnored: true };

    public bool ShowPolicyManaged => Status is { ManagedByPolicy: true, LocalRulesIgnored: false };

    public string PolicyText => Status is { } s
        ? Loc.F("NoticePolicyText", string.IsNullOrEmpty(s.DomainName) ? Loc.T("DomainUnknown") : s.DomainName, s.PolicyRuleCount)
        : "";

    public bool ShowThirdParty => Status is { ThirdPartyActive: true };

    public string ThirdPartyText => Status is { } s
        ? Loc.F("NoticeThirdPartyText", string.Join(", ", s.Products.Where(p => p.Enabled && !p.IsWindowsFirewall).Select(p => p.Name)))
        : "";

    public bool ShowProfileOff => Status is { AllProfilesEnabled: false };

    /// <summary>Program rules of other tools (not Windows', not PortShield's) – candidates for the scan.</summary>
    public int UnmanagedRules => Firewall.Rules.Count(r => r.HasProgram && !r.IsPortShield && !r.IsSystem && !r.IsKillSwitch);

    public bool ShowUnmanaged => UnmanagedRules > 0;

    public string UnmanagedText => Loc.F("NoticeUnmanagedText", UnmanagedRules);

    // ------------------------------------------------------------------ Integrity check

    public IReadOnlyList<RuleDrift> Drifts => Firewall.Drifts;

    public bool ShowDrift => Drifts.Count > 0;

    public string DriftText => Loc.F("NoticeDriftText",
        Drifts.Count(d => d.Kind == DriftKind.Missing), Drifts.Count(d => d.Kind == DriftKind.Changed));

    public string DriftDetails => string.Join(Environment.NewLine, Drifts.Take(15).Select(d =>
        (d.Kind == DriftKind.Missing ? "– " : "≠ ") + d.Expected.Name)) + (Drifts.Count > 15 ? Environment.NewLine + "…" : "");

    [RelayCommand]
    private async Task RestoreDriftAsync()
    {
        try
        {
            Main.IsBusy = true;
            var result = await Firewall.RestoreDriftsAsync();
            Main.ShowResult(result, "ToastDriftRestored");
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

    [RelayCommand]
    private async Task AcceptDriftAsync()
    {
        var confirm = await Host.ConfirmAsync(Loc.T("AcceptDriftTitle"), Loc.T("AcceptDriftText"), Loc.T("BtnAccept"), danger: false, confirmIcon: "IconCheck");
        if (confirm.Confirmed)
        {
            await Firewall.AcceptDriftsAsync();
            Main.ShowToast(Loc.T("ToastDriftAccepted"));
        }
    }

    // ------------------------------------------------------------------ Temporarily allowed

    public bool ShowTemporary => Firewall.Temporary.Entries.Count > 0;

    public string TemporaryText => Firewall.Temporary.Next is { } next
        ? Loc.F("NoticeTemporaryText", Firewall.Temporary.Entries.Count, next.ToString("t"))
        : "";

    public string TemporaryDetails => string.Join(Environment.NewLine, Firewall.Temporary.Entries.Take(15).Select(e => e.Name + " – " + e.Until.ToString("t")));

    [RelayCommand]
    private Task BlockTemporaryNowAsync() => Main.RestoreTemporaryAsync(all: true);

    // ------------------------------------------------------------------ Watched rule sets

    public ObservableCollection<WatchNotice> WatchNotices { get; } = [];

    public bool HasWatchNotices => WatchNotices.Count > 0;

    private bool _checkingWatch;

    /// <summary>Resolves the watched rule sets in the background (file system) and shows sets with new programs.</summary>
    public async Task CheckWatchedAsync()
    {
        if (_checkingWatch || !FirewallService.IsSupported)
        {
            return;
        }

        try
        {
            _checkingWatch = true;
            var found = await Task.Run(() => RuleSetsViewModel.FindNewPrograms(Firewall, Ui));
            Dispatcher.UIThread.Post(() =>
            {
                WatchNotices.Clear();
                foreach (var (file, missing) in found)
                {
                    WatchNotices.Add(new WatchNotice(file, missing));
                }

                OnPropertyChanged(nameof(HasWatchNotices));
            });
        }
        catch (Exception)
        {
            // Not critical – checked again on the next refresh.
        }
        finally
        {
            _checkingWatch = false;
        }
    }

    [RelayCommand]
    private async Task ApplyWatchAsync(WatchNotice? notice)
    {
        if (notice is null)
        {
            return;
        }

        var model = AddRulesModel.ForDefinitions(Main, Loc.F("ApplyRuleSetTitle", notice.File.Set.Name), Loc.F("WatchReviewSubtitle", notice.Programs), notice.Missing);
        await Main.ReviewAsync(model, SnapshotReason.BeforeRuleSet);
        await CheckWatchedAsync();
    }

    [RelayCommand]
    private void IgnoreWatch(WatchNotice? notice)
    {
        if (notice is not null)
        {
            RuleSetsViewModel.Ignore(notice.File, notice.Missing);
            WatchNotices.Remove(notice);
            OnPropertyChanged(nameof(HasWatchNotices));
        }
    }

    [RelayCommand]
    private async Task OpenScanAsync()
    {
        Main.NavigateTo(Main.Scan);
        await Main.Scan.ScanAsync();
    }

    // ------------------------------------------------------------------ KPIs

    private List<FirewallRuleInfo> OwnRules => _own;

    public int TotalRules => OwnRules.Count;

    public int BlockedOutbound => OwnRules.Count(r => r.Direction == RuleDirection.Outbound && r.Action == RuleAction.Block && r.Enabled);

    public int BlockedInbound => OwnRules.Count(r => r.Direction == RuleDirection.Inbound && r.Action == RuleAction.Block && r.Enabled);

    public int AllowedRules => OwnRules.Count(r => r.Action == RuleAction.Allow && r.Enabled);

    public int DisabledRules => OwnRules.Count(r => !r.Enabled);

    public int InternetOnlyRules => OwnRules.Count(r => r.Scope == RuleScope.Internet);

    public int WindowsRules => Firewall.Rules.Count;

    // ------------------------------------------------------------------ Kill switch & whitelist

    public bool KillSwitchOn => Main.KillSwitchOn;

    public string KillSwitchState => Loc.T(KillSwitchOn ? "KillSwitchStateOn" : "KillSwitchStateOff");

    public string KillSwitchButton => Loc.T(KillSwitchOn ? "BtnKillSwitchOff" : "BtnKillSwitchOn");

    public bool KillSwitchLan
    {
        get => Ui.KillSwitchLanAllowed;
        set
        {
            if (Ui.KillSwitchLanAllowed == value)
            {
                return;
            }

            Ui.KillSwitchLanAllowed = value;
            Ui.Save();
            OnPropertyChanged();
            Main.Settings.SyncKillSwitchLan();
            if (KillSwitchOn)
            {
                // Re-create the rules in the new mode.
                _ = Main.SetKillSwitchAsync(true);
            }
        }
    }

    public bool WhitelistOn => Status?.WhitelistMode == true;

    public string WhitelistState => Loc.T(WhitelistOn ? "WhitelistStateOn" : "WhitelistStateOff");

    public string WhitelistButton => Loc.T(WhitelistOn ? "BtnWhitelistOff" : "BtnWhitelistOn");

    public bool OutboundByPolicy => Status?.Profiles.Any(p => p.OutboundByPolicy) == true;

    [RelayCommand]
    private Task ToggleKillSwitchAsync() => Main.SetKillSwitchAsync(!KillSwitchOn);

    [RelayCommand]
    private async Task ToggleWhitelistAsync()
    {
        var on = !WhitelistOn;
        if (on)
        {
            var allowed = Firewall.Rules.Count(r => r.Direction == RuleDirection.Outbound && r.Action == RuleAction.Allow && r.Enabled);
            var confirm = await Host.ConfirmAsync(Loc.T("WhitelistTitle"), Loc.F("WhitelistConfirm", allowed), Loc.T("BtnWhitelistOn"), danger: true,
                confirmIcon: "IconShieldLock");
            if (!confirm.Confirmed)
            {
                return;
            }
        }

        await RunPolicyAsync(() => Firewall.SetWhitelistModeAsync(on), on ? "ToastWhitelistOn" : "ToastWhitelistOff");
    }

    [RelayCommand]
    private async Task ToggleProfileAsync(ProfileRow? row)
    {
        if (row is null)
        {
            return;
        }

        var on = !row.Enabled;
        if (!on)
        {
            var confirm = await Host.ConfirmAsync(Loc.T("ProfileOffTitle"), Loc.F("ProfileOffText", row.Name), Loc.T("BtnTurnOff"), danger: true,
                confirmIcon: "IconShieldAlert");
            if (!confirm.Confirmed)
            {
                return;
            }
        }

        await RunPolicyAsync(() => Firewall.SetFirewallEnabledAsync(row.State.Profile, on), on ? "ToastProfileOn" : "ToastProfileOff");
    }

    [RelayCommand]
    private Task EnableAllProfilesAsync() =>
        RunPolicyAsync(() => Firewall.SetFirewallEnabledAsync(FirewallProfiles.All, true), "ToastProfileOn");

    private async Task RunPolicyAsync(Func<Task<string?>> action, string successKey)
    {
        try
        {
            Main.IsBusy = true;
            var error = await action();
            if (error is null)
            {
                Main.ShowToast(Loc.T(successKey));
            }
            else
            {
                Main.ShowToast(Loc.F("ToastError", error), isError: true);
            }
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

    // ------------------------------------------------------------------ Quick actions

    [RelayCommand]
    private Task AddApplicationAsync() => Main.AddApplicationsAsync(null);

    [RelayCommand]
    private Task AddFolderAsync() => Main.AddFolderAsync(null);

    [RelayCommand]
    private Task AddProcessAsync() => Main.AddProcessAsync(null);

    [RelayCommand]
    private void OpenRules() => Main.NavigateTo(Main.Outbound);

    [RelayCommand]
    private void OpenRuleSets() => Main.NavigateTo(Main.RuleSets);

    [RelayCommand]
    private void OpenExport() => Main.NavigateTo(Main.ImportExport);

    [RelayCommand]
    private Task RefreshAsync() => Main.ReloadAsync();

    [RelayCommand]
    private async Task SnapshotAsync()
    {
        try
        {
            Main.IsBusy = true;
            var snapshot = await Firewall.SnapshotAsync(SnapshotReason.Manual);
            Main.ShowToast(Loc.F("ToastSnapshotCreated", snapshot.PortShieldRules));
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

    [RelayCommand]
    private void OpenConsole()
    {
        if (OperatingSystem.IsWindows())
        {
            Netsh.OpenConsole();
        }
    }

    [RelayCommand]
    private async Task ResetFirewallAsync()
    {
        var confirm = await Host.ConfirmAsync(Loc.T("ResetTitle"), Loc.T("ResetText"), Loc.T("BtnReset"), danger: true, confirmIcon: "IconUndo");
        if (!confirm.Confirmed)
        {
            return;
        }

        await RunPolicyAsync(Firewall.ResetFirewallAsync, "ToastResetDone");
        Main.Snapshots.Reload();
    }
}
