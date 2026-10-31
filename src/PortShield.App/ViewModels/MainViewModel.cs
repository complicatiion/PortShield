using System.Collections.ObjectModel;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.Storage;
using PortShield.Platform.Windows;

namespace PortShield.App.ViewModels;

/// <summary>Main window: navigation, toasts, language, theme, firewall state and the shared "add programs" flows.</summary>
public sealed partial class MainViewModel : ObservableObject
{
    private readonly DispatcherTimer _toastTimer;
    private readonly DispatcherTimer _guardTimer;
    private int _guardTicks;

    public MainViewModel(UiHost host, UiSettings ui)
    {
        Host = host;
        Ui = ui;
        Firewall = new FirewallService(ui);

        Overview = new OverviewViewModel(this);
        Outbound = new RulesViewModel(this, RuleDirection.Outbound);
        Inbound = new RulesViewModel(this, RuleDirection.Inbound);
        RuleSets = new RuleSetsViewModel(this);
        ImportExport = new ImportExportViewModel(this);
        Scan = new ScanViewModel(this);
        Connections = new ConnectionsViewModel(this);
        Snapshots = new SnapshotsViewModel(this);
        Settings = new SettingsViewModel(this);
        About = new AboutViewModel(this);

        OutboundNav = new NavItem("NavOutbound", "IconArrowOut", Outbound);
        InboundNav = new NavItem("NavInbound", "IconArrowIn", Inbound);
        NavGroups =
        [
            new NavGroup(null, [new NavItem("NavOverview", "IconShieldCheck", Overview)]),
            new NavGroup("NavGroupRules",
            [
                OutboundNav,
                InboundNav,
                new NavItem("NavRuleSets", "IconBundle", RuleSets),
                new NavItem("NavConnections", "IconLan", Connections)
            ]),
            new NavGroup("NavGroupManage",
            [
                new NavItem("NavScan", "IconAnalyze", Scan),
                new NavItem("NavSnapshots", "IconBackupRestore", Snapshots),
                new NavItem("NavImportExport", "IconExport", ImportExport)
            ])
        ];
        BottomGroup = new NavGroup(null,
        [
            new NavItem("NavSettings", "IconCog", Settings),
            new NavItem("NavAbout", "IconInfo", About)
        ]);

        foreach (var group in AllGroups)
        {
            group.Activated += OnNavActivated;
        }

        _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
        _toastTimer.Tick += (_, _) =>
        {
            _toastTimer.Stop();
            Toast = null;
        };

        // Temporarily allowed rules are blocked again on time; watched rule sets are checked every 30 minutes.
        _guardTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(20) };
        _guardTimer.Tick += (_, _) => _ = GuardTickAsync();

        Loc.LanguageChanged += OnLanguageChanged;
        Firewall.RulesChanged += () => Dispatcher.UIThread.Post(OnRulesChanged);
        Firewall.StatusChanged += () => Dispatcher.UIThread.Post(OnStatusChanged);

        _isSidebarCollapsed = ui.SidebarCollapsed;
        NavGroups[0].Selected = NavGroups[0].Items[0];
    }

    public UiHost Host { get; }

    public UiSettings Ui { get; }

    public FirewallService Firewall { get; }

    public OverviewViewModel Overview { get; }

    public RulesViewModel Outbound { get; }

    public RulesViewModel Inbound { get; }

    public RuleSetsViewModel RuleSets { get; }

    public ImportExportViewModel ImportExport { get; }

    public ScanViewModel Scan { get; }

    public ConnectionsViewModel Connections { get; }

    public SnapshotsViewModel Snapshots { get; }

    public SettingsViewModel Settings { get; }

    public AboutViewModel About { get; }

    public ObservableCollection<NavGroup> NavGroups { get; }

    public NavGroup BottomGroup { get; }

    public NavItem OutboundNav { get; }

    public NavItem InboundNav { get; }

    private IEnumerable<NavGroup> AllGroups => NavGroups.Append(BottomGroup);

    public IEnumerable<PageViewModel> Pages => AllGroups.SelectMany(g => g.Items).Select(i => i.Page);

    /// <summary>Raised when tray-relevant state changes (language, kill switch, rule counts).</summary>
    public event Action? StateChanged;

    public string WindowTitle { get; } = $"PortShield  v{AppEnvironment.Version}";

    // ------------------------------------------------------------------ Startup

    public async Task InitializeAsync(IReadOnlyList<string> initialAdds)
    {
        ApplyTheme();
        if (!FirewallService.IsSupported)
        {
            ShowToast(Loc.T("ToastWindowsOnly"), isError: true);
            return;
        }

        await ReloadAsync();
        await RestoreTemporaryAsync(all: false);
        _guardTimer.Start();
        if (initialAdds.Count > 0)
        {
            await AddPathsAsync(initialAdds, null);
        }
    }

    /// <summary>Reloads rules and firewall status.</summary>
    public async Task ReloadAsync()
    {
        IsBusy = true;
        try
        {
            await Firewall.RefreshAsync();
            await Firewall.RefreshStatusAsync();
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
        finally
        {
            IsBusy = false;
        }

        _ = Overview.CheckWatchedAsync();
    }

    private async Task GuardTickAsync()
    {
        if (++_guardTicks % 90 == 0 && !IsBusy)
        {
            // Every 30 minutes: reload (integrity check) and look for new programs of watched rule sets.
            await ReloadAsync();
            return;
        }

        if (Firewall.Temporary.Due(DateTime.Now).Count > 0)
        {
            await RestoreTemporaryAsync(all: false, quietOnRepeatedError: true);
        }
    }

    // ------------------------------------------------------------------ Temporarily allowed

    public static readonly IReadOnlyList<int> TemporaryMinutes = [15, 30, 60, 120];

    public async Task AllowTemporarilyAsync(IReadOnlyList<FirewallRuleInfo> rules, int minutes)
    {
        var targets = rules.Where(r => r.IsPortShield && r.PortShieldId is not null).ToList();
        if (targets.Count == 0)
        {
            ShowToast(Loc.T("ToastTemporaryOnlyOwn"));
            return;
        }

        try
        {
            IsBusy = true;
            var result = await Firewall.AllowTemporarilyAsync(targets, TimeSpan.FromMinutes(minutes));
            if (result.Changed == 0 && !result.HasErrors)
            {
                ShowToast(Loc.T("ToastTemporaryNothing"));
            }
            else
            {
                ShowResult(result, "ToastTemporaryAllowed");
            }
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Blocks temporarily allowed rules again (the due ones, or all).</summary>
    private bool _temporaryErrorShown;

    public async Task RestoreTemporaryAsync(bool all, IReadOnlyCollection<string>? ids = null, bool quietOnRepeatedError = false)
    {
        if (!FirewallService.IsSupported)
        {
            return;
        }

        if (Firewall.Temporary.Entries.Count == 0 && !all)
        {
            if (ids is not null)
            {
                ShowToast(Loc.T("ToastNotTemporary"));
            }

            return;
        }

        try
        {
            var result = await Firewall.RestoreTemporaryAsync(all, ids);
            if (result.HasErrors && quietOnRepeatedError && _temporaryErrorShown)
            {
                return;
            }

            _temporaryErrorShown = result.HasErrors;
            if (result.Changed > 0 || result.HasErrors)
            {
                ShowResult(result, "ToastTemporaryRestored");
            }
            else if (ids is not null)
            {
                ShowToast(Loc.T("ToastNotTemporary"));
            }
        }
        catch (Exception ex)
        {
            if (!(quietOnRepeatedError && _temporaryErrorShown))
            {
                ShowError(ex);
            }

            _temporaryErrorShown = true;
        }
    }

    /// <summary>The second start (Explorer context menu) handed paths over.</summary>
    public async Task ProcessPendingAddsAsync()
    {
        var paths = PendingAdds.Take();
        if (paths.Count > 0)
        {
            await AddPathsAsync(paths, null);
        }
    }

    [ObservableProperty]
    private bool _isBusy;

    partial void OnIsBusyChanged(bool value)
    {
        Outbound.NotifyBusy();
        Inbound.NotifyBusy();
    }

    private void OnRulesChanged()
    {
        var own = Firewall.Rules.Where(r => r.IsPortShield && !r.IsKillSwitch).ToList();
        var outbound = own.Count(r => r.Direction == RuleDirection.Outbound);
        var inbound = own.Count - outbound;
        OutboundNav.Badge = outbound > 0 ? outbound.ToString() : null;
        InboundNav.Badge = inbound > 0 ? inbound.ToString() : null;
        foreach (var page in Pages)
        {
            page.OnRulesChanged();
        }

        OnPropertyChanged(nameof(KillSwitchOn));
        StateChanged?.Invoke();
    }

    private void OnStatusChanged()
    {
        foreach (var page in Pages)
        {
            page.OnStatusChanged();
        }

        OnPropertyChanged(nameof(WhitelistOn));
        StateChanged?.Invoke();
    }

    // ------------------------------------------------------------------ Header pills

    public bool IsElevated { get; } = OperatingSystem.IsWindows() && SystemInfo.IsElevated();

    public string AdminPillText => IsElevated ? Loc.T("PillAdmin") : Loc.T("PillNoAdmin");

    public bool KillSwitchOn => Firewall.KillSwitchOn;

    public bool WhitelistOn => Firewall.Status?.WhitelistMode == true;

    // ------------------------------------------------------------------ Navigation

    [ObservableProperty]
    private PageViewModel? _currentPage;

    [ObservableProperty]
    private bool _isSidebarCollapsed;

    public double SidebarWidth => IsSidebarCollapsed ? 68 : 240;

    public Geometry? CurrentPageIcon =>
        AllGroups.SelectMany(g => g.Items).FirstOrDefault(n => ReferenceEquals(n.Page, CurrentPage))?.Icon;

    private void OnNavActivated(NavGroup group, NavItem item)
    {
        foreach (var other in AllGroups)
        {
            if (!ReferenceEquals(other, group))
            {
                other.Selected = null;
            }
        }

        if (!ReferenceEquals(CurrentPage, item.Page))
        {
            CurrentPage = item.Page;
        }
    }

    private PageViewModel? _activePage;

    partial void OnCurrentPageChanged(PageViewModel? value)
    {
        OnPropertyChanged(nameof(CurrentPageIcon));
        _activePage?.OnDeactivated();
        _activePage = value;
        value?.OnActivated();
    }

    public void OnWindowVisibilityChanged(bool visible)
    {
        if (visible)
        {
            CurrentPage?.OnActivated();
        }
        else
        {
            CurrentPage?.OnDeactivated();
        }
    }

    partial void OnIsSidebarCollapsedChanged(bool value)
    {
        OnPropertyChanged(nameof(SidebarWidth));
        Ui.SidebarCollapsed = value;
        Ui.Save();
    }

    public void NavigateTo(PageViewModel page)
    {
        foreach (var group in AllGroups)
        {
            var item = group.Items.FirstOrDefault(n => ReferenceEquals(n.Page, page));
            if (item is not null && group.IsVisible)
            {
                group.Selected = item;
                return;
            }
        }
    }

    [RelayCommand]
    private void ToggleSidebar() => IsSidebarCollapsed = !IsSidebarCollapsed;

    [RelayCommand]
    private void GoOutbound() => NavigateTo(Outbound);

    // ------------------------------------------------------------------ Language & theme

    public void SetLanguage(string code)
    {
        Ui.Language = code;
        Ui.Save();
        Loc.Apply(code);
    }

    private void OnLanguageChanged()
    {
        foreach (var group in AllGroups)
        {
            group.RefreshText();
        }

        foreach (var page in Pages)
        {
            page.OnLanguageChanged();
        }

        OnPropertyChanged(nameof(AdminPillText));
        StateChanged?.Invoke();
    }

    public void ApplyTheme() => Host.ApplyTheme(Ui.Theme);

    // ------------------------------------------------------------------ Adding programs (shared by all pages and the tray)

    public static readonly IReadOnlyList<string> ExePatterns = ["*.exe"];

    /// <summary>Pick one or more .exe files.</summary>
    public async Task AddApplicationsAsync(DirectionChoice? direction)
    {
        var files = await Host.PickFilesAsync(Loc.T("PickApplications"), Loc.T("FileTypePrograms"), ExePatterns, multiple: true);
        if (files.Count > 0)
        {
            await ReviewPathsAsync(files, null, direction);
        }
    }

    /// <summary>Pick a folder: all programs in it (and below).</summary>
    public async Task AddFolderAsync(DirectionChoice? direction)
    {
        var folder = await Host.PickFolderAsync(Loc.T("PickFolder"));
        if (!string.IsNullOrEmpty(folder))
        {
            await ReviewPathsAsync([], folder, direction);
        }
    }

    /// <summary>Pick running programs.</summary>
    public async Task AddProcessAsync(DirectionChoice? direction)
    {
        var picker = new ProcessPickerModel();
        await picker.LoadAsync();
        var paths = await Host.PickProcessesAsync(picker);
        if (paths.Count > 0)
        {
            await ReviewPathsAsync(paths, null, direction);
        }
    }

    /// <summary>Files and folders from the Explorer context menu (--add).</summary>
    public async Task AddPathsAsync(IReadOnlyList<string> paths, DirectionChoice? direction)
    {
        var files = paths.Where(File.Exists).ToList();
        var folders = paths.Where(Directory.Exists).ToList();
        if (folders.Count == 1 && files.Count == 0)
        {
            await ReviewPathsAsync([], folders[0], direction);
            return;
        }

        var recursive = Ui.ScanRecursive;
        var all = await Task.Run(() => files.Concat(folders.SelectMany(f => ProgramPaths.FindExecutables(f, recursive)))
            .Where(p => ProgramPaths.IsExecutable(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList());
        if (all.Count == 0)
        {
            ShowToast(Loc.T("ToastNoPrograms"));
            return;
        }

        await ReviewPathsAsync(all, null, direction);
    }

    private async Task ReviewPathsAsync(IReadOnlyList<string> files, string? folder, DirectionChoice? direction)
    {
        var model = AddRulesModel.ForPaths(this, files, folder, direction ?? Ui.DefaultDirection);
        await ReviewAsync(model, null);
    }

    /// <summary>Shows the review dialog and writes the rules; returns the number of changed rules.</summary>
    public async Task<int> ReviewAsync(AddRulesModel model, SnapshotReason? snapshotReason)
    {
        try
        {
            IsBusy = true;
            await model.PrepareAsync();
        }
        finally
        {
            IsBusy = false;
        }

        if (model.Items.Count == 0)
        {
            ShowToast(Loc.T("ToastNoPrograms"));
            return 0;
        }

        if (!await Host.ReviewRulesAsync(model))
        {
            return 0;
        }

        var plan = model.BuildPlan();
        if (plan.Count == 0)
        {
            ShowToast(Loc.T("ToastNothingToDo"));
            return 0;
        }

        try
        {
            IsBusy = true;
            var result = await Firewall.ApplyAsync(plan, snapshotReason);
            ShowResult(result, "ToastRulesApplied");
            if (Overview.WatchNotices.Count > 0)
            {
                _ = Overview.CheckWatchedAsync();
            }

            return result.Changed;
        }
        catch (Exception ex)
        {
            ShowError(ex);
            return 0;
        }
        finally
        {
            IsBusy = false;
        }
    }

    // ------------------------------------------------------------------ Kill switch

    [RelayCommand]
    private Task ToggleKillSwitchAsync() => SetKillSwitchAsync(!KillSwitchOn);

    public async Task SetKillSwitchAsync(bool on)
    {
        if (on && !Ui.KillSwitchLanAllowed)
        {
            var remote = OperatingSystem.IsWindows() && SystemInfo.IsRemoteSession();
            var confirm = await Host.ConfirmAsync(Loc.T("KillSwitchTitle"),
                Loc.T(remote ? "KillSwitchRemoteWarning" : "KillSwitchFullWarning"), Loc.T("BtnKillSwitchOn"), danger: true, confirmIcon: "IconPower");
            if (!confirm.Confirmed)
            {
                return;
            }
        }

        try
        {
            IsBusy = true;
            var result = await Firewall.SetKillSwitchAsync(on, Ui.KillSwitchLanAllowed);
            if (result.HasErrors)
            {
                ShowResult(result, "ToastRulesApplied");
            }
            else
            {
                ShowToast(Loc.T(on ? (Ui.KillSwitchLanAllowed ? "ToastKillSwitchOnLan" : "ToastKillSwitchOn") : "ToastKillSwitchOff"));
            }
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    // ------------------------------------------------------------------ Toasts

    [ObservableProperty]
    private string? _toast;

    [ObservableProperty]
    private bool _toastIsError;

    public bool HasToast => !string.IsNullOrEmpty(Toast);

    partial void OnToastChanged(string? value) => OnPropertyChanged(nameof(HasToast));

    public void ShowToast(string message, bool isError = false)
    {
        if (!Ui.NotificationsEnabled && !isError)
        {
            return;
        }

        _toastTimer.Stop();
        ToastIsError = isError;
        Toast = message;
        _toastTimer.Interval = TimeSpan.FromSeconds(Math.Clamp(isError ? Ui.ErrorToastSeconds : Ui.ToastSeconds, 1, 120));
        _toastTimer.Start();
    }

    public void ShowError(Exception ex) => ShowToast(Loc.F("ToastError", ex.Message), isError: true);

    /// <summary>"12 rules changed" or the first error.</summary>
    public void ShowResult(ChangeResult result, string successKey)
    {
        if (result.HasErrors)
        {
            var first = result.Errors[0];
            ShowToast(Loc.F("ToastPartialErrors", result.Changed, result.Errors.Count, first.Rule, first.Message), isError: true);
        }
        else
        {
            ShowToast(Loc.F(successKey, result.Changed) + (result.Snapshot is null ? "" : " " + Loc.T("ToastSnapshotTaken")));
        }
    }

    [RelayCommand]
    private void CloseToast()
    {
        _toastTimer.Stop();
        Toast = null;
    }

    public static void ReleaseMemory() => _ = Task.Run(() =>
    {
        System.Runtime.GCSettings.LargeObjectHeapCompactionMode = System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
    });
}
