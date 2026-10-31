using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Models;
using PortShield.Core.Storage;
using PortShield.Platform.Windows;

namespace PortShield.App.ViewModels;

public sealed record ThemeOption(string Code, string Name);

/// <summary>Settings: saved immediately on every change.</summary>
public sealed partial class SettingsViewModel : PageViewModel
{
    private bool _loading;

    public SettingsViewModel(MainViewModel main) : base(main)
    {
        _loading = true;
        _closeToTray = Ui.CloseToTray;
        _notifications = Ui.NotificationsEnabled;
        _namePrefix = Ui.NamePrefix;
        _scanRecursive = Ui.ScanRecursive;
        _skipInstallers = Ui.ScanSkipInstallers;
        _snapshotBeforeChanges = Ui.SnapshotBeforeChanges;
        _snapshotKeep = Math.Clamp(Ui.SnapshotKeep, 1, 500);
        _killSwitchLan = Ui.KillSwitchLanAllowed;
        _protectedPaths = string.Join(Environment.NewLine, Ui.ProtectedPaths);
        _directionIndex = (int)Ui.DefaultDirection;
        _actionIndex = Ui.DefaultAction == RuleAction.Allow ? 1 : 0;
        _scopeIndex = Ui.DefaultScope == RuleScope.Internet ? 1 : 0;
        _shellMenu = OperatingSystem.IsWindows() && ShellIntegration.IsRegistered();
        _loading = false;
    }

    /// <summary>The sign-in task is read in the background (schtasks takes a moment) every time the page opens.</summary>
    public override void OnActivated()
    {
        SyncKillSwitchLan();
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        _ = Task.Run(() => SelfAutostart.IsRegistered(SystemInfo.CurrentUser())).ContinueWith(t =>
        {
            if (t.IsCompletedSuccessfully)
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() => SetQuietly(() => Autostart = t.Result));
            }
        }, TaskScheduler.Default);
    }

    /// <summary>The overview changed the kill switch mode.</summary>
    public void SyncKillSwitchLan() => SetQuietly(() => KillSwitchLan = Ui.KillSwitchLanAllowed);

    private void SetQuietly(Action set)
    {
        _loading = true;
        try
        {
            set();
        }
        finally
        {
            _loading = false;
        }
    }

    public override string TitleKey => "NavSettings";

    // ------------------------------------------------------------------ General

    public IReadOnlyList<LanguageOption> Languages => LanguageOption.All;

    public LanguageOption? SelectedLanguage
    {
        get => LanguageOption.Current;
        set
        {
            if (value is not null && value.Code != Loc.Language)
            {
                Main.SetLanguage(value.Code);
            }
        }
    }

    /// <summary>Dark (default), light, system.</summary>
    public IReadOnlyList<ThemeOption> Themes =>
    [
        new("dark", Loc.T("ThemeDark")),
        new("light", Loc.T("ThemeLight")),
        new("system", Loc.T("ThemeSystem"))
    ];

    public ThemeOption? SelectedTheme
    {
        get => Themes.FirstOrDefault(t => t.Code == Ui.Theme) ?? Themes[0];
        set
        {
            if (value is not null && value.Code != Ui.Theme)
            {
                Ui.Theme = value.Code;
                Ui.Save();
                Main.ApplyTheme();
                OnPropertyChanged();
            }
        }
    }

    public override void OnLanguageChanged()
    {
        base.OnLanguageChanged();
        OnPropertyChanged(nameof(Themes));
        OnPropertyChanged(nameof(SelectedTheme));
        OnPropertyChanged(nameof(SelectedLanguage));
        OnPropertyChanged(nameof(Directions));
        OnPropertyChanged(nameof(DirectionIndex));
        OnPropertyChanged(nameof(Actions));
        OnPropertyChanged(nameof(ActionIndex));
        OnPropertyChanged(nameof(Scopes));
        OnPropertyChanged(nameof(ScopeIndex));
    }

    // ------------------------------------------------------------------ Tray

    [ObservableProperty]
    private bool _closeToTray;

    [ObservableProperty]
    private bool _notifications;

    [ObservableProperty]
    private bool _autostart;

    partial void OnCloseToTrayChanged(bool value) => Save(() => Ui.CloseToTray = value);

    partial void OnNotificationsChanged(bool value) => Save(() => Ui.NotificationsEnabled = value);

    partial void OnAutostartChanged(bool value)
    {
        if (_loading || !OperatingSystem.IsWindows())
        {
            return;
        }

        _ = ChangeAutostartAsync(value);
    }

    private async Task ChangeAutostartAsync(bool value)
    {
        var user = SystemInfo.CurrentUser();
        var exe = AppEnvironment.ExecutablePath;
        var ok = await Task.Run(() => value ? SelfAutostart.Register(user, exe) : SelfAutostart.Unregister(user));
        if (!ok)
        {
            Main.ShowToast(Loc.T("ToastAutostartFailed"), isError: true);
            SetQuietly(() => Autostart = !value);
        }
    }

    // ------------------------------------------------------------------ New rules

    public IReadOnlyList<string> Directions => [Loc.T("DirOut"), Loc.T("DirIn"), Loc.T("DirBoth")];

    public IReadOnlyList<string> Actions => [Loc.T("ActionBlock"), Loc.T("ActionAllow")];

    public IReadOnlyList<string> Scopes => [Loc.T("ScopeAll"), Loc.T("ScopeInternet")];

    [ObservableProperty]
    private int _directionIndex;

    [ObservableProperty]
    private int _actionIndex;

    [ObservableProperty]
    private int _scopeIndex;

    [ObservableProperty]
    private string _namePrefix;

    [ObservableProperty]
    private bool _scanRecursive;

    [ObservableProperty]
    private bool _skipInstallers;

    partial void OnDirectionIndexChanged(int value) => Save(() => Ui.DefaultDirection = (DirectionChoice)Math.Clamp(value, 0, 2));

    partial void OnActionIndexChanged(int value) => Save(() => Ui.DefaultAction = value == 1 ? RuleAction.Allow : RuleAction.Block);

    partial void OnScopeIndexChanged(int value) => Save(() => Ui.DefaultScope = value == 1 ? RuleScope.Internet : RuleScope.All);

    partial void OnNamePrefixChanged(string value) => Save(() => Ui.NamePrefix = string.IsNullOrWhiteSpace(value) ? "PortShield" : value.Trim());

    partial void OnScanRecursiveChanged(bool value) => Save(() => Ui.ScanRecursive = value);

    partial void OnSkipInstallersChanged(bool value) => Save(() => Ui.ScanSkipInstallers = value);

    // ------------------------------------------------------------------ Safety

    [ObservableProperty]
    private bool _snapshotBeforeChanges;

    [ObservableProperty]
    private decimal _snapshotKeep;

    [ObservableProperty]
    private bool _killSwitchLan;

    partial void OnSnapshotBeforeChangesChanged(bool value) => Save(() => Ui.SnapshotBeforeChanges = value);

    partial void OnSnapshotKeepChanged(decimal value) => Save(() => Ui.SnapshotKeep = (int)Math.Clamp(value, 1, 500));

    partial void OnKillSwitchLanChanged(bool value)
    {
        if (!_loading)
        {
            // Same path as the overview switch: saves and re-creates an active kill switch in the new mode.
            Main.Overview.KillSwitchLan = value;
        }
    }

    [ObservableProperty]
    private string _protectedPaths;

    [RelayCommand]
    private void SaveProtected()
    {
        Ui.ProtectedPaths = ProtectedPaths.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.Trim('"'))
            .Where(p => p.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        Ui.Save();
        ProtectedPaths = string.Join(Environment.NewLine, Ui.ProtectedPaths);
        Main.ShowToast(Loc.T("ToastSaved"));
    }

    [RelayCommand]
    private async Task AddProtectedAsync()
    {
        var files = await Host.PickFilesAsync(Loc.T("PickApplications"), Loc.T("FileTypePrograms"), MainViewModel.ExePatterns, multiple: true);
        if (files.Count == 0)
        {
            return;
        }

        ProtectedPaths = string.Join(Environment.NewLine, ProtectedPaths.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Concat(files));
        SaveProtected();
    }

    // ------------------------------------------------------------------ Explorer

    [ObservableProperty]
    private bool _shellMenu;

    partial void OnShellMenuChanged(bool value)
    {
        if (_loading || !OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            if (value)
            {
                ShellIntegration.Register(AppEnvironment.ExecutablePath, Loc.T("ShellMenuFile"), Loc.T("ShellMenuFolder"));
            }
            else
            {
                ShellIntegration.Unregister();
            }
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
    }

    // ------------------------------------------------------------------ Data

    public string DataFolder => AppPaths.DataDirectory;

    [RelayCommand]
    private void OpenDataFolder() => AppEnvironment.OpenFolder(AppPaths.DataDirectory, create: true);

    [RelayCommand]
    private void OpenSettingsFolder() => AppEnvironment.OpenFolder(Path.GetDirectoryName(AppPaths.SettingsFile), create: true);

    [RelayCommand]
    private async Task RemoveAllRulesAsync()
    {
        var count = Firewall.Rules.Count(r => r.IsPortShield);
        if (count == 0)
        {
            Main.ShowToast(Loc.T("ToastNoOwnRules"));
            return;
        }

        var confirm = await Host.ConfirmAsync(Loc.T("RemoveAllTitle"), Loc.F("RemoveAllText", count), Loc.T("BtnRemoveAll"), danger: true);
        if (!confirm.Confirmed)
        {
            return;
        }

        try
        {
            Main.IsBusy = true;
            var result = await Firewall.DeleteAllOwnAsync();
            Main.ShowResult(result, "ToastDeleted");
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

    // ------------------------------------------------------------------ Reset

    /// <summary>Settings back to default (language, appearance, defaults, hidden presets …); rules stay. Restarts PortShield.</summary>
    [RelayCommand]
    private async Task ResetSettingsAsync()
    {
        var confirm = await Host.ConfirmAsync(Loc.T("ResetSettingsTitle"), Loc.T("ResetSettingsText"), Loc.T("BtnResetPortShield"), danger: true,
            confirmIcon: "IconUndo");
        if (!confirm.Confirmed)
        {
            return;
        }

        Ui.DeleteAndFreeze();
        Host.RestartApplication?.Invoke();
    }

    /// <summary>
    /// Everything as after a fresh installation: PortShield rules, kill switch, whitelist mode, own rule sets, watch list,
    /// temporary rules, settings, autostart and context menu. Snapshots only when ticked. Restarts PortShield.
    /// </summary>
    [RelayCommand]
    private async Task FactoryResetAsync()
    {
        var count = Firewall.Rules.Count(r => r.IsPortShield && !r.IsKillSwitch);
        var confirm = await Host.ConfirmAsync(Loc.T("FactoryResetTitle"), Loc.F("FactoryResetText", count), Loc.T("BtnFactoryReset"), danger: true,
            optionText: Loc.T("LblDeleteSnapshotsToo"), optionDefault: false, confirmIcon: "IconRestore");
        if (!confirm.Confirmed)
        {
            return;
        }

        try
        {
            Main.IsBusy = true;
            var result = await Firewall.FactoryResetAsync(confirm.OptionChecked);
            if (result.HasErrors)
            {
                // Something could not be removed: stay open so the user sees it.
                Main.ShowResult(result, "ToastDeleted");
                return;
            }

            if (OperatingSystem.IsWindows())
            {
                var user = SystemInfo.CurrentUser();
                await Task.Run(() =>
                {
                    SelfAutostart.Unregister(user);
                    if (AppPaths.IsPortable)
                    {
                        ShellIntegration.Unregister();
                    }
                    else
                    {
                        // The installer registers the Explorer context menu by default.
                        ShellIntegration.Register(AppEnvironment.ExecutablePath, Loc.T("ShellMenuFile"), Loc.T("ShellMenuFolder"));
                    }
                });
            }

            Ui.DeleteAndFreeze();
            Host.RestartApplication?.Invoke();
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

    private void Save(Action apply)
    {
        if (_loading)
        {
            return;
        }

        apply();
        Ui.Save();
    }
}
