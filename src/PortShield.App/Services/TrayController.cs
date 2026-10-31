using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using PortShield.App.Localization;
using PortShield.App.ViewModels;

namespace PortShield.App.Services;

/// <summary>System tray: left click opens PortShield, right click shows the menu (kill switch, add programs, pages). Every entry has an icon.</summary>
public sealed class TrayController : IDisposable
{
    // Native tray menus have no theme: neutral icons, Royal Blue for the main actions, red for the kill switch.
    private static readonly Color IconColor = Color.Parse("#8A8C91");
    private static readonly Color AccentColor = Color.Parse("#536ADC");
    private static readonly Color DangerColor = Color.Parse("#C93C3C");

    private static readonly Lazy<Bitmap> Logo = new(() =>
    {
        using var stream = AssetLoader.Open(new Uri("avares://PortShield/Assets/tray-logo.png"));
        return new Bitmap(stream);
    });

    private readonly MainViewModel _main;
    private readonly Action _showMainWindow;
    private readonly Action _exit;
    private readonly TrayIcon _trayIcon;

    public TrayController(Application app, MainViewModel main, Action showMainWindow, Action exit)
    {
        _main = main;
        _showMainWindow = showMainWindow;
        _exit = exit;

        using var stream = AssetLoader.Open(new Uri("avares://PortShield/Assets/tray.ico"));
        _trayIcon = new TrayIcon
        {
            Icon = new WindowIcon(stream),
            ToolTipText = "PortShield",
            IsVisible = true
        };
        _trayIcon.Clicked += (_, _) => _showMainWindow();
        TrayIcon.SetIcons(app, new TrayIcons { _trayIcon });

        _main.StateChanged += Update;
        Update();
    }

    private void Update()
    {
        _trayIcon.ToolTipText = _main.KillSwitchOn ? "PortShield – " + Loc.T("PillKillSwitch") : "PortShield";
        _trayIcon.Menu = BuildMenu();
    }

    private NativeMenu BuildMenu()
    {
        var menu = new NativeMenu();
        var header = new NativeMenuItem("PortShield  v" + AppEnvironment.Version) { Icon = Logo.Value };
        header.Click += (_, _) => _showMainWindow();
        menu.Add(header);
        menu.Add(new NativeMenuItemSeparator());

        menu.Add(_main.KillSwitchOn
            ? Item(Loc.T("TrayKillSwitchOff"), "IconPower", () => _ = _main.SetKillSwitchAsync(false), AccentColor)
            : Item(Loc.T("TrayKillSwitchOn"), "IconPower", () => _ = _main.SetKillSwitchAsync(true), DangerColor));
        menu.Add(new NativeMenuItemSeparator());

        menu.Add(Item(Loc.T("BtnAddApplication"), "IconPlus", () => Show(() => _ = _main.AddApplicationsAsync(null)), AccentColor));
        menu.Add(Item(Loc.T("BtnAddFolder"), "IconFolderOpen", () => Show(() => _ = _main.AddFolderAsync(null))));
        menu.Add(Item(Loc.T("BtnAddProcess"), "IconApplication", () => Show(() => _ = _main.AddProcessAsync(null))));
        menu.Add(new NativeMenuItemSeparator());

        menu.Add(Item(Loc.T("TrayOpen"), "IconWindow", _showMainWindow));
        menu.Add(Item(Loc.T("NavOverview"), "IconShieldCheck", () => Navigate(_main.Overview)));
        menu.Add(Item(Loc.T("NavOutbound"), "IconArrowOut", () => Navigate(_main.Outbound)));
        menu.Add(Item(Loc.T("NavInbound"), "IconArrowIn", () => Navigate(_main.Inbound)));
        menu.Add(Item(Loc.T("NavRuleSets"), "IconBundle", () => Navigate(_main.RuleSets)));
        menu.Add(Item(Loc.T("NavConnections"), "IconLan", () => Navigate(_main.Connections)));
        menu.Add(Item(Loc.T("NavScan"), "IconAnalyze", () => Navigate(_main.Scan)));
        menu.Add(Item(Loc.T("NavSnapshots"), "IconBackupRestore", () => Navigate(_main.Snapshots)));
        menu.Add(Item(Loc.T("NavImportExport"), "IconExport", () => Navigate(_main.ImportExport)));
        menu.Add(new NativeMenuItemSeparator());

        menu.Add(Item(Loc.T("NavSettings"), "IconCog", () => Navigate(_main.Settings)));
        menu.Add(Submenu(Loc.T("LblLanguage"), "IconLanguage", BuildLanguageMenu()));
        menu.Add(Item(Loc.T("NavAbout"), "IconInfo", () => Navigate(_main.About)));
        menu.Add(new NativeMenuItemSeparator());
        menu.Add(Item(Loc.T("TrayExit"), "IconExit", _exit));
        return menu;
    }

    private NativeMenu BuildLanguageMenu()
    {
        var menu = new NativeMenu();
        foreach (var language in LanguageOption.All)
        {
            var code = language.Code;
            var header = language.Code == Loc.Language ? $"{language.Name}  ✓" : language.Name;
            var item = new NativeMenuItem(header) { Icon = language.Flag ?? IconRenderer.Render("IconLanguage", IconColor) };
            item.Click += (_, _) => _main.SetLanguage(code);
            menu.Add(item);
        }

        return menu;
    }

    private void Show(Action action)
    {
        _showMainWindow();
        action();
    }

    private void Navigate(PageViewModel page)
    {
        _showMainWindow();
        _main.NavigateTo(page);
    }

    private static NativeMenuItem Item(string header, string iconKey, Action action, Color? color = null)
    {
        var item = new NativeMenuItem(header) { Icon = IconRenderer.Render(iconKey, color ?? IconColor) };
        item.Click += (_, _) => action();
        return item;
    }

    private static NativeMenuItem Submenu(string header, string iconKey, NativeMenu menu) =>
        new(header) { Icon = IconRenderer.Render(iconKey, IconColor), Menu = menu };

    public void Dispose()
    {
        _main.StateChanged -= Update;
        _trayIcon.IsVisible = false;
        _trayIcon.Dispose();
    }
}
