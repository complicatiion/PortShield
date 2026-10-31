using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.App.ViewModels;
using PortShield.App.Views;
using PortShield.Platform.Windows;

namespace PortShield.App;

public partial class App : Application
{
    private TrayController? _tray;
    private MainWindow? _mainWindow;
    private MainViewModel? _viewModel;
    private IClassicDesktopStyleApplicationLifetime? _desktop;

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            _desktop = desktop;
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;

            var ui = UiSettings.Load();
            // No language saved yet: German if Windows shows German (display language, region or keyboard), else English.
            Loc.Apply(ui.Language ?? (OperatingSystem.IsWindows() ? SystemLanguage.Detect() : Loc.DefaultLanguage));

            var host = new UiHost();
            _viewModel = new MainViewModel(host, ui);
            _mainWindow = new MainWindow { DataContext = _viewModel };
            host.MainWindow = _mainWindow;
            host.ShowMainWindow = ShowMainWindow;
            host.ExitApplication = Exit;
            host.RestartApplication = Restart;
            _mainWindow.ExitRequested += Exit;

            _tray = new TrayController(this, _viewModel, ShowMainWindow, Exit);
            desktop.Exit += (_, _) =>
            {
                _tray?.Dispose();
                _viewModel?.Firewall.Dispose();
            };

            StartShowSignalListener();
            if (!Program.StartInTray)
            {
                ShowMainWindow();
            }

            _ = _viewModel.InitializeAsync(Program.InitialAdds);
        }

        base.OnFrameworkInitializationCompleted();
    }

    private void ShowMainWindow()
    {
        if (_mainWindow is null)
        {
            return;
        }

        var window = _mainWindow;
        if (!window.IsVisible)
        {
            window.Show();
            window.NotifyShown();
        }

        if (window.WindowState == WindowState.Minimized)
        {
            window.WindowState = window.DataContext is MainViewModel { Ui.WindowMaximized: true } ? WindowState.Maximized : WindowState.Normal;
        }

        window.Activate();
    }

    /// <summary>Starts a new instance (it waits for this one to end) and exits – used after a reset.</summary>
    private void Restart()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(AppEnvironment.ExecutablePath, "--restarted")
            {
                UseShellExecute = false,
                WorkingDirectory = AppContext.BaseDirectory
            });
        }
        catch (Exception)
        {
            // The user starts PortShield again by hand.
        }

        Exit();
    }

    private void Exit()
    {
        if (_mainWindow is not null)
        {
            _mainWindow.AllowClose = true;
            _mainWindow.Close();
        }

        _desktop?.Shutdown();
    }

    /// <summary>A second app start signals "show window" (and may have handed over paths with --add).</summary>
    private void StartShowSignalListener()
    {
        var signal = Program.ShowSignal;
        if (signal is null)
        {
            return;
        }

        var thread = new Thread(() =>
        {
            try
            {
                while (signal.WaitOne())
                {
                    Dispatcher.UIThread.Post(() =>
                    {
                        ShowMainWindow();
                        if (_viewModel is not null)
                        {
                            _ = _viewModel.ProcessPendingAddsAsync();
                        }
                    });
                }
            }
            catch (ObjectDisposedException)
            {
                // App is exiting.
            }
        })
        {
            IsBackground = true,
            Name = "PortShield.ShowSignal"
        };
        thread.Start();
    }
}
