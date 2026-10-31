using Avalonia;
using PortShield.App.Services;
using PortShield.Platform.Windows;

namespace PortShield.App;

internal static class Program
{
    /// <summary>Signal to the running instance: show window (and take over pending paths).</summary>
    internal static EventWaitHandle? ShowSignal { get; private set; }

    internal static bool StartInTray { get; private set; }

    /// <summary>Paths from "--add" (Explorer context menu) for the first instance.</summary>
    internal static IReadOnlyList<string> InitialAdds { get; private set; } = [];

    [STAThread]
    public static int Main(string[] args)
    {
        bool Has(string flag) => args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

        // Command line for the installer (no window).
        if (OperatingSystem.IsWindows())
        {
            if (Has("--register-autostart"))
            {
                return SelfAutostart.Register(SystemInfo.CurrentUser(), Environment.ProcessPath ?? "") ? 0 : 1;
            }

            if (Has("--unregister-autostart"))
            {
                return SelfAutostart.Unregister(SystemInfo.CurrentUser()) ? 0 : 1;
            }

            if (Has("--unregister-autostart-all"))
            {
                SelfAutostart.UnregisterAll();
                return 0;
            }
        }

        // Command line (list, block, export …): no window, no single-instance check.
        if (Cli.CliRunner.IsCliCall(args))
        {
            return Cli.CliRunner.Run(args);
        }

        StartInTray = Has("--tray");
        var adds = PendingAdds.Parse(args);

        Mutex? mutex = null;
        if (OperatingSystem.IsWindows())
        {
            // One instance per session; a second start brings the window to front and hands over --add paths.
            mutex = new Mutex(true, @"Local\PortShield.App", out var createdNew);
            if (!createdNew && Has("--restarted"))
            {
                // Restart after a reset: wait until the previous instance has exited.
                try
                {
                    createdNew = mutex.WaitOne(TimeSpan.FromSeconds(30));
                }
                catch (AbandonedMutexException)
                {
                    createdNew = true;
                }
            }

            if (!createdNew)
            {
                PendingAdds.Write(adds);
                try
                {
                    using var existing = EventWaitHandle.OpenExisting(@"Local\PortShield.App.Show");
                    existing.Set();
                }
                catch
                {
                    // First instance not ready yet.
                }

                mutex.Dispose();
                return 0;
            }

            ShowSignal = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\PortShield.App.Show");
        }

        InitialAdds = adds;

        try
        {
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args, Avalonia.Controls.ShutdownMode.OnExplicitShutdown);
        }
        finally
        {
            ShowSignal?.Dispose();
            mutex?.ReleaseMutex();
            mutex?.Dispose();
        }
    }

    // Also used by the Avalonia designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
