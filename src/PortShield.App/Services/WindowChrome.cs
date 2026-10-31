using Avalonia;
using Avalonia.VisualTree;
using Avalonia.Controls;
using Avalonia.Styling;
using Avalonia.Threading;
using PortShield.Platform.Windows;

namespace PortShield.App.Services;

/// <summary>Native title bar in the theme colors (sidebar colour of dark or light), optionally maximized after opening.</summary>
public static class WindowChrome
{
    private static readonly List<WeakReference<Window>> Windows = [];

    public static void Apply(Window window, bool maximize)
    {
        Windows.Add(new WeakReference<Window>(window));
        window.Closed += (_, _) => Windows.RemoveAll(w => !w.TryGetTarget(out var t) || ReferenceEquals(t, window));
        window.Opened += (_, _) =>
        {
            Color(window);

            // Windows and dialogs fade in softly.
            Controls.Motion.FadeIn(window.Content as Visual, offsetY: 8, milliseconds: 220);
            if (maximize)
            {
                // After the first layout pass: maximizing earlier can push the title bar off screen.
                Dispatcher.UIThread.Post(() => window.WindowState = WindowState.Maximized, DispatcherPriority.Loaded);
            }
        };
        window.ActualThemeVariantChanged += (_, _) => Color(window);
    }

    /// <summary>After a theme switch.</summary>
    public static void RefreshAll()
    {
        Dispatcher.UIThread.Post(() =>
        {
            foreach (var reference in Windows.ToList())
            {
                if (reference.TryGetTarget(out var window) && window.IsVisible)
                {
                    Color(window);
                }
            }
        }, DispatcherPriority.Background);
    }

    private static void Color(Window window)
    {
        if (!OperatingSystem.IsWindows() || window.TryGetPlatformHandle()?.Handle is not { } hwnd)
        {
            return;
        }

        var dark = window.ActualThemeVariant != ThemeVariant.Light;
        var caption = Resource(window, "ColorBgSidebar") ?? (dark ? 0x24272C : 0xFFFFFF);
        var text = Resource(window, "ColorTextPrimary") ?? (dark ? 0xE6E6E8 : 0x24272C);
        DwmTitleBar.Apply(hwnd, caption, text, dark);
    }

    private static int? Resource(Window window, string key) =>
        window.TryFindResource(key, window.ActualThemeVariant, out var value) && value is Avalonia.Media.Color c
            ? (c.R << 16) | (c.G << 8) | c.B
            : null;
}
