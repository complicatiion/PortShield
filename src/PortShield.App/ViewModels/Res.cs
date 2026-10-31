using Avalonia;
using Avalonia.Media;

namespace PortShield.App.ViewModels;

/// <summary>Theme resources (brushes, icons) for view models.</summary>
public static class Res
{
    public static IBrush Brush(string key)
    {
        if (Application.Current is { } app && app.TryGetResource(key, app.ActualThemeVariant, out var value) && value is IBrush brush)
        {
            return brush;
        }

        return Brushes.Gray;
    }

    public static Geometry? Icon(string key)
    {
        if (Application.Current is { } app && app.TryGetResource(key, null, out var value) && value is Geometry geometry)
        {
            return geometry;
        }

        return null;
    }
}
