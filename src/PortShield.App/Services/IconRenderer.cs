using Avalonia;
using Avalonia.Media;
using Avalonia.Media.Imaging;

namespace PortShield.App.Services;

/// <summary>Renders 24×24 vector icons to bitmaps (tray menu).</summary>
public static class IconRenderer
{
    private static readonly Dictionary<string, Bitmap> Cache = new();

    public static Geometry? GetGeometry(string key)
    {
        if (Application.Current is { } app && app.TryGetResource(key, null, out var value) && value is Geometry geometry)
        {
            return geometry;
        }

        return null;
    }

    public static Bitmap? Render(string key, Color color, int size = 32)
    {
        var cacheKey = $"{key}|{color}|{size}";
        if (Cache.TryGetValue(cacheKey, out var cached))
        {
            return cached;
        }

        var geometry = GetGeometry(key);
        if (geometry is null)
        {
            return null;
        }

        var bitmap = new RenderTargetBitmap(new PixelSize(size, size), new Vector(96, 96));
        using (var context = bitmap.CreateDrawingContext())
        {
            var scale = size / 24d;
            using (context.PushTransform(Matrix.CreateScale(scale, scale)))
            {
                context.DrawGeometry(new SolidColorBrush(color), null, geometry);
            }
        }

        Cache[cacheKey] = bitmap;
        return bitmap;
    }
}
