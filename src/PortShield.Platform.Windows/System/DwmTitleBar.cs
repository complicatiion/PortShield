using System.Runtime.InteropServices;

namespace PortShield.Platform.Windows;

/// <summary>Colors the native window title bar (dark mode on Windows 10 20H1+, caption color on Windows 11).</summary>
public static class DwmTitleBar
{
    private const int DwmwaUseImmersiveDarkModeOld = 19;
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaBorderColor = 34;
    private const int DwmwaCaptionColor = 35;
    private const int DwmwaTextColor = 36;

    /// <param name="hwnd">Native window handle.</param>
    /// <param name="caption">Caption color as 0xRRGGBB.</param>
    /// <param name="text">Title text color as 0xRRGGBB.</param>
    /// <param name="dark">Dark title bar buttons (Windows 10).</param>
    public static void Apply(IntPtr hwnd, int caption, int text, bool dark = true)
    {
        if (hwnd == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var on = dark ? 1 : 0;
            if (DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref on, sizeof(int)) != 0)
            {
                DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeOld, ref on, sizeof(int));
            }

            // Ignored before Windows 11 (returns an error code, no exception).
            var captionRef = ToColorRef(caption);
            var textRef = ToColorRef(text);
            DwmSetWindowAttribute(hwnd, DwmwaCaptionColor, ref captionRef, sizeof(int));
            DwmSetWindowAttribute(hwnd, DwmwaBorderColor, ref captionRef, sizeof(int));
            DwmSetWindowAttribute(hwnd, DwmwaTextColor, ref textRef, sizeof(int));
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
    }

    // COLORREF is 0x00BBGGRR.
    private static int ToColorRef(int rgb) =>
        ((rgb & 0xFF) << 16) | (rgb & 0xFF00) | ((rgb >> 16) & 0xFF);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
