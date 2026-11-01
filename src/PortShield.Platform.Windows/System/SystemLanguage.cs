using System.Globalization;
using System.Runtime.InteropServices;
using PortShield.Core.Localization;

namespace PortShield.Platform.Windows;

/// <summary>Reads display language, regional format and installed keyboard layouts for the first-start language.</summary>
public static class SystemLanguage
{
    public static string Detect()
    {
        try
        {
            return LanguageDetection.Choose(CultureInfo.CurrentUICulture.Name, CultureInfo.CurrentCulture.Name, KeyboardLanguageIds());
        }
        catch (Exception)
        {
            return "en";
        }
    }

    /// <summary>Language ids of the keyboard layouts installed for the current user (GetKeyboardLayoutList).</summary>
    public static IReadOnlyList<int> KeyboardLanguageIds()
    {
        var count = GetKeyboardLayoutList(0, null);
        if (count <= 0)
        {
            return [];
        }

        var layouts = new IntPtr[count];
        count = GetKeyboardLayoutList(layouts.Length, layouts);
        return layouts.Take(Math.Max(0, count)).Select(h => (int)((long)h & 0xFFFF)).Distinct().ToList();
    }

    [DllImport("user32.dll")]
    private static extern int GetKeyboardLayoutList(int count, [Out] IntPtr[]? list);
}
