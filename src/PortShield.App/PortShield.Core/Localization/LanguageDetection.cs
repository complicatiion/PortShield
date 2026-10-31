namespace PortShield.Core.Localization;

/// <summary>
/// First-start language: German when Windows shows any sign of German (display language, region, or an installed
/// German keyboard layout – e.g. English display language with a German keyboard), otherwise English. Only used while
/// no language is saved; a language chosen in the settings always wins.
/// </summary>
public static class LanguageDetection
{
    // Multilingual regions (CH, LU) only count through the display language or a German keyboard layout.
    private static readonly string[] GermanRegions = ["DE", "AT", "LI"];

    /// <param name="uiCulture">Windows display language, e.g. "en-US".</param>
    /// <param name="regionCulture">Regional format, e.g. "de-DE".</param>
    /// <param name="keyboardLanguageIds">Language ids (low word of the HKL) of the installed keyboard layouts.</param>
    public static string Choose(string? uiCulture, string? regionCulture, IEnumerable<int> keyboardLanguageIds)
    {
        if (IsGermanLanguage(uiCulture) || IsGermanLanguage(regionCulture) || IsGermanRegion(regionCulture))
        {
            return "de";
        }

        // Primary language id 0x07 = German (de-DE 0x0407, de-CH 0x0807, de-AT 0x0C07, de-LU 0x1007, de-LI 0x1407).
        return keyboardLanguageIds.Any(id => (id & 0x3FF) == 0x07) ? "de" : "en";
    }

    private static bool IsGermanLanguage(string? culture) =>
        !string.IsNullOrEmpty(culture) && (culture.Equals("de", StringComparison.OrdinalIgnoreCase) || culture.StartsWith("de-", StringComparison.OrdinalIgnoreCase));

    private static bool IsGermanRegion(string? culture)
    {
        if (string.IsNullOrEmpty(culture))
        {
            return false;
        }

        var dash = culture.LastIndexOf('-');
        return dash > 0 && GermanRegions.Contains(culture[(dash + 1)..], StringComparer.OrdinalIgnoreCase);
    }
}
