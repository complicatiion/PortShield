using System.Globalization;
using Avalonia;
using Avalonia.Controls;

namespace PortShield.App.Localization;

/// <summary>Runtime language switch (English/German). Texts are app resources bound via DynamicResource.</summary>
public static class Loc
{
    private static IReadOnlyDictionary<string, string> _current = Strings.En;
    private static ResourceDictionary? _applied;

    /// <summary>English unless the user picked another language.</summary>
    public const string DefaultLanguage = "en";

    public static string Language { get; private set; } = DefaultLanguage;

    public static event Action? LanguageChanged;

    public static IReadOnlyList<(string Code, string Name)> Languages { get; } =
    [
        ("en", "English"),
        ("de", "Deutsch")
    ];

    public static void Apply(string? language)
    {
        Language = string.Equals(language, "de", StringComparison.OrdinalIgnoreCase) ? "de" : "en";
        _current = Language == "de" ? Strings.De : Strings.En;

        // Swap one dictionary: a single change notification instead of hundreds.
        var resources = Application.Current?.Resources;
        if (resources is not null)
        {
            var dictionary = new ResourceDictionary();
            foreach (var pair in Strings.En)
            {
                dictionary[pair.Key] = _current.TryGetValue(pair.Key, out var value) ? value : pair.Value;
            }

            if (_applied is not null)
            {
                resources.MergedDictionaries.Remove(_applied);
            }

            resources.MergedDictionaries.Add(dictionary);
            _applied = dictionary;
        }

        LanguageChanged?.Invoke();
    }

    public static string T(string key) =>
        _current.TryGetValue(key, out var value) ? value
        : Strings.En.TryGetValue(key, out var fallback) ? fallback
        : key;

    public static string F(string key, params object?[] args)
    {
        try
        {
            return string.Format(CultureInfo.CurrentCulture, T(key), args);
        }
        catch (FormatException)
        {
            return T(key);
        }
    }
}
