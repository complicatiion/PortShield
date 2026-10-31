using Avalonia.Media.Imaging;
using Avalonia.Platform;

namespace PortShield.App.Localization;

/// <summary>Language with flat flag icon.</summary>
public sealed record LanguageOption(string Code, string Name, Bitmap? Flag)
{
    private static readonly Lazy<IReadOnlyList<LanguageOption>> Catalog = new(() =>
        Loc.Languages.Select(l => new LanguageOption(l.Code, l.Name, LoadFlag(l.Code))).ToList());

    public static IReadOnlyList<LanguageOption> All => Catalog.Value;

    public static LanguageOption Current => All.FirstOrDefault(l => l.Code == Loc.Language) ?? All[0];

    private static Bitmap? LoadFlag(string code)
    {
        try
        {
            using var stream = AssetLoader.Open(new Uri($"avares://PortShield/Assets/flag-{code}.png"));
            return new Bitmap(stream);
        }
        catch
        {
            return null;
        }
    }

    public override string ToString() => Name;
}
