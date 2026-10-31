using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;

namespace PortShield.App.ViewModels;

public sealed record ThirdPartyItem(string Name, string Version, string License, string Usage, string Url, string LicenseFile);

/// <summary>About page: version, license, components.</summary>
public sealed partial class AboutViewModel(MainViewModel main) : PageViewModel(main)
{
    public override string TitleKey => "NavAbout";

    public string Version => "v" + AppEnvironment.Version;

    public string Copyright => "Copyright © 2026 Sven Klocke · sksdesign | complicatiion";

    public IReadOnlyList<ThirdPartyItem> ThirdParty =>
    [
        new(".NET", "10.0", "MIT", Loc.T("UsageRuntime"), "https://github.com/dotnet/runtime", "third-party/DOTNET.md"),
        new("Avalonia UI", "11.3", "MIT", Loc.T("UsageUi"), "https://avaloniaui.net", "third-party/AVALONIA.md"),
        new("Avalonia DataGrid", "11.3", "MIT", Loc.T("UsageTables"), "https://github.com/AvaloniaUI/Avalonia.Controls.DataGrid", "third-party/AVALONIA-DATAGRID.md"),
        new("SkiaSharp / HarfBuzzSharp", "–", "MIT · BSD-3-Clause", Loc.T("UsageRendering"), "https://github.com/mono/SkiaSharp", "third-party/SKIASHARP.md"),
        new("CommunityToolkit.Mvvm", "8.4", "MIT", "MVVM", "https://github.com/CommunityToolkit/dotnet", "third-party/COMMUNITYTOOLKIT-MVVM.md"),
        new("Material Design Icons", "7.4", "Apache-2.0", Loc.T("UsageIcons"), "https://pictogrammers.com/library/mdi/", "third-party/MATERIAL-DESIGN-ICONS.md"),
        new("Inter", "4.x", "SIL OFL 1.1", Loc.T("UsageFont"), "https://rsms.me/inter/", "third-party/INTER-FONT.md")
    ];

    public override void OnLanguageChanged()
    {
        base.OnLanguageChanged();
        OnPropertyChanged(nameof(ThirdParty));
    }

    [RelayCommand]
    private void OpenProject() => AppEnvironment.OpenUrl(AppEnvironment.ProjectUrl);

    [RelayCommand]
    private void OpenWebsite() => AppEnvironment.OpenUrl(AppEnvironment.WebsiteUrl);

    [RelayCommand]
    private void OpenMitLicense() => AppEnvironment.OpenUrl(AppEnvironment.MitLicenseUrl);

    [RelayCommand]
    private void OpenLicensesFolder() => AppEnvironment.OpenFolder(AppEnvironment.LicensesDirectory);

    [RelayCommand]
    private void OpenLink(string? url) => AppEnvironment.OpenUrl(url);

    [RelayCommand]
    private Task ShowLicenseAsync(string? file) => ShowFileAsync(Loc.T("HdrLicense"), file ?? "LICENSE.md");

    [RelayCommand]
    private Task ShowThirdPartyAsync(ThirdPartyItem? item) =>
        item is null ? Task.CompletedTask : ShowFileAsync(item.Name, item.LicenseFile);

    [RelayCommand]
    private Task ShowDocumentAsync(string? file) => ShowFileAsync(Path.GetFileNameWithoutExtension(file ?? ""), file ?? "README.md");

    private Task ShowFileAsync(string title, string relativePath)
    {
        var path = Path.Combine(AppEnvironment.LicensesDirectory, relativePath.Replace('/', Path.DirectorySeparatorChar));
        string text;
        try
        {
            text = File.Exists(path) ? File.ReadAllText(path) : Loc.F("LicenseFileMissing", path);
        }
        catch (Exception ex)
        {
            text = ex.Message;
        }

        return Host.ShowTextAsync(title, text);
    }
}
