using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
using PortShield.App.ViewModels;
using PortShield.App.Views;

namespace PortShield.App.Services;

public readonly record struct ConfirmResult(bool Confirmed, bool OptionChecked);

/// <summary>Windows, dialogs, clipboard and pickers for view models.</summary>
public sealed class UiHost
{
    public Window? MainWindow { get; set; }

    public Action? ShowMainWindow { get; set; }

    public Action? ExitApplication { get; set; }

    /// <summary>Exit and start again (after a reset).</summary>
    public Action? RestartApplication { get; set; }

    /// <summary>dark, light or system.</summary>
    public void ApplyTheme(string theme)
    {
        if (Application.Current is not { } app)
        {
            return;
        }

        app.RequestedThemeVariant = theme switch
        {
            "light" => ThemeVariant.Light,
            "system" => ThemeVariant.Default,
            _ => ThemeVariant.Dark
        };

        WindowChrome.RefreshAll();
    }

    public async Task CopyAsync(string? text)
    {
        if (!string.IsNullOrEmpty(text) && MainWindow?.Clipboard is { } clipboard)
        {
            await clipboard.SetTextAsync(text);
        }
    }

    public async Task<string?> PickFolderAsync(string title, string? startPath = null)
    {
        var window = EnsureWindow();
        if (window is null)
        {
            return null;
        }

        IStorageFolder? start = null;
        if (!string.IsNullOrWhiteSpace(startPath) && Directory.Exists(startPath))
        {
            start = await window.StorageProvider.TryGetFolderFromPathAsync(startPath);
        }

        var result = await window.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            SuggestedStartLocation = start
        });

        return result.Count > 0 ? result[0].TryGetLocalPath() : null;
    }

    /// <summary>File picker; several files when <paramref name="multiple"/> is set.</summary>
    public async Task<IReadOnlyList<string>> PickFilesAsync(string title, string typeName, IReadOnlyList<string> patterns, bool multiple)
    {
        var window = EnsureWindow();
        if (window is null)
        {
            return [];
        }

        var result = await window.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = multiple,
            FileTypeFilter = [new FilePickerFileType(typeName) { Patterns = patterns }]
        });

        return result.Select(f => f.TryGetLocalPath()).Where(p => !string.IsNullOrEmpty(p)).Select(p => p!).ToList();
    }

    public async Task<string?> PickSavePathAsync(string title, string suggestedName, string extension, string typeName)
    {
        var window = EnsureWindow();
        if (window is null)
        {
            return null;
        }

        var file = await window.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedName,
            DefaultExtension = extension,
            ShowOverwritePrompt = true,
            FileTypeChoices = [new FilePickerFileType(typeName) { Patterns = ["*." + extension] }]
        });

        return file?.TryGetLocalPath();
    }

    public async Task<ConfirmResult> ConfirmAsync(string title, string message, string confirmText, bool danger, string? optionText = null,
        bool optionDefault = false, string? confirmIcon = null)
    {
        var window = EnsureWindow();
        if (window is null)
        {
            return default;
        }

        var dialog = new ConfirmWindow(title, message, confirmText, danger, optionText, optionDefault, confirmIcon);
        var confirmed = await dialog.ShowDialog<bool>(window);
        return new ConfirmResult(confirmed, confirmed && dialog.OptionChecked);
    }

    /// <summary>Asks for one value; null = cancelled.</summary>
    public async Task<string?> PromptAsync(string title, string message, string confirmText, string watermark, string? initial = null)
    {
        var window = EnsureWindow();
        if (window is null)
        {
            return null;
        }

        var dialog = new ConfirmWindow(title, message, confirmText, watermark, initial);
        return await dialog.ShowDialog<bool>(window) ? dialog.Input : null;
    }

    /// <summary>Review dialog for new rules (add, import, rule sets); true = create.</summary>
    public async Task<bool> ReviewRulesAsync(AddRulesModel model)
    {
        var window = EnsureWindow();
        if (window is null)
        {
            return false;
        }

        return await new AddRulesWindow { DataContext = model }.ShowDialog<bool>(window);
    }

    /// <summary>Rule set editor; true = save.</summary>
    public async Task<bool> EditRuleSetAsync(RuleSetEditorModel model)
    {
        var window = EnsureWindow();
        if (window is null)
        {
            return false;
        }

        return await new RuleSetEditorWindow { DataContext = model }.ShowDialog<bool>(window);
    }

    /// <summary>Running programs to pick from; empty = cancelled.</summary>
    public async Task<IReadOnlyList<string>> PickProcessesAsync(ProcessPickerModel model)
    {
        var window = EnsureWindow();
        if (window is null)
        {
            return [];
        }

        return await new ProcessPickerWindow { DataContext = model }.ShowDialog<bool>(window) ? model.CheckedPaths : [];
    }

    public async Task ShowTextAsync(string title, string text)
    {
        var window = EnsureWindow();
        if (window is not null)
        {
            await new TextWindow(title, text).ShowDialog(window);
        }
    }

    private Window? EnsureWindow()
    {
        if (MainWindow is { IsVisible: false })
        {
            ShowMainWindow?.Invoke();
        }

        // An open dialog owns nested dialogs and pickers.
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var dialog = desktop.Windows.LastOrDefault(w => w.IsVisible && w.IsActive && w != MainWindow);
            if (dialog is not null)
            {
                return dialog;
            }
        }

        return MainWindow;
    }
}
