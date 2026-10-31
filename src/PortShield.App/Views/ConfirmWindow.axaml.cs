using Avalonia.Controls;
using Avalonia.Interactivity;
using PortShield.App.ViewModels;

namespace PortShield.App.Views;

/// <summary>Confirmation dialog with optional checkbox.</summary>
public partial class ConfirmWindow : Window
{
    public ConfirmWindow()
    {
        InitializeComponent();
        Services.WindowChrome.Apply(this, maximize: false);
    }

    public ConfirmWindow(string title, string message, string confirmText, bool danger, string? optionText = null, bool optionDefault = false,
        string? confirmIcon = null) : this()
    {
        Title = title;
        HeaderText.Text = title;
        MessageText.Text = message;
        ConfirmLabel.Text = confirmText;
        ConfirmLabel.Icon = Res.Icon(confirmIcon ?? (danger ? "IconDelete" : "IconCheck"));
        Glyph.Data = Res.Icon(danger ? "IconAlert" : "IconInfo");
        Glyph.Foreground = Res.Brush(danger ? "BrushDeep" : "BrushAccentText");
        if (danger)
        {
            ConfirmButton.Classes.Remove("primary");
            ConfirmButton.Classes.Add("danger");

            // Destructive: Enter does not confirm by accident.
            ConfirmButton.IsDefault = false;
        }

        if (!string.IsNullOrEmpty(optionText))
        {
            OptionText.Text = optionText;
            OptionCheck.IsChecked = optionDefault;
            OptionRow.IsVisible = true;
        }
    }

    /// <summary>Dialog with one text field (e.g. profile name).</summary>
    public ConfirmWindow(string title, string message, string confirmText, string watermark, string? initial)
        : this(title, message, confirmText, danger: false, confirmIcon: "IconSave")
    {
        InputBox.Watermark = watermark;
        InputBox.Text = initial;
        InputBox.IsVisible = true;
        Opened += (_, _) => InputBox.Focus();
    }

    public string Input => InputBox.Text?.Trim() ?? "";

    public bool OptionChecked => OptionCheck.IsChecked == true;

    private void OnConfirm(object? sender, RoutedEventArgs e) => Close(true);

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(false);
}
