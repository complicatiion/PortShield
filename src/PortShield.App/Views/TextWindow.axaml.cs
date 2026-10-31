using Avalonia.Controls;
using Avalonia.Interactivity;

namespace PortShield.App.Views;

/// <summary>Read-only text viewer (licenses, legal notice).</summary>
public partial class TextWindow : Window
{
    public TextWindow()
    {
        InitializeComponent();
        PortShield.App.Services.WindowChrome.Apply(this, maximize: true);
    }

    public TextWindow(string title, string text) : this()
    {
        Title = title;
        HeaderText.Text = title;
        Body.Text = text;
    }

    private async void OnCopy(object? sender, RoutedEventArgs e)
    {
        if (Clipboard is { } clipboard)
        {
            await clipboard.SetTextAsync(Body.Text ?? "");
        }
    }

    private void OnClose(object? sender, RoutedEventArgs e) => Close();
}
