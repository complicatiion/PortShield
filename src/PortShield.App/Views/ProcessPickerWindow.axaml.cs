using Avalonia.Controls;
using Avalonia.Interactivity;

namespace PortShield.App.Views;

/// <summary>Running programs to block or allow.</summary>
public partial class ProcessPickerWindow : Window
{
    public ProcessPickerWindow()
    {
        InitializeComponent();
        Services.WindowChrome.Apply(this, maximize: false);
    }

    private void OnConfirm(object? sender, RoutedEventArgs e) => Close(true);

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(false);
}
