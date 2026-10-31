using Avalonia.Controls;
using Avalonia.Interactivity;
using PortShield.App.ViewModels;

namespace PortShield.App.Views;

/// <summary>Review of new rules before they are written.</summary>
public partial class AddRulesWindow : Window
{
    public AddRulesWindow()
    {
        InitializeComponent();
        Services.WindowChrome.Apply(this, maximize: false);
    }

    private void OnConfirm(object? sender, RoutedEventArgs e)
    {
        if (DataContext is AddRulesModel { CanConfirm: true })
        {
            Close(true);
        }
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(false);
}
