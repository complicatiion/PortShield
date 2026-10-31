using Avalonia.Controls;
using Avalonia.Interactivity;
using PortShield.App.ViewModels;

namespace PortShield.App.Views;

/// <summary>Editor for own rule sets.</summary>
public partial class RuleSetEditorWindow : Window
{
    public RuleSetEditorWindow()
    {
        InitializeComponent();
        Services.WindowChrome.Apply(this, maximize: false);
    }

    private void OnSave(object? sender, RoutedEventArgs e)
    {
        if (DataContext is RuleSetEditorModel { CanSave: true })
        {
            Close(true);
        }
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(false);
}
