using Avalonia.Controls;
using PortShield.App.ViewModels;

namespace PortShield.App.Views;

public partial class RuleSetsView : UserControl
{
    public RuleSetsView()
    {
        InitializeComponent();
        Scroller.SizeChanged += (_, e) =>
        {
            if (DataContext is RuleSetsViewModel vm)
            {
                vm.UpdateColumns(e.NewSize.Width);
            }
        };
    }
}
