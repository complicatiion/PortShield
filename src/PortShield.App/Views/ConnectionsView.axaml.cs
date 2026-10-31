using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using PortShield.App.ViewModels;

namespace PortShield.App.Views;

public partial class ConnectionsView : UserControl
{
    private ConnectionsViewModel? _vm;

    public ConnectionsView()
    {
        InitializeComponent();
        // DataGrid.SelectedItems cannot be bound – handed to the view model here.
        ConnectionsGrid.SelectionChanged += (_, _) => _vm?.SetSelection(ConnectionsGrid.SelectedItems.OfType<ConnectionRow>().ToList());
        ConnectionsGrid.AddHandler(PointerPressedEvent, OnPointerPressed, RoutingStrategies.Tunnel);
        DataContextChanged += (_, _) =>
        {
            if (_vm is not null)
            {
                _vm.SelectionRequested -= OnSelectionRequested;
            }

            _vm = DataContext as ConnectionsViewModel;
            if (_vm is not null)
            {
                _vm.SelectionRequested += OnSelectionRequested;
            }
        };
    }

    /// <summary>Right click on an unselected row selects it first (the context menu acts on the selection).</summary>
    private void OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(ConnectionsGrid).Properties.IsRightButtonPressed)
        {
            return;
        }

        var row = (e.Source as Avalonia.Visual)?.FindAncestorOfType<DataGridRow>(includeSelf: true);
        if (row?.DataContext is ConnectionRow item && !ConnectionsGrid.SelectedItems.Contains(item))
        {
            ConnectionsGrid.SelectedItem = item;
        }
    }

    private void OnSelectionRequested(SelectionRequest request)
    {
        if (request == SelectionRequest.All)
        {
            ConnectionsGrid.SelectAll();
        }
    }
}
