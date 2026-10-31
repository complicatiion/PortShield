using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using PortShield.App.ViewModels;

namespace PortShield.App.Views;

public partial class ScanView : UserControl
{
    private ScanViewModel? _vm;
    private bool _batch;

    public ScanView()
    {
        InitializeComponent();
        ScanGrid.SelectionChanged += (_, _) => PushSelection();
        ScanGrid.AddHandler(PointerPressedEvent, OnPointerPressed, RoutingStrategies.Tunnel);
        DataContextChanged += (_, _) =>
        {
            if (_vm is not null)
            {
                _vm.SelectionRequested -= OnSelectionRequested;
            }

            _vm = DataContext as ScanViewModel;
            if (_vm is not null)
            {
                _vm.SelectionRequested += OnSelectionRequested;
            }
        };
    }

    private void PushSelection()
    {
        if (!_batch)
        {
            _vm?.SetSelection(ScanGrid.SelectedItems.OfType<ScanRow>().ToList());
        }
    }

    private void OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(ScanGrid).Properties.IsRightButtonPressed)
        {
            return;
        }

        var row = (e.Source as Avalonia.Visual)?.FindAncestorOfType<DataGridRow>(includeSelf: true);
        if (row?.DataContext is ScanRow item && !ScanGrid.SelectedItems.Contains(item))
        {
            ScanGrid.SelectedItem = item;
        }
    }

    private void OnSelectionRequested(SelectionRequest request)
    {
        if (_vm is null)
        {
            return;
        }

        if (request == SelectionRequest.All)
        {
            ScanGrid.SelectAll();
            return;
        }

        var selected = ScanGrid.SelectedItems.OfType<ScanRow>().ToHashSet();
        _batch = true;
        try
        {
            ScanGrid.SelectedItems.Clear();
            if (request == SelectionRequest.Invert)
            {
                foreach (var row in _vm.Rows.Where(r => !selected.Contains(r)))
                {
                    ScanGrid.SelectedItems.Add(row);
                }
            }
        }
        finally
        {
            _batch = false;
        }

        PushSelection();
    }
}
