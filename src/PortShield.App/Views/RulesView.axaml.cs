using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using PortShield.App.ViewModels;

namespace PortShield.App.Views;

public partial class RulesView : UserControl
{
    private RulesViewModel? _vm;
    private bool _batch;

    public RulesView()
    {
        InitializeComponent();
        RulesGrid.SelectionChanged += (_, _) => PushSelection();
        RulesGrid.AddHandler(PointerPressedEvent, OnPointerPressed, RoutingStrategies.Tunnel);
        DataContextChanged += (_, _) =>
        {
            if (_vm is not null)
            {
                _vm.SelectionRequested -= OnSelectionRequested;
                _vm.SelectionRestoreRequested -= OnRestoreRequested;
            }

            _vm = DataContext as RulesViewModel;
            if (_vm is not null)
            {
                _vm.SelectionRequested += OnSelectionRequested;
                _vm.SelectionRestoreRequested += OnRestoreRequested;
            }
        };
    }

    private void PushSelection()
    {
        if (!_batch)
        {
            _vm?.SetSelection(RulesGrid.SelectedItems.OfType<RuleRow>().ToList());
        }
    }

    /// <summary>Right click on a row that is not selected selects it first (like Explorer).</summary>
    private void OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(RulesGrid).Properties.IsRightButtonPressed)
        {
            return;
        }

        var row = (e.Source as Avalonia.Visual)?.FindAncestorOfType<DataGridRow>(includeSelf: true);
        if (row?.DataContext is RuleRow item && !RulesGrid.SelectedItems.Contains(item))
        {
            RulesGrid.SelectedItem = item;
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
            RulesGrid.SelectAll();
            return;
        }

        var selected = RulesGrid.SelectedItems.OfType<RuleRow>().ToHashSet();
        Select(request == SelectionRequest.None ? [] : _vm.Rows.Where(r => !selected.Contains(r)).ToList());
    }

    private void OnRestoreRequested(IReadOnlyList<RuleRow> rows) => Select(rows);

    /// <summary>Selects many rows with one selection update (each Add would raise SelectionChanged).</summary>
    private void Select(IReadOnlyList<RuleRow> rows)
    {
        _batch = true;
        try
        {
            RulesGrid.SelectedItems.Clear();
            foreach (var row in rows)
            {
                RulesGrid.SelectedItems.Add(row);
            }
        }
        finally
        {
            _batch = false;
        }

        PushSelection();
    }
}
