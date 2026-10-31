using Avalonia;
using Avalonia.Controls;
using PortShield.App.ViewModels;
using PortShield.App.Views;

namespace PortShield.App.Controls;

/// <summary>
/// Hosts the page views and only toggles their visibility: switching pages neither re-creates nor re-styles them.
/// Each view is created on its first visit.
/// </summary>
public sealed class PageHost : Grid
{
    public static readonly StyledProperty<PageViewModel?> PageProperty =
        AvaloniaProperty.Register<PageHost, PageViewModel?>(nameof(Page));

    private readonly Dictionary<PageViewModel, Control> _views = new();

    static PageHost()
    {
        PageProperty.Changed.AddClassHandler<PageHost>((host, _) => host.ShowPage());
    }

    public PageViewModel? Page
    {
        get => GetValue(PageProperty);
        set => SetValue(PageProperty, value);
    }

    private void ShowPage()
    {
        var page = Page;
        if (page is not null && !_views.ContainsKey(page))
        {
            var view = Create(page);
            view.DataContext = page;
            view.IsVisible = false;
            _views[page] = view;
            Children.Add(view);
        }

        foreach (var (model, view) in _views)
        {
            var visible = ReferenceEquals(model, page);
            if (visible && !view.IsVisible)
            {
                view.IsVisible = true;
                Motion.FadeIn(view, offsetY: 16, milliseconds: 260);
            }
            else
            {
                view.IsVisible = visible;
            }
        }
    }

    private static Control Create(PageViewModel page) => page switch
    {
        OverviewViewModel => new OverviewView(),
        RulesViewModel => new RulesView(),
        RuleSetsViewModel => new RuleSetsView(),
        ImportExportViewModel => new ImportExportView(),
        ScanViewModel => new ScanView(),
        ConnectionsViewModel => new ConnectionsView(),
        SnapshotsViewModel => new SnapshotsView(),
        SettingsViewModel => new SettingsView(),
        AboutViewModel => new AboutView(),
        _ => new TextBlock { Text = page.GetType().Name }
    };
}
