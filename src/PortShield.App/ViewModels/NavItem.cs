using System.Collections.ObjectModel;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using PortShield.App.Localization;

namespace PortShield.App.ViewModels;

/// <summary>Sidebar entry.</summary>
public sealed partial class NavItem : ObservableObject
{
    public NavItem(string titleKey, string iconKey, PageViewModel page)
    {
        TitleKey = titleKey;
        Page = page;
        Icon = Res.Icon(iconKey);
    }

    public string TitleKey { get; }

    public PageViewModel Page { get; }

    public Geometry? Icon { get; }

    public string Title => Loc.T(TitleKey);

    /// <summary>Tooltip: a longer text where the short title hides something (key "&lt;TitleKey&gt;Tip", e.g. "Import &amp; export"), else the title.</summary>
    public string Tip => Strings.En.ContainsKey(TitleKey + "Tip") ? Loc.T(TitleKey + "Tip") : Title;

    /// <summary>Small counter on the icon (e.g. number of PortShield rules).</summary>
    [ObservableProperty]
    private string? _badge;

    public bool HasBadge => !string.IsNullOrEmpty(Badge);

    /// <summary>Badge on the icon: at most "99+" so it stays round.</summary>
    public string? BadgeText => int.TryParse(Badge, out var n) && n > 99 ? "99+" : Badge;

    partial void OnBadgeChanged(string? value)
    {
        OnPropertyChanged(nameof(HasBadge));
        OnPropertyChanged(nameof(BadgeText));
    }

    public void RefreshText()
    {
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(Tip));
    }
}

/// <summary>Sidebar section with its own list; only one section has a selection at a time.</summary>
public sealed partial class NavGroup : ObservableObject
{
    public NavGroup(string? titleKey, IEnumerable<NavItem> items)
    {
        TitleKey = titleKey;
        Items = new ObservableCollection<NavItem>(items);
    }

    public string? TitleKey { get; }

    public string Title => TitleKey is null ? "" : Loc.T(TitleKey);

    public bool HasTitle => TitleKey is not null;

    public ObservableCollection<NavItem> Items { get; }

    [ObservableProperty]
    private NavItem? _selected;

    /// <summary>Hidden groups (not used in v0.0.1).</summary>
    [ObservableProperty]
    private bool _isVisible = true;

    public event Action<NavGroup, NavItem>? Activated;

    partial void OnSelectedChanged(NavItem? value)
    {
        if (value is not null)
        {
            Activated?.Invoke(this, value);
        }
    }

    public void RefreshText()
    {
        OnPropertyChanged(nameof(Title));
        foreach (var item in Items)
        {
            item.RefreshText();
        }
    }
}
