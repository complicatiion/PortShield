using CommunityToolkit.Mvvm.ComponentModel;
using PortShield.App.Localization;
using PortShield.App.Services;

namespace PortShield.App.ViewModels;

/// <summary>Base of all sidebar pages.</summary>
public abstract class PageViewModel(MainViewModel main) : ObservableObject
{
    public MainViewModel Main { get; } = main;

    protected UiHost Host => Main.Host;

    protected UiSettings Ui => Main.Ui;

    protected FirewallService Firewall => Main.Firewall;

    public abstract string TitleKey { get; }

    public string Title => Loc.T(TitleKey);

    public virtual void OnActivated()
    {
    }

    /// <summary>Another page was opened or the window was hidden.</summary>
    public virtual void OnDeactivated()
    {
    }

    public virtual void OnLanguageChanged()
    {
        OnPropertyChanged(nameof(Title));
    }

    /// <summary>The rule list was reloaded (always called on the UI thread).</summary>
    public virtual void OnRulesChanged()
    {
    }

    /// <summary>Profile state, policy or kill switch changed (UI thread).</summary>
    public virtual void OnStatusChanged()
    {
    }
}
