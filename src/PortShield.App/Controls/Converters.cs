using Avalonia.Data.Converters;

namespace PortShield.App.Controls;

/// <summary>Small value converters for the views.</summary>
public static class Converters
{
    /// <summary>Dims disabled rules.</summary>
    public static readonly IValueConverter EnabledOpacity = new FuncValueConverter<bool, double>(enabled => enabled ? 1.0 : 0.5);
}
