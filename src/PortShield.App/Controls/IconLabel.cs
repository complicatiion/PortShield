using Avalonia;
using Avalonia.Controls.Primitives;
using Avalonia.Media;

namespace PortShield.App.Controls;

/// <summary>Icon left of a text: content of all buttons and menu items.</summary>
public class IconLabel : TemplatedControl
{
    public static readonly StyledProperty<Geometry?> IconProperty =
        AvaloniaProperty.Register<IconLabel, Geometry?>(nameof(Icon));

    public static readonly StyledProperty<string?> TextProperty =
        AvaloniaProperty.Register<IconLabel, string?>(nameof(Text));

    public static readonly StyledProperty<double> IconSizeProperty =
        AvaloniaProperty.Register<IconLabel, double>(nameof(IconSize), 16d);

    public Geometry? Icon
    {
        get => GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }

    public string? Text
    {
        get => GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    public double IconSize
    {
        get => GetValue(IconSizeProperty);
        set => SetValue(IconSizeProperty, value);
    }
}
