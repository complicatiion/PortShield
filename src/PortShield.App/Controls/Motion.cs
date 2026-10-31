using Avalonia;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.VisualTree;
using PortShield.App.ViewModels;

namespace PortShield.App.Controls;

/// <summary>Short, subtle entrance animations (fade + slide) for pages, tabs and notifications.</summary>
public static class Motion
{
    // One running animation per control: a new one replaces it (no jitter on quick repeats).
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Visual, CancellationTokenSource> Running = new();

    /// <summary>
    /// Attached to the root of a list row template: rows freshly inserted by expanding a group (<see cref="IAnimatedRow"/>)
    /// slide in once. Recycled containers of rows scrolled into view are not animated.
    /// </summary>
    public static readonly AttachedProperty<bool> EnterProperty =
        AvaloniaProperty.RegisterAttached<Control, bool>("Enter", typeof(Motion));

    static Motion()
    {
        EnterProperty.Changed.AddClassHandler<Control>((control, e) =>
        {
            if (e.NewValue is true)
            {
                control.DataContextChanged += (_, _) => PlayEnter(control);
                control.AttachedToVisualTree += (_, _) => PlayEnter(control);
            }
        });
    }

    public static bool GetEnter(Control control) => control.GetValue(EnterProperty);

    public static void SetEnter(Control control, bool value) => control.SetValue(EnterProperty, value);

    private static void PlayEnter(Control control)
    {
        if (control.DataContext is not IAnimatedRow row || row.EnterTicks == 0 || control.GetVisualRoot() is null)
        {
            return;
        }

        var age = Environment.TickCount64 - row.EnterTicks;
        var delay = row.EnterDelay;
        row.EnterTicks = 0;
        if (age < 450)
        {
            FadeIn(control, offsetY: -6, milliseconds: 180, delay: delay);
        }
    }

    public static void FadeIn(Visual? target, double offsetX = 0, double offsetY = 10, int milliseconds = 200, int delay = 0)
    {
        if (target is not Animatable animatable)
        {
            return;
        }

        if (Running.TryGetValue(target, out var previous))
        {
            previous.Cancel();
            Running.Remove(target);
        }

        var cts = new CancellationTokenSource();
        Running.Add(target, cts);

        target.RenderTransform ??= new TranslateTransform();
        var animation = new Animation
        {
            Duration = TimeSpan.FromMilliseconds(milliseconds),
            Delay = TimeSpan.FromMilliseconds(delay),
            Easing = new CubicEaseOut(),
            // Backward: during the stagger delay the row already sits at the start frame (no flash).
            FillMode = delay > 0 ? FillMode.Backward : FillMode.None,
            Children =
            {
                new KeyFrame
                {
                    Cue = new Cue(0d),
                    Setters =
                    {
                        new Setter(Visual.OpacityProperty, 0d),
                        new Setter(TranslateTransform.XProperty, offsetX),
                        new Setter(TranslateTransform.YProperty, offsetY)
                    }
                },
                new KeyFrame
                {
                    Cue = new Cue(1d),
                    Setters =
                    {
                        new Setter(Visual.OpacityProperty, 1d),
                        new Setter(TranslateTransform.XProperty, 0d),
                        new Setter(TranslateTransform.YProperty, 0d)
                    }
                }
            }
        };

        _ = animation.RunAsync(animatable, cts.Token);
    }
}
