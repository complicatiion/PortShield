namespace PortShield.App.ViewModels;

/// <summary>
/// A list row that was just inserted by expanding a group: the view plays a short entrance animation once
/// (only if the row is realized within a moment – rows scrolled into view later never animate).
/// </summary>
public interface IAnimatedRow
{
    /// <summary>Environment.TickCount64 when the row was inserted; 0 = no animation.</summary>
    long EnterTicks { get; set; }

    /// <summary>Stagger delay in milliseconds.</summary>
    int EnterDelay { get; set; }
}

public static class AnimatedRows
{
    /// <summary>Marks rows for the entrance animation with a small stagger (capped so long groups do not drag).</summary>
    public static void MarkEntering(IEnumerable<IAnimatedRow> rows)
    {
        var now = Environment.TickCount64;
        var index = 0;
        foreach (var row in rows)
        {
            row.EnterTicks = now;
            row.EnterDelay = Math.Min(index++ * 14, 160);
        }
    }
}
