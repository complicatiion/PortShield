using PortShield.Core.Storage;

namespace PortShield.App.Services;

/// <summary>
/// Explorer context menu: a second start with --add "path" hands the paths to the running instance through a small file
/// in the data folder (both run elevated), then signals "show". The running instance picks them up and opens the add dialog.
/// </summary>
public static class PendingAdds
{
    public static IReadOnlyList<string> Parse(IReadOnlyList<string> args)
    {
        var paths = new List<string>();
        for (var i = 0; i < args.Count; i++)
        {
            if (string.Equals(args[i], "--add", StringComparison.OrdinalIgnoreCase))
            {
                for (var j = i + 1; j < args.Count && !args[j].StartsWith("--", StringComparison.Ordinal); j++)
                {
                    paths.Add(args[j].Trim('"'));
                }
            }
        }

        return paths;
    }

    public static void Write(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0)
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(AppPaths.DataDirectory);
            File.AppendAllLines(AppPaths.PendingAddFile, paths);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Nothing handed over – the user can add the program in the window.
        }
    }

    public static IReadOnlyList<string> Take()
    {
        try
        {
            if (!File.Exists(AppPaths.PendingAddFile))
            {
                return [];
            }

            var lines = File.ReadAllLines(AppPaths.PendingAddFile).Where(l => l.Trim().Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            File.Delete(AppPaths.PendingAddFile);
            return lines;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
