using System.Text.RegularExpressions;

namespace PortShield.Core.Rules;

/// <summary>
/// Program paths: expand environment variables, compare, make portable (%ProgramFiles% …) and resolve * wildcards of rule
/// sets. Windows separators are handled on every platform so the logic is testable.
/// </summary>
public static partial class ProgramPaths
{
    /// <summary>Known folders that make a path portable between machines, most specific first.</summary>
    private static readonly string[] PortableVariables =
    [
        "ProgramFiles(x86)",
        "ProgramW6432",
        "ProgramFiles",
        "ProgramData",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "SystemRoot"
    ];

    [GeneratedRegex(@"^(unins\d*|uninst(all)?.*|.*uninstall.*|setup.*|.*[-_ ]setup|install(er)?|.*installer.*|vc_?redist.*|dotnet-.*|ndp\d+.*|msiexec)\.exe$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InstallerRegex();

    /// <summary>Expands %Variables% and removes surrounding quotes.</summary>
    public static string Expand(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "";
        }

        var trimmed = path.Trim().Trim('"').Trim();
        return Environment.ExpandEnvironmentVariables(trimmed);
    }

    /// <summary>Comparison key: expanded, backslashes, no trailing separator, upper case.</summary>
    public static string Key(string? path)
    {
        var expanded = Expand(path).Replace('/', '\\');
        while (expanded.Contains(@"\\", StringComparison.Ordinal) && !expanded.StartsWith(@"\\", StringComparison.Ordinal))
        {
            expanded = expanded.Replace(@"\\", @"\", StringComparison.Ordinal);
        }

        return expanded.TrimEnd('\\').ToUpperInvariant();
    }

    public static bool Same(string? a, string? b) => Key(a) == Key(b);

    /// <summary>File name of a Windows or Unix path.</summary>
    public static string FileName(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return "";
        }

        var trimmed = path.Trim().Trim('"').TrimEnd('\\', '/');
        var index = trimmed.LastIndexOfAny(['\\', '/']);
        return index >= 0 ? trimmed[(index + 1)..] : trimmed;
    }

    /// <summary>Folder of a Windows or Unix path.</summary>
    public static string Directory(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return "";
        }

        var trimmed = path.Trim().Trim('"').TrimEnd('\\', '/');
        var index = trimmed.LastIndexOfAny(['\\', '/']);
        return index > 0 ? trimmed[..index] : "";
    }

    /// <summary>
    /// Replaces a known folder at the start of the path with its variable (C:\Program Files\X → %ProgramFiles%\X).
    /// Used for exports and rule sets only – rules in the firewall always get literal paths, because the firewall service
    /// cannot expand per-user variables.
    /// </summary>
    public static string ToPortable(string? path, Func<string, string?>? getVariable = null)
    {
        var expanded = Expand(path);
        if (string.IsNullOrEmpty(expanded))
        {
            return "";
        }

        getVariable ??= Environment.GetEnvironmentVariable;
        foreach (var name in PortableVariables)
        {
            var value = getVariable(name);
            if (string.IsNullOrEmpty(value))
            {
                continue;
            }

            var prefix = value.TrimEnd('\\');
            if (expanded.Length > prefix.Length
                && expanded.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                && expanded[prefix.Length] is '\\' or '/')
            {
                // ProgramW6432 is the same folder as ProgramFiles in a 64-bit process – write the common name.
                var variable = name == "ProgramW6432" ? "ProgramFiles" : name;
                return "%" + variable + "%" + expanded[prefix.Length..];
            }
        }

        return expanded;
    }

    /// <summary>Installers, uninstallers and runtime setups: skipped by the folder scan unless the user wants them.</summary>
    public static bool IsInstaller(string? path) => InstallerRegex().IsMatch(FileName(path));

    public static bool IsExecutable(string? path) =>
        FileName(path).EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

    public static bool HasWildcard(string? path) => !string.IsNullOrEmpty(path) && path.IndexOfAny(['*', '?']) >= 0;

    /// <summary>
    /// Resolves a path with * or ? in any segment ("%ProgramFiles%\Adobe\Adobe Photoshop *\Photoshop.exe") to the existing
    /// files. A segment "**" stands for the folder itself and all sub folders ("D:\Tools\App\**\*.exe").
    /// Without wildcards the expanded path is returned when the file exists.
    /// </summary>
    public static IReadOnlyList<string> Resolve(string? pattern)
    {
        var expanded = Expand(pattern);
        if (string.IsNullOrEmpty(expanded))
        {
            return [];
        }

        var separator = Path.DirectorySeparatorChar;
        var normalized = expanded.Replace('\\', separator).Replace('/', separator);
        if (!HasWildcard(normalized))
        {
            return File.Exists(normalized) ? [normalized] : [];
        }

        var segments = normalized.Split(separator);
        var rootEnd = Array.FindIndex(segments, s => s.IndexOfAny(['*', '?']) >= 0);
        var root = string.Join(separator, segments.Take(rootEnd));
        if (string.IsNullOrEmpty(root))
        {
            root = separator.ToString();
        }
        else if (root.EndsWith(':'))
        {
            root += separator;
        }

        var current = new List<string> { root };
        for (var i = rootEnd; i < segments.Length; i++)
        {
            var segment = segments[i];
            var last = i == segments.Length - 1;
            var next = new List<string>();
            foreach (var folder in current)
            {
                try
                {
                    if (!System.IO.Directory.Exists(folder))
                    {
                        continue;
                    }

                    if (segment == "**" && !last)
                    {
                        next.AddRange(SelfAndSubfolders(folder, 2000 - next.Count));
                    }
                    else if (last)
                    {
                        next.AddRange(HasWildcard(segment)
                            ? System.IO.Directory.EnumerateFiles(folder, segment)
                            : File.Exists(Path.Combine(folder, segment)) ? [Path.Combine(folder, segment)] : []);
                    }
                    else
                    {
                        next.AddRange(HasWildcard(segment)
                            ? System.IO.Directory.EnumerateDirectories(folder, segment)
                            : [Path.Combine(folder, segment)]);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Folder not readable: no matches there.
                }
            }

            current = next;
            if (current.Count == 0)
            {
                break;
            }
        }

        return current.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>The folder and all sub folders (no junctions/symlinks), at most <paramref name="limit"/>.</summary>
    private static IEnumerable<string> SelfAndSubfolders(string folder, int limit)
    {
        var result = new List<string>();
        var pending = new Stack<string>();
        pending.Push(folder);
        while (pending.Count > 0 && result.Count < limit)
        {
            var current = pending.Pop();
            result.Add(current);
            try
            {
                foreach (var sub in System.IO.Directory.EnumerateDirectories(current))
                {
                    if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) == 0)
                    {
                        pending.Push(sub);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Skip folders without access.
            }
        }

        return result;
    }

    /// <summary>All .exe files below a folder (optionally recursive), skipping folders that cannot be read.</summary>
    public static IReadOnlyList<string> FindExecutables(string folder, bool recursive, int limit = 5000)
    {
        var result = new List<string>();
        var pending = new Stack<string>();
        pending.Push(folder);
        while (pending.Count > 0 && result.Count < limit)
        {
            var current = pending.Pop();
            try
            {
                foreach (var file in System.IO.Directory.EnumerateFiles(current, "*.exe"))
                {
                    result.Add(file);
                    if (result.Count >= limit)
                    {
                        break;
                    }
                }

                if (recursive)
                {
                    foreach (var sub in System.IO.Directory.EnumerateDirectories(current))
                    {
                        // Junctions and symlinks are not followed (no loops, no duplicates).
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) == 0)
                        {
                            pending.Push(sub);
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Skip folders without access.
            }
        }

        return result.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
