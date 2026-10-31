using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace PortShield.Platform.Windows;

/// <summary>A running program (one entry per executable, with the number of processes).</summary>
public sealed record RunningProgram(string Path, string Name, int Processes, string? Description, string? Company, string? WindowTitle);

/// <summary>Running processes with their full image path (also 32-bit and other users' processes when elevated).</summary>
public static class ProcessList
{
    private const int ProcessQueryLimitedInformation = 0x1000;

    public static IReadOnlyList<RunningProgram> Read()
    {
        var byPath = new Dictionary<string, (string Name, int Count, string? Title)>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (process.Id is 0 or 4)
                    {
                        continue;
                    }

                    var path = ImagePath(process.Id);
                    if (string.IsNullOrEmpty(path))
                    {
                        continue;
                    }

                    var title = SafeTitle(process);
                    if (byPath.TryGetValue(path, out var existing))
                    {
                        byPath[path] = (existing.Name, existing.Count + 1, existing.Title ?? title);
                    }
                    else
                    {
                        byPath[path] = (process.ProcessName, 1, title);
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    // Process ended meanwhile.
                }
            }
        }

        return byPath
            .Select(p =>
            {
                var facts = FileInspector.Read(p.Key);
                return new RunningProgram(p.Key, p.Value.Name, p.Value.Count, facts.Description, facts.Company, p.Value.Title);
            })
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? SafeTitle(Process process)
    {
        try
        {
            var title = process.MainWindowTitle;
            return string.IsNullOrWhiteSpace(title) ? null : title;
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            return null;
        }
    }

    public static string? ImagePath(int processId)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new StringBuilder(1024);
            var size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
