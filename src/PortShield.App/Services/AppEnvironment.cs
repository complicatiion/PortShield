using System.Diagnostics;
using System.Reflection;

namespace PortShield.App.Services;

/// <summary>Paths and shell actions of the app.</summary>
public static class AppEnvironment
{
    public const string ProjectUrl = "https://github.com/complicatiion/PortShield";
    public const string MitLicenseUrl = "https://opensource.org/license/mit";
    public const string WebsiteUrl = "https://sksdesign.de";

    public static string Version =>
        Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(AppEnvironment).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? "0.0.0";

    public static string Generator => "PortShield " + Version;

    public static string BaseDirectory => AppContext.BaseDirectory;

    public static string ExecutablePath => Environment.ProcessPath ?? Path.Combine(BaseDirectory, "PortShield.exe");

    public static string LicensesDirectory => Path.Combine(BaseDirectory, "licenses");

    public static void OpenUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {
            // No default browser.
        }
    }

    /// <summary>Opens a folder (or selects a file) in Explorer. Only PortShield's own data folders are created when missing.</summary>
    public static void OpenFolder(string? path, bool create = false)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            if (File.Exists(path) && OperatingSystem.IsWindows())
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = false });
                return;
            }

            if (create)
            {
                Directory.CreateDirectory(path);
            }
            else if (!Directory.Exists(path))
            {
                return;
            }

            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch
        {
            // Ignore.
        }
    }

    /// <summary>Starts a program (Rules › Run program).</summary>
    public static bool Run(string path)
    {
        try
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(path) ?? "" });
            return true;
        }
        catch
        {
            return false;
        }
    }
}
