using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace PortShield.Platform.Windows;

/// <summary>Elevation, user, edition and session facts.</summary>
public static class SystemInfo
{
    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static string CurrentUser()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.Name;
        }
        catch (Exception)
        {
            return Environment.UserDomainName + "\\" + Environment.UserName;
        }
    }

    public static bool IsServer() =>
        string.Equals(ReadCurrentVersion("InstallationType"), "Server", StringComparison.OrdinalIgnoreCase);

    public static string ProductName() => ReadCurrentVersion("ProductName") ?? "Windows";

    public static int Build() => int.TryParse(ReadCurrentVersion("CurrentBuild"), out var build) ? build : 0;

    /// <summary>The app runs in a remote desktop session – blocking all inbound traffic would cut it off.</summary>
    public static bool IsRemoteSession()
    {
        try
        {
            return GetSystemMetrics(0x1000) != 0; // SM_REMOTESESSION
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    private static string? ReadCurrentVersion(string name)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return key?.GetValue(name)?.ToString();
        }
        catch (Exception)
        {
            return null;
        }
    }

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);
}
