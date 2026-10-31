using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace PortShield.Platform.Windows;

/// <summary>
/// Explorer context menu "Block with PortShield" for .exe files and folders (HKLM\Software\Classes, all users).
/// The command starts PortShield with --add "%1"; a running instance takes the path over.
/// </summary>
public static class ShellIntegration
{
    private const string ExeKey = @"SOFTWARE\Classes\exefile\shell\PortShield.Block";
    private const string FolderKey = @"SOFTWARE\Classes\Directory\shell\PortShield.Block";

    public static bool IsRegistered()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(ExeKey + @"\command");
            return key is not null;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static void Register(string executable, string fileLabel, string folderLabel)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        Write(hklm, ExeKey, fileLabel, executable);
        Write(hklm, FolderKey, folderLabel, executable);
    }

    public static void Unregister()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        hklm.DeleteSubKeyTree(ExeKey, throwOnMissingSubKey: false);
        hklm.DeleteSubKeyTree(FolderKey, throwOnMissingSubKey: false);
    }

    private static void Write(RegistryKey hklm, string path, string label, string executable)
    {
        using var key = hklm.CreateSubKey(path);
        key.SetValue("MUIVerb", label);
        key.SetValue("Icon", $"\"{executable}\",0");
        using var command = key.CreateSubKey("command");
        command.SetValue("", $"\"{executable}\" --add \"%1\"");
    }

    /// <summary>Opens the Windows properties dialog of a file.</summary>
    public static bool ShowProperties(string path)
    {
        var info = new ShellExecuteInfo
        {
            Size = Marshal.SizeOf<ShellExecuteInfo>(),
            Verb = "properties",
            File = path,
            Show = 1,
            Mask = 0x0000000C // SEE_MASK_INVOKEIDLIST
        };
        return ShellExecuteEx(ref info);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ShellExecuteInfo
    {
        public int Size;
        public uint Mask;
        public IntPtr Hwnd;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Verb;
        [MarshalAs(UnmanagedType.LPWStr)] public string? File;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Parameters;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Directory;
        public int Show;
        public IntPtr InstApp;
        public IntPtr IdList;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Class;
        public IntPtr KeyClass;
        public uint HotKey;
        public IntPtr IconOrMonitor;
        public IntPtr Process;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ShellExecuteEx(ref ShellExecuteInfo info);
}
