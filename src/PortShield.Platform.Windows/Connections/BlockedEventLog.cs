using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using PortShield.Core.Connections;
using PortShield.Core.Diagnostics;

namespace PortShield.Platform.Windows;

/// <summary>
/// Audit policy "Filtering Platform Connection" (failure = blocked connections, event 5157). Read and set through the
/// audit API with the subcategory GUID, so it works in every Windows language. Needs administrator rights.
/// </summary>
public static class ConnectionAudit
{
    private const uint AuditSuccess = 0x1;
    private const uint AuditFailure = 0x2;
    private const uint AuditNone = 0x4;

    /// <summary>Blocked connections are recorded (failure auditing on); null = unknown (no rights).</summary>
    public static bool? IsEnabled()
    {
        var info = Query();
        return info is null ? null : (info.Value & AuditFailure) != 0;
    }

    /// <summary>Turns failure auditing on or off; success auditing (allowed connections) stays as it is.</summary>
    public static void SetEnabled(bool on)
    {
        var current = Query() ?? 0;
        var success = current & AuditSuccess;
        var value = on ? success | AuditFailure : success != 0 ? AuditSuccess : AuditNone;
        EnableSecurityPrivilege();
        var policy = new[] { new AuditPolicyInformation { SubCategory = BlockedConnections.AuditSubcategory, AuditingInformation = value } };
        if (!AuditSetSystemPolicy(policy, 1))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    private static uint? Query()
    {
        try
        {
            EnableSecurityPrivilege();
            if (!AuditQuerySystemPolicy([BlockedConnections.AuditSubcategory], 1, out var buffer) || buffer == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                return Marshal.PtrToStructure<AuditPolicyInformation>(buffer).AuditingInformation;
            }
            finally
            {
                AuditFree(buffer);
            }
        }
        catch (Exception ex) when (ex is Win32Exception or EntryPointNotFoundException or DllNotFoundException)
        {
            return null;
        }
    }

    /// <summary>The audit API needs SeSecurityPrivilege – administrators have it, but disabled.</summary>
    private static void EnableSecurityPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out var luid))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var privileges = new TokenPrivileges { Count = 1, LuidLow = luid.Low, LuidHigh = luid.High, Attributes = SePrivilegeEnabled };
            AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
            var error = Marshal.GetLastWin32Error();
            if (error != 0)
            {
                // 1300 = ERROR_NOT_ALL_ASSIGNED: not an administrator.
                throw new Win32Exception(error);
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private const uint TokenAdjustPrivileges = 0x20;
    private const uint TokenQuery = 0x8;
    private const uint SePrivilegeEnabled = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid SubCategory;
        public uint AuditingInformation;
        public Guid Category;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint Low;
        public int High;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TokenPrivileges
    {
        public uint Count;
        public uint LuidLow;
        public int LuidHigh;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] subCategories, uint count, out IntPtr policy);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditSetSystemPolicy([In] AuditPolicyInformation[] policy, uint count);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges newState, uint length, IntPtr previous, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>Reads the blocked connections (event 5157) from the Security log via wevtutil.</summary>
public static class BlockedEventLog
{
    public static IReadOnlyList<BlockedConnection> Read(TimeSpan range, int max)
    {
        var milliseconds = ((long)Math.Max(1, range.TotalMilliseconds)).ToString(CultureInfo.InvariantCulture);
        var query = $"*[System[(EventID={BlockedConnections.EventId}) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]";
        string[] args = ["qe", "Security", "/q:" + query, "/f:xml", "/rd:true", "/c:" + max.ToString(CultureInfo.InvariantCulture)];

        // UTF-16 output keeps non-ASCII program paths intact; older builds without /uni fall back to the console code page.
        var run = ProcessRunner.Run("wevtutil.exe", [.. args, "/uni:true"], TimeSpan.FromSeconds(60), encoding: Encoding.Unicode);
        if (!run.Output.Contains("<Event", StringComparison.Ordinal))
        {
            var plain = ProcessRunner.Run("wevtutil.exe", args, TimeSpan.FromSeconds(60));
            if (!plain.Success && !plain.Output.Contains("<Event", StringComparison.Ordinal))
            {
                if (plain.Output.Trim().Length > 0 && !run.Success)
                {
                    throw new InvalidOperationException(plain.Output.Trim());
                }

                return [];
            }

            run = plain;
        }

        var map = DevicePaths.Snapshot();
        return BlockedConnections.Parse(run.Output, map.ToDosPath);
    }
}

/// <summary>"\device\harddiskvolume3\program files\…" → "C:\program files\…" (QueryDosDevice for every drive letter).</summary>
public sealed class DevicePaths
{
    private readonly List<(string Device, string Drive)> _map;

    private DevicePaths(List<(string, string)> map) => _map = map;

    public static DevicePaths Snapshot()
    {
        var map = new List<(string, string)>();
        var buffer = new StringBuilder(1024);
        foreach (var drive in Environment.GetLogicalDrives())
        {
            var letter = drive.TrimEnd('\\');
            buffer.Clear();
            if (QueryDosDevice(letter, buffer, buffer.Capacity) > 0)
            {
                map.Add((buffer.ToString(), letter));
            }
        }

        // Longest device first: \Device\HarddiskVolume1 must not match \Device\HarddiskVolume10.
        return new DevicePaths(map.OrderByDescending(m => m.Item1.Length).ToList());
    }

    public string ToDosPath(string path)
    {
        foreach (var (device, drive) in _map)
        {
            if (path.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return drive + path[device.Length..];
            }
        }

        return path;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int QueryDosDevice(string deviceName, StringBuilder targetPath, int max);
}
