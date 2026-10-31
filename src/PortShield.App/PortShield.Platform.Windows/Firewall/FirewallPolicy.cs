using System.Runtime.InteropServices;
using Microsoft.Win32;
using PortShield.Core.Diagnostics;
using PortShield.Core.Models;
using PortShield.Core.Rules;

namespace PortShield.Platform.Windows;

/// <summary>
/// Firewall profiles and their policy: read from the registry (local store and group policy), changed with netsh.
/// Group policy values win over local ones; with AllowLocalPolicyMerge = 0 local rules – including PortShield's – are ignored.
/// </summary>
public static class FirewallPolicy
{
    private const string LocalKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    private const string PolicyKey = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";

    private static readonly (FirewallProfiles Profile, string Local, string Policy, string Netsh)[] Profiles =
    [
        (FirewallProfiles.Domain, "DomainProfile", "DomainProfile", "domainprofile"),
        (FirewallProfiles.Private, "StandardProfile", "PrivateProfile", "privateprofile"),
        (FirewallProfiles.Public, "PublicProfile", "PublicProfile", "publicprofile")
    ];

    public static FirewallStatus Read(FirewallProfiles activeProfiles)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var states = new List<ProfileState>();
        var managed = false;
        foreach (var (profile, local, policy, _) in Profiles)
        {
            using var localKey = hklm.OpenSubKey(LocalKey + "\\" + local);
            using var policyKey = hklm.OpenSubKey(PolicyKey + "\\" + policy);
            var gpoEnabled = Dword(policyKey, "EnableFirewall");
            var gpoOutbound = Dword(policyKey, "DefaultOutboundAction");
            var gpoInbound = Dword(policyKey, "DefaultInboundAction");
            var merge = Dword(policyKey, "AllowLocalPolicyMerge");
            managed |= gpoEnabled is not null || gpoOutbound is not null || gpoInbound is not null || merge is not null;

            var enabled = (gpoEnabled ?? Dword(localKey, "EnableFirewall") ?? 1) != 0;
            var blockOut = (gpoOutbound ?? Dword(localKey, "DefaultOutboundAction") ?? 0) != 0;
            var blockIn = (gpoInbound ?? Dword(localKey, "DefaultInboundAction") ?? 1) != 0;
            states.Add(new ProfileState(profile, enabled, blockOut, blockIn, activeProfiles.HasFlag(profile),
                gpoEnabled is not null, gpoOutbound is not null, merge == 0));
        }

        using var rulesKey = hklm.OpenSubKey(PolicyKey + @"\FirewallRules");
        var policyRules = rulesKey?.ValueCount ?? 0;
        var (joined, domain) = DomainJoin();
        return new FirewallStatus
        {
            Profiles = states,
            ManagedByPolicy = managed || policyRules > 0,
            PolicyRuleCount = policyRules,
            DomainJoined = joined,
            DomainName = domain,
            IsServer = SystemInfo.IsServer(),
            ServiceRunning = IsServiceRunning(),
            Products = SecurityCenterProducts()
        };
    }

    /// <summary>Firewall rules delivered by group policy (read only).</summary>
    public static IReadOnlyList<PolicyRule> ReadPolicyRules()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(PolicyKey + @"\FirewallRules");
            if (key is null)
            {
                return [];
            }

            return key.GetValueNames()
                .Select(n => key.GetValue(n) as string)
                .Where(v => !string.IsNullOrEmpty(v))
                .Select(v => RuleScanner.ParsePolicyRule(v!))
                .Where(r => r is not null)
                .Select(r => r!)
                .ToList();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return [];
        }
    }

    private static int? Dword(RegistryKey? key, string name) => key?.GetValue(name) is int value ? value : null;

    /// <summary>Switches the firewall of the given profiles on or off (netsh advfirewall set … state).</summary>
    public static ProcessRunner.Result SetEnabled(FirewallProfiles profiles, bool on)
    {
        ProcessRunner.Result last = new(0, "", false);
        foreach (var (profile, _, _, netsh) in Profiles)
        {
            if (profiles.HasFlag(profile))
            {
                last = Netsh.Run("advfirewall", "set", netsh, "state", on ? "on" : "off");
                if (!last.Success)
                {
                    return last;
                }
            }
        }

        return last;
    }

    /// <summary>
    /// Whitelist mode: default outbound action Block (on) or Allow (off) on all profiles. The inbound default of each
    /// profile is kept as it is.
    /// </summary>
    public static ProcessRunner.Result SetOutboundDefault(bool block)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        ProcessRunner.Result last = new(0, "", false);
        foreach (var (_, local, _, netsh) in Profiles)
        {
            using var key = hklm.OpenSubKey(LocalKey + "\\" + local);
            var inbound = (Dword(key, "DoNotAllowExceptions") ?? 0) != 0
                ? "blockinboundalways"
                : (Dword(key, "DefaultInboundAction") ?? 1) != 0 ? "blockinbound" : "allowinbound";
            last = Netsh.Run("advfirewall", "set", netsh, "firewallpolicy", inbound + "," + (block ? "blockoutbound" : "allowoutbound"));
            if (!last.Success)
            {
                return last;
            }
        }

        return last;
    }

    public static bool IsServiceRunning()
    {
        var run = ProcessRunner.Run("sc.exe", ["query", "mpssvc"], TimeSpan.FromSeconds(10));
        // "STATE : 4 RUNNING" – the number is language independent.
        return run.Success && run.Output.Contains(": 4", StringComparison.Ordinal);
    }

    /// <summary>Firewall products registered in the Security Center (client editions; servers have none).</summary>
    public static IReadOnlyList<FirewallProduct> SecurityCenterProducts()
    {
        if (SystemInfo.IsServer())
        {
            return [];
        }

        var script = "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop | " +
                     "ForEach-Object { '{0}|{1}' -f $_.displayName, $_.productState }";
        var run = ProcessRunner.Run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            TimeSpan.FromSeconds(20), encoding: System.Text.Encoding.UTF8);
        if (!run.Success)
        {
            return [];
        }

        var result = new List<FirewallProduct>();
        foreach (var line in run.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = line.Split('|');
            if (parts.Length != 2 || !int.TryParse(parts[1], out var state))
            {
                continue;
            }

            // productState: second byte 0x10/0x11 = on.
            var enabled = ((state >> 12) & 0xF) == 1;
            var name = parts[0].Trim();
            result.Add(new FirewallProduct(name, enabled, name.Contains("Windows", StringComparison.OrdinalIgnoreCase) || name.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase)));
        }

        return result;
    }

    private static (bool Joined, string? Domain) DomainJoin()
    {
        try
        {
            if (NetGetJoinInformation(null, out var buffer, out var status) != 0)
            {
                return (false, null);
            }

            try
            {
                // NetSetupDomainName = 3
                return status == 3 ? (true, Marshal.PtrToStringUni(buffer)) : (false, null);
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return (false, null);
        }
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetGetJoinInformation(string? server, out IntPtr name, out int status);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}

/// <summary>netsh advfirewall: policy export/import (.wfw) and reset.</summary>
public static class Netsh
{
    public static ProcessRunner.Result Run(params string[] arguments) =>
        ProcessRunner.Run("netsh.exe", arguments, TimeSpan.FromMinutes(2));

    /// <summary>Exports the complete firewall policy (all rules and profile settings) to a .wfw file.</summary>
    public static ProcessRunner.Result Export(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (File.Exists(path))
        {
            File.Delete(path);
        }

        var run = Run("advfirewall", "export", path);
        return run.Success && File.Exists(path) ? run : run with { ExitCode = run.ExitCode == 0 ? -1 : run.ExitCode };
    }

    /// <summary>Replaces the complete local firewall policy with a .wfw file.</summary>
    public static ProcessRunner.Result Import(string path) => Run("advfirewall", "import", path);

    /// <summary>Restores the Windows default policy – all own rules (also PortShield's) are removed.</summary>
    public static ProcessRunner.Result Reset() => Run("advfirewall", "reset");

    /// <summary>Opens "Windows Defender Firewall with Advanced Security".</summary>
    public static void OpenConsole() => Launch("mmc.exe", "wf.msc");

    /// <summary>Opens the classic firewall control panel.</summary>
    public static void OpenControlPanel() => Launch("control.exe", "firewall.cpl");

    private static void Launch(string file, string arguments)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(file, arguments) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // Not available (Server Core).
        }
    }
}
