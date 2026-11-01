using System.Globalization;
using System.Net;
using System.Net.Sockets;
using PortShield.Core.Models;

namespace PortShield.Core.Rules;

/// <summary>
/// "Internet only" scope: the complement of all local address ranges as a Windows Firewall address list. A block rule with
/// this scope stops a program from reaching the internet while LAN devices (NAS, printer, license server), loopback,
/// link-local and multicast discovery keep working. Computed here instead of the firewall keywords "Internet"/"Intranet",
/// whose meaning depends on the network isolation configuration.
/// </summary>
public static class InternetRanges
{
    /// <summary>IPv4 ranges that stay reachable: "this" network, RFC 1918, loopback, link-local, multicast, reserved/broadcast.</summary>
    internal static readonly (string Start, string End)[] LocalIPv4 =
    [
        ("0.0.0.0", "0.255.255.255"),
        ("10.0.0.0", "10.255.255.255"),
        ("127.0.0.0", "127.255.255.255"),
        ("169.254.0.0", "169.254.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
        ("224.0.0.0", "255.255.255.255")
    ];

    /// <summary>IPv6 ranges that stay reachable: unspecified and loopback, unique local (fc00::/7), link-local (fe80::/10), multicast (ff00::/8).</summary>
    internal static readonly (string Start, string End)[] LocalIPv6 =
    [
        ("::", "::1"),
        ("fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    ];

    private static readonly Lazy<IReadOnlyList<(UInt128 Start, UInt128 End)>> Ipv4Internet = new(() =>
        Complement(LocalIPv4.Select(r => (V4(r.Start), V4(r.End))), uint.MaxValue));

    private static readonly Lazy<IReadOnlyList<(UInt128 Start, UInt128 End)>> Ipv6Internet = new(() =>
        Complement(LocalIPv6.Select(r => (V6(r.Start), V6(r.End))), UInt128.MaxValue));

    private static readonly Lazy<string> AllText = new(() =>
        string.Join(",", Ipv4Internet.Value.Select(r => FormatV4(r.Start) + "-" + FormatV4(r.End))
            .Concat(Ipv6Internet.Value.Select(r => FormatV6(r.Start) + "-" + FormatV6(r.End)))));

    /// <summary>Address list for INetFwRule.RemoteAddresses / New-NetFirewallRule -RemoteAddress / netsh remoteip.</summary>
    public static string All => AllText.Value;

    public static IReadOnlyList<string> Items => All.Split(',');

    public static IReadOnlyList<(UInt128 Start, UInt128 End)> IPv4 => Ipv4Internet.Value;

    public static IReadOnlyList<(UInt128 Start, UInt128 End)> IPv6 => Ipv6Internet.Value;

    /// <summary>
    /// Scope of an address list as Windows returns it. Windows rewrites lists (subnets as "10.0.0.0/255.0.0.0", order,
    /// compressed IPv6), so the list is parsed into merged intervals and compared with the computed ranges.
    /// </summary>
    public static RuleScope DetectScope(string? remoteAddresses)
    {
        var text = remoteAddresses?.Trim();
        if (string.IsNullOrEmpty(text) || text == "*" || text.Equals("Any", StringComparison.OrdinalIgnoreCase))
        {
            return RuleScope.All;
        }

        if (!TryParse(text, out var v4, out var v6))
        {
            return RuleScope.Custom;
        }

        return Equal(v4, Ipv4Internet.Value) && Equal(v6, Ipv6Internet.Value) ? RuleScope.Internet : RuleScope.Custom;
    }

    /// <summary>Parses "a", "a-b", "a/prefix", "a/255.255.0.0" items (IPv4 and IPv6) into merged intervals; false on keywords or errors.</summary>
    public static bool TryParse(string text, out List<(UInt128 Start, UInt128 End)> ipv4, out List<(UInt128 Start, UInt128 End)> ipv6)
    {
        ipv4 = [];
        ipv6 = [];
        foreach (var raw in text.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TryParseItem(raw, out var start, out var end, out var isV6))
            {
                return false;
            }

            (isV6 ? ipv6 : ipv4).Add((start, end));
        }

        ipv4 = Merge(ipv4);
        ipv6 = Merge(ipv6);
        return true;
    }

    private static bool TryParseItem(string item, out UInt128 start, out UInt128 end, out bool isV6)
    {
        start = end = UInt128.Zero;
        isV6 = false;
        try
        {
            var dash = item.IndexOf('-');
            if (dash > 0)
            {
                var a = IPAddress.Parse(item[..dash]);
                var b = IPAddress.Parse(item[(dash + 1)..]);
                if (a.AddressFamily != b.AddressFamily)
                {
                    return false;
                }

                isV6 = a.AddressFamily == AddressFamily.InterNetworkV6;
                start = ToNumber(a);
                end = ToNumber(b);
                return start <= end;
            }

            var slash = item.IndexOf('/');
            if (slash > 0)
            {
                var address = IPAddress.Parse(item[..slash]);
                isV6 = address.AddressFamily == AddressFamily.InterNetworkV6;
                var bits = isV6 ? 128 : 32;
                var maskText = item[(slash + 1)..];
                int prefix;
                if (maskText.Contains('.'))
                {
                    var mask = (uint)ToNumber(IPAddress.Parse(maskText));
                    prefix = System.Numerics.BitOperations.PopCount(mask);
                }
                else if (!int.TryParse(maskText, NumberStyles.Integer, CultureInfo.InvariantCulture, out prefix) || prefix < 0 || prefix > bits)
                {
                    return false;
                }

                var max = isV6 ? UInt128.MaxValue : uint.MaxValue;
                var hostBits = bits - prefix;
                var hostMask = hostBits == 0 ? UInt128.Zero : hostBits == 128 ? UInt128.MaxValue : (UInt128.One << hostBits) - 1;
                var value = ToNumber(address);
                start = value & ~hostMask & max;
                end = start | hostMask;
                return true;
            }

            var single = IPAddress.Parse(item);
            isV6 = single.AddressFamily == AddressFamily.InterNetworkV6;
            start = end = ToNumber(single);
            return true;
        }
        catch (FormatException)
        {
            // Keywords such as LocalSubnet, DNS, Internet.
            return false;
        }
    }

    private static List<(UInt128 Start, UInt128 End)> Merge(List<(UInt128 Start, UInt128 End)> ranges)
    {
        var result = new List<(UInt128 Start, UInt128 End)>();
        foreach (var range in ranges.OrderBy(r => r.Start))
        {
            if (result.Count > 0)
            {
                var last = result[^1];
                if (last.End == UInt128.MaxValue || range.Start <= last.End + 1)
                {
                    result[^1] = (last.Start, range.End > last.End ? range.End : last.End);
                    continue;
                }
            }

            result.Add(range);
        }

        return result;
    }

    private static List<(UInt128 Start, UInt128 End)> Complement(IEnumerable<(UInt128 Start, UInt128 End)> excluded, UInt128 max)
    {
        var result = new List<(UInt128 Start, UInt128 End)>();
        var next = UInt128.Zero;
        var done = false;
        foreach (var range in Merge(excluded.ToList()))
        {
            if (range.Start > next)
            {
                result.Add((next, range.Start - 1));
            }

            if (range.End >= max)
            {
                done = true;
                break;
            }

            next = range.End + 1;
        }

        if (!done)
        {
            result.Add((next, max));
        }

        return result;
    }

    private static bool Equal(List<(UInt128 Start, UInt128 End)> a, IReadOnlyList<(UInt128 Start, UInt128 End)> b) =>
        a.Count == b.Count && a.Zip(b).All(p => p.First == p.Second);

    private static UInt128 V4(string text) => ToNumber(IPAddress.Parse(text));

    private static UInt128 V6(string text) => ToNumber(IPAddress.Parse(text));

    private static UInt128 ToNumber(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        UInt128 value = UInt128.Zero;
        foreach (var b in bytes)
        {
            value = (value << 8) | b;
        }

        return value;
    }

    private static string FormatV4(UInt128 value)
    {
        var v = (uint)value;
        return $"{v >> 24}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}";
    }

    private static string FormatV6(UInt128 value)
    {
        var bytes = new byte[16];
        for (var i = 15; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }

        return new IPAddress(bytes).ToString();
    }
}
