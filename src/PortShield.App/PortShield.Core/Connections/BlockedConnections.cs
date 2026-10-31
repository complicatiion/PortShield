using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Xml.Linq;
using PortShield.Core.Models;

namespace PortShield.Core.Connections;

/// <summary>Kind of the remote address of a connection.</summary>
public enum AddressKind
{
    Internet,
    Lan,
    Loopback,
    LinkLocal,

    /// <summary>Multicast and broadcast (discovery, mDNS, SSDP …).</summary>
    Multicast
}

/// <summary>
/// One connection the Windows Filtering Platform blocked (Security event 5157). For both directions
/// <see cref="LocalAddress"/> is this machine and <see cref="RemoteAddress"/> the other side.
/// </summary>
public sealed record BlockedConnection(
    DateTime Time,
    string Application,
    int ProcessId,
    RuleDirection Direction,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    int Protocol)
{
    public AddressKind RemoteKind => BlockedConnections.Classify(RemoteAddress);

    public bool IsInternet => RemoteKind == AddressKind.Internet;
}

/// <summary>Connections with the same program, direction, remote address, remote port and protocol.</summary>
public sealed record ConnectionGroup(
    string Application,
    RuleDirection Direction,
    string RemoteAddress,
    int RemotePort,
    int Protocol,
    int Count,
    DateTime First,
    DateTime Last)
{
    public AddressKind RemoteKind => BlockedConnections.Classify(RemoteAddress);
}

/// <summary>Parses event 5157 (wevtutil /f:xml) and groups the result.</summary>
public static class BlockedConnections
{
    public const int EventId = 5157;

    /// <summary>Audit subcategory "Filtering Platform Connection" (the GUID works in every Windows language).</summary>
    public static readonly Guid AuditSubcategory = new("0CCE9226-69AE-11D9-BED3-505054503030");

    /// <summary>
    /// Parses the concatenated &lt;Event&gt; elements wevtutil writes. <paramref name="mapPath"/> turns
    /// "\device\harddiskvolume3\…" into "C:\…".
    /// </summary>
    public static IReadOnlyList<BlockedConnection> Parse(string xml, Func<string, string>? mapPath = null)
    {
        var start = xml.IndexOf("<Event", StringComparison.Ordinal);
        if (start < 0)
        {
            return [];
        }

        XElement root;
        try
        {
            root = XElement.Parse("<Events>" + xml[start..] + "</Events>");
        }
        catch (System.Xml.XmlException)
        {
            // Output cut off (count limit, timeout): parse the complete events only.
            var end = xml.LastIndexOf("</Event>", StringComparison.Ordinal);
            if (end < start)
            {
                return [];
            }

            try
            {
                root = XElement.Parse("<Events>" + xml[start..(end + 8)] + "</Events>");
            }
            catch (System.Xml.XmlException)
            {
                return [];
            }
        }

        var result = new List<BlockedConnection>();
        foreach (var e in root.Elements().Where(x => x.Name.LocalName == "Event"))
        {
            var system = e.Elements().FirstOrDefault(x => x.Name.LocalName == "System");
            var id = system?.Elements().FirstOrDefault(x => x.Name.LocalName == "EventID")?.Value;
            if (id != EventId.ToString(CultureInfo.InvariantCulture))
            {
                continue;
            }

            var time = system!.Elements().FirstOrDefault(x => x.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
            var data = e.Descendants().Where(x => x.Name.LocalName == "Data")
                .GroupBy(x => (string?)x.Attribute("Name") ?? "")
                .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);

            var application = data.GetValueOrDefault("Application") ?? "";
            if (mapPath is not null && application.Length > 0)
            {
                application = mapPath(application);
            }

            result.Add(new BlockedConnection(
                DateTime.TryParse(time, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var utc)
                    ? utc.ToLocalTime()
                    : DateTime.MinValue,
                application.Length == 0 ? "System" : application,
                Int(data.GetValueOrDefault("ProcessID") ?? data.GetValueOrDefault("ProcessId")),
                ParseDirection(data.GetValueOrDefault("Direction")),
                data.GetValueOrDefault("SourceAddress") ?? "",
                Int(data.GetValueOrDefault("SourcePort")),
                data.GetValueOrDefault("DestAddress") ?? "",
                Int(data.GetValueOrDefault("DestPort")),
                Int(data.GetValueOrDefault("Protocol"))));
        }

        return result;
    }

    /// <summary>%%14592 inbound, %%14593 outbound (also the resolved English/German text).</summary>
    public static RuleDirection ParseDirection(string? value) =>
        value is not null && (value.Contains("14592", StringComparison.Ordinal)
                              || value.Contains("Inbound", StringComparison.OrdinalIgnoreCase)
                              || value.Contains("Eingehend", StringComparison.OrdinalIgnoreCase))
            ? RuleDirection.Inbound
            : RuleDirection.Outbound;

    public static IReadOnlyList<ConnectionGroup> Group(IEnumerable<BlockedConnection> connections) =>
        connections
            .GroupBy(c => (App: c.Application.ToUpperInvariant(), c.Direction, c.RemoteAddress, c.RemotePort, c.Protocol))
            .Select(g => new ConnectionGroup(g.First().Application, g.Key.Direction, g.Key.RemoteAddress, g.Key.RemotePort, g.Key.Protocol,
                g.Count(), g.Min(c => c.Time), g.Max(c => c.Time)))
            .OrderByDescending(g => g.Last)
            .ToList();

    public static string ProtocolName(int protocol) => protocol switch
    {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => protocol.ToString(CultureInfo.InvariantCulture)
    };

    public static AddressKind Classify(string address)
    {
        if (!IPAddress.TryParse(address, out var ip))
        {
            return AddressKind.Internet;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (IPAddress.IsLoopback(ip))
        {
            return AddressKind.Loopback;
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] switch
            {
                10 => AddressKind.Lan,
                172 when b[1] is >= 16 and <= 31 => AddressKind.Lan,
                192 when b[1] == 168 => AddressKind.Lan,
                100 when b[1] is >= 64 and <= 127 => AddressKind.Lan, // carrier-grade NAT
                169 when b[1] == 254 => AddressKind.LinkLocal,
                >= 224 => AddressKind.Multicast, // multicast, reserved, 255.255.255.255
                0 => AddressKind.Lan,
                _ => AddressKind.Internet
            };
        }

        if (ip.IsIPv6Multicast)
        {
            return AddressKind.Multicast;
        }

        if (ip.IsIPv6LinkLocal)
        {
            return AddressKind.LinkLocal;
        }

        var first = ip.GetAddressBytes()[0];
        return ip.IsIPv6SiteLocal || (first & 0xFE) == 0xFC ? AddressKind.Lan : AddressKind.Internet;
    }

    private static int Int(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : 0;
}
