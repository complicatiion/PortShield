using PortShield.Core.Connections;
using PortShield.Core.Integrity;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.RuleSets;

namespace PortShield.Core.Tests;

/// <summary>Integrity check, temporarily allowed rules, watched rule sets and blocked connections (v0.0.4).</summary>
public class GuardTests
{
    private static FirewallRuleInfo Own(string id, string program, RuleAction action = RuleAction.Block, bool enabled = true, string name = "PortShield · App · Out") => new()
    {
        Key = Guid.NewGuid().ToString(),
        Name = name,
        Program = program,
        Action = action,
        Direction = RuleDirection.Outbound,
        Enabled = enabled,
        Grouping = RuleNaming.Group,
        Description = RuleNaming.WithMarker("x", id)
    };

    // ------------------------------------------------------------------ Integrity

    [Fact]
    public void Integrity_reports_missing_and_changed_rules()
    {
        var a = Own("aaaaaaaa", @"C:\Apps\a.exe");
        var b = Own("bbbbbbbb", @"C:\Apps\b.exe");
        var c = Own("cccccccc", @"C:\Apps\c.exe");
        var baseline = RuleIntegrity.Capture([a, b, c]);
        Assert.Equal(3, baseline.Rules.Count);

        // a unchanged, b disabled from outside, c deleted.
        var drifts = RuleIntegrity.Compare(baseline, [a, b with { Enabled = false }]);
        Assert.Equal(2, drifts.Count);
        Assert.Contains(drifts, d => d.Expected.Id == "bbbbbbbb" && d.Kind == DriftKind.Changed);
        Assert.Contains(drifts, d => d.Expected.Id == "cccccccc" && d.Kind == DriftKind.Missing);
    }

    [Fact]
    public void Integrity_ignores_key_changes_case_and_kill_switch()
    {
        var a = Own("aaaaaaaa", @"C:\Apps\a.exe");
        var kill = Own("kkkkkkkk", "", name: RuleNaming.KillSwitchName + " · Out");
        var baseline = RuleIntegrity.Capture([a, kill]);
        Assert.Single(baseline.Rules);

        // Same rule after a reload: other COM key, path in other case.
        var reloaded = a with { Key = "other", Program = @"c:\apps\A.EXE" };
        Assert.Empty(RuleIntegrity.Compare(baseline, [reloaded]));
    }

    [Fact]
    public void Integrity_detects_action_and_scope_changes()
    {
        var a = Own("aaaaaaaa", @"C:\Apps\a.exe");
        var baseline = RuleIntegrity.Capture([a]);
        Assert.Single(RuleIntegrity.Compare(baseline, [a with { Action = RuleAction.Allow }]));
        Assert.Single(RuleIntegrity.Compare(baseline, [a with { RemoteAddresses = InternetRanges.All }]));
        Assert.Single(RuleIntegrity.Compare(baseline, [a with { Name = "Renamed" }]));
    }

    // ------------------------------------------------------------------ Temporary

    [Fact]
    public void Temporary_list_adds_extends_and_finds_due_entries()
    {
        var now = new DateTime(2026, 10, 31, 12, 0, 0);
        var list = new TemporaryList()
            .With([new TemporaryEntry("a", "A", now.AddMinutes(15)), new TemporaryEntry("b", "B", now.AddMinutes(-1))]);
        Assert.Equal(now.AddMinutes(-1), list.Next);
        Assert.Equal(["b"], list.Due(now).Select(e => e.Id));

        // Extending replaces the entry of the same rule.
        list = list.With([new TemporaryEntry("B", "B", now.AddHours(1))]);
        Assert.Equal(2, list.Entries.Count);
        Assert.Empty(list.Due(now));
        Assert.Equal(now.AddHours(1), list.Find("b")!.Until);

        list = list.Without(["a"]);
        Assert.Single(list.Entries);
    }

    // ------------------------------------------------------------------ Watch

    [Fact]
    public void Watch_list_keeps_one_entry_per_file()
    {
        var list = new WatchList()
            .With(new WatchEntry { File = "adobe.json", IsPreset = true, Name = "Adobe" })
            .With(new WatchEntry { File = "ADOBE.json", IsPreset = true, Name = "Adobe 2" })
            .With(new WatchEntry { File = "adobe.json", IsPreset = false, Name = "Own" });
        Assert.Equal(2, list.Sets.Count);
        Assert.True(list.Contains("adobe.json", true));
        Assert.Equal("Adobe 2", list.Find("adobe.json", true)!.Name);
        Assert.False(list.Without("adobe.json", true).Contains("adobe.json", true));
        Assert.Equal(WatchEntry.IgnoreKey(@"C:\X\a.exe", null, RuleDirection.Outbound), WatchEntry.IgnoreKey(@"c:\x\A.exe", "", RuleDirection.Outbound));
    }

    // ------------------------------------------------------------------ Blocked connections

    private const string Events = """
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5157</EventID><TimeCreated SystemTime='2026-10-31T10:15:00.1234567Z'/></System><EventData><Data Name='ProcessID'>4321</Data><Data Name='Application'>\device\harddiskvolume3\program files\adobe\photoshop.exe</Data><Data Name='Direction'>%%14593</Data><Data Name='SourceAddress'>192.168.1.20</Data><Data Name='SourcePort'>50211</Data><Data Name='DestAddress'>52.1.2.3</Data><Data Name='DestPort'>443</Data><Data Name='Protocol'>6</Data></EventData></Event>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5157</EventID><TimeCreated SystemTime='2026-10-31T10:16:00Z'/></System><EventData><Data Name='ProcessID'>4321</Data><Data Name='Application'>\device\harddiskvolume3\program files\adobe\photoshop.exe</Data><Data Name='Direction'>%%14593</Data><Data Name='SourceAddress'>192.168.1.20</Data><Data Name='SourcePort'>50212</Data><Data Name='DestAddress'>52.1.2.3</Data><Data Name='DestPort'>443</Data><Data Name='Protocol'>6</Data></EventData></Event>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5157</EventID><TimeCreated SystemTime='2026-10-31T10:17:00Z'/></System><EventData><Data Name='ProcessID'>4</Data><Data Name='Application'>System</Data><Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>192.168.1.20</Data><Data Name='SourcePort'>137</Data><Data Name='DestAddress'>192.168.1.255</Data><Data Name='DestPort'>137</Data><Data Name='Protocol'>17</Data></EventData></Event>
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5157</EventID><TimeCreated SystemTime='2026-10-31T10:18
        """;

    [Fact]
    public void Blocked_events_are_parsed_mapped_and_grouped()
    {
        var connections = BlockedConnections.Parse(Events, path => path.Replace(@"\device\harddiskvolume3", "C:", StringComparison.OrdinalIgnoreCase));
        // The cut-off fourth event is dropped.
        Assert.Equal(3, connections.Count);
        var first = connections[0];
        Assert.Equal(@"C:\program files\adobe\photoshop.exe", first.Application);
        Assert.Equal(RuleDirection.Outbound, first.Direction);
        Assert.Equal("52.1.2.3", first.RemoteAddress);
        Assert.Equal(443, first.RemotePort);
        Assert.True(first.IsInternet);
        Assert.Equal(DateTimeKind.Local, first.Time.Kind);
        Assert.Equal(RuleDirection.Inbound, connections[2].Direction);
        Assert.Equal(AddressKind.Lan, connections[2].RemoteKind);

        var groups = BlockedConnections.Group(connections);
        Assert.Equal(2, groups.Count);
        Assert.Equal(2, groups.Single(g => g.RemotePort == 443).Count);
        Assert.Equal("TCP", BlockedConnections.ProtocolName(6));
    }

    [Theory]
    [InlineData("8.8.8.8", AddressKind.Internet)]
    [InlineData("10.1.2.3", AddressKind.Lan)]
    [InlineData("172.20.0.1", AddressKind.Lan)]
    [InlineData("172.32.0.1", AddressKind.Internet)]
    [InlineData("127.0.0.1", AddressKind.Loopback)]
    [InlineData("169.254.10.1", AddressKind.LinkLocal)]
    [InlineData("239.255.255.250", AddressKind.Multicast)]
    [InlineData("255.255.255.255", AddressKind.Multicast)]
    [InlineData("fe80::1", AddressKind.LinkLocal)]
    [InlineData("fd00::1", AddressKind.Lan)]
    [InlineData("ff02::fb", AddressKind.Multicast)]
    [InlineData("2a00:1450:4001::1", AddressKind.Internet)]
    [InlineData("::1", AddressKind.Loopback)]
    public void Remote_addresses_are_classified(string address, AddressKind kind) =>
        Assert.Equal(kind, BlockedConnections.Classify(address));

    [Fact]
    public void Garbage_and_empty_output_give_no_connections()
    {
        Assert.Empty(BlockedConnections.Parse(""));
        Assert.Empty(BlockedConnections.Parse("No events were found that match the specified selection criteria."));
    }
}
