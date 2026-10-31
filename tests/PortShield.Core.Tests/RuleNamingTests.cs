using PortShield.Core.Models;
using PortShield.Core.Rules;

namespace PortShield.Core.Tests;

public class RuleNamingTests
{
    [Fact]
    public void Name_has_prefix_program_and_direction() =>
        Assert.Equal("PortShield · Snagit · Out", RuleNaming.BuildName(null, "Snagit", RuleDirection.Outbound));

    [Fact]
    public void Marker_round_trip()
    {
        var id = RuleNaming.NewId();
        var description = RuleNaming.WithMarker("Blocks Snagit.", id);
        Assert.Equal(id, RuleNaming.ParseId(description));
        Assert.Equal("Blocks Snagit.", RuleNaming.StripMarker(description));
        Assert.Equal(id, RuleNaming.ParseId(RuleNaming.WithMarker(description, id)));
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(RuleNaming.WithMarker(description, id), "ps:"));
    }

    [Fact]
    public void Foreign_rule_has_no_id() => Assert.Null(RuleNaming.ParseId("Core Networking - DNS"));

    [Theory]
    [InlineData(@"C:\Program Files\TechSmith\Snagit 2020\SnagitEditor.exe", "Snagit Editor", "Snagit Editor")]
    [InlineData(@"C:\Program Files\TechSmith\Snagit 2020\SnagPriv.exe", "", "SnagPriv")]
    [InlineData(@"C:\Tools\x.exe", null, "x")]
    public void Display_name(string path, string? description, string expected) =>
        Assert.Equal(expected, RuleNaming.DisplayNameFor(path, description));

    [Fact]
    public void Rule_with_marker_is_portshield_rule()
    {
        var rule = new FirewallRuleInfo { Key = "1", Name = "x", Description = "[ps:0123abcd]" };
        Assert.True(rule.IsPortShield);
        var grouped = new FirewallRuleInfo { Key = "2", Name = "y", Grouping = "PortShield" };
        Assert.True(grouped.IsPortShield);
        Assert.False(new FirewallRuleInfo { Key = "3", Name = "z", Grouping = "@FirewallAPI.dll,-23255" }.IsPortShield);
    }
}
