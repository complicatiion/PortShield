using PortShield.Core.Models;
using PortShield.Core.Rules;

namespace PortShield.Core.Tests;

public class InternetRangesTests
{
    [Fact]
    public void All_excludes_private_ranges_and_covers_public_space()
    {
        var items = InternetRanges.Items;
        Assert.Equal("1.0.0.0-9.255.255.255", items[0]);
        Assert.Contains("11.0.0.0-126.255.255.255", items);
        Assert.Contains("172.32.0.0-192.167.255.255", items);
        Assert.Contains("192.169.0.0-223.255.255.255", items);
        Assert.DoesNotContain(items, i => i.StartsWith("10.", StringComparison.Ordinal));
        Assert.Contains("::2-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", items);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("")]
    [InlineData("Any")]
    public void Any_address_is_scope_all(string text) => Assert.Equal(RuleScope.All, InternetRanges.DetectScope(text));

    [Fact]
    public void Own_list_is_detected_as_internet() =>
        Assert.Equal(RuleScope.Internet, InternetRanges.DetectScope(InternetRanges.All));

    [Fact]
    public void Rewritten_and_reordered_list_is_still_internet()
    {
        // Windows may return subnets with dotted masks, split ranges and change the order.
        var parts = InternetRanges.Items.Reverse().ToList();
        parts.Remove("11.0.0.0-126.255.255.255");
        parts.Add("11.0.0.0/255.0.0.0");
        parts.Add("12.0.0.0-126.255.255.255");
        Assert.Equal(RuleScope.Internet, InternetRanges.DetectScope(string.Join(",", parts)));
    }

    [Theory]
    [InlineData("LocalSubnet")]
    [InlineData("192.168.1.0/24")]
    [InlineData("8.8.8.8,1.1.1.1")]
    public void Other_lists_are_custom(string text) => Assert.Equal(RuleScope.Custom, InternetRanges.DetectScope(text));

    [Fact]
    public void Cidr_prefix_is_parsed()
    {
        Assert.True(InternetRanges.TryParse("10.0.0.0/8,fe80::/10", out var v4, out var v6));
        Assert.Single(v4);
        Assert.Single(v6);
        Assert.Equal((UInt128)0x0A000000, v4[0].Start);
        Assert.Equal((UInt128)0x0AFFFFFF, v4[0].End);
    }
}
