using PortShield.Core.Export;
using PortShield.Core.Import;
using PortShield.Core.Models;
using PortShield.Core.Rules;

namespace PortShield.Core.Tests;

public class ServiceAndScanTests
{
    private const string Svchost = @"C:\Windows\System32\svchost.exe";

    private static readonly RulePlanner.Options NoFileCheck = new() { FileExists = null, SystemRoot = @"C:\Windows" };

    private static FirewallRuleInfo Rule(string program, RuleAction action, string grouping = "", string description = "", bool enabled = true,
        string service = "", string name = "r") => new()
    {
        Key = Guid.NewGuid().ToString(),
        Name = name,
        Program = program,
        Service = service,
        Action = action,
        Direction = RuleDirection.Outbound,
        Enabled = enabled,
        Grouping = grouping,
        Description = description
    };

    [Fact]
    public void Service_rule_on_svchost_is_not_protected_and_keyed_by_service()
    {
        var plan = RulePlanner.Plan([],
        [
            new RuleDefinition { Program = Svchost, Service = "DiagTrack" },
            new RuleDefinition { Program = Svchost, Service = "dmwappushservice" },
            new RuleDefinition { Program = Svchost }
        ], NoFileCheck);
        Assert.Equal([PlanAction.Create, PlanAction.Create, PlanAction.Protected], plan.Select(p => p.Action).ToArray());
    }

    [Fact]
    public void Existing_service_rule_is_matched()
    {
        var existing = new[] { Rule(Svchost, RuleAction.Block, "PortShield", "[ps:aaaaaaaa]", service: "DiagTrack") };
        var plan = RulePlanner.Plan(existing, [new RuleDefinition { Program = Svchost, Service = "diagtrack" }], NoFileCheck);
        Assert.Equal(PlanAction.Unchanged, plan[0].Action);
    }

    [Fact]
    public void Service_survives_csv_round_trip_and_appears_in_scripts()
    {
        var items = new[] { new ExportItem(new RuleDefinition { Program = Svchost, Service = "DiagTrack", Scope = RuleScope.Internet }, "T", true, null, null) };
        var options = new ExportOptions { PortablePaths = false };
        var csv = RuleExporter.Export(ExportFormat.Csv, items, options);
        Assert.Equal("DiagTrack", RuleImporter.Import(csv, "x.csv").Rules[0].Service);
        Assert.Contains("service=\"DiagTrack\"", RuleExporter.Export(ExportFormat.Netsh, items, options));
        Assert.Contains("Service = 'DiagTrack'", RuleExporter.Export(ExportFormat.PowerShell, items, options));
    }

    [Fact]
    public void Scan_sorts_origins_and_findings()
    {
        var rules = new[]
        {
            Rule(@"C:\A\a.exe", RuleAction.Block, name: "Sordum a"),
            Rule(@"C:\A\a.exe", RuleAction.Block, name: "Sordum a again"),
            Rule(@"C:\B\b.exe", RuleAction.Allow, name: "allow b"),
            Rule(@"C:\B\b.exe", RuleAction.Block, "PortShield", "[ps:bbbbbbbb]"),
            Rule(@"C:\Gone\gone.exe", RuleAction.Block),
            Rule(@"C:\Windows\System32\svchost.exe", RuleAction.Allow, "@FirewallAPI.dll,-25000", service: "Dnscache"),
            Rule(@"C:\G\gpo.exe", RuleAction.Block, name: "From GPO"),
            Rule(@"C:\D\d.exe", RuleAction.Block, enabled: false)
        };
        var policy = new[] { new PolicyRule("From GPO", @"C:\G\gpo.exe", "", RuleDirection.Outbound, RuleAction.Block, true) };
        var result = RuleScanner.Scan(rules, policy, p => !p.Contains("Gone"));

        Assert.Equal(RuleOrigin.Other, result.Entries[0].Origin);
        Assert.True(result.Entries[0].Has(ScanFinding.Duplicate));
        Assert.True(result.Entries[2].Has(ScanFinding.Conflict));
        Assert.Equal(RuleOrigin.PortShield, result.Entries[3].Origin);
        Assert.True(result.Entries[4].Has(ScanFinding.Orphan));
        Assert.Equal(RuleOrigin.System, result.Entries[5].Origin);
        Assert.False(result.Entries[5].CanAdopt);
        Assert.Equal(RuleOrigin.Policy, result.Entries[6].Origin);
        Assert.True(result.Entries[7].Has(ScanFinding.Disabled));
        Assert.Equal(5, result.Adoptable);

        var extras = RuleScanner.MergeExtras(result.Entries);
        Assert.Single(extras);
        Assert.Equal("Sordum a again", extras[0].Name);
    }

    [Fact]
    public void Policy_rule_value_is_parsed()
    {
        var rule = RuleScanner.ParsePolicyRule(@"v2.31|Action=Allow|Active=FALSE|Dir=In|App=C:\x.exe|Svc=Foo|Name=Test rule|");
        Assert.NotNull(rule);
        Assert.Equal("Test rule", rule!.Name);
        Assert.Equal(RuleDirection.Inbound, rule.Direction);
        Assert.Equal(RuleAction.Allow, rule.Action);
        Assert.False(rule.Enabled);
        Assert.Equal("Foo", rule.Service);
    }
}

public class BundleAndRecursiveTests
{
    [Fact]
    public void Bundle_round_trip_and_single_set_fallback()
    {
        var bundle = new PortShield.Core.RuleSets.RuleSetBundle
        {
            Sets =
            [
                new PortShield.Core.RuleSets.RuleSet { Name = "A", Rules = [new RuleDefinition { Program = @"C:\a.exe" }] },
                new PortShield.Core.RuleSets.RuleSet { Name = "B", Rules = [new RuleDefinition { Program = @"C:\b.exe", Service = "X" }] }
            ]
        };
        var sets = PortShield.Core.RuleSets.RuleSetBundle.ParseAny(bundle.ToJson(), "f");
        Assert.Equal(2, sets.Count);
        Assert.Equal("X", sets[1].Rules[0].Service);
        var single = PortShield.Core.RuleSets.RuleSetBundle.ParseAny(sets[0].ToJson(), "f");
        Assert.Single(single);
        Assert.Equal("A", single[0].Name);
    }

    [Fact]
    public void Double_star_matches_all_sub_folders()
    {
        var root = Path.Combine(Path.GetTempPath(), "ps-rec-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "x", "y"));
            File.WriteAllText(Path.Combine(root, "a.exe"), "");
            File.WriteAllText(Path.Combine(root, "x", "b.exe"), "");
            File.WriteAllText(Path.Combine(root, "x", "y", "c.exe"), "");
            File.WriteAllText(Path.Combine(root, "x", "y", "d.dll"), "");
            Assert.Equal(3, ProgramPaths.Resolve(Path.Combine(root, "**", "*.exe")).Count);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
}
