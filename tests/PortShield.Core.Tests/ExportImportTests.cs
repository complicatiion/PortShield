using PortShield.Core.Export;
using PortShield.Core.Import;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.RuleSets;

namespace PortShield.Core.Tests;

public class ExportImportTests
{
    private static readonly IReadOnlyList<ExportItem> Items =
    [
        new(new RuleDefinition { Program = @"D:\Apps\Snagit\SnagitEditor.exe", Action = RuleAction.Block, Scope = RuleScope.Internet },
            "PortShield · Snagit Editor · Out", true, new string('a', 64), "TechSmith Corporation"),
        new(new RuleDefinition { Program = @"D:\Apps\Tool; with ""quote""\=tool.exe", Direction = RuleDirection.Inbound, Action = RuleAction.Allow,
                Profiles = FirewallProfiles.Domain | FirewallProfiles.Private, Enabled = false },
            "PortShield · Tool · In", false, null, null)
    ];

    private static readonly ExportOptions Options = new() { PortablePaths = false, Generator = "PortShield test", Created = new DateTime(2026, 10, 31, 12, 0, 0) };

    [Fact]
    public void Every_format_writes_something()
    {
        foreach (var format in RuleExporter.All)
        {
            var text = RuleExporter.Export(format, Items, Options);
            Assert.False(string.IsNullOrWhiteSpace(text), format.ToString());
        }
    }

    [Fact]
    public void Csv_round_trip()
    {
        var csv = RuleExporter.Export(ExportFormat.Csv, Items, Options);
        var result = RuleImporter.Import(csv, "x.csv");
        Assert.Equal(2, result.Rules.Count);
        Assert.Empty(result.Warnings);
        var first = result.Rules[0];
        Assert.Equal(@"D:\Apps\Snagit\SnagitEditor.exe", first.Program);
        Assert.Equal(RuleScope.Internet, first.Scope);
        Assert.Equal(RuleAction.Block, first.Action);
        var second = result.Rules[1];
        Assert.Equal(@"D:\Apps\Tool; with ""quote""\=tool.exe", second.Program);
        Assert.Equal(RuleDirection.Inbound, second.Direction);
        Assert.Equal(RuleAction.Allow, second.Action);
        Assert.False(second.Enabled);
        Assert.Equal(FirewallProfiles.Domain | FirewallProfiles.Private, second.Profiles);
    }

    [Fact]
    public void Json_round_trip()
    {
        var json = RuleExporter.Export(ExportFormat.PortShieldJson, Items, Options);
        var set = RuleSet.Parse(json, "fallback");
        Assert.Equal(2, set.Rules.Count);
        Assert.Equal(RuleScope.Internet, set.Rules[0].Scope);
        Assert.Equal(new string('a', 64), set.Rules[0].Sha256);
        Assert.Equal("PortShield test", set.Generator);
        var imported = RuleImporter.Import(json, "x.json");
        Assert.Equal("JSON", imported.Format);
        Assert.Equal(2, imported.Rules.Count);
    }

    [Fact]
    public void Hash_list_contains_only_known_hashes()
    {
        var text = RuleExporter.Export(ExportFormat.TextHashes, Items, Options);
        Assert.Equal(new string('a', 64), text.Trim());
    }

    [Fact]
    public void PowerShell_escapes_quotes_and_uses_internet_list()
    {
        var script = RuleExporter.Export(ExportFormat.PowerShell, [Items[0] with { Name = "It's" }], Options);
        Assert.Contains("'It''s'", script);
        Assert.Contains("RemoteAddress = $internet", script);
        Assert.Contains("New-NetFirewallRule", script);
    }

    [Fact]
    public void Netsh_uses_ranges_for_internet_scope()
    {
        var script = RuleExporter.Export(ExportFormat.Netsh, Items, Options);
        Assert.Contains("remoteip=1.0.0.0-9.255.255.255", script);
        Assert.Contains("dir=in action=allow", script);
        Assert.Contains("profile=domain,private", script);
    }

    [Fact]
    public void Html_is_encoded()
    {
        var html = RuleExporter.Export(ExportFormat.Html, Items, Options);
        Assert.Contains("&quot;quote&quot;", html);
        Assert.DoesNotContain("<script", html);
    }

    [Fact]
    public void Csv_formula_injection_is_neutralized() =>
        Assert.Equal("'=cmd", RuleExporter.CsvField("=cmd", ';'));

    [Fact]
    public void Text_import_reads_paths_hash_lines_and_skips_comments()
    {
        var text = """
            # my list
            C:\Program Files\A\a.exe
            "C:\Program Files\B\b.exe"
            0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  C:\C\c.exe
            %ProgramFiles%\D\d.exe
            not a path
            """;
        var result = RuleImporter.Import(text, "list.txt", new ImportDefaults { Direction = DirectionChoice.Both, Scope = RuleScope.Internet });
        Assert.Equal(8, result.Rules.Count);
        Assert.Single(result.Warnings);
        Assert.All(result.Rules, r => Assert.Equal(RuleScope.Internet, r.Scope));
        Assert.Contains(result.Rules, r => r.Program == @"C:\C\c.exe");
    }

    [Fact]
    public void Csv_with_german_headers()
    {
        var csv = "Name;Aktiviert;Status;Dateipfad\nSnagit;Ja;Blockieren;C:\\Program Files\\TechSmith\\Snagit32.exe\nLogi;Ja;Zulassen;C:\\Program Files\\Logi\\agent.exe\n";
        var result = RuleImporter.Import(csv, "sordum.csv");
        Assert.Equal(2, result.Rules.Count);
        Assert.Equal(RuleAction.Block, result.Rules[0].Action);
        Assert.Equal(RuleAction.Allow, result.Rules[1].Action);
        Assert.Equal("Snagit", result.Rules[0].Name);
    }

    [Theory]
    [InlineData("a;b;c", ';')]
    [InlineData("a,b,c", ',')]
    [InlineData("a\tb\tc", '\t')]
    public void Delimiter_detection(string header, char expected) => Assert.Equal(expected, RuleImporter.DetectDelimiter(header));

    [Fact]
    public void Unknown_json_format_is_rejected() =>
        Assert.Throws<InvalidDataException>(() => RuleSet.Parse("{\"format\":\"other\"}", "x"));
}
