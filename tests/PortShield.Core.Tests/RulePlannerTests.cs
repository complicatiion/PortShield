using PortShield.Core.Models;
using PortShield.Core.Rules;

namespace PortShield.Core.Tests;

public class RulePlannerTests
{
    private static readonly RulePlanner.Options NoFileCheck = new() { FileExists = null, SystemRoot = @"C:\Windows" };

    private static FirewallRuleInfo Rule(string program, RuleAction action, bool own = true, RuleDirection direction = RuleDirection.Outbound) => new()
    {
        Key = Guid.NewGuid().ToString(),
        Name = "r",
        Program = program,
        Action = action,
        Direction = direction,
        Enabled = true,
        Description = own ? "[ps:aaaaaaaa]" : "",
        Grouping = own ? "PortShield" : ""
    };

    private static RuleDefinition Want(string program, RuleAction action = RuleAction.Block, RuleScope scope = RuleScope.All,
        RuleDirection direction = RuleDirection.Outbound) =>
        new() { Program = program, Action = action, Scope = scope, Direction = direction };

    [Fact]
    public void New_program_is_created()
    {
        var plan = RulePlanner.Plan([], [Want(@"C:\A\a.exe")], NoFileCheck);
        Assert.Equal(PlanAction.Create, plan[0].Action);
    }

    [Fact]
    public void Identical_rule_is_unchanged_and_different_action_is_updated()
    {
        var existing = new[] { Rule(@"C:\A\a.exe", RuleAction.Block) };
        Assert.Equal(PlanAction.Unchanged, RulePlanner.Plan(existing, [Want(@"c:\a\A.EXE")], NoFileCheck)[0].Action);
        Assert.Equal(PlanAction.Update, RulePlanner.Plan(existing, [Want(@"C:\A\a.exe", RuleAction.Allow)], NoFileCheck)[0].Action);
        Assert.Equal(PlanAction.Update, RulePlanner.Plan(existing, [Want(@"C:\A\a.exe", scope: RuleScope.Internet)], NoFileCheck)[0].Action);
    }

    [Fact]
    public void Other_direction_is_a_new_rule()
    {
        var existing = new[] { Rule(@"C:\A\a.exe", RuleAction.Block) };
        Assert.Equal(PlanAction.Create, RulePlanner.Plan(existing, [Want(@"C:\A\a.exe", direction: RuleDirection.Inbound)], NoFileCheck)[0].Action);
    }

    [Fact]
    public void Duplicates_protected_and_missing()
    {
        var options = NoFileCheck with { FileExists = p => !p.Contains("missing", StringComparison.OrdinalIgnoreCase), OwnExecutable = @"C:\PS\PortShield.exe" };
        var plan = RulePlanner.Plan([],
        [
            Want(@"C:\A\a.exe"),
            Want(@"C:\A\A.exe"),
            Want(@"C:\Windows\System32\svchost.exe"),
            Want(@"C:\PS\PortShield.exe"),
            Want(@"C:\A\missing.exe")
        ], options);
        Assert.Equal([PlanAction.Create, PlanAction.Duplicate, PlanAction.Protected, PlanAction.Protected, PlanAction.Missing], plan.Select(p => p.Action).ToArray());
    }

    [Fact]
    public void Allow_against_foreign_block_is_flagged()
    {
        var existing = new[] { Rule(@"C:\A\a.exe", RuleAction.Block, own: false) };
        var item = RulePlanner.Plan(existing, [Want(@"C:\A\a.exe", RuleAction.Allow)], NoFileCheck)[0];
        Assert.Equal(PlanAction.Create, item.Action);
        Assert.True(item.BlockedByOtherRule);
    }

    [Fact]
    public void Protected_list_and_system_folder()
    {
        Assert.True(ProtectedPrograms.IsProtected(@"C:\Windows\SysWOW64\svchost.exe", systemRoot: @"C:\Windows"));
        Assert.False(ProtectedPrograms.IsProtected(@"C:\Temp\svchost.exe", systemRoot: @"C:\Windows"));
        Assert.True(ProtectedPrograms.IsProtected(@"D:\x.exe", extra: [@"d:\X.exe"], systemRoot: @"C:\Windows"));
    }

    [Fact]
    public void Both_directions()
    {
        Assert.Equal([RuleDirection.Outbound, RuleDirection.Inbound], RulePlanner.Directions(DirectionChoice.Both).ToArray());
    }
}
