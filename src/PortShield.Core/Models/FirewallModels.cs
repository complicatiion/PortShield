using PortShield.Core.Rules;

namespace PortShield.Core.Models;

/// <summary>Traffic direction of a rule (values as NET_FW_RULE_DIRECTION).</summary>
public enum RuleDirection
{
    Inbound = 1,
    Outbound = 2
}

/// <summary>Rule action (values as NET_FW_ACTION).</summary>
public enum RuleAction
{
    Block = 0,
    Allow = 1
}

/// <summary>Which remote addresses a rule covers.</summary>
public enum RuleScope
{
    /// <summary>Every remote address (LAN and internet).</summary>
    All,

    /// <summary>Only public addresses: LAN, loopback, link-local and multicast stay reachable.</summary>
    Internet,

    /// <summary>Any other address list (rules not made by PortShield, or edited in wf.msc).</summary>
    Custom
}

/// <summary>Firewall profiles (values as NET_FW_PROFILE_TYPE2).</summary>
[Flags]
public enum FirewallProfiles
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
    All = Domain | Private | Public
}

/// <summary>Where a rule should be created: one direction or both.</summary>
public enum DirectionChoice
{
    Outbound,
    Inbound,
    Both
}

/// <summary>
/// A rule as read from the Windows Firewall. <see cref="Key"/> identifies the live rule within one load (the platform keeps
/// the COM object behind it); <see cref="PortShieldId"/> is the stable id of rules PortShield created.
/// </summary>
public sealed record FirewallRuleInfo
{
    public required string Key { get; init; }

    public required string Name { get; init; }

    public string Description { get; init; } = "";

    /// <summary>Program path as stored in the rule (may contain environment variables); empty for rules without a program.</summary>
    public string Program { get; init; } = "";

    public string Service { get; init; } = "";

    public RuleDirection Direction { get; init; }

    public RuleAction Action { get; init; }

    public bool Enabled { get; init; }

    public FirewallProfiles Profiles { get; init; } = FirewallProfiles.All;

    /// <summary>"*" for any address, otherwise the address list as Windows stores it.</summary>
    public string RemoteAddresses { get; init; } = "*";

    /// <summary>IANA protocol number; 256 = any.</summary>
    public int Protocol { get; init; } = 256;

    public string LocalPorts { get; init; } = "";

    public string RemotePorts { get; init; } = "";

    public string Grouping { get; init; } = "";

    /// <summary>Id from the PortShield marker in the description; null for foreign rules.</summary>
    public string? PortShieldId => RuleNaming.ParseId(Description);

    public bool IsPortShield => PortShieldId is not null || string.Equals(Grouping, RuleNaming.Group, StringComparison.OrdinalIgnoreCase);

    public RuleScope Scope => InternetRanges.DetectScope(RemoteAddresses);

    /// <summary>The kill switch rules (no program, block everything) are handled separately.</summary>
    public bool IsKillSwitch => IsPortShield && Name.StartsWith(RuleNaming.KillSwitchName, StringComparison.OrdinalIgnoreCase);

    /// <summary>Program path with environment variables expanded (for file checks and comparisons).</summary>
    public string ExpandedProgram => ProgramPaths.Expand(Program);

    public bool HasProgram => !string.IsNullOrWhiteSpace(Program) && !string.Equals(Program, "System", StringComparison.OrdinalIgnoreCase);

    public bool HasService => !string.IsNullOrWhiteSpace(Service) && Service != "*";

    /// <summary>Windows' own rules: group or name is a resource reference ("@FirewallAPI.dll,-23255").</summary>
    public bool IsSystem => Grouping.StartsWith('@') || Name.StartsWith('@');
}

/// <summary>
/// A rule as PortShield describes it in rule sets, imports and exports: program, direction, action and scope.
/// Platform-neutral; the firewall layer turns it into a Windows rule.
/// </summary>
public sealed record RuleDefinition
{
    /// <summary>Display name of the rule; empty = derived from the program ("PortShield · Snagit · Out").</summary>
    public string Name { get; init; } = "";

    /// <summary>Program path; may contain environment variables (%ProgramFiles%) and, in rule sets, * wildcards.</summary>
    public string Program { get; init; } = "";

    /// <summary>
    /// Windows service short name (e.g. "DiagTrack") for services running inside svchost.exe – the rule then only applies
    /// to that service. Empty = the whole program.
    /// </summary>
    public string? Service { get; init; }

    public bool HasService => !string.IsNullOrWhiteSpace(Service);

    public RuleDirection Direction { get; init; } = RuleDirection.Outbound;

    public RuleAction Action { get; init; } = RuleAction.Block;

    public RuleScope Scope { get; init; } = RuleScope.All;

    /// <summary>Only used with <see cref="RuleScope.Custom"/>.</summary>
    public string? RemoteAddresses { get; init; }

    public FirewallProfiles Profiles { get; init; } = FirewallProfiles.All;

    public bool Enabled { get; init; } = true;

    public string? Description { get; init; }

    /// <summary>Optional: SHA-256 of the program at export time (for AV block lists, not used to match).</summary>
    public string? Sha256 { get; init; }

    /// <summary>Optional: publisher / company of the program at export time.</summary>
    public string? Publisher { get; init; }

    /// <summary>Address list Windows gets for this rule.</summary>
    public string EffectiveRemoteAddresses => Scope switch
    {
        RuleScope.Internet => InternetRanges.All,
        RuleScope.Custom when !string.IsNullOrWhiteSpace(RemoteAddresses) => RemoteAddresses!,
        _ => "*"
    };

    public static RuleDefinition FromRule(FirewallRuleInfo rule) => new()
    {
        Name = rule.Name,
        Program = rule.Program,
        Service = rule.HasService ? rule.Service : null,
        Direction = rule.Direction,
        Action = rule.Action,
        Scope = rule.Scope,
        RemoteAddresses = rule.Scope == RuleScope.Custom ? rule.RemoteAddresses : null,
        Profiles = rule.Profiles == FirewallProfiles.None ? FirewallProfiles.All : rule.Profiles,
        Enabled = rule.Enabled,
        Description = RuleNaming.StripMarker(rule.Description)
    };
}

/// <summary>State of one firewall profile, local setting combined with group policy.</summary>
public sealed record ProfileState(
    FirewallProfiles Profile,
    bool Enabled,
    bool BlockOutboundByDefault,
    bool BlockInboundByDefault,
    bool IsActive,
    bool EnabledByPolicy,
    bool OutboundByPolicy,
    bool LocalRulesIgnored);

/// <summary>Firewall product registered in the Windows Security Center (client editions only).</summary>
public sealed record FirewallProduct(string Name, bool Enabled, bool IsWindowsFirewall);

/// <summary>Everything the overview shows about the firewall of this machine.</summary>
public sealed record FirewallStatus
{
    public IReadOnlyList<ProfileState> Profiles { get; init; } = [];

    public bool ServiceRunning { get; init; } = true;

    public bool DomainJoined { get; init; }

    public string? DomainName { get; init; }

    public bool IsServer { get; init; }

    /// <summary>Group policy configures the firewall (any profile setting or rules under Policies\Microsoft\WindowsFirewall).</summary>
    public bool ManagedByPolicy { get; init; }

    /// <summary>Firewall rules delivered by group policy.</summary>
    public int PolicyRuleCount { get; init; }

    /// <summary>A profile ignores local rules (AllowLocalPolicyMerge = 0): PortShield rules have no effect there.</summary>
    public bool LocalRulesIgnored => Profiles.Any(p => p.LocalRulesIgnored);

    public IReadOnlyList<FirewallProduct> Products { get; init; } = [];

    /// <summary>Another firewall is registered and active – it usually turns the Windows Firewall off.</summary>
    public bool ThirdPartyActive => Products.Any(p => p.Enabled && !p.IsWindowsFirewall);

    public bool AllProfilesEnabled => Profiles.Count > 0 && Profiles.All(p => p.Enabled);

    /// <summary>Whitelist mode: outbound traffic is blocked unless a rule allows it (all profiles).</summary>
    public bool WhitelistMode => Profiles.Count > 0 && Profiles.All(p => p.BlockOutboundByDefault);
}
