using System.Runtime.InteropServices;
using PortShield.Core.Models;
using PortShield.Core.Rules;

namespace PortShield.Platform.Windows;

/// <summary>A rule write that failed (rule name and Windows' message).</summary>
public sealed record RuleError(string Rule, string Message);

/// <summary>Result of a batch of rule writes.</summary>
public sealed record WriteResult(int Succeeded, IReadOnlyList<RuleError> Errors)
{
    public static readonly WriteResult Empty = new(0, []);

    public bool HasErrors => Errors.Count > 0;
}

/// <summary>
/// Windows Firewall rules through the official COM API (HNetCfg.FwPolicy2, late-bound via IDispatch) – fast, works in bulk,
/// no process per rule. The firewall stores rules by name only, and names are not unique; therefore every read keeps the
/// live COM object behind each <see cref="FirewallRuleInfo.Key"/>, and changes go to exactly that object.
/// <para>Not thread-safe: the app calls it from one worker at a time (never from the UI thread).</para>
/// </summary>
public sealed class FirewallStore : IDisposable
{
    private const int ProfilesAll = 0x7FFFFFFF;
    private const int ProtocolAny = 256;

    private readonly Dictionary<string, object> _live = new(StringComparer.Ordinal);
    private object? _policy;
    private int _generation;

    private dynamic Policy => _policy ??= Create("HNetCfg.FwPolicy2");

    private static object Create(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: true)!;
        return Activator.CreateInstance(type) ?? throw new COMException($"{progId} could not be created.");
    }

    // ------------------------------------------------------------------ Read

    /// <summary>All rules of the local store (system, third-party and PortShield). Keys are valid until the next load.</summary>
    public IReadOnlyList<FirewallRuleInfo> Load()
    {
        ReleaseLive();
        _generation++;
        var result = new List<FirewallRuleInfo>(1024);
        dynamic rules = Policy.Rules;
        var index = 0;
        foreach (var item in Enumerate((object)rules))
        {
            if (item is null)
            {
                continue;
            }

            var key = $"{_generation}:{index++}";
            try
            {
                var info = Read(item, key);
                _live[key] = item;
                result.Add(info);
            }
            catch (Exception ex) when (ex is COMException or InvalidCastException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
            {
                // A broken rule must not stop the list.
            }
        }

        return result;
    }

    /// <summary>
    /// INetFwRules is enumerated through IEnumerable (IDispatch DISPID_NEWENUM); if the runtime cannot map that, the
    /// IEnumVARIANT behind _NewEnum is walked directly.
    /// </summary>
    private static IEnumerable<object> Enumerate(object rules)
    {
        List<object> items;
        try
        {
            items = ((System.Collections.IEnumerable)rules).Cast<object>().ToList();
        }
        catch (InvalidCastException)
        {
            items = [];
            dynamic d = rules;
            object raw = d._NewEnum;
            var enumerator = (System.Runtime.InteropServices.ComTypes.IEnumVARIANT)raw;
            var buffer = new object[1];
            while (enumerator.Next(1, buffer, IntPtr.Zero) == 0)
            {
                if (buffer[0] is { } item)
                {
                    items.Add(item);
                }
            }
        }

        return items;
    }

    private static FirewallRuleInfo Read(object comRule, string key)
    {
        dynamic r = comRule;
        int profiles = r.Profiles;
        return new FirewallRuleInfo
        {
            Key = key,
            Name = Str(() => r.Name),
            Description = Str(() => r.Description),
            Program = Str(() => r.ApplicationName),
            Service = Str(() => r.serviceName),
            Direction = (int)r.Direction == 1 ? RuleDirection.Inbound : RuleDirection.Outbound,
            Action = (int)r.Action == 1 ? RuleAction.Allow : RuleAction.Block,
            Enabled = (bool)r.Enabled,
            Profiles = profiles == ProfilesAll ? FirewallProfiles.All : (FirewallProfiles)(profiles & (int)FirewallProfiles.All),
            RemoteAddresses = Str(() => r.RemoteAddresses, "*"),
            Protocol = Int(() => r.Protocol, ProtocolAny),
            LocalPorts = Str(() => r.LocalPorts),
            RemotePorts = Str(() => r.RemotePorts),
            Grouping = Str(() => r.Grouping)
        };
    }

    private static string Str(Func<object?> read, string fallback = "")
    {
        try
        {
            return read() as string ?? fallback;
        }
        catch (Exception ex) when (ex is COMException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            return fallback;
        }
    }

    private static int Int(Func<object?> read, int fallback)
    {
        try
        {
            return read() is int value ? value : fallback;
        }
        catch (Exception ex) when (ex is COMException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            return fallback;
        }
    }

    /// <summary>Profiles of the networks this machine is connected to right now.</summary>
    public FirewallProfiles CurrentProfiles()
    {
        try
        {
            int types = Policy.CurrentProfileTypes;
            return (FirewallProfiles)(types & (int)FirewallProfiles.All);
        }
        catch (COMException)
        {
            return FirewallProfiles.None;
        }
    }

    // ------------------------------------------------------------------ Create

    /// <summary>Rule as created by PortShield (group, marker, literal program path).</summary>
    public sealed record NewRule(string Name, string Program, RuleDirection Direction, RuleAction Action, string RemoteAddresses,
        FirewallProfiles Profiles, bool Enabled, string Description)
    {
        /// <summary>Service short name for svchost rules (null = whole program).</summary>
        public string? Service { get; init; }
    }

    public static NewRule Prepare(RuleDefinition definition, string name, string id) => new(
        name,
        ProgramPaths.Expand(definition.Program),
        definition.Direction,
        definition.Action,
        definition.EffectiveRemoteAddresses,
        definition.Profiles,
        definition.Enabled,
        RuleNaming.WithMarker(string.IsNullOrWhiteSpace(definition.Description) ? RuleNaming.DefaultDescription(definition) : definition.Description, id))
    {
        Service = definition.HasService ? definition.Service!.Trim() : null
    };

    public WriteResult Add(IEnumerable<NewRule> rules, IProgress<int>? progress = null)
    {
        var errors = new List<RuleError>();
        var done = 0;
        dynamic collection = Policy.Rules;
        foreach (var rule in rules)
        {
            try
            {
                dynamic r = Create("HNetCfg.FWRule");
                r.Name = rule.Name;
                r.Description = rule.Description;
                if (!string.IsNullOrEmpty(rule.Program))
                {
                    r.ApplicationName = rule.Program;
                }

                if (!string.IsNullOrEmpty(rule.Service))
                {
                    r.serviceName = rule.Service;
                }

                r.Protocol = ProtocolAny;
                r.Direction = (int)rule.Direction;
                if (!string.IsNullOrEmpty(rule.RemoteAddresses) && rule.RemoteAddresses != "*")
                {
                    r.RemoteAddresses = rule.RemoteAddresses;
                }

                r.Profiles = ToComProfiles(rule.Profiles);
                r.Grouping = RuleNaming.Group;
                r.Action = (int)rule.Action;
                r.Enabled = rule.Enabled;
                collection.Add(r);
                done++;
            }
            catch (Exception ex) when (ex is COMException or ArgumentException or UnauthorizedAccessException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
            {
                errors.Add(new RuleError(rule.Name, Message(ex)));
            }

            progress?.Report(done + errors.Count);
        }

        return new WriteResult(done, errors);
    }

    // ------------------------------------------------------------------ Change

    public WriteResult SetEnabled(IEnumerable<FirewallRuleInfo> rules, bool enabled) =>
        Change(rules, r => r.Enabled = enabled);

    public WriteResult SetAction(IEnumerable<FirewallRuleInfo> rules, RuleAction action) =>
        Change(rules, r => r.Action = (int)action);

    public WriteResult SetRemoteAddresses(IEnumerable<FirewallRuleInfo> rules, string remoteAddresses) =>
        Change(rules, r => r.RemoteAddresses = string.IsNullOrWhiteSpace(remoteAddresses) ? "*" : remoteAddresses);

    public WriteResult SetProfiles(IEnumerable<FirewallRuleInfo> rules, FirewallProfiles profiles) =>
        Change(rules, r => r.Profiles = ToComProfiles(profiles));

    public WriteResult Rename(FirewallRuleInfo rule, string name) =>
        Change([rule], r => r.Name = name);

    /// <summary>Applies a planned update (action, scope, profiles, state) to an existing rule.</summary>
    public WriteResult Update(FirewallRuleInfo rule, RuleDefinition definition) =>
        Change([rule], r =>
        {
            r.Action = (int)definition.Action;
            r.RemoteAddresses = definition.EffectiveRemoteAddresses;
            r.Profiles = ToComProfiles(definition.Profiles);
            r.Enabled = definition.Enabled;
        });

    /// <summary>
    /// Adopts rules of other tools: only the PortShield marker is added to the description (and the name changed when
    /// <paramref name="rename"/> returns one). Group, program, action and scope stay as they are – no duplicate is created.
    /// </summary>
    public WriteResult Adopt(IEnumerable<FirewallRuleInfo> rules, Func<FirewallRuleInfo, string?>? rename = null) =>
        ChangeEach(rules, (r, info) =>
        {
            r.Description = RuleNaming.WithMarker(info.Description, RuleNaming.NewId());
            if (rename?.Invoke(info) is { Length: > 0 } name)
            {
                r.Name = name;
            }
        });

    /// <summary>
    /// Deletes exactly these rules. INetFwRules.Remove works by name and removes only one of several equally named rules,
    /// so each rule first gets a unique temporary name.
    /// </summary>
    public WriteResult Delete(IEnumerable<FirewallRuleInfo> rules)
    {
        var errors = new List<RuleError>();
        var done = 0;
        dynamic collection = Policy.Rules;
        foreach (var rule in rules)
        {
            if (!_live.TryGetValue(rule.Key, out var com))
            {
                errors.Add(new RuleError(rule.Name, "The rule list is out of date – refresh and try again."));
                continue;
            }

            try
            {
                dynamic r = com;
                var temp = "PortShield-delete-" + Guid.NewGuid().ToString("N");
                r.Name = temp;
                collection.Remove(temp);
                _live.Remove(rule.Key);
                done++;
            }
            catch (Exception ex) when (ex is COMException or ArgumentException or UnauthorizedAccessException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
            {
                errors.Add(new RuleError(rule.Name, Message(ex)));
            }
        }

        return new WriteResult(done, errors);
    }

    private WriteResult Change(IEnumerable<FirewallRuleInfo> rules, Action<dynamic> change) =>
        ChangeEach(rules, (r, _) => change(r));

    private WriteResult ChangeEach(IEnumerable<FirewallRuleInfo> rules, Action<dynamic, FirewallRuleInfo> change)
    {
        var errors = new List<RuleError>();
        var done = 0;
        foreach (var rule in rules)
        {
            if (!_live.TryGetValue(rule.Key, out var com))
            {
                errors.Add(new RuleError(rule.Name, "The rule list is out of date – refresh and try again."));
                continue;
            }

            try
            {
                change(com, rule);
                done++;
            }
            catch (Exception ex) when (ex is COMException or ArgumentException or UnauthorizedAccessException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
            {
                errors.Add(new RuleError(rule.Name, Message(ex)));
            }
        }

        return new WriteResult(done, errors);
    }

    // ------------------------------------------------------------------ Kill switch

    /// <summary>
    /// Kill switch: two block rules without a program (outbound and inbound). Block beats every allow rule, so – unlike the
    /// default outbound policy – nothing gets through. <paramref name="lanAllowed"/> limits them to internet addresses, so
    /// LAN shares, printers and remote desktop from the LAN keep working.
    /// </summary>
    public WriteResult SetKillSwitch(IReadOnlyList<FirewallRuleInfo> current, bool on, bool lanAllowed)
    {
        var existing = current.Where(r => r.IsKillSwitch).ToList();
        if (!on)
        {
            return Delete(existing);
        }

        // Replace (the mode may have changed).
        var removed = Delete(existing);
        var id = RuleNaming.NewId();
        var addresses = lanAllowed ? InternetRanges.All : "*";
        var description = RuleNaming.WithMarker(lanAllowed
            ? "PortShield kill switch: blocks all internet traffic, LAN stays reachable."
            : "PortShield kill switch: blocks all network traffic.", id);
        var added = Add(
        [
            new NewRule(RuleNaming.KillSwitchName + " · Out", "", RuleDirection.Outbound, RuleAction.Block, addresses, FirewallProfiles.All, true, description),
            new NewRule(RuleNaming.KillSwitchName + " · In", "", RuleDirection.Inbound, RuleAction.Block, addresses, FirewallProfiles.All, true, description)
        ]);
        return new WriteResult(added.Succeeded, removed.Errors.Concat(added.Errors).ToList());
    }

    // ------------------------------------------------------------------ Helpers

    private static int ToComProfiles(FirewallProfiles profiles)
    {
        var p = profiles & FirewallProfiles.All;
        return p is FirewallProfiles.All or FirewallProfiles.None ? ProfilesAll : (int)p;
    }

    private static string Message(Exception ex) => ex switch
    {
        UnauthorizedAccessException => "Access denied – PortShield needs administrator rights.",
        COMException com when com.HResult == unchecked((int)0x80070005) => "Access denied – PortShield needs administrator rights.",
        COMException com when com.HResult == unchecked((int)0x80070057) => "Windows rejected a value of this rule (invalid parameter).",
        _ => ex.Message
    };

    private void ReleaseLive()
    {
        foreach (var com in _live.Values)
        {
            try
            {
                Marshal.ReleaseComObject(com);
            }
            catch (ArgumentException)
            {
                // Not a COM object.
            }
        }

        _live.Clear();
    }

    public void Dispose()
    {
        ReleaseLive();
        if (_policy is not null)
        {
            Marshal.ReleaseComObject(_policy);
            _policy = null;
        }
    }
}
