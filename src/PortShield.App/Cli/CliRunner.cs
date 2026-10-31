using System.Runtime.InteropServices;
using System.Text.Json;
using PortShield.App.Services;
using PortShield.Core.Export;
using PortShield.Core.Import;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.RuleSets;
using PortShield.Core.Storage;
using PortShield.Platform.Windows;

namespace PortShield.App.Cli;

/// <summary>
/// Command line without a window – for scripts, deployment and the uninstaller. Bulk changes (--apply, --import,
/// --remove-all) only write with --confirm; without it they show what would happen.
/// Exit codes: 0 success, 1 errors or nothing done, 2 invalid arguments.
/// </summary>
public static class CliRunner
{
    public const string UsageText =
        """
        PortShield command line

          PortShield.exe --status                          firewall profiles, policy, kill switch, rule counts
          PortShield.exe --list [--all] [--json]           PortShield rules (--all: all program rules)
          PortShield.exe --block <program.exe> [...]       block programs (default: outbound)
          PortShield.exe --allow <program.exe> [...]       allow programs
          PortShield.exe --unblock <program.exe> [...]     remove PortShield's rules of these programs
          PortShield.exe --apply <ruleset.json> [--confirm]
          PortShield.exe --import <file.json|csv|txt> [--confirm]
          PortShield.exe --export <file> [--format <format>] [--all] [--literal-paths] [--hashes]
          PortShield.exe --snapshot [--note <text>]
          PortShield.exe --kill-switch on|off [--full]
          PortShield.exe --remove-all --confirm            delete every PortShield rule
          PortShield.exe --restore-temporary [--all]       block temporarily allowed rules again (due ones, or all)
          PortShield.exe --register-shell | --unregister-shell
                                                           Explorer context menu "Block with PortShield"
          PortShield.exe --help                            this help

        Options for --block, --allow and plain text lists
          --inbound | --both     direction (default: outbound)
          --internet             internet only – LAN, loopback and multicast stay reachable
          --profiles <list>      domain,private,public (default: all)

        Export formats
          json (PortShield rule set) · csv · txt (paths) · hashes (SHA-256) · ps1 (PowerShell) · cmd (netsh) · md · html · xml
          Default: taken from the file extension.

        Exit codes: 0 success · 1 errors or nothing done · 2 invalid arguments
        """;

    private static readonly string[] Commands =
    [
        "--status", "--list", "--block", "--allow", "--unblock", "--apply", "--import", "--export", "--snapshot", "--kill-switch",
        "--remove-all", "--restore-temporary", "--register-shell", "--unregister-shell", "--help", "-h", "-?", "/?"
    ];

    public static bool IsCliCall(string[] args) => args.Any(a => Commands.Contains(a, StringComparer.OrdinalIgnoreCase));

    public static int Run(string[] args)
    {
        AttachToParentConsole();
        try
        {
            if (args.Any(x => x is "--help" or "-h" or "-?" or "/?"))
            {
                Console.WriteLine(UsageText);
                return 0;
            }

            if (!OperatingSystem.IsWindows())
            {
                Console.Error.WriteLine("PortShield needs Windows.");
                return 1;
            }

            return Execute(new Arguments(args));
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            Console.Error.WriteLine("PortShield.exe --help shows all commands.");
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
            return 1;
        }
    }

    private static int Execute(Arguments a)
    {
        if (a.Has("--help") || a.Has("-h") || a.Has("-?") || a.Has("/?"))
        {
            Console.WriteLine(UsageText);
            return 0;
        }

        if (!SystemInfo.IsElevated())
        {
            Console.Error.WriteLine("PortShield needs administrator rights (start the console as administrator).");
            return 1;
        }

        var ui = UiSettings.Load();
        using var store = new FirewallStore();
        _store = store;
        var rules = store.Load();

        if (a.Has("--restore-temporary"))
        {
            var pending = RuleGuard.LoadTemporary().Entries.Select(e => e.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
            _touched = rules.Where(r => r.PortShieldId is { } id && pending.Contains(id)).ToList();
            var restored = RuleGuard.RestoreTemporary(store, rules, a.Has("--all"));
            return Report(restored, "blocked again");
        }

        if (a.Has("--status"))
        {
            return Status(store, rules);
        }

        if (a.Has("--list"))
        {
            return List(rules, a.Has("--all"), a.Has("--json"));
        }

        if (a.Has("--block") || a.Has("--allow"))
        {
            var action = a.Has("--allow") ? RuleAction.Allow : RuleAction.Block;
            var paths = a.Values(action == RuleAction.Allow ? "--allow" : "--block");
            if (paths.Count == 0)
            {
                throw new ArgumentException("No program given.");
            }

            var defaults = Defaults(a, action);
            var definitions = paths.SelectMany(p => RulePlanner.Directions(defaults.Direction).Select(d => new RuleDefinition
            {
                Program = Path.GetFullPath(ProgramPaths.Expand(p)),
                Direction = d,
                Action = action,
                Scope = defaults.Scope,
                Profiles = defaults.Profiles
            })).ToList();
            return Apply(store, rules, ui, definitions, confirm: true);
        }

        if (a.Has("--unblock"))
        {
            var keys = a.Values("--unblock").Select(p => ProgramPaths.Key(Path.GetFullPath(ProgramPaths.Expand(p)))).ToHashSet();
            var matches = rules.Where(r => r.IsPortShield && r.HasProgram && keys.Contains(ProgramPaths.Key(r.Program))).ToList();
            if (matches.Count == 0)
            {
                Console.WriteLine("No PortShield rules for these programs.");
                return 1;
            }

            _touched = matches;
            return Report(store.Delete(matches), "removed");
        }

        if (a.Has("--apply"))
        {
            var file = a.Value("--apply") ?? throw new ArgumentException("--apply needs a rule set file.");
            var set = RuleSet.Load(file);
            Console.WriteLine($"Rule set: {set.Name} ({set.Rules.Count} entries)");
            return Apply(store, rules, ui, FirewallService.Resolve(set.Rules), a.Has("--confirm"), SnapshotReason.BeforeRuleSet);
        }

        if (a.Has("--import"))
        {
            var file = a.Value("--import") ?? throw new ArgumentException("--import needs a file.");
            var result = RuleImporter.ImportFile(file, Defaults(a, RuleAction.Block));
            foreach (var warning in result.Warnings)
            {
                Console.WriteLine("  ! " + warning);
            }

            return Apply(store, rules, ui, FirewallService.Resolve(result.Rules), a.Has("--confirm"), SnapshotReason.BeforeImport);
        }

        if (a.Has("--export"))
        {
            return Export(a, rules);
        }

        if (a.Has("--snapshot"))
        {
            var snapshot = SnapshotManager.Create(SnapshotReason.Manual, rules, AppEnvironment.Version, a.Value("--note"));
            Console.WriteLine($"Snapshot: {snapshot.Directory} ({snapshot.PortShieldRules} PortShield rules, policy: {(snapshot.HasPolicy ? "yes" : "no")})");
            return 0;
        }

        if (a.Has("--kill-switch"))
        {
            var mode = a.Value("--kill-switch")?.ToLowerInvariant();
            if (mode is not ("on" or "off"))
            {
                throw new ArgumentException("--kill-switch needs on or off.");
            }

            return Report(store.SetKillSwitch(rules, mode == "on", lanAllowed: !a.Has("--full")), mode == "on" ? "created" : "removed");
        }

        if (a.Has("--remove-all"))
        {
            var own = rules.Where(r => r.IsPortShield).ToList();
            if (!a.Has("--confirm"))
            {
                Console.WriteLine($"{own.Count} PortShield rule(s) would be removed. Add --confirm to remove them.");
                return 1;
            }

            if (own.Count == 0)
            {
                Console.WriteLine("No PortShield rules.");
                return 0;
            }

            if (ui.SnapshotBeforeChanges)
            {
                SnapshotManager.Create(SnapshotReason.BeforeDelete, rules, AppEnvironment.Version, "Command line --remove-all");
            }

            _touched = null;
            return Report(store.Delete(own), "removed");
        }

        if (a.Has("--register-shell"))
        {
            ShellIntegration.Register(AppEnvironment.ExecutablePath, "Block with PortShield", "Block programs in this folder with PortShield");
            Console.WriteLine("Explorer context menu registered.");
            return 0;
        }

        if (a.Has("--unregister-shell"))
        {
            ShellIntegration.Unregister();
            Console.WriteLine("Explorer context menu removed.");
            return 0;
        }

        throw new ArgumentException("Unknown command.");
    }

    // ------------------------------------------------------------------ Commands

    private static int Status(FirewallStore store, IReadOnlyList<FirewallRuleInfo> rules)
    {
        var status = FirewallPolicy.Read(store.CurrentProfiles());
        Console.WriteLine($"Firewall service: {(status.ServiceRunning ? "running" : "STOPPED")}");
        foreach (var p in status.Profiles)
        {
            Console.WriteLine($"  {p.Profile,-8} {(p.Enabled ? "on " : "OFF")}  outbound default: {(p.BlockOutboundByDefault ? "block" : "allow")}" +
                              $"{(p.IsActive ? "  [active]" : "")}{(p.EnabledByPolicy || p.OutboundByPolicy ? "  [group policy]" : "")}{(p.LocalRulesIgnored ? "  [LOCAL RULES IGNORED]" : "")}");
        }

        Console.WriteLine($"Domain: {(status.DomainJoined ? status.DomainName : "–")} · group policy: {(status.ManagedByPolicy ? $"yes ({status.PolicyRuleCount} rules)" : "no")}");
        foreach (var product in status.Products.Where(p => p.Enabled && !p.IsWindowsFirewall))
        {
            Console.WriteLine($"Other firewall active: {product.Name}");
        }

        var own = rules.Where(r => r.IsPortShield && !r.IsKillSwitch).ToList();
        Console.WriteLine($"Kill switch: {(rules.Any(r => r.IsKillSwitch && r.Enabled) ? "ON" : "off")} · whitelist mode: {(status.WhitelistMode ? "on" : "off")}");
        Console.WriteLine($"PortShield rules: {own.Count} (blocked: {own.Count(r => r.Action == RuleAction.Block)}, allowed: {own.Count(r => r.Action == RuleAction.Allow)}) · all rules: {rules.Count}");
        return 0;
    }

    private static int List(IReadOnlyList<FirewallRuleInfo> rules, bool all, bool json)
    {
        var list = rules.Where(r => all ? r.HasProgram : r.IsPortShield).OrderBy(r => r.Direction).ThenBy(r => r.Name).ToList();
        if (json)
        {
            var rows = list.Select(r => new
            {
                r.Name,
                Program = r.ExpandedProgram,
                Direction = r.Direction.ToString(),
                Action = r.Action.ToString(),
                Scope = r.Scope.ToString(),
                Profiles = RuleExporter.ProfilesText(r.Profiles),
                r.Enabled,
                r.IsPortShield
            });
            Console.WriteLine(JsonSerializer.Serialize(rows, PortShieldJson.Options));
            return 0;
        }

        foreach (var r in list)
        {
            Console.WriteLine($"{(r.Direction == RuleDirection.Outbound ? "OUT" : "IN "),-4}{(r.Action == RuleAction.Block ? "block" : "allow"),-6}{(r.Enabled ? "" : "(off) ")}" +
                              $"{(r.Scope == RuleScope.Internet ? "[internet] " : "")}{r.Name}  ->  {r.ExpandedProgram}");
        }

        Console.WriteLine($"{list.Count} rule(s).");
        return 0;
    }

    private static int Apply(FirewallStore store, IReadOnlyList<FirewallRuleInfo> rules, UiSettings ui, IReadOnlyList<RuleDefinition> definitions, bool confirm,
        SnapshotReason? snapshot = null)
    {
        var plan = RulePlanner.Plan(rules, definitions, new RulePlanner.Options
        {
            OwnExecutable = AppEnvironment.ExecutablePath,
            ProtectedPaths = ui.ProtectedPaths,
            FileExists = File.Exists
        });

        foreach (var item in plan)
        {
            Console.WriteLine($"  {item.Action,-10} {(item.Definition.Direction == RuleDirection.Outbound ? "OUT" : "IN "),-4}{item.Definition.Action,-6} {item.Definition.Program}" +
                              (item.BlockedByOtherRule ? "   (another rule blocks this program – block wins)" : ""));
        }

        var changes = plan.Where(p => p.WillChange).ToList();
        if (changes.Count == 0)
        {
            Console.WriteLine("Nothing to change.");
            return 1;
        }

        if (!confirm)
        {
            Console.WriteLine($"{changes.Count} change(s). Add --confirm to write them.");
            return 1;
        }

        if (snapshot is not null && ui.SnapshotBeforeChanges)
        {
            SnapshotManager.Create(snapshot.Value, rules, AppEnvironment.Version, "Command line");
            SnapshotManager.Prune(ui.SnapshotKeep);
        }

        var errors = new List<RuleError>();
        var done = 0;
        var create = changes.Where(c => c.Action == PlanAction.Create)
            .Select(c => FirewallStore.Prepare(c.Definition, FirewallService.NameFor(c.Definition, ui.NamePrefix), RuleNaming.NewId())).ToList();
        var added = store.Add(create);
        done += added.Succeeded;
        errors.AddRange(added.Errors);
        foreach (var update in changes.Where(c => c.Action == PlanAction.Update && c.Existing is not null))
        {
            var result = store.Update(update.Existing!, update.Definition);
            done += result.Succeeded;
            errors.AddRange(result.Errors);
        }

        _touched = changes.Where(c => c.Action == PlanAction.Update && c.Existing is not null).Select(c => c.Existing!).ToList();
        return Report(new WriteResult(done, errors), "written");
    }

    private static int Export(Arguments a, IReadOnlyList<FirewallRuleInfo> rules)
    {
        var file = a.Value("--export") ?? throw new ArgumentException("--export needs a file name.");
        var format = ParseFormat(a.Value("--format"), file);
        var list = rules.Where(r => !r.IsKillSwitch && (a.Has("--all") ? r.HasProgram : r.IsPortShield)).ToList();
        var hashes = RuleExporter.NeedsHashes(format) || a.Has("--hashes");
        var items = list.Select(r =>
        {
            var facts = r.HasProgram ? FileInspector.Read(r.ExpandedProgram) : FileFacts.Missing;
            return new ExportItem(RuleDefinition.FromRule(r), r.Name, facts.Exists, hashes && facts.Exists ? FileInspector.Sha256(r.ExpandedProgram) : null, facts.Company);
        }).ToList();
        var text = RuleExporter.Export(format, items, new ExportOptions
        {
            PortablePaths = !a.Has("--literal-paths"),
            Generator = AppEnvironment.Generator,
            Machine = Environment.MachineName
        });
        File.WriteAllText(file, text, RuleExporter.EncodingFor(format));
        Console.WriteLine($"{items.Count} rule(s) exported to {Path.GetFullPath(file)} ({format}).");
        return 0;
    }

    private static ExportFormat ParseFormat(string? format, string file) =>
        (format ?? Path.GetExtension(file).TrimStart('.')).ToLowerInvariant() switch
        {
            "json" => ExportFormat.PortShieldJson,
            "csv" => ExportFormat.Csv,
            "txt" or "paths" => ExportFormat.TextPaths,
            "hashes" or "sha256" => ExportFormat.TextHashes,
            "ps1" or "powershell" => ExportFormat.PowerShell,
            "cmd" or "bat" or "netsh" => ExportFormat.Netsh,
            "md" or "markdown" => ExportFormat.Markdown,
            "html" or "htm" => ExportFormat.Html,
            "xml" => ExportFormat.Xml,
            var other => throw new ArgumentException($"Unknown export format \"{other}\".")
        };

    private static ImportDefaults Defaults(Arguments a, RuleAction action) => new()
    {
        Direction = a.Has("--both") ? DirectionChoice.Both : a.Has("--inbound") ? DirectionChoice.Inbound : DirectionChoice.Outbound,
        Action = action,
        Scope = a.Has("--internet") ? RuleScope.Internet : RuleScope.All,
        Profiles = RuleImporter.ParseProfiles(a.Value("--profiles")) ?? FirewallProfiles.All
    };

    /// <summary>Store of the running command – changes are recorded for the app's integrity check.</summary>
    private static FirewallStore? _store;

    /// <summary>Rules the running command wrote (null = all; empty = only new rules, e.g. the kill switch).</summary>
    private static IReadOnlyList<FirewallRuleInfo>? _touched = [];

    private static int Report(WriteResult result, string verb)
    {
        if (_store is not null && result.Succeeded > 0)
        {
            // Rules not written by this command keep their pending integrity reports.
            RuleGuard.Commit(_store.Load(), _touched);
        }

        foreach (var error in result.Errors)
        {
            Console.Error.WriteLine($"  ! {error.Rule}: {error.Message}");
        }

        Console.WriteLine($"{result.Succeeded} rule(s) {verb}" + (result.HasErrors ? $", {result.Errors.Count} error(s)." : "."));
        return result.HasErrors ? 1 : 0;
    }

    // ------------------------------------------------------------------ Arguments

    private sealed class Arguments(string[] args)
    {
        public bool Has(string flag) => args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

        public string? Value(string flag)
        {
            var index = Array.FindIndex(args, a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));
            return index >= 0 && index + 1 < args.Length && !args[index + 1].StartsWith("--", StringComparison.Ordinal) ? args[index + 1] : null;
        }

        /// <summary>All values after the flag up to the next option.</summary>
        public IReadOnlyList<string> Values(string flag)
        {
            var index = Array.FindIndex(args, a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));
            var result = new List<string>();
            for (var i = index + 1; index >= 0 && i < args.Length && !args[i].StartsWith("--", StringComparison.Ordinal); i++)
            {
                result.Add(args[i]);
            }

            return result;
        }
    }

    /// <summary>PortShield is a window app; output goes to the console it was started from.</summary>
    private static void AttachToParentConsole()
    {
        if (!OperatingSystem.IsWindows() || !Native.AttachConsole(-1))
        {
            return;
        }

        try
        {
            if (!Console.IsOutputRedirected)
            {
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            }

            if (!Console.IsErrorRedirected)
            {
                Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
            }

            Console.WriteLine();
        }
        catch (Exception)
        {
            // No console available.
        }
    }

    private static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AttachConsole(int processId);
    }
}
