using System.Globalization;
using System.Net;
using System.Text;
using System.Xml;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.RuleSets;

namespace PortShield.Core.Export;

/// <summary>Export formats. Machine formats (JSON, CSV, scripts, XML) are always written in English.</summary>
public enum ExportFormat
{
    /// <summary>PortShield rule set – lossless, re-importable, works with wildcards and variables.</summary>
    PortShieldJson,

    /// <summary>Table for Excel, inventories and tickets (also re-importable).</summary>
    Csv,

    /// <summary>One program path per line – for allow/block lists of other security products.</summary>
    TextPaths,

    /// <summary>One SHA-256 per line – for hash block lists (EDR/AV indicators, application control).</summary>
    TextHashes,

    /// <summary>Idempotent New-NetFirewallRule script, optionally into a GPO store.</summary>
    PowerShell,

    /// <summary>netsh advfirewall batch file (legacy systems, Server Core).</summary>
    Netsh,

    /// <summary>Readable report.</summary>
    Markdown,

    /// <summary>Standalone report page (dark and light).</summary>
    Html,

    /// <summary>Generic XML for other tools.</summary>
    Xml
}

/// <summary>One rule with the file facts known at export time.</summary>
public sealed record ExportItem(RuleDefinition Rule, string Name, bool FileExists, string? Sha256, string? Publisher)
{
    public string ExpandedProgram => ProgramPaths.Expand(Rule.Program);
}

public sealed record ExportOptions
{
    /// <summary>Write %ProgramFiles% … instead of literal paths (recommended for other machines).</summary>
    public bool PortablePaths { get; init; } = true;

    public char CsvDelimiter { get; init; } = ';';

    public string Title { get; init; } = "PortShield rules";

    /// <summary>"PortShield 0.0.1".</summary>
    public string Generator { get; init; } = "PortShield";

    public string? Machine { get; init; }

    public DateTime Created { get; init; } = DateTime.Now;
}

/// <summary>Writes rules in all export formats.</summary>
public static class RuleExporter
{
    public static IReadOnlyList<ExportFormat> All { get; } = Enum.GetValues<ExportFormat>();

    public static string Extension(ExportFormat format) => format switch
    {
        ExportFormat.PortShieldJson => "json",
        ExportFormat.Csv => "csv",
        ExportFormat.TextPaths => "txt",
        ExportFormat.TextHashes => "txt",
        ExportFormat.PowerShell => "ps1",
        ExportFormat.Netsh => "cmd",
        ExportFormat.Markdown => "md",
        ExportFormat.Html => "html",
        ExportFormat.Xml => "xml",
        _ => "txt"
    };

    /// <summary>Suggested file name: portshield-rules-20261031.csv, portshield-hashes-20261031.txt.</summary>
    public static string SuggestedFileName(ExportFormat format, DateTime date)
    {
        var kind = format switch
        {
            ExportFormat.TextPaths => "paths",
            ExportFormat.TextHashes => "hashes",
            ExportFormat.PowerShell or ExportFormat.Netsh => "apply",
            ExportFormat.Markdown or ExportFormat.Html => "report",
            _ => "rules"
        };
        return $"portshield-{kind}-{date.ToString("yyyyMMdd", CultureInfo.InvariantCulture)}.{Extension(format)}";
    }

    /// <summary>Formats that need the SHA-256 of every program (computed before exporting).</summary>
    public static bool NeedsHashes(ExportFormat format) => format == ExportFormat.TextHashes;

    /// <summary>Formats that show hashes when they were computed.</summary>
    public static bool CanIncludeHashes(ExportFormat format) =>
        format is ExportFormat.TextHashes or ExportFormat.Csv or ExportFormat.PortShieldJson or ExportFormat.Html or ExportFormat.Markdown or ExportFormat.Xml;

    public static string Export(ExportFormat format, IReadOnlyList<ExportItem> items, ExportOptions? options = null)
    {
        options ??= new ExportOptions();
        return format switch
        {
            ExportFormat.PortShieldJson => Json(items, options),
            ExportFormat.Csv => Csv(items, options),
            ExportFormat.TextPaths => TextPaths(items, options),
            ExportFormat.TextHashes => TextHashes(items),
            ExportFormat.PowerShell => PowerShell(items, options),
            ExportFormat.Netsh => Netsh(items, options),
            ExportFormat.Markdown => Markdown(items, options),
            ExportFormat.Html => Html(items, options),
            ExportFormat.Xml => Xml(items, options),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };
    }

    /// <summary>UTF-8 with BOM for CSV (Excel detects the encoding), without BOM for everything else.</summary>
    public static Encoding EncodingFor(ExportFormat format) => format switch
    {
        ExportFormat.Csv => new UTF8Encoding(true),
        // Windows PowerShell 5.1 reads BOM-less scripts as ANSI – umlauts in paths would break.
        ExportFormat.PowerShell => new UTF8Encoding(true),
        _ => new UTF8Encoding(false)
    };

    // ------------------------------------------------------------------ Helpers

    private static string PathOf(ExportItem item, ExportOptions options) =>
        options.PortablePaths ? ProgramPaths.ToPortable(item.Rule.Program) : item.ExpandedProgram;

    public static string ProfilesText(FirewallProfiles profiles)
    {
        var p = profiles & FirewallProfiles.All;
        if (p is FirewallProfiles.All or FirewallProfiles.None)
        {
            return "All";
        }

        var parts = new List<string>();
        if (p.HasFlag(FirewallProfiles.Domain))
        {
            parts.Add("Domain");
        }

        if (p.HasFlag(FirewallProfiles.Private))
        {
            parts.Add("Private");
        }

        if (p.HasFlag(FirewallProfiles.Public))
        {
            parts.Add("Public");
        }

        return string.Join("|", parts);
    }

    private static string DirectionText(RuleDirection direction) => direction == RuleDirection.Outbound ? "Outbound" : "Inbound";

    private static string ScopeAddresses(RuleDefinition rule) => rule.Scope switch
    {
        RuleScope.Internet => "Internet",
        RuleScope.Custom => rule.RemoteAddresses ?? "*",
        _ => "*"
    };

    private static string Stamp(ExportOptions options) => options.Created.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    // ------------------------------------------------------------------ JSON

    private static string Json(IReadOnlyList<ExportItem> items, ExportOptions options)
    {
        var set = new RuleSet
        {
            Name = options.Title,
            Description = $"Exported from {options.Machine ?? "this PC"} on {Stamp(options)}.",
            Created = options.Created,
            Generator = options.Generator,
            Rules = items.Select(i => i.Rule with
            {
                Name = i.Name,
                Program = PathOf(i, options),
                Sha256 = i.Sha256 ?? i.Rule.Sha256,
                Publisher = i.Publisher ?? i.Rule.Publisher
            }).ToList()
        };
        return set.ToJson();
    }

    // ------------------------------------------------------------------ CSV

    public static readonly string[] CsvColumns =
        ["Name", "Program", "Service", "Direction", "Action", "Scope", "RemoteAddresses", "Profiles", "Enabled", "Publisher", "SHA256", "FileExists"];

    private static string Csv(IReadOnlyList<ExportItem> items, ExportOptions options)
    {
        var d = options.CsvDelimiter;
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(d, CsvColumns));
        foreach (var item in items)
        {
            var r = item.Rule;
            string[] fields =
            [
                item.Name,
                PathOf(item, options),
                r.Service ?? "",
                DirectionText(r.Direction),
                r.Action.ToString(),
                r.Scope.ToString(),
                ScopeAddresses(r),
                ProfilesText(r.Profiles),
                r.Enabled ? "true" : "false",
                item.Publisher ?? r.Publisher ?? "",
                item.Sha256 ?? r.Sha256 ?? "",
                item.FileExists ? "true" : "false"
            ];
            sb.AppendLine(string.Join(d, fields.Select(f => CsvField(f, d))));
        }

        return sb.ToString();
    }

    public static string CsvField(string value, char delimiter)
    {
        // Formula injection: a leading = + - @ would run as a formula in Excel.
        var safe = value.Length > 0 && value[0] is '=' or '+' or '-' or '@' ? "'" + value : value;
        return safe.IndexOfAny([delimiter, '"', '\r', '\n']) >= 0 ? "\"" + safe.Replace("\"", "\"\"") + "\"" : safe;
    }

    // ------------------------------------------------------------------ TXT

    private static string TextPaths(IReadOnlyList<ExportItem> items, ExportOptions options) =>
        string.Join(Environment.NewLine, items
            .Select(i => PathOf(i, options))
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)) + Environment.NewLine;

    private static string TextHashes(IReadOnlyList<ExportItem> items) =>
        string.Join(Environment.NewLine, items
            .Select(i => i.Sha256 ?? i.Rule.Sha256)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(h => h!.ToLowerInvariant())
            .Distinct()) + Environment.NewLine;

    // ------------------------------------------------------------------ PowerShell

    private static string Ps(string value) => "'" + value.Replace("'", "''") + "'";

    private static string PsProfile(FirewallProfiles profiles) =>
        ProfilesText(profiles) == "All" ? "Any" : ProfilesText(profiles).Replace('|', ',');

    private static string PowerShell(IReadOnlyList<ExportItem> items, ExportOptions options)
    {
        var sb = new StringBuilder();
        sb.AppendLine("#Requires -RunAsAdministrator");
        sb.AppendLine("<#");
        sb.AppendLine($"    {options.Title} – generated by {options.Generator} on {Stamp(options)}" + (options.Machine is null ? "" : $" ({options.Machine})"));
        sb.AppendLine($"    {items.Count} rule(s). Creates missing rules, updates existing ones (same display name), -Remove deletes them.");
        sb.AppendLine();
        sb.AppendLine("    .\\portshield-apply.ps1                                     # local firewall");
        sb.AppendLine("    .\\portshield-apply.ps1 -PolicyStore 'contoso.local\\Firewall Workstations'   # group policy object");
        sb.AppendLine("    .\\portshield-apply.ps1 -Remove                             # delete these rules again");
        sb.AppendLine("#>");
        sb.AppendLine("[CmdletBinding()]");
        sb.AppendLine("param(");
        sb.AppendLine("    # Target store: empty = local (PersistentStore), or a GPO as 'domain\\GPO name'.");
        sb.AppendLine("    [string] $PolicyStore,");
        sb.AppendLine("    [switch] $Remove");
        sb.AppendLine(")");
        sb.AppendLine();
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("# Internet only: everything except LAN (RFC 1918), loopback, link-local and multicast.");
        sb.AppendLine("$internet = @(" + string.Join(", ", InternetRanges.Items.Select(Ps)) + ")");
        sb.AppendLine();
        sb.AppendLine("$rules = @(");
        for (var i = 0; i < items.Count; i++)
        {
            var item = items[i];
            var r = item.Rule;
            var remote = r.Scope switch
            {
                RuleScope.Internet => "$internet",
                RuleScope.Custom => "@(" + string.Join(", ", (r.RemoteAddresses ?? "Any").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(Ps)) + ")",
                _ => "'Any'"
            };
            var description = string.IsNullOrWhiteSpace(r.Description) ? RuleNaming.DefaultDescription(r) : r.Description!;
            sb.Append("    @{ ")
                .Append("DisplayName = ").Append(Ps(item.Name)).Append("; ")
                .Append("Program = ").Append(Ps(PathOf(item, options))).Append("; ")
                .Append("Service = ").Append(Ps(r.Service ?? "")).Append("; ")
                .Append("Direction = ").Append(Ps(DirectionText(r.Direction))).Append("; ")
                .Append("Action = ").Append(Ps(r.Action.ToString())).Append("; ")
                .Append("RemoteAddress = ").Append(remote).Append("; ")
                .Append("Profile = ").Append(Ps(PsProfile(r.Profiles))).Append("; ")
                .Append("Enabled = ").Append(Ps(r.Enabled ? "True" : "False")).Append("; ")
                .Append("Description = ").Append(Ps(description))
                .AppendLine(i == items.Count - 1 ? " }" : " },");
        }

        sb.AppendLine(")");
        sb.AppendLine();
        sb.AppendLine("$store = @{}");
        sb.AppendLine("if ($PolicyStore) { $store.PolicyStore = $PolicyStore }");
        sb.AppendLine("$created = 0; $updated = 0; $removed = 0");
        sb.AppendLine("foreach ($rule in $rules) {");
        sb.AppendLine("    # In a GPO the path stays as written (variables are resolved on the target machine).");
        sb.AppendLine("    $program = if ($PolicyStore) { $rule.Program } else { [Environment]::ExpandEnvironmentVariables($rule.Program) }");
        sb.AppendLine("    $existing = @(Get-NetFirewallRule -DisplayName ([WildcardPattern]::Escape($rule.DisplayName)) @store -ErrorAction SilentlyContinue)");
        sb.AppendLine("    if ($Remove) {");
        sb.AppendLine("        if ($existing.Count -gt 0) { $existing | Remove-NetFirewallRule; $removed++ }");
        sb.AppendLine("        continue");
        sb.AppendLine("    }");
        sb.AppendLine("    if ($existing.Count -gt 0) {");
        sb.AppendLine("        $existing | Set-NetFirewallRule -Action $rule.Action -Enabled $rule.Enabled -Profile $rule.Profile -RemoteAddress $rule.RemoteAddress");
        sb.AppendLine("        $updated++");
        sb.AppendLine("    }");
        sb.AppendLine("    else {");
        sb.AppendLine("        $service = @{}");
        sb.AppendLine("        if ($rule.Service) { $service.Service = $rule.Service }");
        sb.AppendLine("        New-NetFirewallRule -DisplayName $rule.DisplayName -Group 'PortShield' -Program $program -Direction $rule.Direction `");
        sb.AppendLine("            -Action $rule.Action -RemoteAddress $rule.RemoteAddress -Profile $rule.Profile -Enabled $rule.Enabled `");
        sb.AppendLine("            -Description $rule.Description @service @store | Out-Null");
        sb.AppendLine("        $created++");
        sb.AppendLine("    }");
        sb.AppendLine("}");
        sb.AppendLine("Write-Host \"PortShield: $created created, $updated updated, $removed removed.\"");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ netsh

    private static string Cmd(string value) => value.Replace("\"", "'").Replace("%", "%%");

    /// <summary>Paths keep their %Variables% so cmd.exe resolves them on the target machine.</summary>
    private static string CmdPath(string value) => value.Replace("\"", "'");

    private static string Netsh(IReadOnlyList<ExportItem> items, ExportOptions options)
    {
        var sb = new StringBuilder();
        sb.AppendLine("@echo off");
        sb.AppendLine($"rem {Cmd(options.Title)} - generated by {Cmd(options.Generator)} on {Stamp(options)}");
        sb.AppendLine($"rem {items.Count} rule(s). Run as administrator. Existing rules with the same name are replaced.");
        sb.AppendLine("net session >nul 2>&1 || (echo Please run this file as administrator. & exit /b 1)");
        sb.AppendLine();
        foreach (var item in items)
        {
            var r = item.Rule;
            var name = Cmd(item.Name);
            var dir = r.Direction == RuleDirection.Outbound ? "out" : "in";
            var remote = r.Scope switch
            {
                RuleScope.Internet => InternetRanges.All,
                RuleScope.Custom => r.RemoteAddresses ?? "any",
                _ => "any"
            };
            var profile = ProfilesText(r.Profiles) == "All" ? "any" : ProfilesText(r.Profiles).Replace('|', ',').ToLowerInvariant();
            var description = Cmd(string.IsNullOrWhiteSpace(r.Description) ? RuleNaming.DefaultDescription(r) : r.Description!);
            sb.AppendLine($"netsh advfirewall firewall delete rule name=\"{name}\" dir={dir} >nul 2>&1");
            sb.AppendLine($"netsh advfirewall firewall add rule name=\"{name}\" dir={dir} action={r.Action.ToString().ToLowerInvariant()} " +
                          $"program=\"{CmdPath(PathOf(item, options))}\" {(r.HasService ? "service=\"" + Cmd(r.Service!) + "\" " : "")}enable={(r.Enabled ? "yes" : "no")} profile={profile} remoteip={remote} " +
                          $"description=\"{description}\" >nul");
        }

        sb.AppendLine();
        sb.AppendLine("echo PortShield: done.");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ Markdown

    private static string Md(string value) => value.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");

    private static string Markdown(IReadOnlyList<ExportItem> items, ExportOptions options)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# {Md(options.Title)}");
        sb.AppendLine();
        sb.AppendLine($"Generated by {options.Generator} on {Stamp(options)}" + (options.Machine is null ? "." : $" on **{Md(options.Machine)}**."));
        sb.AppendLine();
        sb.AppendLine($"- Rules: **{items.Count}** · blocked: **{items.Count(i => i.Rule.Action == RuleAction.Block)}** · allowed: **{items.Count(i => i.Rule.Action == RuleAction.Allow)}**");
        sb.AppendLine($"- Outbound: {items.Count(i => i.Rule.Direction == RuleDirection.Outbound)} · inbound: {items.Count(i => i.Rule.Direction == RuleDirection.Inbound)} · disabled: {items.Count(i => !i.Rule.Enabled)}");
        sb.AppendLine();
        sb.AppendLine("| Name | Direction | Action | Scope | Enabled | Program | Service | Publisher | SHA-256 |");
        sb.AppendLine("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
        foreach (var item in items)
        {
            var r = item.Rule;
            sb.AppendLine($"| {Md(item.Name)} | {DirectionText(r.Direction)} | {r.Action} | {r.Scope} | {(r.Enabled ? "yes" : "no")} | `{Md(PathOf(item, options))}` | {Md(r.Service ?? "")} | {Md(item.Publisher ?? "")} | {(item.Sha256 is null ? "" : "`" + item.Sha256 + "`")} |");
        }

        return sb.ToString();
    }

    // ------------------------------------------------------------------ HTML

    private static string H(string? value) => WebUtility.HtmlEncode(value ?? "");

    private static string Html(IReadOnlyList<ExportItem> items, ExportOptions options)
    {
        var blocked = items.Count(i => i.Rule.Action == RuleAction.Block);
        var sb = new StringBuilder();
        sb.AppendLine("<!doctype html>");
        sb.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine($"<title>{H(options.Title)}</title>");
        sb.AppendLine("""
            <style>
            :root{--bg:#1C1E22;--card:#24272C;--border:#393939;--text:#E6E6E8;--muted:#AFAFB0;--accent:#8C9CEB;--block:#E87A7A;--allow:#5CC596;--soft:#123178}
            @media (prefers-color-scheme: light){:root{--bg:#F3F4F6;--card:#FFFFFF;--border:#DADCE0;--text:#24272C;--muted:#5A5D63;--accent:#3348B8;--block:#B42323;--allow:#1E7A4C;--soft:#DCE2F8}}
            *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",Inter,system-ui,sans-serif;padding:32px 16px}
            main{max-width:1280px;margin:0 auto}h1{font-size:24px;margin:0 0 4px}p.meta{color:var(--muted);margin:0 0 20px}
            .kpis{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}.kpi{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 18px;min-width:140px}
            .kpi b{display:block;font-size:24px}.kpi span{color:var(--muted);font-size:12px}
            .table{background:var(--card);border:1px solid var(--border);border-radius:10px;overflow-x:auto}
            table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top}
            th{color:var(--accent);font-size:11px;text-transform:uppercase;letter-spacing:.06em}tr:last-child td{border-bottom:0}
            code{font:12px Consolas,"Cascadia Mono",monospace;word-break:break-all}
            .b{display:inline-block;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:600;background:var(--soft)}
            .block{color:var(--block)}.allow{color:var(--allow)}.off{opacity:.55}footer{color:var(--muted);font-size:12px;margin-top:16px}
            </style>
            """);
        sb.AppendLine("</head><body><main>");
        sb.AppendLine($"<h1>{H(options.Title)}</h1>");
        sb.AppendLine($"<p class=\"meta\">Generated by {H(options.Generator)} on {H(Stamp(options))}{(options.Machine is null ? "" : " · " + H(options.Machine))}</p>");
        sb.AppendLine("<div class=\"kpis\">");
        sb.AppendLine($"<div class=\"kpi\"><b>{items.Count}</b><span>Rules</span></div>");
        sb.AppendLine($"<div class=\"kpi\"><b class=\"block\">{blocked}</b><span>Blocked</span></div>");
        sb.AppendLine($"<div class=\"kpi\"><b class=\"allow\">{items.Count - blocked}</b><span>Allowed</span></div>");
        sb.AppendLine($"<div class=\"kpi\"><b>{items.Count(i => i.Rule.Scope == RuleScope.Internet)}</b><span>Internet only</span></div>");
        sb.AppendLine($"<div class=\"kpi\"><b>{items.Count(i => !i.Rule.Enabled)}</b><span>Disabled</span></div>");
        sb.AppendLine("</div><div class=\"table\"><table><thead><tr><th>Name</th><th>Direction</th><th>Action</th><th>Scope</th><th>Profiles</th><th>Program</th><th>Service</th><th>Publisher</th><th>SHA-256</th></tr></thead><tbody>");
        foreach (var item in items)
        {
            var r = item.Rule;
            var cls = r.Action == RuleAction.Block ? "block" : "allow";
            sb.Append($"<tr class=\"{(r.Enabled ? "" : "off")}\">")
                .Append($"<td>{H(item.Name)}</td>")
                .Append($"<td>{DirectionText(r.Direction)}</td>")
                .Append($"<td><span class=\"b {cls}\">{r.Action}</span></td>")
                .Append($"<td>{r.Scope}</td>")
                .Append($"<td>{H(ProfilesText(r.Profiles))}</td>")
                .Append($"<td><code>{H(PathOf(item, options))}</code>{(item.FileExists ? "" : " <span class=\"b block\">missing</span>")}</td>")
                .Append($"<td>{H(r.Service)}</td>")
                .Append($"<td>{H(item.Publisher)}</td>")
                .Append($"<td><code>{H(item.Sha256)}</code></td>")
                .AppendLine("</tr>");
        }

        sb.AppendLine("</tbody></table></div>");
        sb.AppendLine($"<footer>{H(options.Generator)} · MIT License · Windows Firewall rule export</footer>");
        sb.AppendLine("</main></body></html>");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ XML

    private static string Xml(IReadOnlyList<ExportItem> items, ExportOptions options)
    {
        var settings = new XmlWriterSettings { Indent = true, OmitXmlDeclaration = false, Encoding = new UTF8Encoding(false) };
        using var stream = new MemoryStream();
        using (var writer = XmlWriter.Create(stream, settings))
        {
            writer.WriteStartDocument();
            writer.WriteStartElement("PortShieldRules");
            writer.WriteAttributeString("version", RuleSet.CurrentVersion.ToString(CultureInfo.InvariantCulture));
            writer.WriteAttributeString("generator", options.Generator);
            writer.WriteAttributeString("created", options.Created.ToString("s", CultureInfo.InvariantCulture));
            if (options.Machine is not null)
            {
                writer.WriteAttributeString("machine", options.Machine);
            }

            foreach (var item in items)
            {
                var r = item.Rule;
                writer.WriteStartElement("Rule");
                writer.WriteAttributeString("name", item.Name);
                writer.WriteAttributeString("direction", DirectionText(r.Direction));
                writer.WriteAttributeString("action", r.Action.ToString());
                writer.WriteAttributeString("scope", r.Scope.ToString());
                writer.WriteAttributeString("profiles", ProfilesText(r.Profiles));
                writer.WriteAttributeString("enabled", r.Enabled ? "true" : "false");
                writer.WriteElementString("Program", PathOf(item, options));
                if (r.HasService)
                {
                    writer.WriteElementString("Service", r.Service);
                }
                if (r.Scope == RuleScope.Custom && r.RemoteAddresses is not null)
                {
                    writer.WriteElementString("RemoteAddresses", r.RemoteAddresses);
                }

                if (!string.IsNullOrEmpty(item.Publisher))
                {
                    writer.WriteElementString("Publisher", item.Publisher);
                }

                if (!string.IsNullOrEmpty(item.Sha256))
                {
                    writer.WriteElementString("Sha256", item.Sha256);
                }

                writer.WriteEndElement();
            }

            writer.WriteEndElement();
            writer.WriteEndDocument();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }
}
