using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.App.Localization;
using PortShield.App.Services;
using PortShield.Core.Connections;
using PortShield.Core.Models;
using PortShield.Core.Rules;
using PortShield.Core.Storage;
using PortShield.Platform.Windows;

namespace PortShield.App.ViewModels;

/// <summary>Blocked connections of one program to one remote address and port.</summary>
public sealed class ConnectionRow(ConnectionGroup group)
{
    public ConnectionGroup Group { get; } = group;

    public string Program => Group.Application;

    public bool HasProgram => Group.Application.Contains('\\');

    public string FileName => HasProgram ? ProgramPaths.FileName(Group.Application) : Group.Application;

    public string Folder => HasProgram ? ProgramPaths.Directory(Group.Application) : "";

    public bool IsOutbound => Group.Direction == RuleDirection.Outbound;

    public string DirectionText => Loc.T(IsOutbound ? "DirOut" : "DirIn");

    public string Remote => Group.RemoteAddress.Contains(':') ? $"[{Group.RemoteAddress}]:{Group.RemotePort}" : $"{Group.RemoteAddress}:{Group.RemotePort}";

    public string ProtocolText => BlockedConnections.ProtocolName(Group.Protocol);

    public bool IsInternet => Group.RemoteKind == AddressKind.Internet;

    public string KindText => Loc.T("AddressKind" + Group.RemoteKind);

    public int Count => Group.Count;

    public string LastText => Group.Last.ToString("g");

    public DateTime Last => Group.Last;

    public string Tooltip => Group.Application + Environment.NewLine + Loc.F("ConnectionFirstLast", Group.First.ToString("g"), Group.Last.ToString("g"));
}

/// <summary>
/// Connections the Windows Firewall blocked, from the Security log (event 5157). Recording needs the audit policy
/// "Filtering Platform Connection – failure", which PortShield turns on and off here.
/// </summary>
public sealed partial class ConnectionsViewModel(MainViewModel main) : PageViewModel(main)
{
    private IReadOnlyList<ConnectionGroup> _groups = [];
    private IReadOnlyList<ConnectionRow> _selected = [];
    private int _events;

    public override string TitleKey => "NavConnections";

    public ObservableCollection<ConnectionRow> Rows { get; } = [];

    public event Action<SelectionRequest>? SelectionRequested;

    // ------------------------------------------------------------------ Recording

    /// <summary>null = unknown (no administrator rights).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RecordingOn), nameof(RecordingOff), nameof(RecordingUnknown), nameof(RecordingButton))]
    private bool? _recording;

    public bool RecordingOn => Recording == true;

    public bool RecordingOff => Recording == false;

    public bool RecordingUnknown => Recording is null;

    public string RecordingButton => Loc.T(RecordingOn ? "BtnRecordingOff" : "BtnRecordingOn");

    [ObservableProperty]
    private bool _isLoading;

    private bool _loaded;

    /// <summary>The range changed while loading – load again afterwards.</summary>
    private bool _reloadPending;

    public override void OnActivated()
    {
        if (!FirewallService.IsSupported)
        {
            return;
        }

        _ = ReadRecordingAsync();
        if (!_loaded)
        {
            _ = LoadAsync();
        }
    }

    private async Task ReadRecordingAsync()
    {
        var state = await Task.Run(ConnectionAudit.IsEnabled);
        Recording = state;
    }

    [RelayCommand]
    private async Task ToggleRecordingAsync()
    {
        var on = !RecordingOn;
        try
        {
            await Task.Run(() => ConnectionAudit.SetEnabled(on));
            MarkRecording(on);
            Recording = await Task.Run(ConnectionAudit.IsEnabled);
            Main.ShowToast(Loc.T(on ? "ToastRecordingOn" : "ToastRecordingOff"));
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
    }

    /// <summary>Remembers that PortShield turned recording on – a factory reset turns it off again.</summary>
    private static void MarkRecording(bool on)
    {
        try
        {
            if (on)
            {
                Directory.CreateDirectory(AppPaths.DataDirectory);
                File.WriteAllText(AppPaths.AuditMarkerFile, DateTime.Now.ToString("O"));
            }
            else
            {
                File.Delete(AppPaths.AuditMarkerFile);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    // ------------------------------------------------------------------ Filters

    /// <summary>0 last hour · 1 last 24 hours · 2 last 7 days.</summary>
    [ObservableProperty]
    private int _rangeIndex = 1;

    /// <summary>0 all · 1 outbound · 2 inbound.</summary>
    [ObservableProperty]
    private int _directionIndex = 1;

    /// <summary>Hide LAN, loopback, link-local and multicast/broadcast noise.</summary>
    [ObservableProperty]
    private bool _internetOnly = true;

    [ObservableProperty]
    private string _search = "";

    partial void OnRangeIndexChanged(int value) => _ = LoadAsync();

    partial void OnDirectionIndexChanged(int value) => ApplyFilter();

    partial void OnInternetOnlyChanged(bool value) => ApplyFilter();

    partial void OnSearchChanged(string value) => ApplyFilter();

    public IReadOnlyList<string> Ranges => [Loc.T("RangeHour"), Loc.T("RangeDay"), Loc.T("RangeWeek")];

    public IReadOnlyList<string> DirectionFilters => [Loc.T("FilterAllDirections"), Loc.T("DirOut"), Loc.T("DirIn")];

    private TimeSpan Range => RangeIndex switch
    {
        0 => TimeSpan.FromHours(1),
        2 => TimeSpan.FromDays(7),
        _ => TimeSpan.FromDays(1)
    };

    public override void OnLanguageChanged()
    {
        base.OnLanguageChanged();
        OnPropertyChanged(nameof(Ranges));
        OnPropertyChanged(nameof(RangeIndex));
        OnPropertyChanged(nameof(DirectionFilters));
        OnPropertyChanged(nameof(DirectionIndex));
        OnPropertyChanged(nameof(RecordingButton));
        ApplyFilter();
    }

    // ------------------------------------------------------------------ Counters

    public int EventCount => _events;

    public int ProgramCount => Rows.Select(r => r.Program).Distinct(StringComparer.OrdinalIgnoreCase).Count();

    public int RemoteCount => Rows.Select(r => r.Group.RemoteAddress).Distinct(StringComparer.OrdinalIgnoreCase).Count();

    public int InternetCount => Rows.Where(r => r.IsInternet).Sum(r => r.Count);

    public string CountText => Loc.F("RulesCount", Rows.Count, _groups.Count);

    public bool HasRows => Rows.Count > 0;

    public bool IsEmpty => !IsLoading && Rows.Count == 0;

    public bool HasSelection => _selected.Count > 0;

    public string SelectionText => _selected.Count == 0 ? "" : Loc.F("RulesSelected", _selected.Count);

    /// <summary>Event limit per load (the newest events first).</summary>
    public const int MaxEvents = 5000;

    public bool HitLimit => _events >= MaxEvents;

    // ------------------------------------------------------------------ Load

    [RelayCommand]
    public async Task LoadAsync()
    {
        if (!FirewallService.IsSupported)
        {
            return;
        }

        if (IsLoading)
        {
            _reloadPending = true;
            return;
        }

        try
        {
            IsLoading = true;
            OnPropertyChanged(nameof(IsEmpty));
            var range = Range;
            var events = await Task.Run(() => BlockedEventLog.Read(range, MaxEvents));
            _events = events.Count;
            _groups = BlockedConnections.Group(events);
            _loaded = true;
        }
        catch (Exception ex)
        {
            Main.ShowError(ex);
        }
        finally
        {
            IsLoading = false;
        }

        ApplyFilter();
        if (_reloadPending)
        {
            _reloadPending = false;
            await LoadAsync();
        }
    }

    private void ApplyFilter()
    {
        Rows.Clear();
        var text = Search.Trim();
        foreach (var group in _groups.Where(g =>
                     (DirectionIndex == 0 || (DirectionIndex == 1) == (g.Direction == RuleDirection.Outbound))
                     && (!InternetOnly || g.RemoteKind == AddressKind.Internet)
                     && (text.Length == 0 || g.Application.Contains(text, StringComparison.OrdinalIgnoreCase)
                                          || g.RemoteAddress.Contains(text, StringComparison.OrdinalIgnoreCase)
                                          || g.RemotePort.ToString().Contains(text, StringComparison.Ordinal))))
        {
            Rows.Add(new ConnectionRow(group));
        }

        SetSelection([]);
        OnPropertyChanged(nameof(EventCount));
        OnPropertyChanged(nameof(ProgramCount));
        OnPropertyChanged(nameof(RemoteCount));
        OnPropertyChanged(nameof(InternetCount));
        OnPropertyChanged(nameof(CountText));
        OnPropertyChanged(nameof(HasRows));
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(HitLimit));
    }

    public void SetSelection(IReadOnlyList<ConnectionRow> rows)
    {
        _selected = rows;
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(SelectionText));
    }

    [RelayCommand]
    private void SelectAll() => SelectionRequested?.Invoke(SelectionRequest.All);

    // ------------------------------------------------------------------ Actions

    /// <summary>Block rule for the programs of the selected connections (direction of the connection), with review.</summary>
    [RelayCommand]
    private Task BlockProgramAsync() => CreateRulesAsync(RuleAction.Block);

    /// <summary>Allow rule (e.g. in whitelist mode) for the programs of the selected connections, with review.</summary>
    [RelayCommand]
    private Task AllowProgramAsync() => CreateRulesAsync(RuleAction.Allow);

    private async Task CreateRulesAsync(RuleAction action)
    {
        var definitions = _selected.Where(r => r.HasProgram)
            .Select(r => new RuleDefinition { Program = r.Program, Direction = r.Group.Direction, Action = action, Scope = Ui.DefaultScope, Profiles = Ui.DefaultProfiles })
            .DistinctBy(d => (ProgramPaths.Key(d.Program), d.Direction))
            .ToList();
        if (definitions.Count == 0)
        {
            Main.ShowToast(Loc.T("ToastNoPrograms"));
            return;
        }

        var model = AddRulesModel.ForDefinitions(Main, Loc.T(action == RuleAction.Block ? "ConnectionsBlockTitle" : "ConnectionsAllowTitle"), null, definitions);
        await Main.ReviewAsync(model, null);
    }

    [RelayCommand]
    private async Task CopyAddressAsync()
    {
        if (_selected.Count > 0)
        {
            await Host.CopyAsync(string.Join(Environment.NewLine, _selected.Select(r => r.Group.RemoteAddress).Distinct()));
            Main.ShowToast(Loc.T("ToastCopied"));
        }
    }

    [RelayCommand]
    private void OpenLocation()
    {
        if (_selected.FirstOrDefault(r => r.HasProgram) is { } row)
        {
            AppEnvironment.OpenFolder(row.Program);
        }
    }
}
