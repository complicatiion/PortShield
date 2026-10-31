using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PortShield.Core.Rules;
using PortShield.Platform.Windows;

namespace PortShield.App.ViewModels;

public sealed partial class ProcessItem : ObservableObject
{
    public required string Path { get; init; }

    public required string Name { get; init; }

    public int Count { get; init; }

    public string? Description { get; init; }

    public string? Company { get; init; }

    public string? WindowTitle { get; init; }

    public string Folder => ProgramPaths.Directory(Path);

    public string CountText => Count > 1 ? "×" + Count : "";

    public string Details => string.Join(" · ", new[] { Description, Company, WindowTitle }.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct());

    [ObservableProperty]
    private bool _isChecked;
}

/// <summary>Running programs (one entry per executable) to block or allow.</summary>
public sealed partial class ProcessPickerModel : ObservableObject
{
    private List<ProcessItem> _all = [];

    public ObservableCollection<ProcessItem> Items { get; } = [];

    [ObservableProperty]
    private string _search = "";

    [ObservableProperty]
    private bool _hideWindows = true;

    [ObservableProperty]
    private bool _isLoading;

    partial void OnSearchChanged(string value) => Filter();

    partial void OnHideWindowsChanged(bool value) => Filter();

    public IReadOnlyList<string> CheckedPaths => _all.Where(i => i.IsChecked).Select(i => i.Path).ToList();

    public async Task LoadAsync()
    {
        IsLoading = true;
        try
        {
            var list = OperatingSystem.IsWindows() ? await Task.Run(ProcessList.Read) : [];
            _all = list.Select(p => new ProcessItem
            {
                Path = p.Path,
                Name = p.Name,
                Count = p.Processes,
                Description = p.Description,
                Company = p.Company,
                WindowTitle = p.WindowTitle
            }).ToList();
            Filter();
        }
        finally
        {
            IsLoading = false;
        }
    }

    private void Filter()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var text = Search.Trim();
        Items.Clear();
        foreach (var item in _all.Where(i =>
                     (!HideWindows || string.IsNullOrEmpty(windows) || !i.Path.StartsWith(windows, StringComparison.OrdinalIgnoreCase))
                     && (text.Length == 0 || i.Path.Contains(text, StringComparison.OrdinalIgnoreCase) || i.Details.Contains(text, StringComparison.OrdinalIgnoreCase))))
        {
            Items.Add(item);
        }
    }

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();
}
