using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.ApplicationModel.DataTransfer;

namespace Bastion.Shell;

/// <summary>
/// Tasks results (design A, Mac TaskResultsGrid.swift): one row per host with a status dot, the last line, exit code and
/// duration. Click a row for its output; Group same output folds identical hosts; select two rows (Ctrl-click) for
/// Compare, a line diff shown in place; Copy copies labelled output; Open in Terminal hands the host to a normal connect.
/// The model is <see cref="TaskGrid"/>; this class only draws it. <see cref="Update"/> is called on every poll.
/// </summary>
internal sealed class TaskResultsGrid
{
    private const double DotSize = 10;
    private const double HostColumnWidth = 160;
    private const double OutputMaxHeight = 220;
    private const double ListMaxHeight = 420;
    private const string MonoFont = "Cascadia Mono, Consolas";

    private readonly Action<string> _openOne;
    private readonly Action<IReadOnlyList<string>> _openAll;
    private readonly ListView _list = new() { SelectionMode = ListViewSelectionMode.Extended, IsItemClickEnabled = true, MaxHeight = ListMaxHeight };
    private readonly CheckBox _group = new() { Content = "Group same output", IsChecked = true };
    private readonly Button _compare = new() { Content = "Compare", IsEnabled = false };
    private readonly Button _copy = new() { Content = "Copy All" };
    private readonly Button _openAllButton = new() { Content = "Open All in Terminals" };
    private readonly Button _back = new() { Content = "Back to Results", Visibility = Visibility.Collapsed };
    private readonly ScrollViewer _diff = new() { MaxHeight = ListMaxHeight, Visibility = Visibility.Collapsed, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto };
    private readonly HashSet<string> _expanded = [];
    private readonly double _overtimeLimit;
    private readonly DateTime _started = DateTime.UtcNow;
    private IReadOnlyList<TaskGridRow> _rows = [];
    private List<GridGroup> _shown = [];
    private string _layoutKey = "";

    public UIElement View { get; }

    public TaskResultsGrid(Action<string> openOne, Action<IReadOnlyList<string>> openAll, int taskTimeoutSecs)
    {
        _openOne = openOne;
        _openAll = openAll;
        _overtimeLimit = TaskGrid.OvertimeLimit(taskTimeoutSecs);
        AutomationProperties.SetName(_list, "Task results");
        AutomationProperties.SetAutomationId(_list, "TaskResultsGrid");
        AutomationProperties.SetName(_diff, "Compare");
        ToolTipService.SetToolTip(_compare, "Select two rows (Ctrl-click) to compare their output");
        ToolTipService.SetToolTip(_copy, "Copy each host's output, labelled; only the selected rows when some are selected");
        _group.Checked += (_, _) => Rebuild(force: true);
        _group.Unchecked += (_, _) => Rebuild(force: true);
        _list.SelectionChanged += (_, _) => SyncButtons();
        _list.ItemClick += (_, e) => Toggle(e.ClickedItem as Grid);
        _compare.Click += (_, _) => ShowCompare();
        _back.Click += (_, _) => HideCompare();
        _copy.Click += (_, _) => Copy();
        _openAllButton.Click += (_, _) => _openAll(_rows.Select(r => r.Id).ToList());
        var bar = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { _group, _compare, _copy, _openAllButton, _back } };
        View = new StackPanel { Spacing = Ui.Double("Space8"), Children = { bar, _list, _diff } };
    }

    /// <summary>New rows from the poll: redraw only when the grouping changes, else refresh texts in place.</summary>
    public void Update(IReadOnlyList<TaskGridRow> rows)
    {
        _rows = rows;
        Rebuild(force: false);
    }

    private List<GridGroup> Grouped() => _group.IsChecked == true ? TaskGrid.Groups(_rows) : _rows.Select(r => new GridGroup([r])).ToList();

    private void Rebuild(bool force)
    {
        var groups = Grouped();
        var key = string.Join("|", groups.Select(g => g.Id));
        if (force || key != _layoutKey)
        {
            var selected = SelectedGroups().Select(g => g.Id).ToHashSet();
            _layoutKey = key;
            _list.Items.Clear();
            foreach (var g in groups) _list.Items.Add(RowView(g));
            foreach (var item in _list.Items.OfType<Grid>().Where(i => selected.Contains((string)i.Tag)).ToList()) _list.SelectedItems.Add(item);
        }
        else
        {
            for (var i = 0; i < groups.Count; i++) Fill((Grid)_list.Items[i], groups[i]);
        }
        _shown = groups;
        SyncButtons();
    }

    private Grid RowView(GridGroup g)
    {
        var row = new Grid { Tag = g.Id, ColumnSpacing = Ui.Double("Space8"), MinHeight = Ui.Double("MinHitTarget") };
        foreach (var w in new[] { GridLength.Auto, new GridLength(HostColumnWidth), new GridLength(1, GridUnitType.Star), GridLength.Auto, GridLength.Auto, GridLength.Auto })
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        row.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        row.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var dot = new Ellipse { Width = DotSize, Height = DotSize, VerticalAlignment = VerticalAlignment.Center };
        var host = Ui.Text("", "BodyStrongTextStyle");
        var summary = Ui.Text("", "CaptionTextStyle");
        var exit = Ui.Text("", "CaptionSecondaryTextStyle");
        var time = Ui.Text("", "CaptionSecondaryTextStyle");
        foreach (var t in new[] { host, summary, exit, time }) { t.TextTrimming = TextTrimming.CharacterEllipsis; t.VerticalAlignment = VerticalAlignment.Center; }
        var id = g.Id;
        var open = new Button { Content = "Open in Terminal", Style = Ui.Style("SubtleButtonStyle") };
        open.Click += (_, _) => OpenGroup(id);
        var output = new TextBox
        {
            IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, MaxHeight = OutputMaxHeight,
            FontFamily = new FontFamily(MonoFont), Visibility = Visibility.Collapsed,
        };
        Grid.SetRow(output, 1);
        Grid.SetColumn(output, 1);
        Grid.SetColumnSpan(output, 5);
        FrameworkElement[] cells = [dot, host, summary, exit, time, open];
        for (var i = 0; i < cells.Length; i++) { Grid.SetColumn(cells[i], i); row.Children.Add(cells[i]); }
        row.Children.Add(output);
        Fill(row, g);
        return row;
    }

    private void OpenGroup(string id)
    {
        if (_shown.FirstOrDefault(x => x.Id == id) is not { } g) return;
        if (g.IsGroup) _openAll(g.Rows.Select(r => r.Id).ToList()); else _openOne(g.First.Id);
    }

    /// <summary>Texts of a row from its group; the output box only while expanded.</summary>
    private void Fill(Grid row, GridGroup g)
    {
        row.Tag = g.Id;
        var r = g.First;
        ((Ellipse)row.Children[0]).Fill = new SolidColorBrush(r.Status switch
        {
            GridStatus.Ok => Colors.SeaGreen,
            GridStatus.Failed => Colors.Firebrick,
            _ => Colors.DarkOrange,
        });
        var overtime = TaskGrid.IsOvertime(r, (DateTime.UtcNow - _started).TotalSeconds, _overtimeLimit);
        var summary = overtime ? $"Still running after {(int)_overtimeLimit} s: open it in a terminal" : r.Summary.Length > 0 ? r.Summary : StatusText(r);
        SetText(row.Children[1], g.Title, g.IsGroup ? string.Join(", ", g.Rows.Select(x => x.Host)) : r.Host);
        SetText(row.Children[2], summary, summary);
        SetText(row.Children[3], r.Exit is { } e ? $"exit {e}" : r.IsFinished ? StatusText(r) : "", null);
        SetText(row.Children[4], r.IsFinished || r.Millis > 0 ? TaskGrid.Duration(r.Millis) : "", null);
        AutomationProperties.SetName(row, $"{g.Title}: {StatusText(r)}, {summary}");
        var output = (TextBox)row.Children[6];
        var text = r.Output;
        if (output.Text != text) output.Text = text;
        output.Visibility = _expanded.Contains(g.Id) && text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        AutomationProperties.SetName(output, "Output from " + g.Title);
    }

    private static void SetText(UIElement e, string text, string? tip)
    {
        var t = (TextBlock)e;
        if (t.Text != text) t.Text = text;
        if (tip is not null) ToolTipService.SetToolTip(t, tip);
    }

    private static string StatusText(TaskGridRow r) => r.Status switch
    {
        GridStatus.Ok => "OK",
        GridStatus.Failed => r.State switch { "timed_out" => "Timed out", "cancelled" => "Cancelled", _ => "Failed" },
        GridStatus.Running => "Running",
        _ => "Waiting",
    };

    private void Toggle(Grid? row)
    {
        if (row?.Tag is not string id) return;
        if (!_expanded.Remove(id)) _expanded.Add(id);
        if (_shown.FirstOrDefault(g => g.Id == id) is { } g) Fill(row, g);
    }

    private List<GridGroup> SelectedGroups()
    {
        var ids = _list.SelectedItems.OfType<Grid>().Select(i => i.Tag as string).ToHashSet();
        return _shown.Where(g => ids.Contains(g.Id)).ToList();
    }

    private void SyncButtons()
    {
        var picked = SelectedGroups();
        _compare.IsEnabled = picked.Count == 2;
        var copy = picked.Count > 0 ? "Copy Selected" : "Copy All";
        _copy.Content = copy;
        AutomationProperties.SetName(_copy, copy);
        _openAllButton.IsEnabled = _rows.Count > 0;
    }

    private void Copy()
    {
        var picked = SelectedGroups();
        var rows = picked.Count > 0 ? picked.SelectMany(g => g.Rows) : _rows;
        var data = new DataPackage();
        data.SetText(TaskGrid.Labelled(rows));
        Clipboard.SetContent(data);
    }

    /// <summary>The line diff of the two selected rows, in place of the list (the grid already sits in a dialog).</summary>
    private void ShowCompare()
    {
        var picked = SelectedGroups();
        if (picked.Count != 2) return;
        var lines = new StackPanel();
        lines.Children.Add(Ui.Text($"− {picked[0].Title}    + {picked[1].Title}", "BodyStrongTextStyle"));
        foreach (var d in TaskGrid.Diff(picked[0].First.Output, picked[1].First.Output))
        {
            var text = (d.Kind switch { DiffKind.Left => "− ", DiffKind.Right => "+ ", _ => "  " }) + d.Text;
            var line = new TextBlock { Text = text, FontFamily = new FontFamily(MonoFont), IsTextSelectionEnabled = true };
            if (d.Kind != DiffKind.Same) line.Foreground = new SolidColorBrush(d.Kind == DiffKind.Left ? Colors.Firebrick : Colors.SeaGreen);
            lines.Children.Add(line);
        }
        if (lines.Children.Count == 1) lines.Children.Add(Ui.Text("Both outputs are empty.", "CaptionSecondaryTextStyle"));
        _diff.Content = lines;
        _list.Visibility = Visibility.Collapsed;
        _diff.Visibility = Visibility.Visible;
        _back.Visibility = Visibility.Visible;
    }

    private void HideCompare()
    {
        _diff.Content = null;
        _diff.Visibility = Visibility.Collapsed;
        _back.Visibility = Visibility.Collapsed;
        _list.Visibility = Visibility.Visible;
    }
}
