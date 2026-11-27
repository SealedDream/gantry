using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.System;

namespace Bastion.Shell;

/// <summary>One row of the All Tabs list: what it shows and what it searches.</summary>
internal sealed record AllTabsRow(object Key, string Title, string? Group, bool IsActive);

/// <summary>
/// All Tabs (Ctrl+Shift+A, as the Mac's Shift+Cmd+A): every open tab in strip order, searchable by title or group name,
/// each with a close button. Enter opens the first match, Escape closes. A self-contained control so the header can host
/// it wherever the tab strip sits (top bar or its own row). The Vertical Tabs switch stays at the bottom.
/// </summary>
internal sealed partial class AllTabsPanel : UserControl
{
    private const double PanelWidth = 320;
    private const double ListMaxHeight = 340;
    private const double CloseHitTarget = 28;

    private readonly TextBox _search = new();
    private readonly ListView _list = new() { SelectionMode = ListViewSelectionMode.None, IsItemClickEnabled = true, MaxHeight = ListMaxHeight };
    private readonly ToggleSwitch _vertical = new() { OnContent = "Vertical Tabs", OffContent = "Vertical Tabs" };
    private readonly Func<IReadOnlyList<AllTabsRow>> _rows;
    private readonly Action<object> _pick;
    private readonly Action<object> _close;
    private IReadOnlyList<AllTabsRow> _shown = [];

    public event EventHandler? Done;

    public AllTabsPanel(Func<IReadOnlyList<AllTabsRow>> rows, Action<object> pick, Action<object> close, bool vertical, Action<bool> setVertical)
    {
        _rows = rows;
        _pick = pick;
        _close = close;
        AutomationProperties.SetName(this, "All tabs list");
        AutomationProperties.SetName(_search, "Search tabs");
        AutomationProperties.SetName(_list, "Tabs");
        AutomationProperties.SetName(_vertical, "Vertical Tabs");
        _vertical.IsOn = vertical;
        _vertical.Toggled += (_, _) => setVertical(_vertical.IsOn);
        _search.TextChanged += (_, _) => Refill();
        _search.KeyDown += SearchKeyDown;
        _list.ItemClick += (_, e) => { if (e.ClickedItem is FrameworkElement { Tag: AllTabsRow r }) Pick(r); };
        var root = new StackPanel { Width = PanelWidth, Spacing = 6 };
        root.Children.Add(_search);
        root.Children.Add(_list);
        root.Children.Add(_vertical);
        Content = root;
        Refill();
    }

    /// <summary>Put the caret in the search box (called once the flyout has opened).</summary>
    public void FocusSearch() => _search.Focus(FocusState.Programmatic);

    private void FocusAfterClose(int index)
    {
        if (_list.Items.Count == 0) { _search.Focus(FocusState.Keyboard); return; }
        var row = _list.Items[Math.Clamp(index, 0, _list.Items.Count - 1)] as Panel;
        var close = row?.Children.OfType<Button>().LastOrDefault();
        if (close is null || !close.Focus(FocusState.Keyboard)) _search.Focus(FocusState.Keyboard);
    }

    /// <summary>The rows that match <paramref name="query"/> (title or group, any case); all rows for a blank query.</summary>
    internal static IReadOnlyList<AllTabsRow> Filter(IReadOnlyList<AllTabsRow> rows, string query)
    {
        var q = query.Trim();
        if (q.Length == 0) return rows;
        return rows.Where(r => r.Title.Contains(q, StringComparison.OrdinalIgnoreCase)
                               || (r.Group?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false)).ToList();
    }

    private void Refill()
    {
        var all = _rows();
        _search.PlaceholderText = $"Search {all.Count} tabs";
        _shown = Filter(all, _search.Text);
        _list.Items.Clear();
        foreach (var row in _shown) _list.Items.Add(RowView(row));
    }

    private Grid RowView(AllTabsRow row)
    {
        var grid = new Grid { Tag = row, ColumnSpacing = 8 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var title = new TextBlock { Text = row.Title, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
        if (row.IsActive) title.FontWeight = Microsoft.UI.Text.FontWeights.SemiBold;
        grid.Children.Add(title);
        if (row.Group is { Length: > 0 } g)
        {
            var group = new TextBlock { Text = g, Opacity = 0.7, VerticalAlignment = VerticalAlignment.Center, MaxWidth = 110, TextTrimming = TextTrimming.CharacterEllipsis };
            Grid.SetColumn(group, 1);
            grid.Children.Add(group);
        }
        var close = new Button
        {
            Content = new FontIcon { Glyph = "", FontSize = 10 },
            MinWidth = CloseHitTarget, MinHeight = CloseHitTarget, Padding = new Thickness(0),
            Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Transparent), BorderThickness = new Thickness(0),
        };
        LazyToolTip.Set(close, "Close tab");
        AutomationProperties.SetName(close, $"Close {row.Title}");
        close.Click += (_, _) =>
        {
            var index = _shown.ToList().IndexOf(row);
            _close(row.Key);
            Refill();
            if (_shown.Count == 0 && _rows().Count == 0) { Done?.Invoke(this, EventArgs.Empty); return; }
            // Focus stays in the list (safety: keys must not reach a terminal): the next row's close, else the search box.
            DispatcherQueue.TryEnqueue(() => FocusAfterClose(index));
        };
        Grid.SetColumn(close, 2);
        grid.Children.Add(close);
        AutomationProperties.SetName(grid, row.Title);
        return grid;
    }

    private void SearchKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter && _shown.Count > 0) { e.Handled = true; Pick(_shown[0]); }
        else if (e.Key == VirtualKey.Escape) { e.Handled = true; Done?.Invoke(this, EventArgs.Empty); }
    }

    private void Pick(AllTabsRow row)
    {
        _pick(row.Key);
        Done?.Invoke(this, EventArgs.Empty);
    }
}
