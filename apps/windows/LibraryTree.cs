using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.Foundation;
using Windows.System;

namespace Bastion.Shell;

/// <summary>
/// WIN-FLAT-TREE: the library pane's tree, drawn as one flat, virtualized list of the rows that are open on screen.
/// WinUI's TreeView created and tore down a container (and its automation peer and weak-reference bookkeeping) for
/// every row a search keystroke added or removed, so a 5,000-connection filter stayed near 300 ms at p95 however the
/// bound list was changed. Here a keystroke builds the open-row list (a walk of the expanded items) and hands it to an
/// ItemsRepeater in one assignment; the repeater only rebinds the rows that are in view, recycling their elements.
/// The rows draw their own indent and chevron (<see cref="LibraryRow"/>) and keep the tree's keyboard, selection and
/// UI Automation behaviour (TreeItem rows with SelectionItem, ExpandCollapse and ScrollItem), so it looks and tests
/// like the tree it replaces.
/// </summary>
public sealed partial class LibraryTree : Grid
{
    private Microsoft.UI.Xaml.Media.Brush? _selectionBarOverride;

    /// <summary>UI-06: the selection bar's brush when the accent reads under 3:1 on the window tones; null = the accent.</summary>
    internal Microsoft.UI.Xaml.Media.Brush? SelectionBarOverride
    {
        get => _selectionBarOverride;
        set
        {
            if (ReferenceEquals(_selectionBarOverride, value)) return;
            _selectionBarOverride = value;
            foreach (var row in _realized) row.UpdateState();
        }
    }

    /// <summary>Left indent per level, as WinUI's TreeView.</summary>
    public const double IndentPerLevel = 16;

    private readonly ScrollViewer _scroller;
    private readonly ItemsRepeater _repeater;
    private readonly HashSet<LibraryRow> _realized = [];
    private IList<TreeItem>? _roots;
    private List<TreeItem> _rows = [];
    /// <summary>The repeater's source: <see cref="_rows"/> kept in step by small inserts and removes, or replaced.</summary>
    private System.Collections.ObjectModel.ObservableCollection<TreeItem>? _source;
    /// <summary>
    /// Up to this many rows added plus removed, the change is applied in place so every other row keeps its element (a
    /// menu anchored on a row, the focused row); more (a search keystroke) and the list is replaced in one go.
    /// </summary>
    private const int InPlaceLimit = 32;
    private List<int> _depths = [];
    private Dictionary<TreeItem, int> _index = new(ReferenceEqualityComparer.Instance);
    private TreeItem? _selected;
    private bool _refreshQueued;
    private bool _firstPrepared;
    private double _rowHeight = 30;
    /// <summary>Test-hooks diagnostics (BASTION_TREE_INPUT_LOG): set by MainWindow, null otherwise.</summary>
    internal static Action<string>? Trace;

    public LibraryTree()
    {
        _repeater = new ItemsRepeater
        {
            Layout = new StackLayout { Orientation = Orientation.Vertical },
            TabFocusNavigation = KeyboardNavigationMode.Once,
        };
        _repeater.ElementPrepared += Repeater_ElementPrepared;
        _repeater.ElementClearing += Repeater_ElementClearing;
        _scroller = new ScrollViewer
        {
            Content = _repeater,
            Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Transparent),
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            VerticalScrollBarVisibility = ScrollBarVisibility.Hidden,
            IsTabStop = false,
        };
        Children.Add(_scroller);
        KeyDown += Tree_KeyDown;
        // The item events are static: follow them only while shown, so a refresh never runs on a closed window (closing
        // a 5,000-row window crashed in CoreMessaging when a queued refresh rebound the repeater during teardown).
        Loaded += (_, _) => { TreeItem.ExpandedChanged += QueueRefresh; TreeChildren.AnyChanged += QueueRefresh; QueueRefresh(); };
        Unloaded += (_, _) => { TreeItem.ExpandedChanged -= QueueRefresh; TreeChildren.AnyChanged -= QueueRefresh; };
    }

    /// <summary>The row template (a <see cref="LibraryRow"/> bound to a <see cref="TreeItem"/>).</summary>
    public DataTemplate? ItemTemplate
    {
        get => _repeater.ItemTemplate as DataTemplate;
        set => _repeater.ItemTemplate = value;
    }

    /// <summary>Row height (the core's density metric).</summary>
    public double RowHeight
    {
        get => _rowHeight;
        set
        {
            _rowHeight = value;
            foreach (var row in _realized) row.MinHeight = value;
        }
    }

    /// <summary>
    /// The top-level items (a list of TreeItem). Setting it shows the new rows at once (one rebind of the visible rows).
    /// Typed object so XAML's type info does not take TreeItem in (it would construct and set it).
    /// </summary>
    public object? ItemsSource
    {
        get => _roots;
        set { _roots = value as IList<TreeItem>; Trace?.Invoke($"items-source roots={_roots?.Count ?? 0}"); Refresh(); }
    }

    public event TypedEventHandler<LibraryTree, LibraryTreeSelectionChangedEventArgs>? SelectionChanged;
    public event TypedEventHandler<LibraryTree, LibraryTreeExpandEventArgs>? Expanding;
    public event TypedEventHandler<LibraryTree, LibraryTreeExpandEventArgs>? Collapsed;
    public event TypedEventHandler<LibraryTree, LibraryTreeInvokedEventArgs>? ItemInvoked;
    /// <summary>A row element was given an item (created or recycled).</summary>
    public event Action<LibraryRow>? RowPrepared;

    /// <summary>The selected row's item. Setting an item that is not shown (inside a closed folder) does nothing.</summary>
    public object? SelectedItem
    {
        get => _selected;
        set => Select(value as TreeItem);
    }

    /// <summary>Whether the item is a shown row.</summary>
    public bool IsShown(TreeItem item) => _index.ContainsKey(item);

    public LibraryRow? ContainerFromItem(object? item) =>
        item is TreeItem t && _index.TryGetValue(t, out var i) ? _repeater.TryGetElement(i) as LibraryRow : null;

    public object? ItemFromContainer(DependencyObject? container) => (container as LibraryRow)?.Item;

    internal int DepthOf(TreeItem item) => _index.TryGetValue(item, out var i) && i < _depths.Count ? _depths[i] : 0;

    /// <summary>
    /// The row's 1-based place among its siblings and their count (UIA PositionInSet / SizeOfSet), so a screen reader
    /// says "3 of 5" as it does in the TreeView. Siblings are the open rows at the same depth under the same parent.
    /// </summary>
    internal (int Position, int Size) SetOf(TreeItem item)
    {
        if (!_index.TryGetValue(item, out var at) || at >= _depths.Count) return (0, 0);
        var depth = _depths[at];
        var first = at;
        while (first > 0 && _depths[first - 1] >= depth) first--;
        var position = 0;
        var size = 0;
        for (var i = first; i < _depths.Count && _depths[i] >= depth; i++)
        {
            if (_depths[i] != depth) continue;
            size++;
            if (i <= at) position++;
        }
        return (position, size);
    }

    internal bool IsSelected(TreeItem item) => ReferenceEquals(_selected, item) || _more.Contains(item);

    // ---- Rows ----

    private void QueueRefresh()
    {
        if (_refreshQueued) return;
        _refreshQueued = true;
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.High, () => { _refreshQueued = false; if (IsLoaded) Refresh(); });
    }

    /// <summary>Rebuild the open-row list from the items; rebinds the visible rows only when the list changed.</summary>
    public void Refresh()
    {
        var watch = Trace is null ? null : System.Diagnostics.Stopwatch.StartNew();
        try { RefreshRows(); }
        finally { if (watch is not null) Trace?.Invoke($"refresh rows={_rows.Count} ms={watch.Elapsed.TotalMilliseconds:0.0}"); }
    }

    private void RefreshRows()
    {
        var rows = new List<TreeItem>(_rows.Count);
        var depths = new List<int>(_rows.Count);
        if (_roots is not null) Walk(_roots, 0, rows, depths);
        if (SameRows(rows))
        {
            _depths = depths;
            foreach (var row in _realized) row.UpdateState();
            return;
        }
        var index = new Dictionary<TreeItem, int>(rows.Count, ReferenceEqualityComparer.Instance);
        for (var i = 0; i < rows.Count; i++) index.TryAdd(rows[i], i);
        var old = _rows;
        _rows = rows;
        _depths = depths;
        _index = index;
        ApplyRows(old, rows);
        foreach (var row in _realized) row.UpdateState();
        if (_selected is not null && !index.ContainsKey(_selected)) ChangeSelection(null);
        if (_more.RemoveWhere(m => !index.ContainsKey(m)) > 0) MultiSelectionChanged?.Invoke();
    }

    /// <summary>
    /// Bring the repeater's source from <paramref name="old"/> to <paramref name="rows"/> in place when few rows changed,
    /// so every other row keeps its element; else one new list (a search keystroke). WIN-TREE-REBUILD: a rebuild keeps
    /// unchanged rows, so its few changes are spread over the list (a folder near the top, the connection further down,
    /// the Application section at the end); <see cref="RowEdits"/> finds them. A run of rows that moved (a session row
    /// reordered) is still handled as one changed span between the shared head and tail.
    /// </summary>
    private void ApplyRows(List<TreeItem> old, List<TreeItem> rows)
    {
        if (_source is null) { ReplaceRows(rows, "first"); return; }
        if (RowEdits.Plan(old, rows, InPlaceLimit) is { } edits)
        {
            RowEdits.Apply(_source, edits);
            if (PerfTrace.Enabled) PerfTrace.Line($"DETAIL tree-rows in-place edits={edits.Count} rows={rows.Count}");
            return;
        }
        var shared = Math.Min(old.Count, rows.Count);
        var head = 0;
        while (head < shared && ReferenceEquals(old[head], rows[head])) head++;
        var tail = 0;
        while (tail < shared - head && ReferenceEquals(old[^(tail + 1)], rows[^(tail + 1)])) tail++;
        var removed = old.Count - head - tail;
        var added = rows.Count - head - tail;
        if (removed + added > InPlaceLimit) { ReplaceRows(rows, "replace"); return; }
        for (var i = 0; i < removed; i++) _source.RemoveAt(head);
        for (var i = 0; i < added; i++) _source.Insert(head + i, rows[head + i]);
        if (PerfTrace.Enabled) PerfTrace.Line($"DETAIL tree-rows span edits={removed + added} rows={rows.Count}");
    }

    private void ReplaceRows(List<TreeItem> rows, string why)
    {
        _source = new(rows);
        _repeater.ItemsSource = _source;
        if (PerfTrace.Enabled) PerfTrace.Line($"DETAIL tree-rows {why} rows={rows.Count}");
    }

    private static void Walk(IEnumerable<TreeItem> items, int depth, List<TreeItem> rows, List<int> depths)
    {
        foreach (var item in items)
        {
            rows.Add(item);
            depths.Add(depth);
            if (item.Expanded && item.Children.Count > 0) Walk(item.Children, depth + 1, rows, depths);
        }
    }

    private bool SameRows(List<TreeItem> rows)
    {
        if (_source is null || rows.Count != _rows.Count) return false;
        for (var i = 0; i < rows.Count; i++)
            if (!ReferenceEquals(rows[i], _rows[i])) return false;
        return true;
    }

    private void Repeater_ElementPrepared(ItemsRepeater sender, ItemsRepeaterElementPreparedEventArgs args)
    {
        if (args.Element is not LibraryRow row) return;
        var prepT0 = PerfTrace.Now();
        if (!_firstPrepared) { _firstPrepared = true; Trace?.Invoke($"first-row-prepared index={args.Index}"); }
        row.Attach(this, sender.ItemsSourceView?.GetAt(args.Index) as TreeItem);
        AutomationProperties.SetAccessibilityView(row, AccessibilityView.Content);
        row.MinHeight = _rowHeight;
        _realized.Add(row);
        row.UpdateState();
        RowPrepared?.Invoke(row);
        if (PerfTrace.Enabled) PerfTrace.Write("row-prepare", PerfTrace.Ms(prepT0)); // speed suite: cost of one row bind while scrolling
    }

    /// <summary>
    /// A row going back to the recycle pool keeps its last name, so UI Automation would find a ghost of a row that is no
    /// longer shown (a test selected one and cleared the real selection). Pooled rows leave the automation tree.
    /// </summary>
    private void Repeater_ElementClearing(ItemsRepeater sender, ItemsRepeaterElementClearingEventArgs args)
    {
        if (args.Element is not LibraryRow row) return;
        _realized.Remove(row);
        row.Detach();
        AutomationProperties.SetAccessibilityView(row, AccessibilityView.Raw);
    }

    // ---- Expansion ----

    /// <summary>Open or close a row, as the chevron, a double click, the keyboard or UI Automation does.</summary>
    public void SetExpanded(TreeItem item, bool on)
    {
        if (item.Children.Count == 0 || item.Expanded == on) return;
        var args = new LibraryTreeExpandEventArgs(item);
        if (on) Expanding?.Invoke(this, args); else Collapsed?.Invoke(this, args);
        item.Expanded = on;
        Refresh();
        ContainerFromItem(item)?.RaiseExpandState(on);
    }

    internal void Toggle(TreeItem item) => SetExpanded(item, !item.Expanded);

    // ---- Selection ----

    private void Select(TreeItem? item)
    {
        if (item is not null && !_index.ContainsKey(item)) return;
        ChangeSelection(item);
    }

    private void ChangeSelection(TreeItem? item)
    {
        ClearMore();
        if (ReferenceEquals(_selected, item)) return;
        var old = _selected;
        _selected = item;
        ContainerFromItem(old)?.UpdateState();
        var row = ContainerFromItem(item);
        row?.UpdateState();
        row?.RaiseSelected();
        SelectionChanged?.Invoke(this, new LibraryTreeSelectionChangedEventArgs(
            item is null ? [] : [item], old is null ? [] : [old]));
    }

    /// <summary>A press on a row selects it (and gives it focus).</summary>
    internal void RowPressed(LibraryRow row, FocusState how, bool right = false)
    {
        Trace?.Invoke($"row-pressed item={row.Item?.Name ?? "null"} shown={(row.Item is { } t && _index.ContainsKey(t))} selected={_selected?.Name ?? "null"}");
        if (row.Item is not { } item) return;
        if (PressWithModifiers(row, item, right, how)) return;
        Select(item);
        row.Focus(how);
    }

    /// <summary>A row took keyboard focus: select it (selection follows focus).</summary>
    internal void RowFocused(LibraryRow row)
    {
        if (row.Item is not { } item) return;
        // Keyboard focus moves without Ctrl or Shift (the arrow keys, which WinUI's own navigation may handle before
        // Tree_KeyDown) go back to one row, the focused one, as on the Mac (runner 4, q-win-tree-multi-5).
        if (!IsSelected(item) || (_more.Count > 0 && !IsDown(VirtualKey.Control) && !IsDown(VirtualKey.Shift))) Select(item);
    }

    /// <summary>A click on a row: ItemInvoked, as the TreeView raised it.</summary>
    internal void RowInvoked(LibraryRow row)
    {
        if (_suppressInvoke) { _suppressInvoke = false; return; }
        if (row.Item is { } item) ItemInvoked?.Invoke(this, new LibraryTreeInvokedEventArgs(item));
    }

    /// <summary>Select the row at <paramref name="index"/>, scroll it into view and focus it.</summary>
    private void MoveTo(int index)
    {
        if (_rows.Count == 0) return;
        index = Math.Clamp(index, 0, _rows.Count - 1);
        Select(_rows[index]);
        if (_repeater.GetOrCreateElement(index) is LibraryRow row)
        {
            row.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false });
            row.Focus(FocusState.Keyboard);
        }
    }

    /// <summary>Focus the row for <paramref name="item"/>, realizing it first when it is scrolled out of view.</summary>
    public bool FocusItem(TreeItem item, FocusState how)
    {
        if (!_index.TryGetValue(item, out var index)) return false;
        if (_repeater.GetOrCreateElement(index) is not LibraryRow row) return false;
        row.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false });
        return row.Focus(how);
    }

    private int CurrentIndex(KeyRoutedEventArgs e)
    {
        if (FindRow(e.OriginalSource as DependencyObject)?.Item is { } focused && _index.TryGetValue(focused, out var f)) return f;
        return _selected is not null && _index.TryGetValue(_selected, out var s) ? s : -1;
    }

    private static LibraryRow? FindRow(DependencyObject? d)
    {
        for (; d is not null; d = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(d))
            if (d is LibraryRow row) return row;
        return null;
    }

    private int PageRows => Math.Max(1, (int)(_scroller.ViewportHeight / Math.Max(1, _rowHeight)) - 1);

    private static bool IsDown(VirtualKey key) =>
        InputKeyboardSource.GetKeyStateForCurrentThread(key).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down);

    private void Tree_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (!e.Handled && e.Key == VirtualKey.A && IsDown(VirtualKey.Control) && !IsDown(VirtualKey.Shift) && !IsDown(VirtualKey.Menu) && _rows.Count > 0) { SelectAll(); e.Handled = true; return; }
        if (e.Handled || IsDown(VirtualKey.Control) || IsDown(VirtualKey.Menu) || _rows.Count == 0) return;
        var at = CurrentIndex(e);
        var item = at >= 0 ? _rows[at] : null;
        switch (e.Key)
        {
            case VirtualKey.Down: MoveTo(at + 1); break;
            case VirtualKey.Up: MoveTo(at < 0 ? 0 : at - 1); break;
            case VirtualKey.Home: MoveTo(0); break;
            case VirtualKey.End: MoveTo(_rows.Count - 1); break;
            case VirtualKey.PageDown: MoveTo(at + PageRows); break;
            case VirtualKey.PageUp: MoveTo(at - PageRows); break;
            case VirtualKey.Right when item is not null:
                if (item.Children.Count == 0) return;
                if (!item.Expanded) SetExpanded(item, true); else MoveTo(at + 1);
                break;
            case VirtualKey.Left when item is not null:
                if (item.Expanded && item.Children.Count > 0) { SetExpanded(item, false); break; }
                for (var p = at - 1; p >= 0; p--) if (_depths[p] < _depths[at]) { MoveTo(p); break; }
                break;
            case VirtualKey.Enter or VirtualKey.Space when item is not null:
                Trace?.Invoke($"key {e.Key} at={at} item={(item.IsSession ? "session:" : "")}{item.Name} selected={(_selected?.IsSession == true ? "session:" : "")}{_selected?.Name}");
                var invoked = new LibraryTreeInvokedEventArgs(item);
                ItemInvoked?.Invoke(this, invoked);
                if (!invoked.Handled && item.Children.Count > 0) Toggle(item);
                break;
            default: return;
        }
        e.Handled = true;
    }

    protected override AutomationPeer OnCreateAutomationPeer() => new LibraryTreePeer(this);

    private sealed partial class LibraryTreePeer(LibraryTree owner) : FrameworkElementAutomationPeer(owner), ISelectionProvider
    {
        protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Tree;
        protected override string GetClassNameCore() => "TreeView";
        protected override object GetPatternCore(PatternInterface patternInterface) =>
            patternInterface == PatternInterface.Selection ? this : base.GetPatternCore(patternInterface);

        public bool CanSelectMultiple => true;
        public bool IsSelectionRequired => false;

        public IRawElementProviderSimple[] GetSelection() =>
            owner.SelectedItems.Select(owner.ContainerFromItem).OfType<LibraryRow>().Select(FromElement).OfType<AutomationPeer>().Select(ProviderFromPeer).ToArray();
    }
}

public sealed class LibraryTreeSelectionChangedEventArgs(IList<object> added, IList<object> removed) : EventArgs
{
    public IList<object> AddedItems { get; } = added;
    public IList<object> RemovedItems { get; } = removed;
}

// Item properties are typed object, as on TreeView's args, so XAML's type info does not take TreeItem in.
public sealed class LibraryTreeExpandEventArgs(TreeItem item) : EventArgs
{
    public object Item { get; } = item;
}

public sealed class LibraryTreeInvokedEventArgs(TreeItem item) : EventArgs
{
    public object InvokedItem { get; } = item;
    public bool Handled { get; set; }
}
