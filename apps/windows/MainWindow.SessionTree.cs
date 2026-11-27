using System.Diagnostics;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.System;

namespace Bastion.Shell;

// UI-05: every open tab is also a row in the library tree, under the connection it was opened from
// (docs/design/SESSION-TREE.md; the Mac counterpart is apps/macos SessionTree.swift and LibraryOutline.swift).
// Session rows are UI-only children merged into the core's library tree, keyed by the tab's strip id. They are
// updated by diff (insert, move, remove, repaint one row), never by reloading the tree, and never saved.
public sealed partial class MainWindow
{
    /// <summary>The Other sessions heading (tabs without a saved connection); shown only while it has rows.</summary>
    private readonly TreeItem _otherSessions = new()
    {
        Id = TreeItem.OtherSessionsId, Name = "Other sessions", IsFolder = false, IsGroup = true,
        Glyph = FluentIcons.Action("tab"), IconLabel = "Other sessions", Description = "Open sessions without a saved connection",
    };

    /// <summary>Connections whose session rows the user collapsed; forgotten when their last session closes.</summary>
    private readonly HashSet<string> _sessionCollapsed = new();

    /// <summary>Library connection rows by id (rebuilt when <see cref="_roots"/> is replaced).</summary>
    private Dictionary<string, TreeItem>? _connectionIndex;
    private List<TreeItem>? _indexedRoots;

    /// <summary>Rows that currently hold session children, so a sync never walks the whole library.</summary>
    private readonly Dictionary<string, TreeItem> _sessionParents = new();

    /// <summary>The tree whose folders' connected counts are current (<see cref="RefreshFolderStatus"/>).</summary>
    private List<TreeItem>? _folderStatusRoots;

    /// <summary>Times the TreeView's whole item list was replaced (ApplyFilter); a session change must not add to it.</summary>
    private int _treeReloads;

    /// <summary>Why the last sync touched rows (test trace only; never holds titles).</summary>
    private readonly List<string> _syncWhy = new();

    private void InitSessionTree()
    {
        Tree.AddHandler(UIElement.KeyDownEvent, new KeyEventHandler(SessionTree_KeyDown), handledEventsToo: true);
    }

    /// <summary>The library row a tab belongs to: its connection, or the web / RDP connection it opened.</summary>
    private static string? SessionConnectionId(WorkspaceTab tab) =>
        tab.ConnectionId ?? (tab.Rdp is not null || tab.Web is not null ? tab.HostColorId : null);

    private static SessionRowState SessionState(WorkspaceTab tab)
    {
        if (tab.Waiting is not null) return SessionRowState.NotStarted;
        if (tab.Link is { } link)
            return link.Status.State switch
            {
                SessionLinkState.Connecting or SessionLinkState.Reconnecting or SessionLinkState.Suspended => SessionRowState.Connecting,
                SessionLinkState.Failed or SessionLinkState.Closed => SessionRowState.Failed,
                _ => SessionRowState.Connected,
            };
        return tab.Exited ? SessionRowState.Failed : SessionRowState.Connected;
    }

    private TreeItem? LibraryConnection(string id)
    {
        if (!ReferenceEquals(_indexedRoots, _roots) || _connectionIndex is null)
        {
            _indexedRoots = _roots;
            _connectionIndex = new();
            void Walk(IEnumerable<TreeItem> level)
            {
                foreach (var i in level)
                {
                    if (i.Connection is not null && !i.IsMirror)
                    {
                        _connectionIndex[i.Id] = i;
                        // A row a rebuild kept (WIN-TREE-REBUILD) still holds its session rows: the sync must see it.
                        if (i.Children.Count > 0 && i.Children[0].IsSession) _sessionParents[i.Id] = i;
                    }
                    if (i.IsFolder) Walk(i.Children);
                }
            }
            _sessionParents.Clear(); // the old rows went with the old tree; kept rows are added back by the walk
            Walk(_roots);
        }
        return _connectionIndex.GetValueOrDefault(id);
    }

    /// <summary>
    /// Bring the session rows in line with the tab list: called when a tab opens, closes, moves, changes state or title,
    /// and after the tree is rebuilt. Cheap when nothing changed (no row is touched).
    /// </summary>
    private void SyncSessionRows()
    {
        var clock = Stopwatch.StartNew();
        var wanted = new Dictionary<TreeItem, List<WorkspaceTab>>();
        var other = new List<WorkspaceTab>();
        foreach (var tab in _tabs)
        {
            var parent = SessionConnectionId(tab) is { } id ? LibraryConnection(id) : null;
            if (parent is null) other.Add(tab);
            else
            {
                if (!wanted.TryGetValue(parent, out var list)) wanted[parent] = list = new();
                list.Add(tab);
            }
        }
        var changed = 0;
        _syncWhy.Clear();
        foreach (var gone in _sessionParents.Values.Where(p => p != _otherSessions && !wanted.ContainsKey(p)).ToList())
            changed += SyncChildren(gone, []);
        foreach (var (parent, tabs) in wanted) changed += SyncChildren(parent, tabs);
        if (_query.Length > 0) other = other.Where(t => t.Title.Contains(_query, StringComparison.OrdinalIgnoreCase)).ToList();
        changed += SyncChildren(_otherSessions, other);
        ShowOtherSessions(other.Count > 0);
        SyncPluginSidebarRows();
        // A rebuild keeps unchanged rows with their counts (WIN-TREE-REBUILD), so a new folder row above a kept connection
        // with sessions needs its count even when no session row moved.
        if (changed > 0 || !ReferenceEquals(_folderStatusRoots, _roots)) { RefreshFolderStatus(_roots); _folderStatusRoots = _roots; }
        if (changed > 0) TraceSessionTree($"sync rows={changed} ms={clock.Elapsed.TotalMilliseconds:F2} reloads={_treeReloads} tabs={_tabs.Count} why={string.Join(',', _syncWhy)}");
    }

    /// <summary>UI-01: a collapsed folder's connected count; returns the connected items inside.</summary>
    private static int RefreshFolderStatus(IEnumerable<TreeItem> level)
    {
        var total = 0;
        foreach (var i in level)
        {
            if (i.IsFolder) { var n = RefreshFolderStatus(i.Children); i.ConnectedInside = n; total += n; }
            else if (i.Connection is not null && !i.IsMirror && i.LinkState == SessionRowState.Connected) total++;
        }
        return total;
    }

    /// <summary>Make <paramref name="parent"/>'s leading session rows match <paramref name="tabs"/>; returns rows touched.</summary>
    private int SyncChildren(TreeItem parent, List<WorkspaceTab> tabs)
    {
        var rows = parent.Children;
        var before = parent.SessionCount;
        var touched = 0;
        for (var i = 0; i < tabs.Count; i++)
        {
            var tab = tabs[i];
            var at = -1;
            for (var j = i; j < rows.Count && rows[j].IsSession; j++) if (rows[j].TabId == tab.StripId) { at = j; break; }
            if (at < 0) { rows.Insert(i, NewSessionRow(tab, parent)); touched++; _syncWhy.Add("insert"); continue; }
            if (at != i) { rows.Move(at, i); touched++; _syncWhy.Add("move"); }
            var row = rows[i];
            var title = tab.Title;
            var state = SessionState(tab);
            if (row.Title != title || row.State != state || row.SessionOf != SessionParentName(parent))
            {
                if (TestHooks.SessionTreeTrace is not null)
                    _syncWhy.Add(row.Title != title ? "title" : row.State != state ? $"state:{row.State}>{state}" : "parent");
                row.SessionOf = SessionParentName(parent);
                row.Title = title;
                row.State = state;
                touched++;
            }
        }
        while (tabs.Count < rows.Count && rows[tabs.Count].IsSession) { rows.RemoveAt(tabs.Count); touched++; _syncWhy.Add("remove"); }
        var after = tabs.Count;
        if (after > 0) _sessionParents[parent.Id] = parent; else _sessionParents.Remove(parent.Id);
        if (before != after)
        {
            if (parent.Connection is not null)
            {
                if (before == 0) SetSessionParentExpanded(parent, !_sessionCollapsed.Contains(parent.Id)); // first session: open
                // A plain row again; a plugin entry whose tree is open stays open (PLUG-API-13).
                if (after == 0) { _sessionCollapsed.Remove(parent.Id); if (!_sidebarViews.ContainsKey(parent.Id)) parent.Expanded = false; }
            }
        }
        if (touched > 0) parent.SessionsChanged(); // UI-01: the row's status mark follows its sessions' state
        return touched;
    }

    private string SessionParentName(TreeItem parent) => parent.Connection is null ? "" : parent.Name;

    private static TreeItem NewSessionRow(WorkspaceTab tab, TreeItem parent) => new()
    {
        Id = "session:" + tab.StripId, Name = tab.Title, IsFolder = false, IsSession = true, TabId = tab.StripId,
        ParentId = parent.Id, Glyph = "", Expanded = false,
        SessionOf = parent.Connection is null ? "" : parent.Name, Title = tab.Title, State = SessionState(tab),
    };

    private void SetSessionParentExpanded(TreeItem parent, bool on)
    {
        parent.Expanded = on; // the tree follows on its next pass (TreeItem.ExpandedChanged)
    }

    /// <summary>The Other sessions heading sits at the bottom of the library, before the Application section.</summary>
    private void ShowOtherSessions(bool show)
    {
        var at = _shownSource.IndexOf(_otherSessions);
        if (show == at >= 0) return;
        if (!show)
        {
            _shownSource.RemoveAt(at);
            _shown.Remove(_otherSessions);
            return;
        }
        // Expanded first: the template binds IsExpanded once, when the container is made on insert.
        _otherSessions.Expanded = true;
        var index = _shownSource.Count > 0 && _shownSource[^1].Id == TreeItem.ApplicationGroupId ? _shownSource.Count - 1 : _shownSource.Count;
        _shownSource.Insert(index, _otherSessions);
        _shown.Insert(Math.Min(index, _shown.Count), _otherSessions);
    }

    /// <summary>The tab a session row stands for.</summary>
    private WorkspaceTab? TabForRow(TreeItem? row) => row is { IsSession: true } ? _tabs.FirstOrDefault(t => t.StripId == row.TabId) : null;

    /// <summary>Click, Enter or Space on a session row focuses its tab; it never opens a new session.</summary>
    private bool InvokeSessionRow(TreeItem? row)
    {
        if (TabForRow(row) is not { } tab) return row is { IsSession: true };
        PickTab(tab); // DASH-01: hides a folder dashboard shown over the tabs
        return true;
    }

    private void SessionTree_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        _treeLog?.Invoke($"session-key {e.Key} handled={e.Handled} selected={(Tree.SelectedItem is TreeItem { IsSession: true } t ? "session:" + t.Name + " tab=" + (TabForRow(t) is not null) : (Tree.SelectedItem as TreeItem)?.Name)} focus={FocusManager.GetFocusedElement(Tree.XamlRoot)?.GetType().Name}");
        if (Tree.SelectedItem is not TreeItem { IsSession: true } row) return;
        var ctrl = Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Control).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down);
        switch (e.Key)
        {
            case VirtualKey.W when ctrl:
                if (TabForRow(row) is { } tab) _ = RequestCloseTab(tab, FocusState.Keyboard);
                e.Handled = true;
                break;
            case VirtualKey.Space:
                InvokeSessionRow(row);
                e.Handled = true;
                break;
        }
    }

    /// <summary>The context menu of a session row: Go to Tab, Close Tab, Reveal Connection.</summary>
    private void ShowSessionMenu(TreeItem row, FrameworkElement anchor, Microsoft.UI.Xaml.Controls.Primitives.FlyoutShowOptions options)
    {
        var menu = new MenuFlyout();
        var go = new MenuFlyoutItem { Text = "Go to Tab" };
        go.Click += (_, _) => InvokeSessionRow(row);
        var close = new MenuFlyoutItem { Text = "Close Tab", KeyboardAcceleratorTextOverride = "Ctrl+W" };
        close.Click += (_, _) => { if (TabForRow(row) is { } tab) _ = RequestCloseTab(tab, FocusState.Pointer); };
        menu.Items.Add(go);
        menu.Items.Add(close);
        if (row.ParentId is { } parent && parent != TreeItem.OtherSessionsId)
        {
            var reveal = new MenuFlyoutItem { Text = "Reveal Connection" };
            reveal.Click += (_, _) => { SelectItem(parent); FocusTreeSelection(FocusState.Keyboard); };
            menu.Items.Add(reveal);
        }
        menu.ShowAt(anchor, options);
    }

    private void TraceSessionTree(string line)
    {
        if (TestHooks.SessionTreeTrace is not { } path) return;
        try { File.AppendAllText(path, line + Environment.NewLine); }
        catch (IOException) { /* a trace is best effort */ }
    }
}
