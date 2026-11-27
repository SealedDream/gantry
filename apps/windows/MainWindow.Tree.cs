using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;

namespace Bastion.Shell;

// The navigation tree on the core registry (C ABI 15): context menus come from core/src/actions.rs, limited to
// `Handled`, which is exactly the set of action ids RunAsync implements, so the core never offers an action without a
// handler here (the same rule as apps/macos Commands.swift). Also: persisted expansion (ui-state.json), drag-and-drop
// ordering, rename, duplicate, sort, favourites and the core's icons with their full names.
public sealed partial class MainWindow
{
    private static readonly string[] Handled =
    [
        "connect", "connect-new-tab", "reconnect", "disconnect", "open-sftp",
        "copy-ssh-command", "copy-hostname", "copy-username", "copy-address",
        "new-connection", "new-subfolder", "connect-all", "disconnect-all", "reconnect-all", "expand-all", "collapse-all", "sort",
        "rename", "duplicate", "save-as-template", "move", "toggle-favorite", "add-to-workspace", "properties", "delete",
    ];

    private const string DragFormat = "bastion-node";

    /// <summary>Persisted open folders; null in demo mode, where <see cref="_expanded"/> lives in memory only.</summary>
    private TreeStateClient? _treeState;
    private HashSet<string> _expanded = new();
    private string? _dragId;
    private Dictionary<string, string>? _iconColors;
    private readonly Dictionary<string, Brush> _iconBrushes = new();

    private void InitTreeState()
    {
        if (_demo)
        {
            // Snapshot mode shows the demo library open; nothing is written.
            _expanded = AllFolderIds(TreeItem.Build(_library.Tree(), _ => null)).ToHashSet();
            return;
        }
        try
        {
            var path = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(_personal.Path) ?? ".", "ui-state.json");
            var first = !File.Exists(path);
            _treeState = TreeStateClient.Open(path);
            // A library opened for the first time shows its folders open, as before the state was kept.
            if (first) _treeState.SetSubtree(_library, null, true);
            _expanded = _treeState.Expanded();
        }
        catch (BastionException)
        {
            _treeState = null; // view state is disposable: folders open in memory only
            _expanded = AllFolderIds(TreeItem.Build(_library.Tree(), _ => null)).ToHashSet();
        }
    }

    private static IEnumerable<string> AllFolderIds(IEnumerable<TreeItem> items) =>
        items.Where(i => i.IsFolder).SelectMany(i => AllFolderIds(i.Children).Prepend(i.Id));

    /// <summary>The core's tint (<c>icon.terminal</c>) for the current theme, as a brush.</summary>
    private Brush? IconBrush(string token)
    {
        if (_iconColors is null)
        {
            _iconBrushes.Clear();
            try { _iconColors = LibraryClient.ThemeColors(RootGrid.ActualTheme == ElementTheme.Dark); }
            catch (BastionException) { _iconColors = new(); }
        }
        if (_iconBrushes.TryGetValue(token, out var cached)) return cached;
        if (!_iconColors.TryGetValue(token, out var hex) || hex.Length != 7) return Ui.Brush(RootGrid, "TextSecondaryBrush");
        var brush = new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(0xFF, Convert.ToByte(hex[1..3], 16), Convert.ToByte(hex[3..5], 16), Convert.ToByte(hex[5..7], 16)));
        _iconBrushes[token] = brush;
        return brush;
    }

    /// <summary>Typing pause before a search runs (WIN-FILTER-INPLACE: 120 ms, coordinator 2026-11-15).</summary>
    private const int SearchDebounceMs = 120;

    /// <summary>While searching, the folders on the path to the first this-many matches open; the rest stay shut with
    /// their matches inside (WIN-FILTER-INPLACE: opening every folder of a broad match made the tree lay out thousands of
    /// rows per keystroke). About two screens of rows.</summary>
    private const int SearchAutoOpenMatches = 50;

    /// <summary>Ids that open during the current search; empty when not searching.</summary>
    private HashSet<string> _searchOpen = new();

    /// <summary>The folders (and connections with session rows) on the path to the first <see cref="SearchAutoOpenMatches"/>
    /// connections of <paramref name="shown"/>, in tree order.</summary>
    internal static HashSet<string> SearchOpenIds(IEnumerable<TreeItem> shown, int limit)
    {
        var open = new HashSet<string>();
        var path = new List<string>();
        var left = limit;
        void Walk(IEnumerable<TreeItem> items)
        {
            foreach (var item in items)
            {
                if (left <= 0) return;
                if (item.Connection is not null && !item.IsSession)
                {
                    left--;
                    open.UnionWith(path);
                    if (item.HasChildren) open.Add(item.Id);
                    continue;
                }
                if (!item.HasChildren) continue;
                path.Add(item.Id);
                Walk(item.Children);
                path.RemoveAt(path.Count - 1);
            }
        }
        Walk(shown);
        return open;
    }

    /// <summary>Folders open when the user opened them before; while searching the folders on the path to the first
    /// matches open (<see cref="SearchAutoOpenMatches"/>).</summary>
    private void MarkExpanded(IEnumerable<TreeItem> items)
    {
        if (ReferenceEquals(items, _shown)) _searchOpen = _query.Length > 0 ? SearchOpenIds(_shown, TestHooks.FilterRebind ? int.MaxValue : SearchAutoOpenMatches) : new(); // the test switch is the old behaviour
        MarkExpandedCore(items);
    }

    private void MarkExpandedCore(IEnumerable<TreeItem> items)
    {
        foreach (var item in items.Where(i => i.HasChildren))
        {
            // Section headings and Credentials stay open; Default Settings opens when asked (it lists every type).
            // UI-05: a connection with sessions keeps its own choice (open unless the user collapsed it).
            // PLUG-API-13: a plugin's tree shows while its session runs; its item rows keep their own state.
            item.Expanded = item.IsPluginRow ? item.Expanded
                : item.HasSidebarTree && item.SessionCount == 0 ? _sidebarViews.ContainsKey(item.Id)
                : item.Connection is not null
                ? (_query.Length > 0 ? _searchOpen.Contains(item.Id) : !_sessionCollapsed.Contains(item.Id))
                : (item.IsGroup && (!item.IsAppRow || item.Id == TreeItem.CredentialsGroupId)) || (_query.Length > 0 ? _searchOpen.Contains(item.Id) : _expanded.Contains(item.Id));
            MarkExpandedCore(item.Children);
        }
    }

    private void Tree_Expanding(LibraryTree sender, LibraryTreeExpandEventArgs args)
    {
        if (args.Item is not TreeItem item) return;
        if (item.Connection is not null) _sessionCollapsed.Remove(item.Id);
        if (_query.Length == 0 && item.IsFolder) SaveExpanded(item.Id, true);
        if (item.HasSidebarTree) OpenPluginSidebar(item);
        else if (item.IsPluginRow) ExpandPluginRow(item);
    }

    private void Tree_Collapsed(LibraryTree sender, LibraryTreeExpandEventArgs args)
    {
        if (args.Item is not TreeItem item) return;
        if (item.Connection is not null && item.SessionCount > 0) _sessionCollapsed.Add(item.Id);
        if (_query.Length == 0 && item.IsFolder) SaveExpanded(item.Id, false);
        if (item.HasSidebarTree) ClosePluginSidebar(item.Id);
        else if (item.IsPluginRow) CollapsePluginRow(item);
    }

    private void SaveExpanded(string id, bool on)
    {
        if (on ? !_expanded.Add(id) : !_expanded.Remove(id)) return;
        try { _treeState?.SetExpanded(id, on); }
        catch (BastionException) { /* the next change retries; the tree itself is right */ }
    }

    /// <summary>Expand All / Collapse All on a folder (null = the whole library), saved at once.</summary>
    private void SetSubtree(string? folderId, bool on)
    {
        var scope = folderId is null ? _roots : TreeItem.Find(_roots, folderId) is { } f ? [f] : [];
        foreach (var id in AllFolderIds(scope))
        {
            if (on) _expanded.Add(id); else _expanded.Remove(id);
        }
        try
        {
            if (_treeState is { } state)
            {
                state.SetSubtree(_library, folderId, on);
                _expanded = state.Expanded();
            }
        }
        catch (BastionException ex)
        {
            _ = ShowModal("Could not save the view state", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
        }
        ApplyFilter(keepSelection: true);
    }

    /// <summary>Forget folders that no longer exist (after a delete).</summary>
    private void PruneTreeState()
    {
        try { _treeState?.Prune(_library); }
        catch (BastionException) { /* stale ids are harmless */ }
    }

    // ---- Registry context menu ----

    /// <summary>Connections with an open tab, for the core's Show Session / Disconnect wording.</summary>
    private IEnumerable<string> ConnectedIds => _tabs.Where(t => t.ConnectionId is not null).Select(t => t.ConnectionId!).Distinct();

    /// <summary>Connections with a tab whose session is up or coming up: not ended by Disconnect (the tab stays, WIN-RECONNECT-PANE)
    /// nor lost for good. What the folder dashboard calls Connected.</summary>
    private IEnumerable<string> LiveConnectionIds => _tabs
        .Where(t => t.ConnectionId is not null && SessionState(t) is SessionRowState.Connected or SessionRowState.Connecting)
        .Select(t => t.ConnectionId!).Distinct();

    private void Tree_ContextRequested(UIElement sender, ContextRequestedEventArgs args)
    {
        args.Handled = true;
        OpenTreeMenu(args.OriginalSource as DependencyObject, anchor => args.TryGetPosition(anchor, out var p) ? p : null);
    }

    /// <summary>
    /// Diagnostics for WIN-MAIN-UI-FIXES: with BASTION_TREE_INPUT_LOG set to a file path, the tree's pointer and context
    /// events (handled ones too) are appended there. Off by default; nothing is recorded but event names and button state.
    /// </summary>
    /// <summary>Test-hooks diagnostics (BASTION_TREE_INPUT_LOG): set by InitTreeInputLog, null otherwise.</summary>
    private Action<string>? _treeLog;

    private void InitTreeInputLog()
    {
        var path = TestHooks.TreeInputLog; // test-hooks builds only
        if (string.IsNullOrEmpty(path)) return;
        void Log(string what)
        {
            try { File.AppendAllText(path, $"{DateTime.Now:HH:mm:ss.fff} {what}{Environment.NewLine}"); }
            catch (IOException) { /* diagnostics only */ }
            catch (UnauthorizedAccessException) { /* diagnostics only */ }
        }
        string Kind(PointerRoutedEventArgs e) => e.GetCurrentPoint(Tree).Properties.PointerUpdateKind.ToString();
        Tree.AddHandler(UIElement.PointerEnteredEvent, new PointerEventHandler((_, e) => Log($"entered {e.OriginalSource?.GetType().Name}")), true);
        Tree.AddHandler(UIElement.PointerPressedEvent, new PointerEventHandler((_, e) => Log($"pressed {Kind(e)} handled={e.Handled} {e.OriginalSource?.GetType().Name}")), true);
        Tree.AddHandler(UIElement.PointerReleasedEvent, new PointerEventHandler((_, e) => Log($"released {Kind(e)} handled={e.Handled}")), true);
        Tree.AddHandler(UIElement.PointerCaptureLostEvent, new PointerEventHandler((_, _) => Log("capture-lost")), true);
        Tree.AddHandler(UIElement.PointerCanceledEvent, new PointerEventHandler((_, _) => Log("canceled")), true);
        Tree.AddHandler(UIElement.RightTappedEvent, new RightTappedEventHandler((_, e) => Log($"right-tapped handled={e.Handled}")), true);
        Tree.ContextRequested += (_, _) => Log("context-requested");
        string Names(IList<object> items) => string.Join("|", items.Select(i => i is TreeItem t ? (t.IsSession ? "session:" : "") + t.Name : i?.GetType().Name ?? "null"));
        Tree.SelectionChanged += (_, e) => Log($"selection-changed added={Names(e.AddedItems)} removed={Names(e.RemovedItems)}");
        Tree.ContextCanceled += (_, _) => Log("context-canceled");
        Tree.AddHandler(UIElement.ContextRequestedEvent, new Windows.Foundation.TypedEventHandler<UIElement, ContextRequestedEventArgs>((_, e) => Log($"context-requested(any) handled={e.Handled}")), true);
        TreeMenu.Opening += (_, _) => Log("menu-opening");
        Tree.Loaded += (_, _) => Log("tree-loaded");
        Tree.Unloaded += (_, _) => Log("tree-unloaded");
        LibraryTree.Trace = Log;
        _treeLog = what => Log($"{what}");
        TreeMenu.Opened += (_, _) => Log($"menu-opened target={_contextTarget?.Name ?? "root"} items={string.Join("|", TreeMenu.Items.OfType<MenuFlyoutItem>().Select(i => i.Text))} popups={OpenPopups()}");
        TreeMenu.Closing += (_, e) => Log($"menu-closing cancel={e.Cancel} focus={FocusManager.GetFocusedElement(Tree.XamlRoot)?.GetType().Name} popups={OpenPopups()}");
        TreeMenu.Closed += (_, _) => Log("menu-closed");
        if (Content is UIElement root)
        {
            string Chain(DependencyObject? d)
            {
                var names = new List<string>();
                for (; d is not null && names.Count < 14; d = VisualTreeHelper.GetParent(d))
                    names.Add(d is FrameworkElement { Name.Length: > 0 } f ? $"{d.GetType().Name}#{f.Name}" : d.GetType().Name);
                return string.Join(" < ", names);
            }
            root.AddHandler(UIElement.PointerPressedEvent, new PointerEventHandler((_, e) =>
            {
                var at = e.GetCurrentPoint(null).Position;
                var hits = VisualTreeHelper.FindElementsInHostCoordinates(at, root).Take(6).Select(h => h.GetType().Name);
                Log($"root-pressed at={at.X:0},{at.Y:0} handled={e.Handled} src={Chain(e.OriginalSource as DependencyObject)} hits={string.Join("|", hits)}");
            }), true);
        }
        Log("log started");
    }

    private void OpenTreeMenu(DependencyObject? source, Func<UIElement, Windows.Foundation.Point?> position)
    {
        var container = FindAncestor<LibraryRow>(source);
        _contextTarget = container is null ? null : Tree.ItemFromContainer(container) as TreeItem;
        if (_contextTarget is { IsSession: true } session && container is not null)
        {
            // UI-05: a session row has its own menu (Go to Tab, Close Tab, Reveal Connection).
            SelectForMenu(session);
            var at = new FlyoutShowOptions();
            if (position(container) is { } p) at.Position = p;
            ShowSessionMenu(session, container, at);
            return;
        }
        if (_contextTarget is { IsPluginRow: true, PluginMenu.Count: 0 }) return; // a status row of a plugin's tree
        // A section heading has no commands; task rows under Application > Tasks have the task menu (TABBAR-WIN).
        if (_contextTarget is { IsGroup: true } && !IsCredentialTarget(_contextTarget) && !IsTaskRow(_contextTarget)) return;
        SelectForMenu(_contextTarget);
        if (_contextTarget is null) UpdateInspector(null);
        var options = new FlyoutShowOptions();
        FrameworkElement anchor = container is not null ? container : Tree;
        if (position(anchor) is { } point) options.Position = point;
        TreeMenu.ShowAt(anchor, options);
    }

    /// <summary>Commands act on the selection, so right-clicking an item selects it, and empty space means the root.</summary>
    private void SelectForMenu(TreeItem? target)
    {
        if (ReferenceEquals(Tree.SelectedItem, target)) return;
        if (target is not null && Tree.SelectedItems.Count > 1 && Tree.SelectedItems.Contains(target)) return; // keep the multi-selection
        try { Tree.SelectedItem = target; }
        catch { /* Selection is a convenience here; the menu still works from _contextTarget. */ }
    }

    /// <summary>
    /// A right press selects its row before the menu is asked for (as Explorer does). Selected in ContextRequested
    /// instead, the TreeView's own work for the new selection landed while the menu was opening and closed it again
    /// within 60 ms (WIN-MAIN-UI-FIXES: every failing right-click changed the selection; Shift+F10 and right-clicks on
    /// the already selected row opened it). A press on empty space clears the selection for the root menu the same way.
    /// Registered for handled presses too, since the row handles its own.
    /// </summary>
    private void InitTreeRightPress() =>
        Tree.AddHandler(UIElement.PointerPressedEvent, new PointerEventHandler((_, e) =>
        {
            if (!e.GetCurrentPoint(Tree).Properties.IsRightButtonPressed) return;
            // Empty space means the library root: clear the selection here too, not in ContextRequested, where the
            // deselection's work closed the just-opened root menu (q869l: 'right-click on empty space' failed).
            if (FindAncestor<LibraryRow>(e.OriginalSource as DependencyObject) is not { } row) { SelectForMenu(null); return; }
            if (Tree.ItemFromContainer(row) is not TreeItem { IsGroup: false } item) return;
            SelectForMenu(item);
        }), true);

    private string OpenPopups() =>
        string.Join(",", Microsoft.UI.Xaml.Media.VisualTreeHelper.GetOpenPopupsForXamlRoot(Tree.XamlRoot).Select(p => p.Child?.GetType().Name ?? "null"));


    private void TreeMenu_Opening(object sender, object e)
    {
        TreeMenu.Items.Clear();
        if (_contextTarget is { IsPluginRow: true } pluginRow)
        {
            foreach (var entry in PluginRowMenu(pluginRow)) TreeMenu.Items.Add(entry);
            return;
        }
        var entries = IsCredentialTarget(_contextTarget) ? CredentialMenuEntries(_contextTarget!)
            : _contextTarget is not null && TreeMultiSelection() is { } many && many.Any(i => i.Id == _contextTarget.Id) ? SelectionMenuEntries(many)
            : MenuEntries(_contextTarget);
        foreach (var entry in entries) TreeMenu.Items.Add(entry);
    }

    /// <summary>
    /// The registry's menu for <paramref name="target"/> (null = library root) as flyout items, with separators between
    /// sections, then the Windows-only credential assignments in their own section. Shared by the tree and the inspector.
    /// </summary>
    private List<MenuFlyoutItemBase> MenuEntries(TreeItem? target)
    {
        if (TaskRowMenu(target) is { } taskMenu) return taskMenu; // TABBAR-WIN: task rows in Application > Tasks
        var full = target is null ? null : TreeItem.Find(_roots, target.Id) ?? target;
        List<MenuItemDto> items;
        try { items = _library.Menu(full?.Id, Handled, ConnectedIds); }
        catch (BastionException) { items = []; }
        if (full is null && items.Count == 0) return RootMenuEntries();
        var result = new List<MenuFlyoutItemBase>();
        for (var i = 0; i < items.Count; i++)
        {
            var m = items[i];
            if (i > 0 && items[i - 1].Section != m.Section) result.Add(new MenuFlyoutSeparator());
            result.Add(m.Id == "add-to-workspace" && full?.Connection is { } c ? AddToWorkspaceMenu(m, c) : MenuEntry(m, full));
        }
        if (full?.Connection is not null)
        {
            result.Add(new MenuFlyoutSeparator());
            if (ProtocolMenu(full.Connection) is { } protocol) result.Add(protocol);
            if (WakeEntry(full.Connection) is { } wake) result.Add(wake);
            if (IsSsh(full)) result.Add(ExtraEntry("Connect as…", "credential", (_, _) => _ = ConnectAsync(full, connectAs: true)));
            if (RunTaskMenu(full) is { } runTask) result.Add(runTask);
            result.Add(ExtraEntry("Attached Tasks…", "task", (_, _) => _ = EditTaskHooksAsync(full)));
            AddSystemViewEntries(result, full);
            result.Add(ExtraEntry("Assign credential…", "credential", (_, _) => _ = AssignCredentialAsync()));
            result.Add(ExtraEntry("Logins…", "credential", (_, _) => _ = ShowLoginsDialogAsync(full.Connection.Id, full.Name)));
            result.Add(ExtraEntry("Assign Vaultwarden login…", "vault", (_, _) => _ = AssignVaultwardenAsync()));
        }
        else if (full?.Folder is not null)
        {
            result.Add(new MenuFlyoutSeparator());
            if (RunTaskMenu(full) is { } runTask) result.Add(runTask);
            result.Add(ExtraEntry("Attached Tasks…", "task", (_, _) => _ = EditTaskHooksAsync(full)));
            result.Add(ExtraEntry("Assign credential…", "credential", (_, _) => _ = AssignCredentialAsync()));
            AddDynamicFolderEntries(result, full);
        }
        return result;
    }

    private static FontIcon MenuIcon(string glyph) =>
        new() { Glyph = glyph, FontFamily = (FontFamily)Application.Current.Resources["SymbolFontFamily"] };

    private MenuFlyoutItem MenuEntry(MenuItemDto m, TreeItem? target)
    {
        var entry = new MenuFlyoutItem { Text = m.Label, IsEnabled = m.Enabled, Icon = MenuIcon(FluentIcons.Action(m.Glyph)) };
        if (m.Primary) entry.FontWeight = Microsoft.UI.Text.FontWeights.SemiBold;
        if (KeyHint(m.Id) is { } keys) entry.KeyboardAcceleratorTextOverride = keys;
        // A disabled entry says why (the core's reason), for the pointer and for screen readers.
        if (m.DisabledReason is { } why)
        {
            ToolTipService.SetToolTip(entry, why);
            AutomationProperties.SetHelpText(entry, why);
        }
        // Empty space is the library root: there it is New Folder, not New Subfolder (owner 2026-11-15, as on the Mac).
        if (target is null && m.Id == "new-subfolder") { entry.Text = "New Folder"; AutomationProperties.SetName(entry, "New Folder"); }
        entry.Click += (_, _) => _ = PerformAsync(m, target);
        return entry;
    }

    private static MenuFlyoutItem ExtraEntry(string label, string icon, RoutedEventHandler click)
    {
        var entry = new MenuFlyoutItem { Text = label, Icon = MenuIcon(FluentIcons.Object(icon)) };
        AutomationProperties.SetName(entry, label.TrimEnd('…'));
        entry.Click += click;
        return entry;
    }

    /// <summary>The keys shown beside a menu entry.</summary>
    private static string? KeyHint(string action) => action switch
    {
        "connect" => "Enter",
        "rename" => "F2",
        "properties" => "Alt+Enter",
        "delete" => "Del",
        "new-connection" => "Ctrl+N",
        "new-subfolder" => "Ctrl+Shift+N",
        _ => null,
    };

    /// <summary>
    /// Add to Workspace: the saved workspaces (one already opening the connection is checked and disabled), then
    /// New Workspace…, as on macOS.
    /// </summary>
    private MenuFlyoutSubItem AddToWorkspaceMenu(MenuItemDto m, ConnectionDto c)
    {
        var sub = new MenuFlyoutSubItem { Text = m.Label, IsEnabled = m.Enabled, Icon = MenuIcon(FluentIcons.Action(m.Glyph)) };
        IReadOnlyList<WorkspaceDto> all;
        try { all = Workspaces.List(); }
        catch (BastionException) { all = []; }
        foreach (var ws in all)
        {
            var member = ws.Tabs.Any(t => t.Connection == c.Id && t.Mode == "terminal");
            var item = new ToggleMenuFlyoutItem { Text = ws.Name, IsChecked = member, IsEnabled = !member };
            AutomationProperties.SetName(item, member ? $"{ws.Name}, already opens {c.Name}" : "Add to " + ws.Name);
            item.Click += (_, _) => _ = AddToWorkspaceAsync(c, ws);
            sub.Items.Add(item);
        }
        if (all.Count > 0) sub.Items.Add(new MenuFlyoutSeparator());
        var create = new MenuFlyoutItem { Text = "New Workspace…" };
        AutomationProperties.SetName(create, "New workspace with " + c.Name);
        create.Click += (_, _) => _ = NewWorkspaceWithAsync(c);
        sub.Items.Add(create);
        return sub;
    }

    /// <summary>Run a menu entry, asking first when the core says it needs confirmation.</summary>
    private async Task PerformAsync(MenuItemDto item, TreeItem? target)
    {
        if (!item.Enabled) return;
        // Delete keeps its own dialog, which names what goes with a folder.
        if (item.Confirm is { } question && item.Id != "delete")
        {
            var body = Ui.Text(target?.Name ?? "Library", "BodyTextStyle");
            if (!await ShowModal(question, body, primary: item.Label.Replace("…", ""), cancel: "Cancel", focusCancel: item.Destructive)) return;
        }
        await RunAsync(item.Id, target);
    }

    private async Task RunAsync(string action, TreeItem? target)
    {
        var full = target is null ? null : TreeItem.Find(_roots, target.Id) ?? target;
        var c = full?.Connection;
        switch (action)
        {
            case "connect" when full is not null:
                // A tab whose session is up (or coming up) is shown; an SSH tab ended by Disconnect connects again in its place.
                if (_tabs.FirstOrDefault(t => t.ConnectionId == full.Id && SessionState(t) != SessionRowState.Failed) is { } open) PickTab(open);
                else if (ReconnectTarget(full) is { } ended) { PickTab(ended); await ConnectAsync(full, replacing: ended); }
                else await ConnectAsync(full);
                break;
            case "connect-new-tab" when full is not null: await ConnectAsync(full); break;
            case "reconnect" when full is not null:
                // An SSH terminal tab is replaced in place once the new session is up: closing it first showed the start
                // page until the new tab came (WIN-RECONNECT-PANE, Mac #1274). Its other tabs close, as before.
                if (ReconnectTarget(full) is { } inPlace)
                {
                    foreach (var other in _tabs.Where(t => t.ConnectionId == full.Id && !ReferenceEquals(t, inPlace)).ToList()) CloseTab(other);
                    PickTab(inPlace);
                    await ConnectAsync(full, replacing: inPlace);
                    break;
                }
                // Other kinds (desktops, Telnet) as before: their tabs close, then a new connect.
                CloseConnectionTabs([full.Id]);
                await ConnectAsync(full);
                break;
            case "open-sftp" when full is not null:
                var before = _tabs.Count;
                await ConnectAsync(full);
                if (_tabs.Count > before && _tabs[^1].Files is null) await ToggleFilesAsync(_tabs[^1]);
                break;
            case "disconnect" when full is not null: Disconnect([full.Id]); break;
            case "connect-all": await ConnectAllAsync(full); break;
            case "disconnect-all": Disconnect(ConnectionIdsUnder(full)); break;
            case "reconnect-all": await ReconnectAllAsync(full); break;
            case "copy-hostname" when c is not null: CopyToClipboard(c.Host, "Host name copied"); break;
            case "copy-username" when c is not null: CopyToClipboard(EffectiveUser(c) ?? "", "User name copied"); break;
            case "copy-address" when full is not null: CopyLibraryText(full.Id, sshCommand: false, "Address copied"); break;
            case "copy-ssh-command" when full is not null: CopyLibraryText(full.Id, sshCommand: true, "SSH command copied"); break;
            case "new-connection": await NewConnectionAsync(); break;
            case "new-subfolder": await NewFolderInAsync(full is null ? null : full.IsFolder ? full : CurrentParent()); break; // empty space: the root
            case "expand-all": SetSubtree(full?.Id, true); break;
            case "collapse-all": SetSubtree(full?.Id, false); break;
            case "sort": await Mutate(() => { _library.Sort(full?.Id); return full?.Id; }, "Could not sort"); break;
            case "rename" when full is not null: await RenameAsync(full); break;
            case "duplicate" when full is not null: await Mutate(() => _library.Duplicate(full.Id), "Could not duplicate " + full.Name); break;
            case "move" when full is not null: await MoveToAsync(full); break;
            case "save-as-template" when c is not null && full is not null: await SaveAsTemplateAsync(full); break;
            case "toggle-favorite" when c is not null:
                await Mutate(() => { _library.SetFavorite(c.Id, !c.Favorite); return c.Id; }, "Could not change Favorites");
                break;
            case "add-to-workspace" when c is not null: await NewWorkspaceWithAsync(c); break; // without its submenu (palette)
            case "properties" when full is not null: await PropertiesAsync(full); break;
            case "properties": await EditDefaultsAsync(new EditorTarget.Folder(_library.Tree().Id, "Library")); break; // the root's Default Settings
            case "delete" when full is not null: await DeleteAsync(); break;
        }
    }

    private WorkspaceTab? OpenTabFor(string connectionId) => _tabs.FirstOrDefault(t => t.ConnectionId == connectionId);

    /// <summary>
    /// End every session of these connections; nothing reconnects (their supervisors are cancelled). A terminal tab stays,
    /// disconnected, with its Reconnect button: closing it emptied the session area and showed the start page
    /// (WIN-RECONNECT-PANE, as Mac #1274). Other tabs (desktops, files, web) close.
    /// </summary>
    private void Disconnect(IEnumerable<string> connectionIds)
    {
        var ids = connectionIds.ToHashSet();
        foreach (var tab in _tabs.Where(t => t.ConnectionId is { } id && ids.Contains(id)).ToList())
        {
            if (tab.View is not null && tab.Window is null) DisconnectInPlace(tab); else CloseTab(tab);
        }
    }

    /// <summary>Close every tab of these connections (Reconnect All and non-SSH Reconnect open new ones in their place).</summary>
    private void CloseConnectionTabs(IEnumerable<string> connectionIds)
    {
        var ids = connectionIds.ToHashSet();
        foreach (var tab in _tabs.Where(t => t.ConnectionId is { } id && ids.Contains(id)).ToList()) CloseTab(tab);
    }

    /// <summary>End a terminal tab's sessions and keep the tab, shown disconnected (bar, dot, tooltip) with Reconnect.</summary>
    private void DisconnectInPlace(WorkspaceTab tab)
    {
        tab.Link?.Dispose(); // cancel first: a closed session must not be reconnected
        tab.Link = null;
        // PR-1289 HIGH: the Files panel's SFTP channel ends with the session; the core's close also ends the SSH transport.
        if (tab.Files is { } files)
        {
            tab.Body.Children.Remove(files);
            files.Dispose();
            tab.Files = null;
            SetFilesColumn(tab, open: false);
        }
        FinishTabLogs(tab, "disconnected by user"); // LOG-CORE-02 footer before the session closes
        foreach (var pane in tab.AllPanes) pane.Session.Close(); // the view's Exited follows on its next poll
        tab.Exited = true;
        tab.UserDisconnected = true;
        SessionEnded(tab); // B5: after-disconnect hooks, once per session end
        SetTabStatus(tab, "disconnected");
        tab.Bar?.SetState(SessionBarState.Disconnected);
        tab.View?.SetBanner(null);
        SyncSessionRows();
        if (tab.ConnectionId is { } id) RefreshInspectorFor(id);
        RefreshFolderDashboard(); // its row no longer reads Connected
    }

    /// <summary>The tab Reconnect replaces in place: the shown tab of this SSH connection, else its first terminal tab.</summary>
    private WorkspaceTab? ReconnectTarget(TreeItem item)
    {
        if (!IsSsh(item)) return null;
        var open = _tabs.Where(t => t.ConnectionId == item.Id && t.View is not null && t.Window is null && t.Waiting is null).ToList();
        return open.FirstOrDefault(t => ReferenceEquals(t, _active)) ?? open.FirstOrDefault();
    }

    private IEnumerable<string> ConnectionIdsUnder(TreeItem? folder)
    {
        IEnumerable<TreeItem> Walk(IEnumerable<TreeItem> items) => items.SelectMany(i => i.IsFolder ? Walk(i.Children) : [i]);
        return Walk(folder is null ? _roots : folder.Children).Select(i => i.Id);
    }

    /// <summary>The user name that applies (own, folder or type default), as Connect pre-fills it.</summary>
    private string? EffectiveUser(ConnectionDto c)
    {
        try { return _library.PropertyValues(c.Id).FirstOrDefault(v => v.Key == "username")?.Effective ?? c.Username; }
        catch (BastionException) { return c.Username; }
    }

    private void CopyLibraryText(string id, bool sshCommand, string announcement)
    {
        try { CopyToClipboard(_library.CopyText(id, sshCommand), announcement); }
        catch (BastionException ex) { _ = ShowModal("Could not copy", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
    }

    private void CopyToClipboard(string text, string announcement)
    {
        var data = new DataPackage();
        data.SetText(text);
        Clipboard.SetContent(data);
        Announce(announcement);
    }

    /// <summary>Tell screen readers that something happened without moving focus.</summary>
    private void Announce(string text)
    {
        var peer = Microsoft.UI.Xaml.Automation.Peers.FrameworkElementAutomationPeer.FromElement(RootGrid)
            ?? Microsoft.UI.Xaml.Automation.Peers.FrameworkElementAutomationPeer.CreatePeerForElement(RootGrid);
        peer?.RaiseNotificationEvent(Microsoft.UI.Xaml.Automation.Peers.AutomationNotificationKind.ActionCompleted,
            Microsoft.UI.Xaml.Automation.Peers.AutomationNotificationProcessing.ImportantMostRecent, text, "BastionAnnounce");
    }

    internal async Task RenameAsync(TreeItem item)
    {
        if (_modal is not null) return;
        var form = new RenameForm(item.Name);
        if (!await ShowModal(item.IsFolder ? "Rename folder" : "Rename connection", form.Body, primary: "Rename", cancel: "Cancel",
                validate: form.Validate, focus: form.Field)) return;
        if (form.NewName == item.Name) return;
        await Mutate(() => { _library.Rename(item.Id, form.NewName); return item.Id; }, "Could not rename " + item.Name);
    }

    /// <summary>
    /// Move to…: pick the destination folder in a list of every folder that can take the item (a folder's own subtree is
    /// left out; the core refuses it too). The current folder is preselected, so Enter without a choice changes nothing.
    /// </summary>
    private MoveForm? _moveForm;

    internal async Task MoveToAsync(TreeItem item)
    {
        if (_modal is not null) return;
        var form = _moveForm = new MoveForm(item, _roots);
        if (!await ShowModal($"Move “{item.Name}”", form.Body, primary: "Move", cancel: "Cancel", validate: form.Validate, focus: form.List)) return;
        if (form.Destination == item.ParentId) return;
        if (form.Destination is { } folder) SaveExpanded(folder, true); // show where it went
        await Mutate(() => { _library.MoveBefore(item.Id, form.Destination, null); return item.Id; }, "Could not move " + item.Name);
    }

    // ---- Add to Workspace ----

    private async Task AddToWorkspaceAsync(ConnectionDto c, WorkspaceDto ws)
    {
        try
        {
            Workspaces.AddTab(ws.Id, new WorkspaceTabDto(c.Id, "terminal"));
            Announce($"Added {c.Name} to {ws.Name}");
        }
        catch (BastionException ex)
        {
            await ShowModal("Could not add to the workspace", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
        }
    }

    /// <summary>Add to Workspace › New Workspace…: name a workspace that opens this one connection.</summary>
    private async Task NewWorkspaceWithAsync(ConnectionDto c)
    {
        if (_modal is not null) return;
        var name = new TextBox { Header = "Workspace name", PlaceholderText = "For example: Acme on-call", IsSpellCheckEnabled = false };
        var error = new FieldMessage();
        name.TextChanged += (_, _) => error.Hide();
        var note = Ui.Text($"Opens {c.Name} when you open the workspace. Saved by connection only: no passwords or keys.", "CaptionTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        bool Validate()
        {
            try
            {
                if (Workspaces.List().Any(w => string.Equals(w.Name, name.Text.Trim(), StringComparison.OrdinalIgnoreCase)))
                {
                    error.Show("A workspace with this name exists. Use Add to Workspace on it instead.");
                    return false;
                }
                Workspaces.SaveLayout(name.Text, [new WorkspaceTabDto(c.Id, "terminal")], 0);
                return true;
            }
            catch (BastionException ex)
            {
                error.Show(ex.Message);
                return false;
            }
        }
        await ShowModal("New workspace", new StackPanel { Spacing = Ui.Double("Space8"), Children = { name, error.Element, note } },
            primary: "Create workspace", cancel: "Cancel", validate: Validate, focus: name);
    }

    // ---- Drag and drop: a drop on a folder moves into it, on a connection moves before it ----
    // The row starts the drag (UIElement.CanDrag), not the TreeView: TreeView's own item drag (CanDragItems) reorders its
    // items itself when a real drop lands on a row and never raises Drop, so the view changed (and lost rows) while the
    // library did not. With the row as the source, only MoveAsync below moves anything, through the core.

    private void TreeItem_DragStarting(UIElement sender, DragStartingEventArgs args)
    {
        var item = (sender as FrameworkElement)?.DataContext as TreeItem;
        if (item is { IsSession: true } || item?.Id == TreeItem.OtherSessionsId) { args.Cancel = true; return; } // UI-05: not a drag source
        TraceDrag($"start {item?.Name} [{item?.Id}] credential={item?.Credential is not null} vaultOpen={_credentials is not null}");
        // W12: a vault row (credential or credential folder) drags too; CredentialDragOver/Drop below decide what it does.
        if (item?.Credential is { } cred && _credentials is not null)
        {
            _dragCredential = cred;
            args.Data.SetData(DragFormat, item.Id);
            args.Data.RequestedOperation = DataPackageOperation.Move;
            args.AllowedOperations = DataPackageOperation.Move | DataPackageOperation.Link;
            return;
        }
        // Filtered rows are copies and Favorites rows mirror the library: only library rows move.
        if (item is null or { IsGroup: true } or { IsMirror: true } || _query.Length > 0) { args.Cancel = true; return; }
        _dragId = item.Id;
        args.Data.SetData(DragFormat, item.Id);
        args.Data.RequestedOperation = DataPackageOperation.Move;
        args.AllowedOperations = DataPackageOperation.Move;
    }

    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<LibraryRow, object> _dropHooked = new();

    /// <summary>
    /// W12: DragOver and Drop are added with handledEventsToo. A folder row's TreeViewItem handled drag events itself
    /// (hover-to-expand) and marked them handled, so XAML-attached handlers never saw a credential dragged over a library
    /// folder (the drop showed the no-drop cursor). Once per container, since containers are recycled.
    /// </summary>
    private void HookRowDrop(LibraryRow row)
    {
        if (_dropHooked.TryGetValue(row, out _)) return;
        _dropHooked.Add(row, new object());
        // Drag events bubble to the ancestor rows too (a row's children are inside it), and handledEventsToo lets those
        // run: only the innermost row under the pointer acts, so a parent never overrides the decision or drops again.
        row.AddHandler(UIElement.DragOverEvent, new DragEventHandler((o, e) => { if (IsInnermostRow(o, e)) TreeItem_DragOver(o, e); }), handledEventsToo: true);
        row.AddHandler(UIElement.DropEvent, new DragEventHandler((o, e) => { if (IsInnermostRow(o, e)) TreeItem_Drop(o, e); }), handledEventsToo: true);
    }

    private static bool IsInnermostRow(object sender, DragEventArgs e)
    {
        for (var d = e.OriginalSource as DependencyObject; d is not null; d = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(d))
            if (d is LibraryRow row) return ReferenceEquals(row, sender);
        return false;
    }

    private void TreeItem_DropCompleted(UIElement sender, DropCompletedEventArgs args) { _dragId = null; _dragCredential = null; }

    private void TreeItem_DragOver(object sender, DragEventArgs e)
    {
        if (_dragCredential is null && _dragId is null) TraceDrag($"over {((sender as FrameworkElement)?.DataContext as TreeItem)?.Name} with nothing being dragged");
        if (_dragCredential is { } dragged)
        {
            var (op, caption) = CredentialDropAction(dragged, (sender as FrameworkElement)?.DataContext as TreeItem);
            e.AcceptedOperation = op;
            if (caption is not null) e.DragUIOverride.Caption = caption;
            e.Handled = true;
            return;
        }
        var target = _dragId is { } id && DropTarget(sender) is { } t && t.Id != id && !IsInside(t, id) ? t : null;
        e.AcceptedOperation = target is null ? DataPackageOperation.None : DataPackageOperation.Move;
        if (target is not null) e.DragUIOverride.Caption = target.IsFolder ? "Move into " + target.Name : "Move before " + target.Name;
        e.Handled = true;
    }

    private void TreeItem_Drop(object sender, DragEventArgs e)
    {
        e.Handled = true;
        TraceDrag($"drop on {((sender as FrameworkElement)?.DataContext as TreeItem)?.Name} credential={_dragCredential?.Name}");
        if (_dragCredential is { } dragged)
        {
            _dragCredential = null;
            _ = DropCredentialAsync(dragged, (sender as FrameworkElement)?.DataContext as TreeItem);
            return;
        }
        if (_dragId is not { } id || DropTarget(sender) is not { } target || target.Id == id || IsInside(target, id)) return;
        _dragId = null;
        _ = MoveAsync(id, target);
    }

    /// <summary>Move <paramref name="id"/> into a folder (at the end) or before a connection, keeping the library order.</summary>
    internal Task MoveAsync(string id, TreeItem target)
    {
        var (parent, before) = target.IsFolder ? (target.Id, (string?)null) : (target.ParentId, target.Id);
        if (target.IsFolder) SaveExpanded(target.Id, true); // show where it went
        return Mutate(() => { _library.MoveBefore(id, parent, before); return id; }, "Could not move the item");
    }

    /// <summary>Whether <paramref name="target"/> lies inside the folder <paramref name="folderId"/> (the core refuses that too).</summary>
    private bool IsInside(TreeItem target, string folderId)
    {
        for (var p = target.ParentId; p is not null; p = TreeItem.Find(_roots, p)?.ParentId)
            if (p == folderId) return true;
        return false;
    }

    private TreeItem? DropTarget(object sender) =>
        sender is FrameworkElement { DataContext: TreeItem { IsGroup: false, IsMirror: false, IsSession: false } item } ? TreeItem.Find(_roots, item.Id) : null;

    // ---- Snapshot mode hooks (SnapshotRunner, BASTION_SNAPSHOT_TREE) ----

    private TreeItem LibraryItemForSnapshot(string name) =>
        Flatten(_roots).FirstOrDefault(i => i.Name == name) ?? throw new InvalidOperationException("no item named " + name);

    private static IEnumerable<TreeItem> Flatten(IEnumerable<TreeItem> items) => items.SelectMany(i => Flatten(i.Children).Prepend(i));

    /// <summary>Snapshot only: favourite these connections (in memory: the demo library is never saved).</summary>
    internal void SetFavoritesForSnapshot(params string[] names)
    {
        foreach (var name in names) _library.SetFavorite(LibraryItemForSnapshot(name).Id, true);
        Reload(Selected?.Id);
    }

    /// <summary>Snapshot only: open the tree's context menu on a row (null = empty space, the library root).</summary>
    internal async Task OpenTreeMenuForSnapshot(string? name)
    {
        TreeItem? target = null;
        if (name is not null)
        {
            target = ShownLibrary.SelectMany(i => Flatten([i])).FirstOrDefault(i => i.Name == name) ?? throw new InvalidOperationException("no row named " + name);
            SelectItem(target.Id);
            await Task.Delay(400); // the selection lands on a later pass; opening first would let it dismiss the menu
        }
        _contextTarget = target;
        // Anchored on the tree at the row's place (a menu anchored on the row itself closed again in snapshot mode).
        var at = target is not null && Tree.ContainerFromItem(target) is { } row
            ? row.TransformToVisual(Tree).TransformPoint(new Windows.Foundation.Point(48, row.ActualHeight / 2))
            : new Windows.Foundation.Point(48, Tree.ActualHeight - 40);
        TreeMenu.ShowAt(Tree, new Microsoft.UI.Xaml.Controls.Primitives.FlyoutShowOptions { Position = at });
    }

    /// <summary>Snapshot only: the menu entries the registry gave the open tree menu (separators as "-").</summary>
    internal IReadOnlyList<string> TreeMenuLabelsForSnapshot() =>
        TreeMenu.Items.Select(i => i switch { MenuFlyoutSubItem sub => sub.Text + " ›", MenuFlyoutItem m => m.IsEnabled ? m.Text : $"({m.Text})", _ => "-" }).ToList();

    internal void CloseTreeMenuForSnapshot() => TreeMenu.Hide();

    /// <summary>Snapshot only: open the inspector's More actions menu.</summary>
    internal void OpenInspectorMoreForSnapshot() { EnsureInspector(); InspectorMoreButton.Flyout.ShowAt(InspectorMoreButton); }

    internal void CloseInspectorMoreForSnapshot() => InspectorMoreMenu.Hide();

    /// <summary>Snapshot only: run a registry action on a named row as its menu entry would.</summary>
    internal Task RunActionForSnapshot(string action, string? name) => RunAsync(action, name is null ? null : LibraryItemForSnapshot(name));

    /// <summary>Snapshot only: the drop that drag-and-drop performs, onto a named row.</summary>
    internal Task MoveForSnapshot(string name, string targetName) => MoveAsync(LibraryItemForSnapshot(name).Id, LibraryItemForSnapshot(targetName));

    /// <summary>Snapshot only: choose a destination in the open Move to… dialog.</summary>
    internal void SelectMoveDestinationForSnapshot(string folderName) => _moveForm?.Select(folderName);

    /// <summary>Snapshot only: the tree in display order, one line per row, indented, with ★ for favourites.</summary>
    internal IReadOnlyList<string> TreeLinesForSnapshot()
    {
        var lines = new List<string>();
        void Walk(IEnumerable<TreeItem> items, int depth)
        {
            foreach (var i in items)
            {
                lines.Add(new string(' ', depth * 2) + (i.IsHeading ? "[" + i.Name + "]" : i.Name) + (i.Connection is { Favorite: true } && !i.IsMirror ? " ★" : "")
                          + (i.Connection is not null ? $"  ({i.IconLabel})" : ""));
                if (i.HasChildren && i.Expanded) Walk(i.Children, depth + 1);
            }
        }
        Walk(_shown, 0);
        return lines;
    }

    /// <summary>
    /// Snapshot only: the persisted expansion as the app keeps it. A throwaway ui-state.json next to the demo library is
    /// written through the core, read back by a second client (as on the next launch) and pruned after a delete.
    /// </summary>
    internal string ExpansionRoundTripForSnapshot(string dir)
    {
        var path = System.IO.Path.Combine(dir, "ui-state.json");
        var acme = LibraryItemForSnapshot("Acme Corp").Id;
        var staging = LibraryItemForSnapshot("Staging").Id;
        using (var first = TreeStateClient.Open(path))
        {
            first.SetSubtree(_library, null, true);
            first.SetExpanded(acme, false);
        }
        using var again = TreeStateClient.Open(path);
        var open = again.Expanded();
        if (open.Contains(acme) || !open.Contains(staging)) throw new InvalidOperationException("ui-state.json did not keep the expansion");
        return $"expansion: {open.Count} folders open after reopening ui-state.json, Acme Corp collapsed as saved";
    }
}

/// <summary>The Rename dialog body: one field, refused when blank.</summary>
internal sealed class RenameForm
{
    private readonly TextBox _name;
    private readonly FieldMessage _error = new();

    public StackPanel Body { get; }
    public Control Field => _name;
    public string NewName => _name.Text.Trim();

    public RenameForm(string current)
    {
        _name = new TextBox { Header = "Name", Text = current, IsSpellCheckEnabled = false };
        _name.SelectAll();
        Body = new StackPanel { Children = { _name, _error.Element } };
        _name.TextChanged += (_, _) => _error.Hide();
    }

    public bool Validate()
    {
        if (NewName.Length > 0) return true;
        _error.Show("Enter a name.");
        _name.Focus(FocusState.Programmatic);
        return false;
    }
}

/// <summary>The Move to… dialog body: the library root and every folder that can receive the item, indented by depth.</summary>
internal sealed class MoveForm
{
    private readonly List<(string? Id, string Name)> _targets = new();
    private readonly FieldMessage _error = new();

    public StackPanel Body { get; }
    public ListView List { get; }

    /// <summary>The chosen folder's id; null is the library root.</summary>
    public string? Destination => List.SelectedIndex is var i and >= 0 ? _targets[i].Id : null;

    public MoveForm(TreeItem item, IReadOnlyList<TreeItem> roots)
    {
        List = new ListView { SelectionMode = ListViewSelectionMode.Single, MaxHeight = 320, ItemContainerTransitions = new Microsoft.UI.Xaml.Media.Animation.TransitionCollection() };
        AutomationProperties.SetName(List, "Destination folder");
        Add(null, "Library", 0, root: true);
        void Walk(IEnumerable<TreeItem> level, int depth)
        {
            foreach (var f in level.Where(i => i.IsFolder && i.Id != item.Id))
            {
                Add(f.Id, f.Name, depth, root: false);
                Walk(f.Children, depth + 1);
            }
        }
        Walk(roots, 1);
        List.SelectedIndex = Math.Max(0, _targets.FindIndex(t => t.Id == item.ParentId));
        List.SelectionChanged += (_, _) => _error.Hide();
        var note = Ui.Text(item.IsFolder ? "The folder moves with everything in it." : "The connection keeps its settings and credentials.", "CaptionSecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        Body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { List, _error.Element, note } };
    }

    private void Add(string? id, string name, int depth, bool root)
    {
        _targets.Add((id, name));
        var row = Ui.IconLabel(new AppIcon { Kind = "Folder" }, root ? "Library (top level)" : name);
        row.Margin = new Thickness(depth * Ui.Double("Space16"), 0, 0, 0);
        AutomationProperties.SetName(row, root ? "Library (top level)" : name);
        List.Items.Add(row);
    }

    /// <summary>Snapshot only: select a destination by name.</summary>
    internal void Select(string name) => List.SelectedIndex = _targets.FindIndex(t => t.Name == name);

    public bool Validate()
    {
        if (List.SelectedIndex >= 0) return true;
        _error.Show("Choose a folder.");
        return false;
    }
}
