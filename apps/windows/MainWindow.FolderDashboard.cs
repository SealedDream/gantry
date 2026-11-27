using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Dispatching;
using DispatcherQueueTimer = Microsoft.UI.Dispatching.DispatcherQueueTimer;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using Windows.System;

namespace Bastion.Shell;

// DASH-01 folder dashboard (Native Windows; Native Mac is FolderDashboard.swift and DashboardTable.swift). Selecting a
// folder shows one row per object from core folder_overview (C ABI 97) over the session area, as the Mac covers its
// session area; picking a tab or a connection hides it. The rows are a virtualised ListView with a fixed row height and
// no item transitions (the WinUI idle-CPU rule). Rows are sorted once per load or sort change with a precomputed key;
// the filter is debounced and only narrows that sorted list. Delete, Move and Properties act only on the selected rows
// on screen, and Delete names exactly those rows. No password, key or inline secret reaches this page: the core
// returns names and login states only.
public sealed partial class MainWindow
{
    private enum DashColumn { Name, Address, Type, Status, User, Login, LastConnected, LastResult, Folder, Tags, Port }

    /// <summary>Column title and width (a genuine layout constraint: the header and the rows share these).</summary>
    private static readonly Dictionary<DashColumn, (string Title, double Width)> DashColumns = new()
    {
        [DashColumn.Name] = ("Name", 220), [DashColumn.Address] = ("Address", 180), [DashColumn.Type] = ("Type", 120),
        [DashColumn.Status] = ("Status", 100), [DashColumn.User] = ("User", 120), [DashColumn.Login] = ("Login", 170),
        [DashColumn.LastConnected] = ("Last connected", 150), [DashColumn.LastResult] = ("Last result", 170),
        [DashColumn.Folder] = ("Folder", 200), [DashColumn.Tags] = ("Tags", 140), [DashColumn.Port] = ("Port", 70),
    };

    private const double DashRowHeight = 32;
    private const double DashNarrowWidth = 640;
    private const int NaturalDigits = 12;
    private const string DashLockGlyph = ""; // Segoe Fluent Icons "Lock"
    private static readonly TimeSpan DashFilterDelay = TimeSpan.FromMilliseconds(150);

    /// <summary>Column choice, remembered for every folder (Name is always shown; Folder shows by itself with subfolders).</summary>
    private static readonly HashSet<DashColumn> DashChosen = DashColumnStore.Load();

    private sealed class DashRow
    {
        public required OverviewRowDto Dto { get; init; }
        public required TreeItem? Item { get; init; }
        public required string FilterKey { get; init; }
        public string Id => Dto.Id;
    }

    private Grid? _dash;
    private string? _dashFolderId;
    private string? _dashTreeSelection;
    private readonly Dictionary<string, bool> _dashSubfolders = new();
    private List<DashRow> _dashSorted = [];
    private List<DashRow> _dashVisible = [];
    private readonly HashSet<string> _dashSelected = new();
    private HashSet<string> _dashConnected = new();
    private DashColumn _dashSort = DashColumn.Name;
    private bool _dashDescending;
    private bool _dashSyncing;
    private bool _dashLocked;
    private int _dashLayout;
    /// <summary>The columns the header and the row cells were built for (<see cref="SyncDashLayout"/>).</summary>
    private List<DashColumn> _dashLayoutColumns = [];
    private DispatcherQueueTimer? _dashFilterTimer;

    private ListView _dashList = null!;
    private Grid _dashHeaderRow = null!;
    private TextBlock _dashTitle = null!, _dashPath = null!, _dashCounts = null!;
    private TextBox _dashFilter = null!;
    private CheckBox _dashSubfoldersBox = null!;
    private StackPanel _dashEmpty = null!, _dashWide = null!;
    private ScrollViewer _dashTable = null!;
    private Button _dashConnect = null!, _dashDisconnect = null!, _dashRunTask = null!, _dashMove = null!, _dashDelete = null!, _dashProperties = null!;
    private DropDownButton _dashMore = null!;
    private MenuFlyoutItem _dashMoreRunTask = null!, _dashMoreMove = null!, _dashMoreDelete = null!, _dashMoreProperties = null!;

    private bool DashboardShown => _dash is { Visibility: Visibility.Visible };

    // ---- Showing and hiding ----

    /// <summary>The tree selection changed: a folder shows its dashboard, anything else hides it.</summary>
    private void ShowFolderDashboard(TreeItem? chosen)
    {
        // A tree rebuild (library change) clears and restores the selection; that is not a new choice, so neither the
        // passing null nor the same folder again brings back a dashboard the user left for a session.
        if (chosen is null) return;
        var same = chosen.Id == _dashTreeSelection;
        _dashTreeSelection = chosen.Id;
        if (same && !DashboardShown) return;
        if (chosen is not { IsFolder: true, IsGroup: false, IsAppRow: false, Folder: not null }) { HideFolderDashboard(); return; }
        OpenFolderDashboard(chosen.Id);
    }

    /// <summary>The page has been shown once (its first show splits page and rows over two frames).</summary>
    private bool _dashShownOnce;

    private void OpenFolderDashboard(string folderId)
    {
        DashPhaseStart();
        EnsureDashboard();
        if (_dashFolderId != folderId) { _dashSelected.Clear(); _dashFolderId = folderId; }
        _dash!.Visibility = Visibility.Visible;
        if (_dashShownOnce) { LoadDashboardRows(); return; }
        _dashShownOnce = true;
        // First show: the page's layout in this frame, the rows in the next one, so the click or key that opened it does
        // not pay for both at once. Its controls and templates are usually made at idle already (PrewarmDashboard). The
        // load is queued from the first layout pass, so it runs after that frame and not before it.
        _dashTitle.Text = TreeItem.Find(_roots, folderId)?.Name ?? "Folder";
        EventHandler<object>? laidOut = null;
        laidOut = (_, _) =>
        {
            _dash!.LayoutUpdated -= laidOut;
            DashPhase("page-laid-out");
            DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
            {
                // A refresh in between may have loaded them already (_dashLoadedRoots is set by every load).
                if (DashboardShown && _dashFolderId == folderId && _dashLoadedRoots is null) LoadDashboardRows();
            });
        };
        _dash!.LayoutUpdated += laidOut;
    }

    private void HideFolderDashboard()
    {
        if (_dash is null) return;
        _dash.Visibility = Visibility.Collapsed;
        _dashFolderId = null;
        _dashSelected.Clear();
    }

    /// <summary>The user picked a session (tab click, tab menu, Ctrl+Tab, Ctrl+number, Show Session): the session comes
    /// to the front and the dashboard goes, as on the Mac. A session opened from the dashboard leaves it in place.</summary>
    private void PickTab(WorkspaceTab tab)
    {
        HideFolderDashboard();
        ActivateTab(tab);
    }

    /// <summary>
    /// Tie a tab to its saved connection. The tab is opened before it is tied, so the refresh at opening still saw the
    /// old connected set; refresh again so the dashboard counts it as connected (q-dash-r3e). Only a change in the
    /// connected set reloads (see <see cref="RefreshFolderDashboard"/>).
    /// </summary>
    private void TieTab(WorkspaceTab tab, string? connectionId)
    {
        tab.ConnectionId = connectionId;
        RefreshFolderDashboard();
    }

    /// <summary>The library and the connected set the rows were last loaded from.</summary>
    private List<TreeItem>? _dashLoadedRoots;

    /// <summary>
    /// The library or the open sessions changed (no polling): reload the rows and their status. Nothing to do when the
    /// library is the same and the same connections are connected: opening or closing a local shell, a web tab or a
    /// Quick Connect tab changes neither. The full reload (a core call and every cell) was inside the 70-100 ms user
    /// stalls of 'new local shell' and 'close the local shell tab' (q-trace-steps2).
    /// </summary>
    private void RefreshFolderDashboard()
    {
        if (!DashboardShown || _dashFolderId is null) return;
        if (TreeItem.Find(_roots, _dashFolderId) is null) { HideFolderDashboard(); return; }
        if (ReferenceEquals(_dashLoadedRoots, _roots) && _dashConnected.SetEquals(LiveConnectionIds)) return;
        LoadDashboardRows();
    }

    // ---- Rows: MainWindow.FolderDashboardRows.cs ----

    private List<DashColumn> ShownColumns()
    {
        var deep = _dashFolderId is { } id && _dashSubfolders.GetValueOrDefault(id);
        return Enum.GetValues<DashColumn>().Where(c => DashChosen.Contains(c) || (c == DashColumn.Folder && deep)).ToList();
    }

    // ---- Filter and selection ----

    private void DashFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        _dashFilterTimer!.Stop();
        _dashFilterTimer.Start();
    }

    /// <summary>Narrow the sorted rows (their order is kept) and keep only the selected rows still on screen.</summary>
    private void ApplyDashFilter()
    {
        var tq = TagQuery.Parse(_dashFilter.Text.Trim());
        var q = tq.Text.Trim().ToLowerInvariant();
        _dashVisible = q.Length == 0 && tq.Tags.Count == 0 ? _dashSorted
            : _dashSorted.Where(r => (tq.Tags.Count == 0 || (r.Item?.Connection is not null && tq.Admits(r.Dto.Tags))) && r.FilterKey.Contains(q, StringComparison.Ordinal)).ToList();
        var fill = ++_dashFills;
        if (_dashList.Items.Count == 0 && _dashVisible.Count > DashRowsPerFrame) BindDashRowsInSteps(DashRowsPerFrame, fill);
        else BindDashRows();
        var empty = _dashSorted.Count == 0;
        _dashEmpty.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        _dashTable.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;
        UpdateDashState();
    }

    /// <summary>All the shown rows, and the selection on them.</summary>
    private void BindDashRows()
    {
        _dashSyncing = true;
        try
        {
            _dashList.ItemsSource = _dashVisible;
            var keep = new HashSet<string>();
            foreach (var row in _dashVisible)
            {
                if (!_dashSelected.Contains(row.Id)) continue;
                _dashList.SelectedItems.Add(row);
                keep.Add(row.Id);
            }
            _dashSelected.IntersectWith(keep); // a row hidden by the filter is no longer selected
        }
        finally { _dashSyncing = false; }
    }

    private void DashList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_dashSyncing) return;
        _dashSelected.Clear();
        foreach (var o in _dashList.SelectedItems) if (o is DashRow r) _dashSelected.Add(r.Id);
        UpdateDashState();
    }

    /// <summary>The selected rows on screen, in table order. Every action uses this, never rows hidden by the filter.</summary>
    private List<DashRow> DashSelection() => _dashList.SelectedItems.OfType<DashRow>().ToList();

    private void UpdateDashState()
    {
        var selection = DashSelection();
        var connected = _dashSorted.Count(r => _dashConnected.Contains(r.Id));
        var shown = _dashVisible.Count == _dashSorted.Count ? Plural(_dashSorted.Count, "item") : $"{_dashVisible.Count} of {Plural(_dashSorted.Count, "item")}";
        _dashCounts.Text = $"{shown} · {connected} connected · {selection.Count} selected";
        AutomationProperties.SetName(_dashCounts, _dashCounts.Text);

        var connections = selection.Where(r => !r.Dto.IsFolder).ToList();
        _dashConnect.IsEnabled = connections.Any(r => !_dashConnected.Contains(r.Id));
        _dashDisconnect.IsEnabled = connections.Any(r => _dashConnected.Contains(r.Id));
        _dashRunTask.IsEnabled = _dashMoreRunTask.IsEnabled = connections.Count > 0;
        _dashMove.IsEnabled = _dashMoreMove.IsEnabled = selection.Count > 0;
        _dashDelete.IsEnabled = _dashMoreDelete.IsEnabled = selection.Count > 0;
        var bulk = BulkEditIds(selection) is { } ids;
        _dashProperties.IsEnabled = _dashMoreProperties.IsEnabled = selection.Count == 1 || bulk;
        ToolTipService.SetToolTip(_dashProperties, bulk ? $"Edit {selection.Count} Connections…" : selection.Count > 1 ? "Select connections only to edit them together" : "Properties");
    }

    // ---- Actions ----

    /// <summary>Double-click or Enter: a folder row opens that folder's dashboard; a connection runs its primary action
    /// (Connect, or show the live session).</summary>
    private async Task OpenDashRowAsync(DashRow row)
    {
        if (row.Dto.IsFolder)
        {
            // Open the page directly: the tree selection may not move (the row can be hidden by the tree search, or its
            // container not yet realised), and the dashboard must not depend on it.
            SelectItem(row.Id);
            _dashTreeSelection = row.Id;
            OpenFolderDashboard(row.Id);
            return;
        }
        if (row.Item is null) return;
        List<MenuItemDto> menu;
        try { menu = _library.Menu(row.Id, Handled, ConnectedIds); }
        catch (BastionException) { return; }
        if (menu.FirstOrDefault(m => m.Primary) is { } primary) await PerformAsync(primary, row.Item);
    }

    /// <summary>Each selected connection connects through the normal path and its sign-in rules, one after another.</summary>
    private async Task DashConnectAsync()
    {
        foreach (var row in DashSelection().Where(r => !r.Dto.IsFolder && r.Item is not null && !_dashConnected.Contains(r.Id)).ToList())
            await RunAsync("connect", row.Item);
    }

    private void DashDisconnect() => Disconnect(DashSelection().Where(r => !r.Dto.IsFolder).Select(r => r.Id));

    private void ShowDashTaskMenu(FrameworkElement anchor)
    {
        var targets = DashSelection().Where(r => !r.Dto.IsFolder && r.Item is not null).Select(r => r.Item!).ToList();
        var menu = new MenuFlyout();
        List<TaskDto> tasks;
        try { tasks = TaskClient.List(_library); }
        catch (BastionException) { tasks = []; }
        foreach (var t in tasks.OrderByDescending(t => t.Favorite).ThenBy(t => t.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            var item = new MenuFlyoutItem { Text = t.Name };
            AutomationProperties.SetName(item, $"Run {t.Name} on {Plural(targets.Count, "connection")}");
            item.Click += (_, _) => _ = RunTaskOnTargetsAsync(t, targets);
            menu.Items.Add(item);
        }
        if (menu.Items.Count == 0) menu.Items.Add(new MenuFlyoutItem { Text = "No tasks yet", IsEnabled = false });
        menu.ShowAt(anchor);
    }

    private async Task DashMoveAsync()
    {
        if (_modal is not null) return;
        var rows = DashSelection().Where(r => r.Item is not null).ToList();
        if (rows.Count == 0) return;
        var form = _moveForm = new MoveForm(rows[0].Item!, _roots);
        var title = rows.Count == 1 ? $"Move “{rows[0].Dto.Name}”" : $"Move {rows.Count} items";
        if (!await ShowModal(title, form.Body, primary: "Move", cancel: "Cancel", validate: form.Validate, focus: form.List)) return;
        var destination = form.Destination;
        if (destination is { } folder) SaveExpanded(folder, true);
        var keep = _dashFolderId;
        await Mutate(() =>
        {
            foreach (var r in rows) if (r.Item!.ParentId != destination) _library.MoveBefore(r.Id, destination, null);
            return keep;
        }, "Could not move the items");
    }

    /// <summary>Delete asks first and names exactly the rows it removes: the selected rows on screen.</summary>
    private async Task DashDeleteAsync()
    {
        if (_modal is not null) return;
        var rows = DashSelection();
        if (rows.Count == 0) return;
        var body = new StackPanel { Spacing = Ui.Double("Space8") };
        var lead = Ui.Text(rows.Count == 1 ? "This will be removed from the library:" : $"These {rows.Count} items will be removed from the library:", "BodyTextStyle");
        lead.TextWrapping = TextWrapping.Wrap;
        body.Children.Add(lead);
        var names = Ui.Text(string.Join("\n", rows.Select(r => r.Dto.IsFolder ? $"{r.Dto.Name} (folder and everything in it)" : r.Dto.Name)), "BodyStrongTextStyle");
        names.TextWrapping = TextWrapping.Wrap;
        AutomationProperties.SetAutomationId(names, "folder-dashboard-delete-names");
        body.Children.Add(new ScrollViewer { Content = names, MaxHeight = Ui.Double("DialogWidth") / 2 });
        var title = rows.Count == 1 ? (rows[0].Dto.IsFolder ? "Delete folder?" : "Delete connection?") : $"Delete {rows.Count} items?";
        if (!await ShowModal(title, body, primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
        var keep = _dashFolderId;
        var anyFolder = rows.Any(r => r.Dto.IsFolder);
        await Mutate(() =>
        {
            foreach (var r in rows) _library.Remove(r.Id);
            if (anyFolder) PruneTreeState();
            return keep; // the dashboard's folder stays selected
        }, "Could not delete the items");
    }

    private async Task DashPropertiesAsync()
    {
        var selection = DashSelection();
        if (selection is [{ Item: { } item }]) await RunAsync("properties", item);
        else if (BulkEditIds(selection) is { } ids) await BulkEditAsync(ids);
    }

    /// <summary>B3-BULK-EDIT: two or more selected rows, all connections, or null.</summary>
    private static List<string>? BulkEditIds(List<DashRow> selection) =>
        selection.Count > 1 && selection.All(r => !r.Dto.IsFolder) ? selection.Select(r => r.Id).ToList() : null;

    /// <summary>B3-BULK-EDIT (Mac #1130): set one property on every selected connection, or on none.</summary>
    private async Task BulkEditAsync(List<string> ids)
    {
        BulkEditForm form;
        try { form = new BulkEditForm(_library, ids); }
        catch (BastionException ex)
        {
            await ShowModal("Could not edit the connections", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }
        if (!form.HasProperties) { await ShowModal(form.Title, form.Body, primary: "OK", cancel: null); return; }
        if (!await ShowModal(form.Title, form.Body, primary: form.ApplyLabel, cancel: "Cancel", validate: form.Apply, focus: form.FirstField)) return;
        await Mutate(() => null, "Could not save the connections");
        RefreshFolderDashboard();
    }

    // ---- Building the page ----

    private void EnsureDashboard()
    {
        if (_dash is not null) return;
        _dashFilterTimer = DispatcherQueue.CreateTimer();
        _dashFilterTimer.Interval = DashFilterDelay;
        _dashFilterTimer.IsRepeating = false;
        _dashFilterTimer.Tick += (_, _) => ApplyDashFilter();

        _dash = new Grid { Background = Ui.Brush(RootGrid, "LayerBackgroundBrush"), Padding = Ui.Thickness("DialogPadding"), RowSpacing = Ui.Double("Space8") };
        AutomationProperties.SetName(_dash, "Folder dashboard");
        AutomationProperties.SetAutomationId(_dash, "folder-dashboard");
        for (var i = 0; i < 3; i++) _dash.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        _dash.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        _dashTitle = Ui.Text("", "SubtitleTextStyle");
        _dashTitle.TextTrimming = TextTrimming.CharacterEllipsis;
        AutomationProperties.SetHeadingLevel(_dashTitle, AutomationHeadingLevel.Level1);
        _dashPath = Ui.Text("", "CaptionSecondaryTextStyle");
        _dashPath.TextTrimming = TextTrimming.CharacterEllipsis;
        _dashCounts = Ui.Text("", "BodySecondaryTextStyle");
        AutomationProperties.SetAutomationId(_dashCounts, "folder-dashboard-counts");
        AutomationProperties.SetLiveSetting(_dashCounts, AutomationLiveSetting.Polite);
        _dash.Children.Add(new StackPanel { Spacing = Ui.Double("Space4"), Children = { _dashTitle, _dashPath, _dashCounts } });

        var controls = BuildDashControls();
        Grid.SetRow(controls, 1);
        _dash.Children.Add(controls);
        var actions = BuildDashActions();
        Grid.SetRow(actions, 2);
        _dash.Children.Add(actions);
        var body = BuildDashBody();
        Grid.SetRow(body, 3);
        _dash.Children.Add(body);

        Grid.SetRow(_dash, 1);
        Grid.SetColumn(_dash, 1);
        Workspace.Children.Add(_dash); // last child: it lies over the session area and the start page
    }

    private Grid BuildDashControls()
    {
        var row = new Grid { ColumnSpacing = Ui.Double("Space8") };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _dashFilter = new TextBox { PlaceholderText = "Filter", MinWidth = Ui.Double("Space32") * 4 };
        AutomationProperties.SetName(_dashFilter, "Filter this folder");
        AutomationProperties.SetAutomationId(_dashFilter, "folder-dashboard-filter");
        ToolTipService.SetToolTip(_dashFilter, "Name, address, user or tag. tag:name keeps only connections with that tag.");
        _dashFilter.TextChanged += DashFilter_TextChanged;
        _dashFilter.KeyDown += (_, e) =>
        {
            if (e.Key == VirtualKey.Escape && _dashFilter.Text.Length > 0) { _dashFilter.Text = ""; _dashFilterTimer!.Stop(); ApplyDashFilter(); e.Handled = true; }
            else if (e.Key is VirtualKey.Enter or VirtualKey.Down) { _dashFilterTimer!.Stop(); ApplyDashFilter(); _dashList.Focus(FocusState.Keyboard); e.Handled = true; }
        };
        row.Children.Add(_dashFilter);

        _dashSubfoldersBox = new CheckBox { Content = "Include subfolders", MinWidth = 0 };
        AutomationProperties.SetName(_dashSubfoldersBox, "Include subfolders");
        _dashSubfoldersBox.Click += (_, _) =>
        {
            if (_dashFolderId is not { } id) return;
            _dashSubfolders[id] = _dashSubfoldersBox.IsChecked == true; // per folder, for this run
            LoadDashboardRows();
        };
        Grid.SetColumn(_dashSubfoldersBox, 1);
        row.Children.Add(_dashSubfoldersBox);

        var columns = new DropDownButton { Content = "Columns", Style = Ui.Style("SubtleButtonStyle") };
        AutomationProperties.SetName(columns, "Choose columns");
        AutomationProperties.SetAutomationId(columns, "folder-dashboard-columns");
        ToolTipService.SetToolTip(columns, "Show or hide columns");
        columns.Flyout = DashColumnsFlyout(FlyoutPlacementMode.BottomEdgeAlignedRight);
        Grid.SetColumn(columns, 2);
        row.Children.Add(columns);
        return row;
    }

    private Grid BuildDashActions()
    {
        // Connect is the one accent text button; the others are quiet icon buttons with tooltips (button restyle).
        Button Action(string label, string id, Action click, UIElement? icon = null)
        {
            var b = new Button { Content = (object?)icon ?? label, Style = Ui.Style(icon is null ? "AccentButtonStyle" : "SubtleButtonStyle") };
            if (icon is not null) ToolTipService.SetToolTip(b, label.TrimEnd('…'));
            AutomationProperties.SetName(b, label.TrimEnd('…'));
            AutomationProperties.SetAutomationId(b, "folder-dashboard-" + id);
            b.Click += (_, _) => click();
            return b;
        }
        _dashConnect = Action("Connect", "connect", () => _ = DashConnectAsync());
        _dashDisconnect = Action("Disconnect", "disconnect", DashDisconnect, Ui.Icon("GlyphClose"));
        _dashRunTask = Action("Run Task…", "run-task", () => ShowDashTaskMenu(_dashRunTask), Ui.Icon("GlyphTerminal"));
        _dashMove = Action("Move…", "move", () => _ = DashMoveAsync(), new AppIcon { Kind = "Folder" });
        _dashDelete = Action("Delete", "delete", () => _ = DashDeleteAsync(), Ui.Icon("GlyphDelete"));
        _dashProperties = Action("Properties", "properties", () => _ = DashPropertiesAsync(), Ui.Icon("GlyphSettings"));

        // A narrow workspace keeps Connect and Disconnect and moves the rest into one menu, so nothing is clipped.
        MenuFlyoutItem MoreItem(string label, Action click)
        {
            var m = new MenuFlyoutItem { Text = label };
            AutomationProperties.SetName(m, label.TrimEnd('…'));
            m.Click += (_, _) => click();
            return m;
        }
        _dashMoreRunTask = MoreItem("Run Task…", () => ShowDashTaskMenu(_dashMore));
        _dashMoreMove = MoreItem("Move…", () => _ = DashMoveAsync());
        _dashMoreDelete = MoreItem("Delete", () => _ = DashDeleteAsync());
        _dashMoreProperties = MoreItem("Properties", () => _ = DashPropertiesAsync());
        _dashMore = new DropDownButton
        {
            Content = Ui.Icon("GlyphMore"), Style = Ui.Style("SubtleButtonStyle"), Visibility = Visibility.Collapsed,
            Flyout = new MenuFlyout { Items = { _dashMoreRunTask, _dashMoreMove, _dashMoreDelete, _dashMoreProperties } },
        };
        AutomationProperties.SetName(_dashMore, "More actions");
        ToolTipService.SetToolTip(_dashMore, "More actions");

        _dashWide = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space4"), Children = { _dashRunTask, _dashMove, _dashDelete, _dashProperties } };
        var strip = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space4"), Children = { _dashConnect, _dashDisconnect, _dashWide, _dashMore } };
        var host = new Grid { Children = { strip } };
        host.SizeChanged += (_, e) =>
        {
            var narrow = e.NewSize.Width < DashNarrowWidth;
            _dashWide.Visibility = narrow ? Visibility.Collapsed : Visibility.Visible;
            _dashMore.Visibility = narrow ? Visibility.Visible : Visibility.Collapsed;
        };
        return host;
    }

    private Grid BuildDashBody()
    {
        var body = new Grid();
        _dashEmpty = new StackPanel { Spacing = Ui.Double("Space8"), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Visibility = Visibility.Collapsed };
        _dashEmpty.Children.Add(Ui.Text("This folder is empty.", "BodySecondaryTextStyle"));
        var add = new Button { Content = "Add connection", Style = Ui.Style("TextButtonStyle"), HorizontalAlignment = HorizontalAlignment.Center };
        AutomationProperties.SetName(add, "Add connection to this folder");
        add.Click += NewConnection_Click; // the folder is the tree selection, so it becomes the parent
        _dashEmpty.Children.Add(add);
        body.Children.Add(_dashEmpty);

        // Header and rows scroll sideways together when the columns are wider than the page; the list scrolls itself.
        var table = new Grid();
        table.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        table.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        _dashHeaderRow = new Grid { Padding = new Thickness(Ui.Double("Space12"), 0, Ui.Double("Space12"), 0) };
        _dashHeaderRow.ContextFlyout = DashColumnsFlyout(FlyoutPlacementMode.Bottom);
        table.Children.Add(_dashHeaderRow);

        _dashList = new ListView
        {
            SelectionMode = ListViewSelectionMode.Extended,
            ItemContainerTransitions = new Microsoft.UI.Xaml.Media.Animation.TransitionCollection(),
            ItemTemplate = (DataTemplate)XamlReader.Load("<DataTemplate xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'><Grid /></DataTemplate>"),
        };
        AutomationProperties.SetName(_dashList, "Folder contents");
        AutomationProperties.SetAutomationId(_dashList, "folder-dashboard-table");
        _dashList.ContainerContentChanging += DashList_ContainerContentChanging;
        _dashList.SelectionChanged += DashList_SelectionChanged;
        // handledEventsToo: a ListViewItem marks the taps of a double-click handled for its own selection.
        _dashList.AddHandler(UIElement.DoubleTappedEvent, new DoubleTappedEventHandler(DashList_DoubleTapped), true);
        _dashList.RightTapped += DashList_RightTapped;
        _dashList.KeyDown += (_, e) =>
        {
            if (e.Key != VirtualKey.Enter || DashSelection() is not [var only]) return;
            e.Handled = true;
            _ = OpenDashRowAsync(only);
        };
        Grid.SetRow(_dashList, 1);
        table.Children.Add(_dashList);

        _dashTable = new ScrollViewer
        {
            Content = table, HorizontalScrollMode = ScrollMode.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalScrollMode = ScrollMode.Disabled, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
        };
        body.Children.Add(_dashTable);
        return body;
    }

    /// <summary>The row under a pointer event. The hit element can be the item's chrome (no DataContext), so walk up
    /// to the ListViewItem and ask the list for its item.</summary>
    private DashRow? DashRowOf(object source)
    {
        for (var d = source as DependencyObject; d is not null && d != _dashList; d = VisualTreeHelper.GetParent(d))
        {
            if (d is ListViewItem item) return _dashList.ItemFromContainer(item) as DashRow;
            if (d is FrameworkElement { DataContext: DashRow row }) return row;
        }
        return null;
    }

    private void DashList_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (DashRowOf(e.OriginalSource) is not { } row) return;
        e.Handled = true;
        _ = OpenDashRowAsync(row);
    }

    private void DashList_RightTapped(object sender, RightTappedRoutedEventArgs e)
    {
        if (DashRowOf(e.OriginalSource) is not { } row) return;
        if (!_dashSelected.Contains(row.Id)) { _dashList.SelectedItems.Clear(); _dashList.SelectedItems.Add(row); }
        if (row.Item is null) return;
        var menu = new MenuFlyout();
        if (BulkEditIds(DashSelection()) is { } ids)
        {
            // Mac LibraryOutline: right-click on one of several selected connections offers the bulk editor.
            var bulk = new MenuFlyoutItem { Text = $"Edit {ids.Count} Connections…" };
            bulk.Click += (_, _) => _ = BulkEditAsync(ids);
            menu.Items.Add(bulk);
            menu.Items.Add(new MenuFlyoutSeparator());
        }
        foreach (var entry in MenuEntries(row.Item)) menu.Items.Add(entry); // the tree row's menu, from the core action list
        menu.ShowAt(_dashList, e.GetPosition(_dashList));
        e.Handled = true;
    }

    /// <summary>
    /// New header and row cells only when the shown columns change. A reload with the same columns (a tab opened or
    /// closed, another folder) refills the recycled rows' text; building new cells for every realized row on each
    /// reload cost a layout and template pass on the UI thread.
    /// </summary>
    private void SyncDashLayout()
    {
        var columns = ShownColumns();
        if (columns.SequenceEqual(_dashLayoutColumns)) return;
        _dashLayoutColumns = columns;
        _dashLayout++;
        BuildDashHeader();
    }

    private void BuildDashHeader()
    {
        _dashHeaderRow.Children.Clear();
        _dashHeaderRow.ColumnDefinitions.Clear();
        var index = 0;
        foreach (var c in _dashLayoutColumns)
        {
            var (title, width) = DashColumns[c];
            _dashHeaderRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(width) });
            var arrow = c == _dashSort ? (_dashDescending ? " ▼" : " ▲") : "";
            var label = Ui.Text(title + arrow, "BodyStrongTextStyle");
            label.TextTrimming = TextTrimming.CharacterEllipsis;
            var button = new Button
            {
                Content = label, Style = Ui.Style("SubtleButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Left,
            };
            AutomationProperties.SetName(button, c == _dashSort ? $"{title}, sorted {(_dashDescending ? "descending" : "ascending")}" : "Sort by " + title);
            AutomationProperties.SetAutomationId(button, "folder-dashboard-sort-" + c.ToString().ToLowerInvariant());
            button.Click += (_, _) =>
            {
                if (_dashSort == c) _dashDescending = !_dashDescending; else { _dashSort = c; _dashDescending = false; }
                SortDashboardRows();
                BuildDashHeader();
                ApplyDashFilter();
            };
            Grid.SetColumn(button, index++);
            _dashHeaderRow.Children.Add(button);
        }
    }

    /// <summary>
    /// Fill a row in two phases (WinUI phased rendering). Phase 0, in the frame that shows the row: its accessible name,
    /// and for a new row its columns and name text only; a reused row whose cells are all built gets every value there.
    /// Phase 1, in a later frame: the icon, the colour stripe and the other cells, built there the first time, and their
    /// values. A folder's first show then builds one text per row in the frame of the click or key, not nine
    /// (WIN-STALL-USER: 'Escape' after the tree search spent 42-63 ms in that frame with every cell built in phase 0,
    /// q-stall-ab; 35-69 ms with the name cell's icon and stripe still in phase 0, q-stall-ab2).
    /// </summary>
    private void DashList_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
    {
        if (args.InRecycleQueue || args.Item is not DashRow row || args.ItemContainer.ContentTemplateRoot is not Grid grid) return;
        args.Handled = true;
        var columns = _dashLayoutColumns;
        if (args.Phase == 0)
        {
            if (grid.Tag is not DashCells built || built.Layout != _dashLayout) BuildDashNameCell(grid, columns);
            AutomationProperties.SetName(args.ItemContainer, DashSummary(row, columns));
            // A reused row has all its cells: its values are set now, so no cell shows the old row's value or a blank.
            if (((DashCells)grid.Tag).Complete) { FillDashRow(grid, row, columns); return; }
            SetDashText((TextBlock)((Grid)grid.Children[0]).Children[0], row, DashColumn.Name);
            args.RegisterUpdateCallback(DashList_ContainerContentChanging);
            return;
        }
        if (grid.Tag is not DashCells cells || cells.Layout != _dashLayout) return; // the columns changed since phase 0: refilled anew
        if (!cells.Complete) BuildDashOtherCells(grid, columns, cells);
        FillDashRow(grid, row, columns);
    }

    /// <summary>A row whose cells are all built: the icon, the stripe and every cell's value.</summary>
    private void FillDashRow(Grid grid, DashRow row, List<DashColumn> columns)
    {
        var nameCell = (Grid)grid.Children[0];
        SetDashText((TextBlock)nameCell.Children[0], row, DashColumn.Name);
        FillDashName(nameCell, row);
        for (var i = 1; i < columns.Count; i++) SetDashText((TextBlock)grid.Children[i], row, columns[i]);
    }

    /// <summary>One cell's text. Plain Text where it can be (TextBlock's fast path); Runs only for the lock glyph.</summary>
    private void SetDashText(TextBlock text, DashRow row, DashColumn column)
    {
        var value = CellText(row, column);
        if (column != DashColumn.Login || !_dashLocked || row.Dto.IsFolder) { text.Text = value; return; }
        text.Inlines.Clear();
        text.Inlines.Add(new Run { Text = value });
        text.Inlines.Add(new Run { Text = " " + DashLockGlyph, FontFamily = (FontFamily)Application.Current.Resources["SymbolFontFamily"] });
    }

    /// <summary>The row's accessible name: the name, then each non-empty column as "Title value".</summary>
    private string DashSummary(DashRow row, List<DashColumn> columns)
    {
        var summary = new StringBuilder();
        foreach (var column in columns)
        {
            var value = CellText(row, column);
            if (column == DashColumn.Login && _dashLocked && !row.Dto.IsFolder) value += ", credentials locked";
            if (value.Length == 0) continue;
            if (summary.Length > 0) summary.Append(", ");
            summary.Append(column == DashColumn.Name ? value : $"{DashColumns[column].Title} {value}");
        }
        return summary.ToString();
    }

    /// <summary>What a recycled row's grid holds: the cells of column layout <see cref="Layout"/>, the name cell only
    /// until phase 1 has built the rest (<see cref="Complete"/>).</summary>
    private sealed class DashCells
    {
        public required int Layout { get; init; }
        public bool Complete { get; set; }
    }

    /// <summary>Phase 0: the row's columns and its name text (the first column; Name is always shown and first). The
    /// stripe and icon columns have their fixed widths already, so the name does not move when phase 1 adds them.</summary>
    private void BuildDashNameCell(Grid grid, List<DashColumn> columns)
    {
        grid.Children.Clear();
        grid.ColumnDefinitions.Clear();
        grid.Height = DashRowHeight;
        foreach (var c in columns) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(DashColumns[c].Width) });
        var text = DashCellText();
        var nameGrid = new Grid { ColumnSpacing = Ui.Double("Space8") };
        nameGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Ui.Double("Space4")) });
        nameGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Ui.Double("IconSize")) });
        nameGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(text, 2);
        nameGrid.Children.Add(text);
        grid.Children.Add(nameGrid);
        grid.Tag = new DashCells { Layout = _dashLayout };
    }

    /// <summary>Phase 1, once per row and layout: the host colour stripe and the icon in the name cell, then the cells
    /// after the name, one per column, in column order.</summary>
    private static void BuildDashOtherCells(Grid grid, List<DashColumn> columns, DashCells cells)
    {
        var nameGrid = (Grid)grid.Children[0];
        var stripe = new Border { Width = Ui.Double("Space4"), Height = Ui.Double("IconSize"), VerticalAlignment = VerticalAlignment.Center };
        var icon = new FontIcon { FontFamily = (FontFamily)Application.Current.Resources["SymbolFontFamily"], FontSize = Ui.Double("IconSize"), VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(icon, 1);
        nameGrid.Children.Add(stripe);
        nameGrid.Children.Add(icon);
        for (var i = 1; i < columns.Count; i++)
        {
            var text = DashCellText();
            Grid.SetColumn(text, i);
            grid.Children.Add(text);
        }
        cells.Complete = true;
    }

    private static TextBlock DashCellText() => new()
    {
        Style = Ui.Style("BodyTextStyle"), VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis,
        Padding = new Thickness(0, 0, Ui.Double("Space8"), 0),
    };

    /// <summary>Protocol icon in the core's tint, and the host colour as a thin bar before it.</summary>
    private void FillDashName(Grid cell, DashRow row)
    {
        var stripe = (Border)cell.Children[1]; // [0] is the name text (phase 0)
        var icon = (FontIcon)cell.Children[2];
        icon.Glyph = row.Dto.IsFolder ? FluentIcons.Object("folder") : row.Item?.Glyph ?? FluentIcons.Object(row.Dto.Icon?.Id ?? "");
        icon.Foreground = row.Item?.IconBrush ?? Ui.Brush(RootGrid, "TextSecondaryBrush");
        stripe.Background = row.Dto.IsFolder ? null : row.Item?.HostColorBrush;
    }
}
