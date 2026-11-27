using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Royal TS layout: one navigation tree. Under the library sits the Application section with Tasks and Triggers (Default Settings moved to Settings, the ⋯ menu and Go to, as on the Mac); a click or Enter on a row opens its
// page. Below the tree, the bottom bar: Add, Settings and Connect menus, the favourite toggle and Connect.
public sealed partial class MainWindow
{
    /// <summary>The Application section, or null while a search matches none of its rows.</summary>
    private TreeItem? ApplicationSection()
    {
        var rows = new List<TreeItem>();
        // Tasks and Triggers only (owner 2026-11-21, as on the Mac); Activity, Audit log, Plugins, Tunnels and
        // Workspaces are in the ⋯ menu › Tools.
        var tasks = AppRow("app:tasks", "Tasks", FluentIcons.Object("app-tasks"), "Tasks: checks and commands to run against a connection", OpenTaskManager);
        tasks.Children.AddRange(TaskRows()); // TABBAR-WIN: each task, right-click for Run, Edit…, Restore Default
        rows.Add(tasks);
        rows.Add(AppRow("app:triggers", "Triggers", FluentIcons.Object("app-triggers"), "Triggers: rules that run on terminal output", () => _ = TriggersAsync()));
        if (_query.Length > 0)
            rows = rows.Where(r => r.Name.Contains(_query, StringComparison.OrdinalIgnoreCase) || r.Children.Count > 0).ToList();
        if (rows.Count == 0) return null;
        var section = new TreeItem
        {
            Id = TreeItem.ApplicationGroupId, Name = "Application", IsFolder = false, IsGroup = true,
            Glyph = FluentIcons.Object("settings"), IconBrush = IconBrush("icon.neutral"), IconLabel = "Application",
            Description = "Application: tasks and triggers",
        };
        section.Children.AddRange(rows);
        return section;
    }

    /// <summary>A row per task under Application > Tasks (as on the Mac); a click opens the Tasks page.</summary>
    private IEnumerable<TreeItem> TaskRows()
    {
        List<Interop.TaskDto> all;
        try { all = Interop.TaskClient.List(_library); }
        catch (Interop.BastionException) { return []; }
        return all.Where(t => _query.Length == 0 || t.Name.Contains(_query, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(t => t.Favorite).ThenBy(t => t.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(t => AppRow(TaskRowPrefix + t.Id, t.Name + (t.Favorite ? " ★" : ""), FluentIcons.Object("task"), "Task " + t.Name, OpenTaskManager, "app:tasks"));
    }

    private const string TaskRowPrefix = "app:task:";

    private static bool IsTaskRow(TreeItem? row) => row is { IsAppRow: true } && row.Id.StartsWith(TaskRowPrefix, StringComparison.Ordinal);

    /// <summary>The right-click menu of a task row, or null for any other row.</summary>
    private List<MenuFlyoutItemBase>? TaskRowMenu(TreeItem? row)
    {
        if (!IsTaskRow(row)) return null;
        var id = row!.Id[TaskRowPrefix.Length..];
        try { return Interop.TaskClient.List(_library).FirstOrDefault(t => t.Id == id) is { } t ? TaskMenuItems(t, withRun: true) : null; }
        catch (Interop.BastionException) { return null; }
    }

    private TreeItem AppRow(string id, string name, string glyph, string description, Action? open, string parent = TreeItem.ApplicationGroupId) => new()
    {
        Id = id, Name = name, IsFolder = false, IsGroup = true, IsAppRow = true, ParentId = parent, Open = open,
        Glyph = glyph, IconBrush = IconBrush("icon.neutral"), IconLabel = name, Description = description,
    };

    /// <summary>A click or Enter on an Application row opens its page; library rows keep their own behaviour.</summary>
    private void Tree_ItemInvoked(LibraryTree sender, LibraryTreeInvokedEventArgs args)
    {
        if (args.InvokedItem is TreeItem { IsSession: true } session)
        {
            args.Handled = true;
            InvokeSessionRow(session); // UI-05: focus the tab, never a new session
            return;
        }
        if (args.InvokedItem is not TreeItem { Open: { } open }) return;
        args.Handled = true;
        open();
    }

    // ---- Bottom bar ----

    private void BottomProperties_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is { } item) _ = PropertiesAsync(item);
        else _ = EditDefaultsAsync(new EditorTarget.Folder(_library.Tree().Id, "Library"));
    }

    /// <summary>The Connect menu: the registry's commands for the selection (Connect, Connect as…, SFTP, Disconnect, …).</summary>
    private void BottomConnectMenu_Opening(object sender, object e)
    {
        BottomConnectMenu.Items.Clear();
        if (Selected is not { Connection: not null } target)
        {
            BottomConnectMenu.Items.Add(new MenuFlyoutItem { Text = "Select a connection first", IsEnabled = false });
            return;
        }
        foreach (var entry in MenuEntries(target)) BottomConnectMenu.Items.Add(entry);
    }

    private void BottomConnect_Click(SplitButton sender, SplitButtonClickEventArgs args) => _ = ConnectAsync(Selected);

    private void BottomFavorite_Click(object sender, RoutedEventArgs e) => _ = ToggleFavoriteFromBarAsync();

    private Task ToggleFavoriteFromBarAsync()
    {
        var item = Selected;
        if (item is null || (TreeItem.Find(_roots, item.Id) ?? item).Connection is not { } c) { UpdateBottomBar(item); return Task.CompletedTask; }
        return Mutate(() => { _library.SetFavorite(c.Id, !c.Favorite); return c.Id; }, "Could not change Favorites");
    }

    /// <summary>Favourite and Connect follow the selection (called with every inspector update).</summary>
    private void UpdateBottomBar(TreeItem? item)
    {
        var connection = item is { IsGroup: false } ? (TreeItem.Find(_roots, item.Id) ?? item).Connection : null;
        var favorite = connection?.Favorite == true;
        BottomFavoriteButton.IsEnabled = connection is not null;
        BottomFavoriteButton.IsChecked = favorite;
        var label = favorite ? "Remove from Favorites" : "Add to Favorites";
        AutomationProperties.SetName(BottomFavoriteButton, label);
        ToolTipService.SetToolTip(BottomFavoriteButton, label);
        // A plugin entry an installed plugin opens: Connect opens its tab, as its default action does (PLUG-PVE-02).
        var pluginEntry = connection is { IsUnavailable: true } && PluginTypeOf(connection) is not null;
        BottomConnectButton.IsEnabled = connection is not null && (CanOpen(item) || pluginEntry) && !_connecting;
    }

    // ---- Snapshot hooks (BASTION_SNAPSHOT_ROYAL_LAYOUT) ----

    /// <summary>Snapshot only: run an Application row's Open as a click would.</summary>
    internal bool OpenAppRowForSnapshot(string id)
    {
        var row = Flatten(_shown).FirstOrDefault(i => i.Id == id);
        if (row?.Open is not { } open) return false;
        open();
        return true;
    }

    /// <summary>Snapshot only: select a library row by name and report the bottom bar's state.</summary>
    internal string SelectForBottomBarSnapshot(string? name)
    {
        if (name is null) { Tree.SelectedItem = null; UpdateInspector(null); }
        else SelectItem(LibraryItemForSnapshot(name).Id);
        return BottomBarStateForSnapshot();
    }

    internal string BottomBarStateForSnapshot() =>
        $"favourite {(BottomFavoriteButton.IsEnabled ? "enabled" : "disabled")} {(BottomFavoriteButton.IsChecked == true ? "on" : "off")}, connect {(BottomConnectButton.IsEnabled ? "enabled" : "disabled")}";

    internal async Task<string> ToggleFavoriteFromBarForSnapshot()
    {
        var before = Selected?.Name ?? "(nothing)";
        await ToggleFavoriteFromBarAsync();
        return $"toggled on {before}, now selected {Selected?.Name ?? "(nothing)"}";
    }

    /// <summary>Snapshot only: whether every bottom-bar button lies inside the navigation pane and the window.</summary>
    internal string BottomBarFitForSnapshot()
    {
        if (Content is not FrameworkElement root) return "no window";
        FrameworkElement[] buttons = [BottomAddButton]; // the only bottom-bar button since WIN-HEADER-MAC
        var pane = NavPane.TransformToVisual(root).TransformBounds(new Windows.Foundation.Rect(0, 0, NavPane.ActualWidth, NavPane.ActualHeight));
        var bad = new List<string>();
        foreach (var b in buttons)
        {
            var r = b.TransformToVisual(root).TransformBounds(new Windows.Foundation.Rect(0, 0, b.ActualWidth, b.ActualHeight));
            if (r.Width < 1 || r.X < pane.X - 0.5 || r.Right > pane.Right + 0.5 || r.Bottom > root.ActualHeight + 0.5 || r.Bottom > pane.Bottom + 0.5)
                bad.Add($"{AutomationProperties.GetName(b)} {r.X:0},{r.Y:0} {r.Width:0}x{r.Height:0}");
        }
        return (bad.Count == 0 ? "fits" : "CLIPPED " + string.Join("; ", bad)) + $": window {root.ActualWidth:0}x{root.ActualHeight:0}, pane {pane.Width:0}x{pane.Height:0}";
    }
}
