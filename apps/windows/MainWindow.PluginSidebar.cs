using System.Text.Json.Nodes;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// PLUG-API-13 (docs/plans/PLUG-API-13.md A/B; Mac PluginSidebar.swift): a plugin entry whose type declares
// sidebar = "tree" lists the plugin's items under it in the library. Expanding the entry opens a second session on it
// (the view "sidebar", one root tree); collapsing stops it. Nothing runs at start or on a timer. The plugin can show no
// prompts there (the core refuses them); a menu choice is the user's action, and an open request shows the core's open
// sheet over the library. Rows are never saved.
public sealed partial class MainWindow
{
    /// <summary>The sidebar view's tree: its only node, the first one (core host/view.rs sidebar_nodes).</summary>
    private const int SidebarTreeNode = 0;
    private const string SidebarLoading = "Loading…";
    private const string SidebarRouteFirst = "Connect the entry once to start its route";

    private readonly Dictionary<string, PluginTabView> _sidebarViews = new();
    private readonly Dictionary<string, HashSet<string>> _sidebarExpanded = new();
    /// <summary>An entry's status row when no session runs (a gateway entry, a missing plugin).</summary>
    private readonly Dictionary<string, string> _sidebarStatus = new();
    /// <summary>What each entry's rows were last built from, so an unchanged update leaves the tree alone.</summary>
    private readonly Dictionary<string, string> _sidebarSig = new();
    private PluginTabView? _sidebarSheet;

    /// <summary>The user expanded a plugin entry with a tree: open its sidebar session and ask for the top level.</summary>
    private async void OpenPluginSidebar(TreeItem item)
    {
        if (item.Connection is not { } c || _sidebarViews.ContainsKey(c.Id) || _sidebarStatus.ContainsKey(c.Id)) return;
        if (PluginTypeOf(c) is not { } type) return;
        try
        {
            // A gateway or tunnel starts only from the entry's own Connect, never from an expand.
            if (PluginEntryClient.Gateway(_library, c.Id) is not null)
            {
                _sidebarStatus[c.Id] = SidebarRouteFirst;
                SyncPluginSidebarRows();
                return;
            }
        }
        catch (BastionException ex)
        {
            _sidebarStatus[c.Id] = ex.Message;
            SyncPluginSidebarRows();
            return;
        }
        var unverified = string.Equals(type.Tier, "unverified", StringComparison.OrdinalIgnoreCase);
        var view = new PluginTabView(type.PluginId) { EntryId = c.Id, SheetsOnly = true };
        _sidebarViews[c.Id] = view;
        _sidebarExpanded[c.Id] = new();
        view.Model.Changed += () => SidebarChanged(c.Id, view);
        view.SheetChanged += on => ShowSidebarSheet(view, on);
        WatchPluginOpens(view, c.Id);
        AppLog.Info($"Plugin sidebar: opening {type.Id}");
        // The saved login comes from the vault, as for the entry's own Connect (the core reads it; never the app).
        CredentialStore? vault = CredentialsIfOpen;
        if (vault is null && c.EffectiveCredentialId is not null && await ConfirmVaultOpenAsync())
        {
            try { vault = OpenCredentials(); }
            catch (BastionException) { vault = null; } // opens without a login; the plugin says the login is missing
        }
        if (!_sidebarViews.TryGetValue(c.Id, out var still) || !ReferenceEquals(still, view)) return; // collapsed meanwhile
        var lib = _library.NativeHandle;
        var vh = vault?.NativeHandle ?? IntPtr.Zero;
        var dir = SessionDataDir;
        var id = c.Id;
        await view.OpenWithAsync(() => PluginViewSession.OpenSidebar(lib, vh, id, dir, unverified));
        if (_sidebarViews.TryGetValue(id, out still) && ReferenceEquals(still, view)) view.Model.AskChildren(SidebarTreeNode, null);
    }

    /// <summary>The user collapsed the entry: stop its session; the placeholder comes back.</summary>
    private void ClosePluginSidebar(string entryId)
    {
        _sidebarStatus.Remove(entryId);
        _sidebarExpanded.Remove(entryId);
        if (_sidebarViews.Remove(entryId, out var view))
        {
            if (ReferenceEquals(_sidebarSheet, view)) ShowSidebarSheet(view, false);
            view.Dispose();
            AppLog.Info("Plugin sidebar: closed");
        }
        SyncPluginSidebarRows();
    }

    private void ExpandPluginRow(TreeItem row)
    {
        if (row.PluginEntryId is not { } entry || row.PluginKey is not { } key || !_sidebarViews.TryGetValue(entry, out var view)) return;
        if (!_sidebarExpanded[entry].Add(key)) return;
        if (view.Model.Children(SidebarTreeNode, key) is null) view.Model.AskChildren(SidebarTreeNode, key);
        SyncPluginSidebarRows();
    }

    private void CollapsePluginRow(TreeItem row)
    {
        if (row.PluginEntryId is { } entry && row.PluginKey is { } key && _sidebarExpanded.TryGetValue(entry, out var open)) open.Remove(key);
    }

    /// <summary>Double-click on an item sends its <c>open</c> menu item (plugin API 1.3); false when it has none.</summary>
    private bool ActivatePluginRow(TreeItem row)
    {
        if (row.PluginMenu.All(m => m.Id != "open")) return false;
        SendPluginMenu(row, "open");
        return true;
    }

    /// <summary>A menu choice on an item: sent to the plugin as the user's action.</summary>
    private void SendPluginMenu(TreeItem row, string item)
    {
        if (row.PluginEntryId is not { } entry || row.PluginKey is not { } key || !_sidebarViews.TryGetValue(entry, out var view)) return;
        view.Model.MenuInput(SidebarTreeNode, key, item);
    }

    /// <summary>The item's menu as the plugin gave it (right-click on a row of a plugin's tree).</summary>
    private List<MenuFlyoutItemBase> PluginRowMenu(TreeItem row) =>
        row.PluginMenu.Select(m =>
        {
            var mi = new MenuFlyoutItem { Text = m.Title };
            mi.Click += (_, _) => SendPluginMenu(row, m.Id);
            return (MenuFlyoutItemBase)mi;
        }).ToList();

    private void SidebarChanged(string entryId, PluginTabView view)
    {
        if (!_sidebarViews.TryGetValue(entryId, out var still) || !ReferenceEquals(still, view)) return;
        if (LibraryConnection(entryId) is { } item) ApplySidebarRows(item);
    }

    /// <summary>The core's open sheet (or a plugin dialog) of a sidebar session, over the library.</summary>
    private void ShowSidebarSheet(PluginTabView view, bool on)
    {
        if (on)
        {
            if (ReferenceEquals(_sidebarSheet, view)) return;
            if (_sidebarSheet is { } old) RootGrid.Children.Remove(old);
            Grid.SetRowSpan(view, Math.Max(1, RootGrid.RowDefinitions.Count));
            RootGrid.Children.Add(view);
            _sidebarSheet = view;
            return;
        }
        if (!ReferenceEquals(_sidebarSheet, view)) return;
        RootGrid.Children.Remove(view);
        _sidebarSheet = null;
        Tree.Focus(FocusState.Programmatic);
    }

    // ---- rows ----

    /// <summary>Puts each plugin entry's rows after its session rows (a placeholder until it is expanded).</summary>
    private void SyncPluginSidebarRows()
    {
        if (TreeItem.SidebarTreeTypes.Count == 0) return;
        void Walk(IEnumerable<TreeItem> level)
        {
            foreach (var i in level)
            {
                if (i.IsFolder || i.IsGroup) Walk(i.Children);
                else if (i.HasSidebarTree) ApplySidebarRows(i);
            }
        }
        Walk(_roots);
        // Sessions of entries no longer in the library stop.
        foreach (var gone in _sidebarViews.Keys.Where(id => LibraryConnection(id) is null).ToList()) ClosePluginSidebar(gone);
    }

    private void ApplySidebarRows(TreeItem entry)
    {
        var rows = BuildSidebarRows(entry.Id);
        var sig = Signature(rows);
        var children = entry.Children;
        var has = children.Any(r => r.IsPluginRow);
        if (has && _sidebarSig.TryGetValue(entry.Id, out var last) && last == sig) return;
        _sidebarSig[entry.Id] = sig;
        for (var i = children.Count - 1; i >= 0; i--) if (children[i].IsPluginRow) children.RemoveAt(i);
        foreach (var r in rows) children.Add(r);
        entry.SessionsChanged(); // HasChildren
    }

    private static string Signature(IEnumerable<TreeItem> rows) =>
        string.Join("|", rows.Select(r => $"{r.Id}={r.Name}:{(r.Expanded ? 1 : 0)}:{string.Join(",", r.PluginMenu.Select(m => m.Id))}[{Signature(r.Children)}]"));

    private List<TreeItem> BuildSidebarRows(string entryId)
    {
        if (_sidebarStatus.TryGetValue(entryId, out var status)) return [StatusRow(entryId, "", status)];
        if (!_sidebarViews.TryGetValue(entryId, out var view)) return [StatusRow(entryId, "", SidebarLoading)];
        var m = view.Model;
        if (m.Ended is { } ended) return [StatusRow(entryId, "", ended)];
        if (m.Message is { } message && m.Children(SidebarTreeNode, null) is null) return [StatusRow(entryId, "", message)];
        return Level(entryId, m, null);
    }

    private List<TreeItem> Level(string entryId, PluginViewModel m, string? parent)
    {
        if (m.Children(SidebarTreeNode, parent) is not { } items) return [StatusRow(entryId, parent ?? "", SidebarLoading)];
        if (items.Count == 0) return [StatusRow(entryId, parent ?? "", "No items")];
        var open = _sidebarExpanded.GetValueOrDefault(entryId) ?? [];
        var list = new List<TreeItem>();
        foreach (var it in items)
        {
            if (PluginViewModel.Str(it, "key") is not { Length: > 0 } key) continue;
            var label = PluginViewModel.Str(it, "label") ?? key;
            var menu = (it["menu"] as JsonArray ?? []).OfType<JsonObject>()
                .Select(e => (Id: PluginViewModel.Str(e, "id") ?? "", Title: PluginViewModel.Str(e, "title") ?? PluginViewModel.Str(e, "id") ?? ""))
                .Where(e => e.Id.Length > 0).ToList();
            var hasChildren = PluginViewModel.Bool(it, "has-children") ?? false;
            var expanded = hasChildren && open.Contains(key);
            var row = new TreeItem
            {
                Id = $"plg:{entryId}:{key}", Name = label, IsFolder = false, ParentId = entryId, Description = label,
                Glyph = FluentIcons.Object(hasChildren ? "server" : "vm-unknown"),
                PluginEntryId = entryId, PluginKey = key, PluginMenu = menu, Expanded = expanded,
            };
            if (hasChildren)
                foreach (var child in expanded ? Level(entryId, m, key) : [StatusRow(entryId, key, SidebarLoading)]) row.Children.Add(child);
            list.Add(row);
        }
        return list;
    }

    private static TreeItem StatusRow(string entryId, string under, string text) => new()
    {
        Id = $"plg:{entryId}:{under}:status", Name = text, IsFolder = false, ParentId = entryId, Description = text,
        Glyph = "", PluginEntryId = entryId, Expanded = false,
    };
}
