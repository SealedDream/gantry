using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Tree multi-select (owner 2026-11-16, Native Mac parity): with several rows selected the details pane shows the bulk
// editor (B3-BULK-EDIT) and the row menu acts on the selection: connect, edit together, move, delete with one confirm.
public sealed partial class MainWindow
{
    /// <summary>The selected library rows (no headings, no session rows), in tree order, when more than one is selected.</summary>
    private List<TreeItem>? TreeMultiSelection()
    {
        var items = Tree.SelectedItems.Where(i => !i.IsGroup && !i.IsSession).Select(i => TreeItem.Find(_roots, i.Id) ?? i).ToList();
        return items.Count > 1 ? items : null;
    }

    /// <summary>The details pane was opened for a multi-selection only (hidden for a new profile); closed when it ends.</summary>
    private bool _multiTransient;

    private void Tree_MultiSelectionChanged()
    {
        if (TreeMultiSelection() is not { } items)
        {
            if (_multiTransient) { _multiTransient = false; EndInspectorTransient(); }
            UpdateInspector(Selected);
            return;
        }
        SetMoreDeleteEnabled(true);
        // As Properties… does: the pane shows for the selection without touching the remembered choice (runner 3:
        // with the pane off, a multi-selection showed nothing).
        _inspectorPending = items.FirstOrDefault(i => !i.IsFolder) ?? items[0];
        if (!_inspectorTransient) _inspectorTransient = _multiTransient = true;
        EnsureInspector();
        UpdatePanes();
        FillMultiInspector(items);
    }

    private void FillMultiInspector(List<TreeItem> items)
    {
        _inspectorStale = false;
        ReleaseNotes();
        InspectorBody.Children.Clear();
        InspectorFooter.Visibility = Visibility.Collapsed;
        InspectorKind.Visibility = InspectorActions.Visibility = Visibility.Collapsed;
        InspectorTitle.Text = $"{items.Count} selected";
        if (items.Any(i => i.IsFolder))
        {
            var hint = Ui.Text("Select connections only to edit them together.", "BodySecondaryTextStyle");
            hint.TextWrapping = TextWrapping.Wrap;
            InspectorBody.Children.Add(hint);
            return;
        }
        BulkEditForm form;
        try { form = new BulkEditForm(_library, items.Select(i => i.Id).ToList()); }
        catch (BastionException ex) { InspectorBody.Children.Add(CodedErrorText("APP", ex.Message)); return; }
        InspectorTitle.Text = form.Title;
        InspectorBody.Children.Add(form.Body);
        if (!form.HasProperties) return;
        var apply = new Button { Content = form.ApplyLabel, Style = Ui.Style("AccentButtonStyle"), Margin = new Thickness(0, Ui.Double("Space12"), 0, 0) };
        AutomationProperties.SetName(apply, form.ApplyLabel);
        apply.Click += async (_, _) =>
        {
            if (!form.Apply()) return;
            var keep = Selected?.Id;
            await Mutate(() => keep, "Could not save the connections");
        };
        InspectorBody.Children.Add(apply);
    }

    /// <summary>The row menu for a right-click inside a multi-selection.</summary>
    private List<MenuFlyoutItemBase> SelectionMenuEntries(List<TreeItem> items)
    {
        var connections = items.Where(i => i.Connection is not null).ToList();
        var result = new List<MenuFlyoutItemBase>();
        void Entry(string text, Func<Task> run, bool enabled = true)
        {
            var entry = new MenuFlyoutItem { Text = text, IsEnabled = enabled };
            entry.Click += (_, _) => _ = run();
            result.Add(entry);
        }
        Entry($"Connect {Plural(connections.Count, "Connection")}", async () =>
        {
            foreach (var c in connections) await RunAsync("connect", c);
        }, connections.Count > 0);
        if (connections.Count == items.Count) Entry($"Edit {items.Count} Connections…", () => BulkEditAsync(items.Select(i => i.Id).ToList()));
        result.Add(new MenuFlyoutSeparator());
        Entry($"Move {items.Count} Items…", () => MoveItemsAsync(items));
        Entry($"Delete {items.Count} Items…", DeleteAsync);
        return result;
    }

    /// <summary>Move several items to one folder (one dialog, one save).</summary>
    private async Task MoveItemsAsync(List<TreeItem> items)
    {
        if (_modal is not null || items.Count == 0) return;
        var form = _moveForm = new MoveForm(items[0], _roots);
        if (!await ShowModal($"Move {items.Count} items", form.Body, primary: "Move", cancel: "Cancel", validate: form.Validate, focus: form.List)) return;
        var destination = form.Destination;
        if (destination is { } folder) SaveExpanded(folder, true);
        await Mutate(() =>
        {
            foreach (var i in items) if (i.ParentId != destination) _library.MoveBefore(i.Id, destination, null);
            return items[0].Id;
        }, "Could not move the items");
    }

    /// <summary>Delete for several selected rows: one confirm that names them all, then each goes as a single delete does.</summary>
    private async Task DeleteManyAsync(List<TreeItem> items)
    {
        var outcome = RetentionDays() > 0 ? "move to Recently Deleted" : "are deleted for good";
        var body = new StackPanel { Spacing = Ui.Double("Space8") };
        var lead = Ui.Text($"These {items.Count} items {outcome}:", "BodyTextStyle");
        lead.TextWrapping = TextWrapping.Wrap;
        body.Children.Add(lead);
        var names = Ui.Text(string.Join("\n", items.Select(i => i.IsFolder ? $"{i.Name} (folder and everything in it)" : i.Name)), "BodyStrongTextStyle");
        names.TextWrapping = TextWrapping.Wrap;
        AutomationProperties.SetAutomationId(names, "tree-delete-names");
        body.Children.Add(new ScrollViewer { Content = names, MaxHeight = Ui.Double("DialogWidth") / 2 });
        if (!await ShowModal($"Delete {items.Count} items?", body, primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
        var parentId = items[0].ParentId;
        // A folder's contents go with it: skip rows inside a selected folder so nothing is trashed twice.
        var ids = items.Select(i => i.Id).ToHashSet();
        var top = items.Where(i => !HasSelectedAncestor(i, ids)).ToList();
        await Mutate(() =>
        {
            foreach (var i in top) TrashItem(i.Id);
            if (top.Any(i => i.IsFolder)) PruneTreeState();
            return parentId;
        }, "Could not delete the items");
    }

    private bool HasSelectedAncestor(TreeItem item, HashSet<string> ids)
    {
        for (var p = item.ParentId; p is not null; p = TreeItem.Find(_roots, p)?.ParentId)
            if (ids.Contains(p)) return true;
        return false;
    }
}
