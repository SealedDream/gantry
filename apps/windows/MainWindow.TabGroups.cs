using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// Edge-style tab groups on the core strip rules (C ABI 32): a coloured group chip leads each group's run of tabs,
/// clicking it collapses or expands the group, and its menu renames, recolours, ungroups or closes it. Tab menus add
/// New Group, Add to Group, Remove from Group and Group Tabs by Folder. The app keeps only the current strip; every
/// change goes through the core, which returns the new order and the tabs to close.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>Group chips are a fixed colour per core colour id (the same eight as Native Mac), not theme colours.</summary>
    private static readonly Dictionary<string, Windows.UI.Color> GroupColors = new()
    {
        ["grey"] = ColorHelper.FromArgb(0xFF, 0x8A, 0x8D, 0x91),
        ["blue"] = ColorHelper.FromArgb(0xFF, 0x3B, 0x82, 0xF6),
        ["red"] = ColorHelper.FromArgb(0xFF, 0xE0, 0x4F, 0x4F),
        ["yellow"] = ColorHelper.FromArgb(0xFF, 0xE0, 0xA8, 0x20),
        ["green"] = ColorHelper.FromArgb(0xFF, 0x2E, 0xA0, 0x5A),
        ["pink"] = ColorHelper.FromArgb(0xFF, 0xE0, 0x5C, 0xA8),
        ["purple"] = ColorHelper.FromArgb(0xFF, 0x8B, 0x5C, 0xE0),
        ["cyan"] = ColorHelper.FromArgb(0xFF, 0x1F, 0xA8, 0xC0),
    };

    private const double GroupMarkSize = 8;
    private const double GroupedTabRule = 2;

    /// <summary>Alpha of a grouped tab's tint (Edge: tabs carry a faint wash of their group's colour).</summary>
    private const byte GroupedTabTintAlpha = 0x24;

    /// <summary>The strip's groups as the core last returned them (replaced, never edited in place).</summary>
    private JsonArray _groups = [];

    /// <summary>Each shown group's chip by group id, rebuilt with the strip (the tab bar scrolls a group's chip into view).</summary>
    private readonly Dictionary<string, Button> _chips = [];

    private static string? ConnectionUuid(WorkspaceTab tab) => Guid.TryParse(tab.ConnectionId, out var id) ? id.ToString() : null;

    private JsonObject StripJson() => new()
    {
        ["tabs"] = new JsonArray(_tabs.Select(t => (JsonNode)new JsonObject
        {
            ["id"] = t.StripId.ToString(),
            ["connection"] = ConnectionUuid(t),
            ["group"] = t.Group,
            ["detached"] = t.Detached,
        }).ToArray()),
        ["groups"] = _groups.DeepClone(),
    };

    private JsonObject? GroupById(string? id) => id is null ? null : _groups.OfType<JsonObject>().FirstOrDefault(g => (string?)g["id"] == id);

    private static bool IsCollapsed(JsonObject? group) => (bool?)group?["collapsed"] ?? false;

    /// <summary>Runs one strip op through the core and shows the result; a refused op (a too-long name) is reported.</summary>
    private async Task RunStripOp(JsonObject op)
    {
        JsonObject change;
        try { change = TabGroups.Apply(StripJson(), op); }
        catch (BastionException ex) { await ShowModal("Could not change the tab group", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }
        ApplyStrip(change["strip"] as JsonObject);
        var closed = (change["closed"] as JsonArray ?? []).Select(n => (string?)n).ToHashSet();
        foreach (var tab in _tabs.Where(t => closed.Contains(t.StripId.ToString())).ToList()) await RequestCloseTab(tab, FocusState.Pointer);
    }

    private async Task GroupByFolderAsync()
    {
        try { ApplyStrip(TabGroups.AutoGroup(_library, StripJson())); }
        catch (BastionException ex) { await ShowModal("Could not group the tabs", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
    }

    /// <summary>
    /// Reopened workspace tabs rejoin their saved groups (Codex Y03): saved definitions (name, colour, collapsed) are
    /// added to the strip unless a group with that id is already there, and each tab moves next to its group's run.
    /// </summary>
    private void RestoreTabGroups(IReadOnlyList<(WorkspaceTab Tab, string Group)> grouped, JsonArray? saved)
    {
        if (grouped.Count == 0 || saved is null) return;
        var defs = saved.OfType<JsonObject>().Where(g => (string?)g["id"] is not null).ToDictionary(g => (string)g["id"]!);
        var groups = (JsonArray)_groups.DeepClone();
        foreach (var id in grouped.Select(p => p.Group).Distinct())
            if (GroupById(id) is null && defs.TryGetValue(id, out var def)) groups.Add(def.DeepClone());
        var known = groups.OfType<JsonObject>().Select(g => (string?)g["id"]).ToHashSet();
        var groupOf = grouped.Where(p => known.Contains(p.Group)).ToDictionary(p => p.Tab, p => p.Group);
        // Keep the strip order, but pull each tab to just after the last tab already in its group, so groups stay contiguous.
        var order = new List<WorkspaceTab>();
        foreach (var tab in _tabs)
        {
            var group = groupOf.GetValueOrDefault(tab) ?? tab.Group;
            var after = group is null ? -1 : order.FindLastIndex(t => (groupOf.GetValueOrDefault(t) ?? t.Group) == group);
            order.Insert(after < 0 ? order.Count : after + 1, tab);
        }
        ApplyStrip(new JsonObject
        {
            ["tabs"] = new JsonArray(order.Select(t => (JsonNode)new JsonObject
            {
                ["id"] = t.StripId.ToString(),
                ["group"] = groupOf.GetValueOrDefault(t) ?? t.Group,
                ["detached"] = t.Detached,
            }).ToArray()),
            ["groups"] = groups,
        });
    }

    /// <summary>Takes the core's strip: the tab order, each tab's group and the groups, then redraws the strip.</summary>
    private void ApplyStrip(JsonObject? strip)
    {
        if (strip is null) return;
        var byId = _tabs.ToDictionary(t => t.StripId.ToString());
        var order = new List<WorkspaceTab>();
        foreach (var node in strip["tabs"] as JsonArray ?? [])
        {
            if ((string?)node?["id"] is not { } id || !byId.Remove(id, out var tab)) continue;
            tab.Group = (string?)node["group"];
            tab.Detached = (bool?)node["detached"] ?? false;
            order.Add(tab);
        }
        order.AddRange(byId.Values); // never drop a tab the core did not echo
        TabStore.Reorder(this, order);
        _groups = strip["groups"]?.DeepClone() as JsonArray ?? [];
        RenderStrip();
    }

    /// <summary>Rebuilds the strip's children in order: a chip before each group's first tab; tabs of a collapsed group
    /// hide (except the active one). Groups left without tabs are dropped.</summary>
    private void RenderStrip()
    {
        // W16/W17: a change the user made (drop, collapse, expand) slides from where the strip was drawn.
        var before = _animateNextStrip ? StripPositions() : null;
        var hiddenBefore = _tabs.Where(t => t.Header.Visibility != Visibility.Visible).ToList();
        _animateNextStrip = false;
        var used = _tabs.Select(t => t.Group).Where(g => g is not null).ToHashSet();
        _groups = new JsonArray(_groups.OfType<JsonObject>().Where(g => used.Contains((string?)g["id"])).Select(g => (JsonNode)g.DeepClone()).ToArray());
        foreach (var t in _tabs.Where(t => GroupById(t.Group) is null)) t.Group = null;

        TabStrip.Children.Clear();
        _chips.Clear();
        string? previous = null;
        foreach (var tab in _tabs)
        {
            // B12-W2b: a torn-off tab's header stays out of this strip.
            if (tab.Window is not null) { tab.Header.Visibility = Visibility.Collapsed; continue; }
            var group = GroupById(tab.Group);
            if (group is not null && tab.Group != previous) TabStrip.Children.Add(_chips[tab.Group!] = GroupChip(group));
            previous = tab.Group;
            tab.Header.Visibility = IsCollapsed(group) && !ReferenceEquals(tab, _active) ? Visibility.Collapsed : Visibility.Visible;
            tab.Header.BorderBrush = group is null ? null : new SolidColorBrush(ColorOf(group));
            tab.Header.BorderThickness = new Thickness(0, 0, 0, group is null ? 0 : GroupedTabRule);
            PaintTab(tab); // grouped tabs take their group's tint (GroupTint)
            AutomationProperties.SetHelpText(tab.Select, group is null ? "" : "In group " + GroupLabel(group));
            TabStrip.Children.Add(tab.Header);
        }
        LayoutTabs();
        if (before is null) return;
        var expanded = hiddenBefore.FirstOrDefault(t => t.Header.Visibility == Visibility.Visible)?.Group;
        AnimateStripFrom(before, expanded is null ? null : "g:" + expanded);
    }

    private static Windows.UI.Color ColorOf(JsonObject group) => GroupColors.GetValueOrDefault((string?)group["color"] ?? "", GroupColors["grey"]);

    /// <summary>An inactive, unhovered tab's fill in its group's colour (Edge-style), or null outside a group.</summary>
    private Brush? GroupTint(WorkspaceTab tab) =>
        GroupById(tab.Group) is { } group ? new SolidColorBrush(WithAlpha(ColorOf(group), GroupedTabTintAlpha)) : null;

    private static Windows.UI.Color WithAlpha(Windows.UI.Color c, byte a) => ColorHelper.FromArgb(a, c.R, c.G, c.B);

    private static string GroupLabel(JsonObject group) => (string?)group["name"] is { Length: > 0 } name ? name : "Unnamed group";

    /// <summary>The chip that leads a group: colour mark plus name (and the tab count when collapsed). Click collapses or expands.</summary>
    private Button GroupChip(JsonObject group)
    {
        var id = (string)group["id"]!;
        var collapsed = IsCollapsed(group);
        var count = _tabs.Count(t => t.Group == id);
        // Edge-style label: a chip filled with the group colour, its name in white (a dot alone when unnamed).
        var colour = ColorOf(group);
        var onColour = new SolidColorBrush(Colors.White);
        var content = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space4") };
        if ((string?)group["name"] is { Length: > 0 } name) content.Children.Add(new TextBlock { Text = name, Foreground = onColour, VerticalAlignment = VerticalAlignment.Center, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        else content.Children.Add(new Border { Width = GroupMarkSize, Height = GroupMarkSize, CornerRadius = new CornerRadius(GroupMarkSize / 2), Background = onColour, VerticalAlignment = VerticalAlignment.Center });
        if (collapsed) content.Children.Add(new TextBlock { Text = count.ToString(), Foreground = onColour, Opacity = 0.85, VerticalAlignment = VerticalAlignment.Center });
        var chip = new Button { Style = Ui.Style("TabSelectButtonStyle"), Content = content, Height = Ui.Double("ControlHeight"),
            Background = new SolidColorBrush(colour), CornerRadius = new CornerRadius(Ui.Double("ControlHeight") / 2) };
        AutomationProperties.SetName(chip, "Tab group " + GroupLabel(group));
        AutomationProperties.SetItemStatus(chip, (collapsed ? "Collapsed, " : "Expanded, ") + (count == 1 ? "1 tab" : $"{count} tabs"));
        ToolTipService.SetToolTip(chip, collapsed ? "Expand group" : "Collapse group");
        chip.Click += (_, _) =>
        {
            void Toggle() => _ = RunStripOp(new JsonObject { ["op"] = "setCollapsed", ["group"] = id, ["collapsed"] = !collapsed });
            if (collapsed) { _animateNextStrip = true; Toggle(); }
            else CollapseGroupAnimated(id, Toggle);
        };
        chip.ContextFlyout = GroupMenu(id);
        return chip;
    }

    private MenuFlyout GroupMenu(string id)
    {
        var menu = new MenuFlyout();
        var rename = new MenuFlyoutItem { Text = "Rename Group…" };
        rename.Click += (_, _) => _ = RenameGroupAsync(id);
        menu.Items.Add(rename);
        menu.Items.Add(ColorMenu(id));
        menu.Items.Add(new MenuFlyoutSeparator());
        var ungroup = new MenuFlyoutItem { Text = "Ungroup" };
        ungroup.Click += (_, _) => _ = RunStripOp(new JsonObject { ["op"] = "ungroup", ["group"] = id });
        var close = new MenuFlyoutItem { Text = "Close Group" };
        close.Click += (_, _) => _ = RunStripOp(new JsonObject { ["op"] = "closeGroup", ["group"] = id });
        menu.Items.Add(ungroup);
        menu.Items.Add(close);
        return menu;
    }

    private MenuFlyoutSubItem ColorMenu(string id)
    {
        var sub = new MenuFlyoutSubItem { Text = "Colour" };
        foreach (var (color, label) in TabGroups.Colors())
        {
            var item = new MenuFlyoutItem
            {
                Text = label,
                Icon = new FontIcon { Glyph = "●", FontFamily = new FontFamily("Segoe UI Symbol"), Foreground = new SolidColorBrush(GroupColors.GetValueOrDefault(color, GroupColors["grey"])) },
            };
            item.Click += (_, _) => _ = RunStripOp(new JsonObject { ["op"] = "recolor", ["group"] = id, ["color"] = color });
            sub.Items.Add(item);
        }
        return sub;
    }

    private async Task RenameGroupAsync(string id)
    {
        var name = new TextBox { Header = "Name", Text = (string?)GroupById(id)?["name"] ?? "" };
        AutomationProperties.SetName(name, "Group name");
        if (await ShowModal("Rename Group", name, primary: "Rename", cancel: "Cancel", focus: name))
            await RunStripOp(new JsonObject { ["op"] = "rename", ["group"] = id, ["name"] = name.Text });
    }

    /// <summary>The group entries of a tab's right-click menu; Add to Group lists the open groups when the menu opens.</summary>
    private void AddGroupItems(MenuFlyout menu, WorkspaceTab tab)
    {
        var newGroup = new MenuFlyoutItem { Text = "Add Tab to New Group" };
        var addTo = new MenuFlyoutSubItem { Text = "Add Tab to Group" };
        var remove = new MenuFlyoutItem { Text = "Remove from Group" };
        var byFolder = new MenuFlyoutItem { Text = "Group Tabs by Folder" };
        newGroup.Click += (_, _) => _ = RunStripOp(new JsonObject { ["op"] = "newGroup", ["tabs"] = new JsonArray(tab.StripId.ToString()) });
        remove.Click += (_, _) => _ = RunStripOp(new JsonObject { ["op"] = "removeFromGroup", ["tab"] = tab.StripId.ToString() });
        byFolder.Click += (_, _) => _ = GroupByFolderAsync();
        menu.Opening += (_, _) =>
        {
            addTo.Items.Clear();
            foreach (var g in _groups.OfType<JsonObject>().Where(g => (string?)g["id"] != tab.Group))
            {
                var gid = (string)g["id"]!;
                var item = new MenuFlyoutItem { Text = GroupLabel(g) };
                item.Click += (_, _) => _ = RunStripOp(new JsonObject { ["op"] = "addToGroup", ["tab"] = tab.StripId.ToString(), ["group"] = gid });
                addTo.Items.Add(item);
            }
            addTo.Visibility = addTo.Items.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            remove.Visibility = tab.Group is null ? Visibility.Collapsed : Visibility.Visible;
            byFolder.IsEnabled = _tabs.Count(t => t.ConnectionId is not null) >= 2;
        };
        menu.Items.Add(new MenuFlyoutSeparator());
        menu.Items.Add(newGroup);
        menu.Items.Add(addTo);
        menu.Items.Add(remove);
        menu.Items.Add(byFolder);
    }

    /// <summary>Selecting a tab of a collapsed group (Ctrl+Tab, a workspace) expands the group through the core.</summary>
    private void RevealGroupOf(WorkspaceTab tab)
    {
        if (IsCollapsed(GroupById(tab.Group))) _ = RunStripOp(new JsonObject { ["op"] = "setCollapsed", ["group"] = tab.Group, ["collapsed"] = false });
    }
}
