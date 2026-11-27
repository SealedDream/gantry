using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Node = Bastion.Shell.PluginViewModel.Node;

namespace Bastion.Shell;

/// <summary>
/// A plugin view's toolbar (owner pick "C", 2026-11-23), the Windows port of Native Mac's PluginToolbar.swift: Refresh
/// as a quiet icon button with the time of the last update, the plugin's labels and other buttons in order, and one
/// accent Connect split button on the right for the run of connection-type buttons (the first is the default action,
/// the others are in its menu).
/// </summary>
internal sealed partial class PluginTabView
{
    /// <summary>Icon names drawn as connection types; a toolbar's buttons with these become one Connect button.</summary>
    private static readonly HashSet<string> ConnectIcons = ["ssh", "rdp", "vnc", "telnet", "web"];
    internal const string ConnectDisabledHint = "Select a row first";

    private static string? IconOf(Node n) => n.Kind == "button" && n.Value is JsonObject r ? PluginViewModel.Str(r, "icon") : null;
    private static JsonObject RecOf(Node n) => n.Value as JsonObject ?? [];
    private static bool EnabledOf(Node n) => PluginViewModel.Bool(RecOf(n), "enabled") ?? true;

    private FrameworkElement Toolbar(int id, IReadOnlyList<Node> list)
    {
        var kids = PluginViewModel.Kids(id, list).ToList();
        var connect = kids.Where(k => IconOf(k) is { } i && ConnectIcons.Contains(i)).ToList();
        var left = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), VerticalAlignment = VerticalAlignment.Center };
        foreach (var k in kids.Except(connect))
        {
            if (IconOf(k) == "refresh") AddRefresh(left, k);
            else left.Children.Add(Element(k, list));
        }
        var grid = new Grid { ColumnSpacing = Ui.Double("Space8"), MinHeight = 32 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.Children.Add(left);
        if (connect.Count > 0)
        {
            var c = ConnectButton(connect);
            Grid.SetColumn(c, 1);
            grid.Children.Add(c);
        }
        return grid;
    }

    private void AddRefresh(StackPanel panel, Node n)
    {
        var label = PluginViewModel.Str(RecOf(n), "label") ?? "Refresh";
        var b = new Button
        {
            Content = Ui.Icon("GlyphRefresh", "SmallIconSize"),
            Style = Ui.Style("SubtleButtonStyle"),
            IsEnabled = EnabledOf(n),
            MinWidth = 32, MinHeight = 32,
            VerticalAlignment = VerticalAlignment.Center,
        };
        ToolTipService.SetToolTip(b, label);
        AutomationProperties.SetName(b, label);
        AutomationProperties.SetAutomationId(b, "plugin-toolbar-refresh");
        var id = n.Id;
        b.Click += (_, _) => _model.Pressed(id);
        panel.Children.Add(b);
        if (_model.UpdatedAt is { } t)
        {
            var u = Ui.Text("Updated " + t.ToString("t"), "CaptionTextStyle");
            u.Foreground = Ui.Brush(this, "TextFillColorSecondaryBrush");
            u.VerticalAlignment = VerticalAlignment.Center;
            AutomationProperties.SetAutomationId(u, "plugin-toolbar-updated");
            panel.Children.Add(u);
        }
    }

    /// <summary>WinUI has no accent SplitButton style: point its own brush keys at the accent fills.</summary>
    private static void Accent(SplitButton b)
    {
        string[] states = ["", "PointerOver", "Pressed"];
        string[] fills = ["AccentFillColorDefaultBrush", "AccentFillColorSecondaryBrush", "AccentFillColorTertiaryBrush"];
        for (var i = 0; i < states.Length; i++)
        {
            b.Resources["SplitButtonBackground" + states[i]] = Application.Current.Resources[fills[i]];
            b.Resources["SplitButtonForeground" + states[i]] = Application.Current.Resources["TextOnAccentFillColorPrimaryBrush"];
            b.Resources["SplitButtonBorderBrush" + states[i]] = Application.Current.Resources["AccentControlElevationBorderBrush"];
        }
    }

    private SplitButton ConnectButton(List<Node> nodes)
    {
        var enabled = nodes.Where(EnabledOf).ToList();
        var first = enabled.FirstOrDefault() ?? nodes[0];
        var firstLabel = PluginViewModel.Str(RecOf(first), "label") ?? "";
        var content = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        // White on the accent fill; the disabled text colour when nothing is selected, so the glyph never vanishes.
        var ink = enabled.Count > 0 ? "#FFFFFF" : Ui.Brush(this, "TextFillColorDisabledBrush") is Microsoft.UI.Xaml.Media.SolidColorBrush d ? ConnectionIcon.Hex(d.Color) : "#808080";
        if (ConnectionIcon.Mono(IconOf(first)!, ink, 16, this) is { } img) content.Children.Add(img);
        content.Children.Add(new TextBlock { Text = "Connect", VerticalAlignment = VerticalAlignment.Center });
        var menu = new MenuFlyout();
        var menuInk = Ui.Brush(this, "TextFillColorPrimaryBrush") is Microsoft.UI.Xaml.Media.SolidColorBrush inkBrush ? ConnectionIcon.Hex(inkBrush.Color) : "#808080";
        foreach (var n in nodes)
        {
            var item = new MenuFlyoutItem { Text = PluginViewModel.Str(RecOf(n), "label") ?? "", IsEnabled = EnabledOf(n) };
            if (ConnectionIcon.Mono(IconOf(n)!, menuInk, 16, this)?.Source is { } src) item.Icon = new ImageIcon { Source = src };
            var nid = n.Id;
            item.Click += (_, _) => _model.Pressed(nid);
            menu.Items.Add(item);
        }
        var split = new SplitButton
        {
            Content = content,
            Flyout = menu,
            IsEnabled = enabled.Count > 0,
            MinHeight = 32,
            VerticalAlignment = VerticalAlignment.Center,
        };
        Accent(split);
        ToolTipService.SetToolTip(split, enabled.Count > 0 ? $"Connect with {firstLabel}" : ConnectDisabledHint);
        AutomationProperties.SetName(split, "Connect");
        AutomationProperties.SetAutomationId(split, "plugin-toolbar-connect");
        var fid = first.Id;
        split.Click += (_, _) => _model.Pressed(fid);
        return split;
    }
}
