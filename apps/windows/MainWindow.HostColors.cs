using System.Collections.Generic;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Per-host colours (core <c>host_color</c>, set in Properties on a connection or a folder and inherited): a dot in the
/// tree, a bar on the tab's leading edge over a faint tint, and a border round the session — as on Native Mac and Tauri.
/// The core picks the colour and its tint, so every UI agrees. Read once per tree reload, never per paint.
/// </summary>
public sealed partial class MainWindow
{
    private const double HostBarWidth = 3;
    private const double HostBorderWidth = 2;
    private Dictionary<string, HostColorDto> _hostColors = new();
    private Dictionary<string, HostColorDto> _hostColorsNext = new();

    /// <summary>Tree-build resolver: the connection's effective colour, remembered for the tabs.</summary>
    private HostColorDto? HostColorFor(string connectionId) => _hostColorsNext.GetValueOrDefault(connectionId);

    /// <summary>Before a tree build: every connection's colour in one core call (one tree pass), not one call per row.</summary>
    private void LoadHostColors() => _hostColorsNext = LoadHostColorsFrom(_library);

    private static Dictionary<string, HostColorDto> LoadHostColorsFrom(LibraryClient library)
    {
        try { return library.HostColors(); }
        catch (BastionException) { return new(); } // a hand-edited value shows as "no colour", never blocks the tree
    }

    /// <summary>The first tree read, started on a worker in the constructor (see MainWindow); null once used.</summary>
    private Task<(FolderDto Tree, Dictionary<string, HostColorDto> Colors)>? _firstTree;

    /// <summary>After a tree build: swap in the colours it read and repaint every tab (a Properties change lands here).</summary>
    private void RepaintHostColors()
    {
        _hostColors = _hostColorsNext;
        _hostColorsNext = new();
        foreach (var tab in _tabs) PaintTab(tab);
    }

    private static Border NewHostBar()
    {
        var bar = new Border { Width = HostBarWidth, HorizontalAlignment = HorizontalAlignment.Left, IsHitTestVisible = false, Visibility = Visibility.Collapsed };
        AutomationProperties.SetAutomationId(bar, "TabHostColor");
        return bar;
    }

    /// <summary>Called from PaintTab: the bar and border take the accent; an idle tab takes the tint as its background.</summary>
    private void PaintHostColor(WorkspaceTab tab, bool active)
    {
        var color = tab.HostColorId is { } id ? _hostColors.GetValueOrDefault(id) : null;
        PaintSessionIdentity(tab, color);
        if (color is null && PaintProduction(tab)) return;
        if (color is null)
        {
            tab.HostBar.Visibility = Visibility.Collapsed;
            AutomationProperties.SetName(tab.HostBar, "");
            tab.Body.BorderThickness = new Thickness(0);
            return;
        }
        var accent = HostColors.Brush(color.Accent);
        tab.HostBar.Background = accent;
        tab.HostBar.Visibility = Visibility.Visible;
        AutomationProperties.SetName(tab.HostBar, "Host colour " + color.Accent);
        tab.Body.BorderBrush = accent;
        tab.Body.BorderThickness = new Thickness(HostBorderWidth);
        if (!active && !tab.Hover) tab.Header.Background = HostColors.Brush(color.Tint);
    }

    /// <summary>UI-01: the session bar's colour strip and "Production" word, from the same core colour as the tab.</summary>
    private void PaintSessionIdentity(WorkspaceTab tab, HostColorDto? color)
    {
        if (tab.Bar is not { } bar) return;
        var tone = color is { FgLight.Length: > 0 } && !Ui.HighContrast
            ? HostColors.Brush(RootGrid.ActualTheme == ElementTheme.Dark ? color.FgDark : color.FgLight) : null;
        bar.SetIdentity(color is null ? null : HostColors.Brush(color.Accent), tone, color?.Privileged == true);
    }
}
