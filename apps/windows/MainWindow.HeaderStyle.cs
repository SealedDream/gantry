using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// The title bar, laid out like Native Mac (owner 2026-11-15, WIN-HEADER-MAC; the Classic toolbar is gone): the library
/// switcher as wide as the sidebar (its right edge is the sidebar's divider), the tab overview with the open-tab count,
/// the tabs, + ▾ (new connection, new folder, local shell), one ⋯ menu and the caption buttons. The sidebar's top row is
/// the one "Search or connect" box and the pin. The command palette stays on its shortcut (Ctrl+Shift+P).
/// </summary>
public sealed partial class MainWindow
{
    private bool _headerApplied;

    private void ApplyHeader()
    {
        if (_headerApplied) return;
        _headerApplied = true;
        UpdateAllTabsButton();
        // Before the first frame the title bar is not built yet (WIN-COLD-LIGHT): its XAML carries the same tip.
        if (_titleBar is not null) ToolTipService.SetToolTip(TerminalProfilesButton, "New connection, new folder or a terminal: local shell, PowerShell or WSL");
        UpdateCompactLibraryWidth();
        _passthrough = null; // the caption's clickable regions change with the controls
        UpdateToolbarLabels();
    }

    /// <summary>The count button's number and tip follow the tabs (called on every change).</summary>
    private void UpdateAllTabsButton()
    {
        if (_titleBar is null) return; // built after the first frame; TitleBarBuilt calls this again (WIN-COLD-LIGHT)
        var count = _tabs.Count.ToString(System.Globalization.CultureInfo.CurrentCulture);
        if (TabCountText.Text == count && _tabCountShown) return;
        _tabCountShown = true;
        TabCountText.Text = count;
        var label = $"All tabs: {Plural(_tabs.Count, "open tab")}";
        ToolTipService.SetToolTip(TabOverviewButton, $"{label} (Ctrl+Shift+A)");
        AutomationProperties.SetHelpText(TabOverviewButton, label);
    }

    private bool _tabCountShown;

    private void ShowSidebar_Click(object sender, RoutedEventArgs e) => ShowNav(true);

    /// <summary>The switcher names the open library (called from UpdateDocumentSwitcher).</summary>
    private void UpdateCompactLibrary(string name)
    {
        _compactLibraryName = name;
        if (_titleBar is null) return; // TitleBarBuilt shows it (WIN-COLD-LIGHT)
        CompactLibraryText.Text = name;
        AutomationProperties.SetName(CompactLibraryButton, $"Library: {name}. Switch library");
        ToolTipService.SetToolTip(CompactLibraryButton, $"Open library: {name}. Click to switch, open or create a document.");
    }

    /// <summary>
    /// The switcher's right edge is the sidebar's divider: its host is as wide as the sidebar column less the toolbar's
    /// left padding (both inside the zoomed RootGrid, so no scale is applied). With the sidebar hidden it shrinks to its
    /// icon and drops the line. Runs on sidebar resize, show and hide.
    /// </summary>
    private void UpdateCompactLibraryWidth()
    {
        if (_windowClosed || _titleBar is null) return; // the title bar is built after the first frame (WIN-COLD-LIGHT)
        var navShown = NavPane.Visibility == Visibility.Visible && Grid.GetColumnSpan(NavPane) == 1;
        // The sidebar shown again has no width until its next layout pass (and its SizeChanged does not fire when the
        // width is the one it had before): measure again once the layout has run.
        if (navShown && NavColumn.ActualWidth <= 0) { DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, UpdateCompactLibraryWidth); }
        // The switcher goes with the sidebar (owner 2026-11-15); while it is hidden only the show-sidebar button is there.
        var width = (navShown ? NavColumn.ActualWidth : 0) - Toolbar.Padding.Left;
        var full = width >= 2 * Ui.Double("MinHitTarget");
        CompactLibraryHost.Visibility = full ? Visibility.Visible : Visibility.Collapsed;
        ShowSidebarButton.Visibility = full ? Visibility.Collapsed : Visibility.Visible;
        if (full) CompactLibraryHost.Width = width;
        _passthrough = null;
    }

    private void OnNavPaneSizeChanged(object sender, SizeChangedEventArgs e) => UpdateCompactLibraryWidth();
}
