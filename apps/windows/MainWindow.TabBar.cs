using System;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Tab bar layout (docs/specs/session-restore-and-tab-bar.md, section 4). The strip stays custom (TabView idles at 100%
// of a core here, see MainWindow.xaml.cs), but behaves like Tabby's: each tab is as wide as its full title (shrinking
// evenly to TabMinWidth only when the bar is full), and once they overflow the strip scrolls with ‹ › buttons. An "All tabs" menu at the right end lists every tab.
public sealed partial class MainWindow
{
    /// <summary>Size each visible tab to its title, then show the scroll buttons if they overflow.</summary>
    private void LayoutTabs()
    {
        SyncSessionRows(); // UI-05: tabs opened, closed or moved; a no-op when the rows already match
        UpdateToolbarLabels(); // tabs opened or closed change how much room labels may take (deferred, coalesced)
        UpdateAllTabsButton();
        UpdateVerticalTabList();
        if (VerticalTabs)
        {
            LayoutVerticalTabs();
            return;
        }
        // The tab area is as wide as its tabs, so the room is computed. It can be zero or less in a narrow window (the
        // toolbar's own buttons take the row): that is an overflow, not "not laid out yet", or the uncapped tabs push +,
        // Terminal profiles and All tabs off-screen. Only a bar with no width yet waits for its SizeChanged.
        if (TabBarSlotWidth() <= 0) return;
        var viewport = TabAreaAvailableWidth();
        var shown = _tabs.Where(t => t.Header.Visibility == Visibility.Visible).ToList();
        if (shown.Count == 0)
        {
            SetTabScrollButtons(false);
            return;
        }
        // Owner point 12 and 2026-11-16: each tab shows its full title while the bar has room (no fixed cap); when the
        // bar is full they shrink evenly (the widest first) with an ellipsis, down to TabMinWidth; past that the strip
        // scrolls with the ‹ › buttons. The full title stays in the tooltip.
        var min = Ui.Double("TabMinWidth");
        foreach (var tab in shown)
        {
            tab.Header.HorizontalAlignment = HorizontalAlignment.Left;
            tab.Header.MinWidth = min;
            tab.Header.MaxWidth = double.PositiveInfinity;
            if (!double.IsNaN(tab.Header.Width)) tab.Header.Width = double.NaN;
        }
        TabStrip.Measure(new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity));
        // Layout rounding at display scales above 100 % can make shrunk tabs measure a pixel over the room; that turned
        // the scroll arrows on, and the arrows' width then stood unused beside the tabs (#1090, 125 %). So the shrink
        // aims RoundingSlack under the room, and the overflow test allows the same slack.
        var cap = TabShareCap(shown.Select(t => t.Header.DesiredSize.Width).ToList(), viewport - RoundingSlack - (TabStrip.DesiredSize.Width - shown.Sum(t => t.Header.DesiredSize.Width)), min);
        var capped = !double.IsPositiveInfinity(cap);
        if (capped) foreach (var tab in shown) tab.Header.MaxWidth = cap;
        TabStrip.Measure(new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity));
        SetTabScrollButtons(TabStrip.DesiredSize.Width > viewport + (capped ? RoundingSlack : 0.5));
        UpdateTabAreaMax();
        RevealActiveTab();
    }

    /// <summary>
    /// The widest a tab may be so <paramref name="widths"/> fit in <paramref name="room"/>: no cap (infinity) when they
    /// fit as they are; otherwise the level where the widest tabs are cut down evenly (narrow tabs keep their size),
    /// never below <paramref name="min"/>.
    /// </summary>
    /// <summary>Pixels allowed for layout rounding when shrunk tabs are fitted to the bar.</summary>
    private const double RoundingSlack = 2;

    internal static double TabShareCap(IReadOnlyList<double> widths, double room, double min)
    {
        if (widths.Count == 0 || widths.Sum() <= room + 0.5) return double.PositiveInfinity;
        var sorted = widths.OrderBy(w => w).ToList();
        var left = room;
        for (var i = 0; i < sorted.Count; i++)
        {
            var share = left / (sorted.Count - i);
            if (sorted[i] > share) return Math.Max(min, Math.Floor(share));
            left -= sorted[i];
        }
        return double.PositiveInfinity;
    }

    /// <summary>
    /// Room for the tabs: the tab bar less its padding, its other buttons and the column gaps (the scroll arrows are
    /// not counted, so showing them cannot flip the overflow decision). The tab area is as wide as the tabs, so
    /// its own width says nothing about the room.
    /// </summary>
    private double TabAreaAvailableWidth()
    {
        var gaps = Math.Max(0, TabBar.ColumnDefinitions.Count - 1) * TabBar.ColumnSpacing;
        var others = TabBar.Children.OfType<FrameworkElement>()
            .Where(c => c != TabArea && c != TabScrollLeftButton && c != TabScrollRightButton && c.Visibility == Visibility.Visible)
            .Sum(c => c.ActualWidth);
        return TabBarSlotWidth() - TabBar.Padding.Left - TabBar.Padding.Right - gaps - others;
    }

    /// <summary>
    /// The width the toolbar gives the tab bar (its star column). Not ActualWidth: when the tabs want more than the
    /// column, WinUI arranges the bar at its wanted width and clips it, so ActualWidth would always report room enough
    /// and the scroll arrows would never turn on (the #1023 regression at 800 px).
    /// </summary>
    private double TabBarSlotWidth()
    {
        var slot = Microsoft.UI.Xaml.Controls.Primitives.LayoutInformation.GetLayoutSlot(TabBar).Width;
        return slot > 0 ? Math.Min(slot, TabBar.ActualWidth) : TabBar.ActualWidth;
    }

    /// <summary>Caps the scroller at the room left after the scroll arrows, so overflowing tabs scroll and + stays in view.</summary>
    private void UpdateTabAreaMax()
    {
        var arrows = TabScrollLeftButton.Visibility == Visibility.Visible ? TabScrollLeftButton.ActualWidth + TabScrollRightButton.ActualWidth : 0;
        var max = Math.Max(0, TabAreaAvailableWidth() - arrows);
        if (Math.Abs(TabScroller.MaxWidth - max) > 0.5) TabScroller.MaxWidth = max;
        TraceTabBar(max);
    }

    /// <summary>Test hooks only (BASTION_TABBAR_TRACE): the numbers behind the overflow decision, one line per layout.</summary>
    private void TraceTabBar(double max)
    {
        if (TestHooks.TabBarTrace is not { } path) return;
        try
        {
            var slot = Microsoft.UI.Xaml.Controls.Primitives.LayoutInformation.GetLayoutSlot(TabBar);
            var kids = string.Join(" ", TabBar.Children.OfType<FrameworkElement>().Select(c =>
                $"{c.Name}[col{Grid.GetColumn(c)} {c.Visibility} want={c.DesiredSize.Width:F0} act={c.ActualWidth:F0}]"));
            var line = $"{DateTime.Now:HH:mm:ss.fff} window={Toolbar.ActualWidth:F0} bar.act={TabBar.ActualWidth:F0} bar.want={TabBar.DesiredSize.Width:F0} slot={slot.Width:F0} room={TabAreaAvailableWidth():F0} strip.want={TabStrip.DesiredSize.Width:F0} cap={max:F0} arrows={TabScrollLeftButton.Visibility} {kids}";
            System.IO.File.AppendAllText(path, line + Environment.NewLine);
        }
        catch (System.IO.IOException) { }
    }

    /// <summary>
    /// Scroll the active tab into view once the strip has its final widths. ActivateTab asks too, but a tab added this
    /// pass has no width yet, so that request lands before the layout above and scrolls nowhere.
    /// </summary>
    private void RevealActiveTab()
    {
        if (_active is not { } tab || tab.Header.Visibility != Visibility.Visible) return;
        // Every tab fits (no scroll arrows): nothing to scroll to, and the strip's own layout puts the offset back to 0.
        // UpdateLayout lays out the whole window inside the open or close handler; skipping it spares that pass.
        if (!VerticalTabs && TabScrollLeftButton.Visibility != Visibility.Visible) return;
        TabStrip.UpdateLayout();
        if (VerticalTabs)
        {
            tab.Header.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false });
            return;
        }
        // Scroll so the active tab shows and its group chip too: bringing only the tab into view left the
        // chip cut to a sliver at the strip's left edge on narrow windows (18 px wide at 640x480, its name gone).
        var viewport = TabScroller.ViewportWidth;
        var tabLeft = LeftInStrip(tab.Header);
        var right = tabLeft + tab.Header.ActualWidth;
        // When both cannot fit, the active tab wins: its icon and title stay whole and the chip is cut (as Native Mac,
        // HEADER-A-MAC). The chip is shown when there is room.
        var left = _chips.TryGetValue(tab.Group ?? "", out var chip) ? LeftInStrip(chip) : tabLeft;
        var offset = TabScroller.HorizontalOffset;
        if (left < offset) offset = left;
        if (right > offset + viewport) offset = right - viewport;
        if (tabLeft < offset) offset = tabLeft;
        if (Math.Abs(offset - TabScroller.HorizontalOffset) > 0.5) TabScroller.ChangeView(offset, null, null, disableAnimation: true);
    }

    private double LeftInStrip(UIElement el) => el.TransformToVisual(TabStrip).TransformPoint(new Windows.Foundation.Point(0, 0)).X;

    private void SetTabScrollButtons(bool overflow)
    {
        var v = overflow ? Visibility.Visible : Visibility.Collapsed;
        if (TabScrollLeftButton.Visibility != v) TabScrollLeftButton.Visibility = TabScrollRightButton.Visibility = v;
        UpdateTabScrollButtons();
    }

    private void UpdateTabScrollButtons()
    {
        TabScrollLeftButton.IsEnabled = TabScroller.HorizontalOffset > 0.5;
        TabScrollRightButton.IsEnabled = TabScroller.HorizontalOffset < TabScroller.ScrollableWidth - 0.5;
    }

    private void TabScroller_SizeChanged(object sender, SizeChangedEventArgs e) => LayoutTabs();

    private void TabScroller_ViewChanged(object? sender, ScrollViewerViewChangedEventArgs e) => UpdateTabScrollButtons();

    /// <summary>Most of a page of tabs per click; no animation (docs/TESTING.md, "WinUI CPU spin").</summary>
    private void ScrollTabs(int direction)
    {
        var page = Math.Max(Ui.Double("TabMinWidth"), TabScroller.ViewportWidth * 0.8);
        var to = Math.Clamp(TabScroller.HorizontalOffset + direction * page, 0, TabScroller.ScrollableWidth);
        TabScroller.ChangeView(to, null, null, disableAnimation: true);
    }

    private void TabScrollLeft_Click(object sender, RoutedEventArgs e) => ScrollTabs(-1);

    private void TabScrollRight_Click(object sender, RoutedEventArgs e) => ScrollTabs(1);

    /// <summary>All Tabs (button or Ctrl+Shift+A): every open tab in strip order, with search and close (AllTabsPanel).</summary>
    private void AllTabsFlyout_Opening(object? sender, object e)
    {
        var panel = new AllTabsPanel(AllTabsRows, key => PickTab((WorkspaceTab)key),
            key => _ = RequestCloseTab((WorkspaceTab)key, FocusState.Pointer), VerticalTabs,
            on => SetSetting("tabs.vertical", on ? "true" : "false"));
        panel.Done += (_, _) => AllTabsFlyout.Hide();
        AllTabsFlyout.Content = panel;
    }

    /// <summary>True while the All tabs list is open: tab switches and closes from it leave keyboard focus in the list.</summary>
    private bool AllTabsListOpen => AllTabsFlyout.IsOpen;

    private void AllTabsFlyout_Opened(object? sender, object e) => (AllTabsFlyout.Content as AllTabsPanel)?.FocusSearch();

    private IReadOnlyList<AllTabsRow> AllTabsRows() =>
        _tabs.Select(t => new AllTabsRow(t, t.Label.Text, GroupById(t.Group) is { } g ? GroupLabel(g) : null, ReferenceEquals(t, _active))).ToList();

    /// <summary>Ctrl+Shift+A outside a terminal (in a terminal it stays Select All, as in Windows Terminal).</summary>
    private void ShowAllTabs()
    {
        if (_tabs.Count == 0) return;
        AllTabsFlyout.ShowAt(TabOverviewButton);
    }
}
