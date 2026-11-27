using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Vertical tabs (core setting <c>tabs.vertical</c>, the same one Native Mac reads): the one tab panel moves from the
/// tab bar's scroller into a list down the left of the session, stacked top to bottom with each row the list's width.
/// The tab bar keeps its buttons (new terminal, profiles, All tabs). Groups, chips, menus and drag work the same way.
/// </summary>
public sealed partial class MainWindow
{
    private bool VerticalTabs => _titleBar is { } bar && ReferenceEquals(VerticalTabScroller.Content, bar.TabStrip);

    private void ApplyTabOrientation(bool vertical)
    {
        _verticalTabsWanted = vertical;
        if (_titleBar is null) return; // the strip is part of the title bar, built after the first frame (WIN-COLD-LIGHT)
        if (vertical == VerticalTabs) return;
        if (vertical)
        {
            TabScroller.Content = null;
            VerticalTabScroller.Content = TabStrip;
        }
        else
        {
            VerticalTabScroller.Content = null;
            TabScroller.Content = TabStrip;
        }
        TabStrip.Orientation = vertical ? Orientation.Vertical : Orientation.Horizontal;
        TabScroller.Visibility = vertical ? Visibility.Collapsed : Visibility.Visible;
        UpdateVerticalTabList();
        RenderStrip();
    }

    /// <summary>The list shows only while tabs are open, so the start page keeps the full width.</summary>
    private void UpdateVerticalTabList() =>
        VerticalTabScroller.Visibility = VerticalTabs && _tabs.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>Rows fill the list's width; chips too, so a long group name trims instead of widening the list.</summary>
    private void LayoutVerticalTabs()
    {
        SetTabScrollButtons(false);
        foreach (var child in TabStrip.Children)
        {
            if (child is not FrameworkElement el) continue;
            el.Width = double.NaN;
            el.MaxWidth = double.PositiveInfinity;
            el.HorizontalAlignment = HorizontalAlignment.Stretch;
        }
        RevealActiveTab();
    }

}
