using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Rows of one section on a single surface with a hairline between them: the grouped form the Mac app uses for
/// Settings, the credential editor and the workspace manager (Form with .grouped style). One surface per section,
/// never one per row.
/// </summary>
public static class GroupedRows
{
    /// <summary>A grouped surface holding <paramref name="rows"/>, each padded and separated by a divider.</summary>
    public static Border Group(IEnumerable<UIElement> rows)
    {
        var stack = new StackPanel();
        var group = new Border
        {
            Child = stack,
            BorderThickness = new Thickness(1),
            CornerRadius = Ui.Radius("RadiusLarge"),
        };
        var dividers = new List<Border>();
        foreach (var row in rows)
        {
            if (stack.Children.Count > 0)
            {
                var divider = new Border { Height = 1, Margin = new Thickness(Ui.Double("Space12"), 0, 0, 0) };
                dividers.Add(divider);
                stack.Children.Add(divider);
            }
            stack.Children.Add(new Border { Child = row, Padding = RowPadding });
        }
        // Theme brushes follow the element's theme (the snapshot renderer switches it), so they are read on load.
        void Paint()
        {
            group.Background = Ui.Brush(group, "LayerBackgroundBrush");
            group.BorderBrush = Ui.Brush(group, "LayerStrokeBrush");
            foreach (var d in dividers) d.Background = Ui.Brush(group, "DividerBrush");
        }
        group.Loaded += (_, _) => Paint();
        group.ActualThemeChanged += (_, _) => Paint();
        return group;
    }

    public static Border Group(params UIElement[] rows) => Group((IEnumerable<UIElement>)rows);

    private static Thickness RowPadding => new(Ui.Double("Space12"), Ui.Double("Space8"), Ui.Double("Space12"), Ui.Double("Space8"));
}
