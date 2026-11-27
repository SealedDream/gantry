using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;

namespace Bastion.Shell;

// TABBAR-WIN (Mac #1277, owner round 2 items 7 and 10): one filter field style on every list page, and a one-line note
// at the top of Activity and Audit Log saying what each is, with a link to the other.
public sealed partial class MainWindow
{
    private const double ListFilterWidth = 200;

    /// <summary>The list page filter field; <paramref name="changed"/> gets the trimmed text on every keystroke.</summary>
    internal static TextBox ListFilterBox(string text, string tip, Action<string> changed)
    {
        var box = new TextBox { PlaceholderText = "Filter", Text = text, Width = ListFilterWidth, HorizontalAlignment = HorizontalAlignment.Left };
        AutomationProperties.SetName(box, "Filter");
        ToolTipService.SetToolTip(box, tip);
        box.TextChanged += (_, _) => changed(box.Text.Trim());
        return box;
    }

    /// <summary>Case-insensitive substring match on any field; an empty filter matches everything.</summary>
    internal static bool FilterMatches(string filter, params string?[] fields) =>
        filter.Length == 0 || fields.Any(f => f is not null && f.Contains(filter, StringComparison.CurrentCultureIgnoreCase));

    /// <summary>Shows only the rows whose text matches; rows are (element, searchable text).</summary>
    internal static void ApplyRowFilter(IEnumerable<(UIElement Row, string[] Text)> rows, string filter)
    {
        foreach (var (row, text) in rows)
            row.Visibility = FilterMatches(filter, text) ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>One caption line with a link to the sibling page, put above row 0 of <paramref name="content"/>.</summary>
    private void AddPageNote(Grid content, string text, string linkText, Action link)
    {
        var line = new TextBlock { Style = Ui.Style("CaptionSecondaryTextStyle"), TextTrimming = TextTrimming.CharacterEllipsis };
        line.Inlines.Add(new Run { Text = text + " " });
        var go = new Hyperlink();
        go.Inlines.Add(new Run { Text = linkText });
        go.Click += (_, _) => link();
        line.Inlines.Add(go);
        ToolTipService.SetToolTip(line, text);
        foreach (var child in content.Children.OfType<FrameworkElement>()) Grid.SetRow(child, Grid.GetRow(child) + 1);
        content.RowDefinitions.Insert(0, new RowDefinition { Height = GridLength.Auto });
        content.Children.Add(line);
    }
}
