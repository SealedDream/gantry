using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// LOG-NATIVE-01 items 1 and 2 (Windows): a History section in the details pane for a connection, and for a folder (its
// subfolders included, with the connection's name on each row). The newest few sessions from the core's activity store,
// read off the UI thread so selecting stays instant; "Show all…" opens Application › Activity for that connection or
// folder. The two-line footer (last connected, last result) is unchanged.
public sealed partial class MainWindow
{
    /// <summary>How many sessions the details pane lists before "Show all…".</summary>
    private const int HistoryRows = 5;

    /// <summary>Add the History section for a connection (<paramref name="kind"/> "connection") or a folder ("folder").</summary>
    private void AddHistorySection(string kind, string id, string name)
    {
        if (_library.IsQuickConnect) return;
        var header = Ui.Text("History", "SectionHeaderTextStyle");
        header.Margin = Ui.Thickness("InspectorSectionMargin");
        AutomationProperties.SetHeadingLevel(header, AutomationHeadingLevel.Level3);
        InspectorBody.Children.Add(header);
        var rows = new StackPanel { Spacing = Ui.Double("Space4") };
        AutomationProperties.SetName(rows, "History");
        rows.Children.Add(Ui.Text("Loading…", "CaptionSecondaryTextStyle"));
        InspectorBody.Children.Add(rows);
        var all = new HyperlinkButton { Content = "Show all…", Padding = new Thickness(0) };
        AutomationProperties.SetName(all, $"Show all sessions of {name}");
        all.Click += (_, _) => OpenActivityFor((kind, id, name));
        InspectorBody.Children.Add(all);
        _ = FillHistoryAsync(rows, kind, id);
    }

    private async Task FillHistoryAsync(StackPanel rows, string kind, string id)
    {
        var dir = SessionDataDir;
        var filter = kind == "folder" ? new ActivityFilter(Folder: id) : new ActivityFilter(Connection: id);
        IReadOnlyList<ActivitySessionDto> page;
        try { page = await Task.Run(() => ActivityClient.Query(dir, filter, 0, HistoryRows)); }
        catch (BastionException ex)
        {
            rows.Children.Clear();
            rows.Children.Add(Ui.Text("History could not be read: " + ex.Message, "CaptionSecondaryTextStyle"));
            return;
        }
        rows.Children.Clear(); // a pane rebuilt meanwhile has dropped these rows; filling them is harmless
        if (page.Count == 0) { rows.Children.Add(Ui.Text("No sessions yet.", "CaptionSecondaryTextStyle")); return; }
        foreach (var s in page)
        {
            var line = ActivityFormat.HistoryLine(s, withConnection: kind == "folder",
                FormatWhen(DateTimeOffset.FromUnixTimeMilliseconds(s.StartedAt).ToLocalTime(), DateTimeOffset.Now));
            var text = Ui.Text(line, "CaptionTextStyle");
            text.TextTrimming = TextTrimming.CharacterEllipsis;
            ToolTipService.SetToolTip(text, line);
            rows.Children.Add(text);
        }
    }
}
