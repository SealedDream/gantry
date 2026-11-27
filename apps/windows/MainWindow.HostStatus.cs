using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// More → Host status: a dashboard of the connections that opted in (Properties › Show on host status, inherited from
/// folders). The core checker (C ABI 68) only runs while this dialog is open; it opens no socket or timer otherwise.
/// </summary>
public sealed partial class MainWindow
{
    private static readonly (string Label, uint Secs)[] HostStatusIntervals = [("Every 30 seconds", 30), ("Every minute", 60), ("Every 5 minutes", 300)];
    private static readonly TimeSpan HostStatusRedraw = TimeSpan.FromSeconds(1);

    private void HostStatus_Click(object sender, RoutedEventArgs e) => _ = HostStatusAsync();

    internal async Task HostStatusAsync()
    {
        if (_modal is not null) return;
        using var dash = new HostStatusDashboard(HostStatusIntervals[1].Secs);
        int count;
        try { count = dash.Load(_library); }
        catch (BastionException ex)
        {
            await ShowModal("Could not open host status", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }

        var body = new StackPanel { Spacing = 10, MinWidth = 420 };
        if (count == 0)
        {
            body.Children.Add(Ui.Text("No connections are on host status.", "BodyStrongTextStyle"));
            body.Children.Add(new TextBlock { Text = "Turn on Properties › Show on host status for a connection or a folder.", TextWrapping = TextWrapping.Wrap });
            await ShowModal("Host status", body, primary: "Close", cancel: null);
            return;
        }

        var list = new ListView { SelectionMode = ListViewSelectionMode.None, MaxHeight = 360 };
        AutomationProperties.SetName(list, "Host status list");
        var interval = new ComboBox { Header = "Check", ItemsSource = HostStatusIntervals.Select(i => i.Label).ToList(), SelectedIndex = 1, MinWidth = 180 };
        AutomationProperties.SetName(interval, "Check interval");
        interval.SelectionChanged += (_, _) => { if (interval.SelectedIndex >= 0) dash.SetInterval(HostStatusIntervals[interval.SelectedIndex].Secs); };
        var checkNow = new Button { Content = Ui.IconLabel(Ui.Icon("GlyphRefresh"), "Check now"), VerticalAlignment = VerticalAlignment.Bottom };
        AutomationProperties.SetName(checkNow, "Check now");
        checkNow.Click += (_, _) => dash.CheckNow();
        var summary = new TextBlock();
        AutomationProperties.SetAutomationId(summary, "HostStatusSummary");
        body.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12, Children = { interval, checkNow } });
        body.Children.Add(summary);
        body.Children.Add(list);

        void Redraw()
        {
            IReadOnlyList<HostStatusDto> rows;
            try { rows = dash.Snapshot(); }
            catch (BastionException ex) { summary.Text = Capitalised(ex.Message); AutomationProperties.SetName(summary, summary.Text); return; }
            var lines = rows.OrderBy(r => StateOrder(r.State)).ThenBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).Select(HostStatusLine).ToList();
            if (!lines.SequenceEqual(list.Items.Cast<string>())) list.ItemsSource = lines;
            summary.Text = $"{rows.Count(r => r.State == "up")} up, {rows.Count(r => r.State == "down")} down, {rows.Count(r => r.State is "unknown" or "skipped")} not checked";
            AutomationProperties.SetName(summary, summary.Text);
        }

        var timer = new DispatcherTimer { Interval = HostStatusRedraw };
        timer.Tick += (_, _) => Redraw();
        dash.SetVisible(true);
        Redraw();
        timer.Start();
        try { await ShowModal("Host status", body, primary: "Close", cancel: null, wide: true); }
        finally
        {
            timer.Stop();
            dash.SetVisible(false);
        }
    }

    /// <summary>Down first so a failing host is never below the fold.</summary>
    private static int StateOrder(string state) => state switch { "down" => 0, "up" => 1, "unknown" => 2, _ => 3 };

    internal static string HostStatusLine(HostStatusDto r)
    {
        var state = r.State switch
        {
            "up" => r.LatencyMs is { } ms ? $"Up, {ms} ms" : "Up",
            "down" => string.IsNullOrWhiteSpace(r.Error) ? "Down" : $"Down: {r.Error}",
            "skipped" => "Not checked (behind a jump host or gateway)",
            _ => "Checking…",
        };
        var since = r.ChangedAt is { } t && r.State is "up" or "down" ? $" since {DateTimeOffset.FromUnixTimeSeconds(t).ToLocalTime():HH:mm}" : "";
        return $"{r.Name} · {state}{since}";
    }
}
