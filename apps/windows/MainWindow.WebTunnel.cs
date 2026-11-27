using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Web tabs through a saved tunnel (core webtunnel, C ABI 37), as apps/macos WebTunnels.swift: a SOCKS (-D) tunnel becomes
// the page's only proxy, DNS included; a local (-L) tunnel replaces the URL's host and port with 127.0.0.1:PORT. The
// tunnel must be running in the Tunnel Manager; a stopped or deleted tunnel is an error, never a direct load. Each tunnel
// keeps its own WebView2 data folder, so cookies never mix between tunnels or with direct tabs.
public sealed partial class MainWindow
{
    /// <summary>Root of the per-tunnel web data folders the core creates and prunes.</summary>
    private string WebTunnelDataDir => SessionDataDir; // the core adds web-tunnels/<id>

    /// <summary>Inspector "Network" for a web connection: which tunnel its tab opens through.</summary>
    private void AddWebTunnelSection(ConnectionDto c)
    {
        var header = Ui.Text("Network", "SectionHeaderTextStyle");
        header.Margin = Ui.Thickness("InspectorSectionMargin");
        AutomationProperties.SetHeadingLevel(header, AutomationHeadingLevel.Level3);
        InspectorBody.Children.Add(header);
        var box = new ComboBox { Header = "Open through", HorizontalAlignment = HorizontalAlignment.Stretch, Margin = Ui.Thickness("InspectorButtonMargin") };
        AutomationProperties.SetName(box, "Open through");
        AutomationProperties.SetAutomationId(box, "WebTunnelPicker");
        string current;
        try { current = _library.WebTunnelPlan(c.Id, WebTunnelDataDir)?.TunnelId ?? ""; }
        catch (BastionException ex)
        {
            InspectorBody.Children.Add(box);
            InspectorBody.Children.Add(Notice(ex.Message));
            return;
        }
        var filling = false;
        // Tunnels can be added in the Tunnel Manager while this inspector is open: reload the list each time it opens.
        void Fill()
        {
            List<(string Id, string Label)> rows = [("", "Direct")];
            try { rows.AddRange(_library.Tunnels().Where(t => t.Kind != "remote").Select(t => (t.Id, $"{t.Name} (via {t.ViaName})"))); }
            catch (BastionException) { }
            var shown = box.Items.OfType<ComboBoxItem>().Select(i => ((string)i.Tag, (string)i.Content));
            if (shown.SequenceEqual(rows)) return; // unchanged: leave an open list alone
            filling = true;
            box.Items.Clear();
            foreach (var (id, label) in rows) box.Items.Add(new ComboBoxItem { Content = label, Tag = id });
            box.SelectedItem = box.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (string)i.Tag == current) ?? box.Items[0];
            filling = false;
        }
        Fill();
        box.DropDownOpened += (_, _) => Fill();
        box.SelectionChanged += (_, _) =>
        {
            if (filling || box.SelectedItem is not ComboBoxItem { Tag: string id } || id == current) return;
            try
            {
                _library.SetWebTunnel(c.Id, id.Length == 0 ? null : id);
                SaveLibrary();
                current = id;
            }
            catch (BastionException ex) { _ = ShowModal("Could not change the tunnel", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        };
        InspectorBody.Children.Add(box);
    }

    /// <summary>
    /// Open a web connection that is set to a tunnel. Returns false when it has none (the caller opens it directly);
    /// true when it was handled, opened or refused with a message.
    /// </summary>
    private bool TryOpenWebThroughTunnel(TreeItem item, ConnectionDto c, Uri url, out WebTabView? opened)
    {
        opened = null;
        WebTunnelPlanDto? plan;
        try { plan = _library.WebTunnelPlan(c.Id, WebTunnelDataDir); }
        catch (BastionException ex)
        {
            _ = ShowModal("Cannot open " + item.Name, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return true;
        }
        if (plan is null) return false;
        if (RunningStatus(plan.TunnelId) is not { Running: true })
        {
            _ = ShowModal("Cannot open " + item.Name, ErrorText($"{item.Name} opens through the tunnel “{plan.TunnelName}”. Start it in the Tunnel Manager first."), primary: "OK", cancel: null);
            return true;
        }
        WebTabView web;
        if (plan.ProxyUrl is { } proxy && Uri.TryCreate(proxy, UriKind.Absolute, out var p) && p.Port > 0)
            web = new WebTabView(url, socksPort: p.Port, dataDir: plan.DataDir);
        else if (plan.ForwardAddress is { } address && ThroughForward(url, address) is { } forwarded)
            web = new WebTabView(forwarded, dataDir: plan.DataDir);
        else
        {
            _ = ShowModal("Cannot open " + item.Name, ErrorText($"The tunnel “{plan.TunnelName}” has no usable address."), primary: "OK", cancel: null);
            return true;
        }
        AddTab(item.Name, null, web, hostId: item.Id);
        opened = web;
        return true;
    }

    /// <summary><paramref name="url"/> with its host and port replaced by a local forward's <c>127.0.0.1:PORT</c>.</summary>
    internal static Uri? ThroughForward(Uri url, string address)
    {
        var parts = address.Split(':');
        if (parts.Length != 2 || !int.TryParse(parts[1], out var port) || port is <= 0 or > 65535) return null;
        return new UriBuilder(url) { Host = parts[0], Port = port }.Uri;
    }
}
