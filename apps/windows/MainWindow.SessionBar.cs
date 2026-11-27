using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Session title bar (owner spec §3, Codex Y06): one SessionBar above each saved SSH connection's tab. Shown or hidden
// for every tab by the core setting terminal.session-bar (Settings › Terminal › Session bar; Unpin turns it off).
public sealed partial class MainWindow
{
    private const string SessionBarSetting = "terminal.session-bar";
    private const int DefaultSshPort = 22;

    /// <summary>Settings › Terminal › Session bar (one setting for every tab; Unpin on a bar turns it off).</summary>
    private bool SessionBarPinned
    {
        get => SettingValue(SessionBarSetting) != "false";
        set => SetSetting(SessionBarSetting, value ? "true" : "false");
    }

    /// <summary>The setting changed (here, from a bar's Unpin, or in Settings): every open bar follows.</summary>
    private void ApplySessionBarSetting(string value)
    {
        foreach (var tab in _tabs) tab.Bar?.SetPinned(value != "false");
    }

    /// <summary>Add the bar once a tab belongs to a saved SSH connection; <paramref name="user"/> is the signed-in user.</summary>
    private void AddSessionBar(WorkspaceTab tab, string connectionId, string? user)
    {
        if (tab.Bar is not null || FindItem(_roots, connectionId)?.Connection is not { } c) return;
        var who = string.IsNullOrWhiteSpace(user) ? c.Username : user;
        // W21 and UI-04: "Name (host:port) · user · SSH"; the bar adds the state word and Logging.
        var status = ConnectionSummary.StatusLine(c.Name, $"{c.Host}:{c.Port ?? DefaultSshPort}", who, c.Protocol);
        var bar = new SessionBar(RootGrid, status, SessionBarPinned, () => _ = ReconnectFromBarAsync(tab), pinned => SessionBarPinned = pinned);
        Grid.SetColumnSpan(bar.Root, 2);
        tab.Body.Children.Add(bar.Root);
        tab.Bar = bar;
        PaintSessionIdentity(tab, tab.HostColorId is { } hid ? _hostColors.GetValueOrDefault(hid) : null); // UI-01
    }

    /// <summary>Reconnect: the normal connect flow for the tab's connection (it may ask to sign in); the new session replaces this tab.</summary>
    private async Task ReconnectFromBarAsync(WorkspaceTab tab)
    {
        if (tab.ConnectionId is not { } id || FindItem(_roots, id) is not { } item || !IsSsh(item))
        {
            Announce("This connection is no longer in the library.");
            return;
        }
        SelectItem(item.Id);
        await ConnectAsync(item, replacing: tab);
    }
}
