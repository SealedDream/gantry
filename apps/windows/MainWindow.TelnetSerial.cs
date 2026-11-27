using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Telnet and serial terminals (B7, docs/plans/B7-TELNET-SERIAL.md). Connect, double-click and Return reach these through
/// <see cref="ConnectAsync"/>; neither uses the SSH sign-in form. The policy check, the password opt-in and the port
/// name check are in the core; this file shows the result.
/// </summary>
public sealed partial class MainWindow
{
    private static bool IsTelnet(TreeItem? item) =>
        item?.Connection is { } c && string.Equals(c.Protocol, "telnet", StringComparison.OrdinalIgnoreCase);

    private static bool IsSerial(TreeItem? item) =>
        item?.Connection is { } c && string.Equals(c.Protocol, "serial", StringComparison.OrdinalIgnoreCase);

    /// <summary>Why Telnet is greyed out, in one short line.</summary>
    internal static string TelnetOffText(bool administrator) =>
        administrator ? "Turned off by your administrator." : "Off. Turn on in Settings › Security › Allow Telnet.";

    /// <summary>Telnet can be opened now (the user's switch under the managed policy).</summary>
    internal bool TelnetAllowed
    {
        get
        {
            try { return TelnetSerial.Allowed(Settings); }
            catch (BastionException) { return false; }
        }
    }

    /// <summary>
    /// Open a saved Telnet connection. While Telnet is off it says why instead. The saved password is looked up only
    /// when the connection's own "Type the saved password after the login prompt" is on, and only password logins.
    /// </summary>
    private async Task ConnectTelnetAsync(TreeItem item, LibraryClient? from)
    {
        if (_modal is not null || _connecting || item.Connection is not { } c) return;
        var library = from ?? _library;
        if (!TelnetAllowed)
        {
            var lockReason = TelnetSerial.PolicyLock;
            var text = lockReason is null ? "Telnet is off. Turn on Allow Telnet in Settings › Security." : "Telnet is turned off by your administrator: " + lockReason;
            await ShowModal("Cannot open " + item.Name, ErrorText(text), primary: "OK", cancel: null);
            return;
        }
        string? user = c.Username;
        SshLoginKind? kind = null;
        string? credentialId = null;
        if (OwnTelnetOptIn(library, c.Id))
        {
            var logins = await SavedLoginsAsync(library, c.Id, passwordsOnly: true);
            if (logins.FirstOrDefault(l => l.Login.AutoUse) is { } saved)
            {
                kind = SshLoginKind.Vault;
                credentialId = saved.Credential.Id;
                if (string.IsNullOrWhiteSpace(user)) user = saved.Login.Username;
            }
        }
        _connecting = true;
        TerminalSession session;
        try
        {
            var settings = Settings;
            // A vault login reads the credential through the session manager, so it needs the open vault (as SSH does).
            if (kind == SshLoginKind.Vault) Sessions.SetCredentials(OpenCredentials());
            session = await Task.Run(() => Sessions.ConnectTelnet(library, settings, c.Id, user, kind, credentialId, 80, 24));
        }
        catch (BastionException ex)
        {
            await ShowModal("Could not open " + item.Name, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }
        finally { _connecting = false; }
        AttachRemote(item.Name, session, c.Id, from, $"{c.Name} ({c.Host}:{c.Port ?? 23})");
    }

    /// <summary>The connection's own opt-in (folders and type defaults cannot turn it on).</summary>
    private static bool OwnTelnetOptIn(LibraryClient library, string id)
    {
        try { return library.PropertyValues(id).FirstOrDefault(v => v.Key == "telnet_send_password")?.Own == "true"; }
        catch (BastionException) { return false; }
    }

    /// <summary>
    /// Serial is not offered on Windows (owner, 2026-11-15). A serial connection saved on another device still loads and
    /// shows in the tree; opening it says so instead of opening a port.
    /// </summary>
    private async Task SerialNotSupportedAsync(TreeItem item)
    {
        if (_modal is not null) return;
        await ShowModal("Cannot open " + item.Name, ErrorText("Serial connections are not supported."), primary: "OK", cancel: null);
    }

    /// <summary>
    /// Put a Telnet or serial session in its own tab with the session bar (status and Reconnect, which reopens the
    /// same host or port on the same screen). A drop shows "Connection lost" or "Port disconnected"; there is no
    /// automatic reconnect, and closing the tab releases the port.
    /// </summary>
    private void AttachRemote(string title, TerminalSession session, string connectionId, LibraryClient? from, string barText)
    {
        var view = AttachSession(title, session, from is null ? connectionId : null);
        if (_tabs.FirstOrDefault(t => ReferenceEquals(t.View, view)) is not { } tab) return;
        if (from is null)
        {
            TieTab(tab, connectionId);
            RunHooks("after_connect", connectionId); // B5
            PaintTab(tab);
            RefreshInspectorFor(connectionId);
            SaveOpenSessions();
        }
        var bar = new SessionBar(RootGrid, barText, SessionBarPinned, () => _ = ReopenAsync(tab, view), pinned => SessionBarPinned = pinned,
            reconnectTip: "Connect to the same host and port again (nothing is typed for you)");
        Grid.SetColumnSpan(bar.Root, 2);
        tab.Body.Children.Add(bar.Root);
        tab.Bar = bar;
        PaintSessionIdentity(tab, tab.HostColorId is { } hid ? _hostColors.GetValueOrDefault(hid) : null); // UI-01
        bar.SetState(SessionBarState.Connected);
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timer.Tick += (_, _) =>
        {
            if (view.Session.IsDisposed || !_tabs.Contains(tab)) { timer.Stop(); return; }
            var lost = view.Session.RemoteStatus;
            view.SetBanner(lost, warning: lost is not null);
            if (bar.State != SessionBarState.Connecting) bar.SetState(lost is null ? SessionBarState.Connected : SessionBarState.Disconnected);
            SetTabStatus(tab, lost);
        };
        timer.Start();
    }

    /// <summary>Reconnect (Telnet) or Reopen (serial) on the same screen, off the UI thread.</summary>
    private async Task ReopenAsync(WorkspaceTab tab, TerminalView view)
    {
        if (tab.Bar is not { } bar || bar.State == SessionBarState.Connecting) return;
        bar.SetState(SessionBarState.Connecting);
        var session = view.Session;
        try
        {
            await Task.Run(session.Reconnect);
            bar.SetState(SessionBarState.Connected);
            view.SetBanner(null);
            SetTabStatus(tab, null);
        }
        catch (BastionException ex)
        {
            bar.SetState(SessionBarState.Disconnected);
            view.SetBanner(ex.Message, warning: true);
        }
    }
}

public sealed partial class MainWindow
{
    /// <summary>
    /// Settings › Security › Allow Telnet: asks once when turned on (the risk in words), never when turned off. Disabled
    /// with the administrator's reason while the managed policy forbids Telnet.
    /// </summary>
    private ToggleSwitch AllowTelnetSwitch(string current)
    {
        var reason = TelnetSerial.PolicyLock;
        var toggle = new ToggleSwitch { IsOn = reason is null && current == "true", OnContent = "On", OffContent = "Off", MinHeight = Ui.Double("ControlHeight"), IsEnabled = reason is null };
        ToolTipService.SetToolTip(toggle, reason ?? TelnetSerial.Warning);
        var reverting = false;
        toggle.Toggled += async (_, _) =>
        {
            if (reverting) return;
            if (!toggle.IsOn) { SetSetting(TelnetSerial.AllowSetting, "false"); return; }
            var ok = await ModalOverSettingsAsync(() => ShowModal("Allow Telnet?", ErrorText(TelnetSerial.Warning), primary: "Allow Telnet", cancel: "Cancel"));
            if (ok) { SetSetting(TelnetSerial.AllowSetting, "true"); return; }
            reverting = true;
            toggle.IsOn = false;
            reverting = false;
        };
        return toggle;
    }
}
