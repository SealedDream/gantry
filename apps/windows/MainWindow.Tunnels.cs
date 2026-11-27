using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Tunnel Manager: saved tunnels (core tunneldefs, the same definitions the macOS app edits) started on their own SSH
// connection with no shell (C ABI 72). Sign-in uses the connect dialog and the strict host-key prompt of a normal SSH
// connect; listeners bind 127.0.0.1 only. Running tunnels stop when removed, when stopped here, or when the window closes.
public sealed partial class MainWindow
{
    private readonly Dictionary<string, RunningTunnelHandle> _runningTunnels = new();
    private bool _tunnelsCloseHooked;
    private string _tunnelFilter = "";

    private void TunnelManager_Click(object sender, RoutedEventArgs e) => OpenTunnelManager();

    internal void OpenTunnelManager()
    {
        _pageKind = "tunnels";
        ShowTunnelManagerPage();
    }

    private void ShowTunnelManagerPage()
    {
        if (_pageKind != "tunnels") return;
        var content = new StackPanel { Spacing = Ui.Double("Space8") };
        var note = Ui.Text("Saved port forwards through an SSH connection. Local and SOCKS listen on this PC only (127.0.0.1). Gantry asks for the sign-in each time a tunnel starts.", "CaptionSecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        content.Children.Add(note);
        try
        {
            var all = _library.Tunnels();
            if (all.Count == 0) content.Children.Add(Ui.Text("No tunnels yet.", "BodySecondaryTextStyle"));
            var rows = all.Select(t => ((UIElement)TunnelRow(t), new[] { t.Name, t.Kind, t.ViaName, $"{t.Host}:{t.Port}", t.LocalPort.ToString(System.Globalization.CultureInfo.InvariantCulture) })).ToList();
            if (all.Count > 0) content.Children.Add(ListFilterBox(_tunnelFilter, "Name, connection or address", f => { _tunnelFilter = f; ApplyRowFilter(rows, f); }));
            foreach (var (row, _) in rows) content.Children.Add(row);
            ApplyRowFilter(rows, _tunnelFilter);
        }
        catch (BastionException ex) { content.Children.Add(CodedErrorText("NET", ex.Message)); }
        var add = new Button { Content = "Add Tunnel…" }.Quiet("GlyphAdd", "Add tunnel");
        add.Click += (_, _) => _ = EditTunnelAsync(null);
        ShowPage(null, "Tunnels", content, add);
    }

    /// <summary>The running tunnel's status, or null when it is not running here or cannot report.</summary>
    private TunnelStatusDto? RunningStatus(string id)
    {
        if (!_runningTunnels.TryGetValue(id, out var run)) return null;
        try { return run.Status(); }
        catch (BastionException) { return null; }
    }

    /// <summary>"Running · 3 connections", "Stopped: reason" or "Stopped".</summary>
    private static string TunnelState(TunnelStatusDto? s) => s switch
    {
        { Running: true, Connections: 1 } => "Running · 1 connection",
        { Running: true } => $"Running · {s.Connections} connections",
        { LastError: { Length: > 0 } e } => "Stopped: " + e,
        _ => "Stopped",
    };

    /// <summary>
    /// A "start with connection" tunnel the core started on an open SSH tab of its connection (ABI 65), as a status, with
    /// the tab's session; null when no open tab runs it.
    /// </summary>
    private (TunnelStatusDto Status, TerminalSession Session)? TabForward(TunnelDefDto t)
    {
        foreach (var tab in _tabs)
        {
            if (tab.ConnectionId != t.ViaId || tab.View?.Session is not { IsDisposed: false } session) continue;
            IReadOnlyList<ForwardStatusDto> rows;
            try { rows = session.Forwards(); }
            catch (BastionException) { continue; }
            if (rows.FirstOrDefault(f => f.Id == t.Id) is { } f && (f.Running || f.LastError is { Length: > 0 }))
                return (new TunnelStatusDto(f.Summary, f.Running, f.Connections, f.LastError), session);
        }
        return null;
    }

    private Grid TunnelRow(TunnelDefDto t)
    {
        var onTab = RunningStatus(t.Id) is null ? TabForward(t) : null;
        var status = RunningStatus(t.Id) ?? onTab?.Status;
        var running = status?.Running == true;
        var row = new Grid { ColumnSpacing = Ui.Double("Space8"), MinHeight = Ui.Double("ControlHeight") };
        foreach (var w in new[] { new GridLength(1, GridUnitType.Star), GridLength.Auto, GridLength.Auto, GridLength.Auto })
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        var where = onTab is { Status.Running: true } ? " with the connection" : "";
        var detail = Ui.Text($"{t.Summary} · via {t.ViaName} · {TunnelState(status)}{where}", "CaptionSecondaryTextStyle");
        AutomationProperties.SetName(detail, $"{t.Name} status: {TunnelState(status)}{where}");
        detail.TextWrapping = TextWrapping.Wrap;
        detail.IsTextSelectionEnabled = true;
        row.Children.Add(new StackPanel { VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Text(t.Name, "BodyTextStyle"), detail } });
        AddRowButton(row, 1, new Button { Content = running ? "Stop" : "Start", Style = Ui.Style("SubtleButtonStyle") },
            (running ? "Stop tunnel " : "Start tunnel ") + t.Name,
            () => _ = !running ? StartTunnelAsync(t) : onTab is { } tab ? StopTabTunnelAsync(t, tab.Session) : StopTunnelAsync(t));
        AddRowButton(row, 2, new Button { Content = "Edit…", IsEnabled = !running }.Quiet("GlyphEdit", "Edit"),
            "Edit " + t.Name, () => _ = EditTunnelAsync(t));
        var remove = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphDelete", "IconSize") };
        ToolTipService.SetToolTip(remove, "Delete");
        AddRowButton(row, 3, remove, "Delete tunnel " + t.Name, () => _ = RemoveTunnelAsync(t));
        return row;
    }

    private static void AddRowButton(Grid row, int column, Button button, string name, Action click)
    {
        AutomationProperties.SetName(button, name);
        button.Click += (_, _) => click();
        Grid.SetColumn(button, column);
        row.Children.Add(button);
    }

    private IReadOnlyList<(string Id, string Name)> SshConnections() =>
        AllConnections().Where(IsSsh).Select(i => (i.Id, i.Name)).OrderBy(c => c.Name, StringComparer.CurrentCultureIgnoreCase).ToList();

    private async Task EditTunnelAsync(TunnelDefDto? existing)
    {
        var form = new TunnelForm(existing, SshConnections());
        while (await ShowModal(existing is null ? "Add tunnel" : "Edit tunnel", form.Body, primary: "Save", cancel: "Cancel", validate: form.Validate, focus: form.FirstField))
        {
            try
            {
                _library.PutTunnel(form.ToDto(existing?.Id ?? ""));
                SaveLibrary();
                break;
            }
            catch (BastionException ex) { form.ShowError(ex.Message); }
        }
        ShowTunnelManagerPage();
    }

    private async Task RemoveTunnelAsync(TunnelDefDto t)
    {
        if (!await ShowModal("Delete tunnel?", ErrorText($"{t.Name} ({t.Summary}) will be removed from the library. A running tunnel stops."), primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
        try
        {
            DropRunningTunnel(t.Id);
            _library.RemoveTunnel(t.Id);
            SaveLibrary();
        }
        catch (BastionException ex) { await ShowModal("Could not delete the tunnel", CodedErrorText("NET", ex.Message), primary: "OK", cancel: null); }
        ShowTunnelManagerPage();
    }

    private Task StopTunnelAsync(TunnelDefDto t)
    {
        DropRunningTunnel(t.Id);
        Announce("Tunnel stopped " + t.Name);
        ShowTunnelManagerPage();
        return Task.CompletedTask;
    }

    /// <summary>Stop a tunnel running on its connection's tab; it stays stopped, also after a reconnect, until Start is used.</summary>
    private async Task StopTabTunnelAsync(TunnelDefDto t, TerminalSession session)
    {
        try
        {
            session.StopForward(t.Id);
            Announce("Tunnel stopped " + t.Name);
        }
        catch (BastionException ex) { await ShowModal("Could not stop " + t.Name, CodedErrorText("NET", ex.Message), primary: "OK", cancel: null); }
        ShowTunnelManagerPage();
    }

    /// <summary>Stop and forget a running tunnel: its listener (or remote forward) closes and the SSH connection drops.</summary>
    private void DropRunningTunnel(string id)
    {
        if (_runningTunnels.Remove(id, out var run)) run.Dispose();
    }

    private void KeepRunningTunnel(string id, RunningTunnelHandle run)
    {
        DropRunningTunnel(id);
        _runningTunnels[id] = run;
        if (_tunnelsCloseHooked) return;
        _tunnelsCloseHooked = true;
        Closed += (_, _) =>
        {
            foreach (var r in _runningTunnels.Values) r.Dispose();
            _runningTunnels.Clear();
        };
    }

    /// <summary>Sign in to the tunnel's SSH connection and start it: the connect dialog, the host-key prompt, a one-time code.</summary>
    private async Task StartTunnelAsync(TunnelDefDto t)
    {
        if (_modal is not null || _connecting) return;
        var via = AllConnections().FirstOrDefault(i => i.Id == t.ViaId)?.Connection;
        var form = new ConnectForm(via?.Username);
        var attempt = new TunnelAttempt();
        try
        {
            while (true)
            {
                if (attempt.AskForLogin && !await ShowModal("Start tunnel " + t.Name, form.Body, primary: "Start", cancel: "Cancel",
                        caption: $"{t.Summary} via {t.ViaName}", validate: form.Validate, focus: form.FirstField)) return;
                var result = await StartTunnelOnceAsync(t, form, attempt);
                if (result is null) return;
                if (result.Tunnel is { } run)
                {
                    KeepRunningTunnel(t.Id, run);
                    Announce("Tunnel running " + t.Summary);
                    return;
                }
                if (!await HandleTunnelFailureAsync(t, form, result, attempt)) return;
            }
        }
        finally
        {
            form.ClearSecrets();
            ShowTunnelManagerPage();
        }
    }

    /// <summary>State carried between start attempts. Fingerprints are only ones the user verified, never seeded from the server.</summary>
    private sealed class TunnelAttempt
    {
        public bool AskForLogin = true;
        public string? Trust;
        public string? Code;
        public readonly Dictionary<string, string> JumpTrust = new();
    }

    private async Task<TunnelStartResult?> StartTunnelOnceAsync(TunnelDefDto t, ConnectForm form, TunnelAttempt a)
    {
        // Copy the fields out before leaving the UI thread; the blocking start must not touch controls.
        var (user, kind, secret, keyPath, trust, code) = (form.UserName, form.Kind, form.Secret, form.KeyPath, a.Trust, a.Code);
        var hopTrust = new Dictionary<string, string>(a.JumpTrust);
        var library = _library;
        a.Code = null; // a one-time code is used for one attempt only
        a.AskForLogin = true;
        if (code is not null && kind == SshLoginKind.Password) kind = SshLoginKind.PasswordAndCode;
        _connecting = true;
        try
        {
            if (kind == SshLoginKind.Vault) Sessions.SetCredentials(OpenCredentials());
            if (kind == SshLoginKind.Vaultwarden) Sessions.SetVaultwarden(Vaultwarden);
            var sessions = Sessions;
            return await Task.Run(() => sessions.StartTunnel(library, t.Id, user, kind, secret, keyPath, trust, hopTrust, code));
        }
        catch (BastionException ex)
        {
            await ShowModal("Could not start " + t.Name, CodedErrorText("NET", ex.Message), primary: "OK", cancel: null);
            return null;
        }
        finally { _connecting = false; }
    }

    /// <summary>Handle a failed start. Returns false to give up; true to retry with what <paramref name="a"/> now holds.</summary>
    private async Task<bool> HandleTunnelFailureAsync(TunnelDefDto t, ConnectForm form, TunnelStartResult result, TunnelAttempt a)
    {
        switch (result.Outcome)
        {
            case ConnectOutcome.HostKeyUnknown when result.Fingerprint is { } fingerprint:
                if (!await ShowModal("Trust this host key?", HostKeyPrompt.Body(result.Hop ?? t.ViaName, fingerprint, result.Hop is not null),
                        primary: "Connect and trust", cancel: "Cancel", focusCancel: true)) return false;
                if (result.Hop is { } hop) a.JumpTrust[hop] = fingerprint; else a.Trust = fingerprint;
                a.AskForLogin = false; // the login is still in the form; retry with the key now trusted
                return true;
            case ConnectOutcome.TwoFactorRequired when form.Kind == SshLoginKind.Password:
                var codeForm = new OneTimeCodeForm(t.ViaName);
                try
                {
                    if (!await ShowModal("Second factor", codeForm.Body, primary: "Continue", cancel: "Cancel",
                            caption: t.ViaName, validate: codeForm.Validate, focus: codeForm.FirstField)) return false;
                    a.Code = codeForm.Code;
                }
                finally { codeForm.Clear(); }
                a.AskForLogin = false;
                return true;
            case ConnectOutcome.TwoFactorRequired:
            case ConnectOutcome.AuthFailed:
                form.ClearSecrets();
                form.ShowFailure("Authentication failed. Check the user name and the password or key.");
                return true;
            default:
                await ShowModal("Could not start " + t.Name, ErrorText(result.Error ?? "The tunnel did not start."), primary: "OK", cancel: null);
                return false;
        }
    }
}

// ---- Snapshot mode hooks (SnapshotRunner, BASTION_SNAPSHOT_TUNNELS) ----
public sealed partial class MainWindow
{
    /// <summary>A local forward and a SOCKS tunnel through the first SSH connection, so the page has rows to show.</summary>
    internal void SeedTunnelsForSnapshot()
    {
        if (_library.Tunnels().Count > 0 || FindFirst(_roots, i => IsSsh(i)) is not { } ssh) return;
        _library.PutTunnel(new TunnelDefDto("", "Postgres", ssh.Id, "", "local", 15432, "db.internal", 5432, "", false));
        _library.PutTunnel(new TunnelDefDto("", "Browse lab", ssh.Id, "", "dynamic", 1080, "", 0, "", true));
    }

    internal Task AddTunnelForSnapshot()
    {
        var form = new TunnelForm(null, SshConnections());
        return ShowModal("Add tunnel", form.Body, primary: "Save", cancel: "Cancel", validate: form.Validate, focus: form.FirstField);
    }

    /// <summary>
    /// Snapshot only: save a local forward through a new SSH connection to <paramref name="host"/>:<paramref name="port"/>, start it
    /// with a password (trusting the key it reports, which only a test may do), and say what a connection to the forward read.
    /// </summary>
    internal async Task<string> StartTunnelLiveForSnapshot(string host, int port, string user, string password, string destHost, int destPort)
    {
        var via = _library.AddConnection(null, "tunnel-test", "ssh", host, port, user);
        var listen = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listen.Start();
        var local = ((System.Net.IPEndPoint)listen.LocalEndpoint).Port;
        listen.Stop();
        var id = _library.PutTunnel(new TunnelDefDto("", "Live", via, "", "local", local, destHost, destPort, "", false));
        var library = _library;
        var sessions = Sessions;
        var first = await Task.Run(() => sessions.StartTunnel(library, id, user, SshLoginKind.Password, password, null, null, null));
        var result = first.Outcome == ConnectOutcome.HostKeyUnknown
            ? await Task.Run(() => sessions.StartTunnel(library, id, user, SshLoginKind.Password, password, null, first.Fingerprint, null))
            : first;
        if (result.Tunnel is not { } run) return $"start {result.Outcome}: {result.Error}";
        KeepRunningTunnel(id, run);
        var banner = await Task.Run(() =>
        {
            using var c = new System.Net.Sockets.TcpClient("127.0.0.1", local);
            c.ReceiveTimeout = 5000;
            var buf = new byte[64];
            var n = c.GetStream().Read(buf, 0, buf.Length);
            return System.Text.Encoding.ASCII.GetString(buf, 0, n).Trim();
        });
        var running = RunningStatus(id);
        _pageKind = "tunnels";
        ShowTunnelManagerPage();
        await Task.Delay(300);
        DropRunningTunnel(id);
        var closed = !CanConnect(local);
        return $"start Ok; forward read \"{banner.Split('\n')[0]}\"; status {TunnelState(running)}; after Stop the port is {(closed ? "closed" : "STILL OPEN")}";
    }

    private static bool CanConnect(int port)
    {
        try { using var c = new System.Net.Sockets.TcpClient("127.0.0.1", port); return true; }
        catch (System.Net.Sockets.SocketException) { return false; }
    }
}
