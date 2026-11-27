using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Gateway Manager (core gateway over C ABI 22): shared SSH gateways stored in the library, the same definitions the macOS app
// edits. A connection, folder or type default picks one in the property editor (Gateway). SSH and SFTP use it as their first
// jump host inside the core; RDP and VNC go over a loopback port forward and web pages over a loopback SOCKS proxy, opened here
// before the protocol connects and closed with the tab. The gateway's host key is checked strictly, like any jump host.
public sealed partial class MainWindow
{
    private string _gatewayFilter = "";

    private void GatewayManager_Click(object sender, RoutedEventArgs e) => OpenGatewayManager();

    internal void OpenGatewayManager()
    {
        _pageKind = "gateways";
        ShowGatewayManagerPage();
    }

    private void ShowGatewayManagerPage()
    {
        var content = new StackPanel { Spacing = Ui.Double("Space8") };
        var note = Ui.Text("SSH hosts that connections are reached through. Choose one as a connection's, folder's or type's Gateway in Properties. Gateways hold no passwords: you sign in to the gateway when you connect.", "CaptionSecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        content.Children.Add(note);
        try
        {
            var all = _library.Gateways();
            if (all.Count == 0) content.Children.Add(Ui.Text("No gateways yet.", "BodySecondaryTextStyle"));
            var rows = all.Select(g => ((UIElement)GatewayRow(g), new[] { g.Name, GatewayAddress(g) })).ToList();
            if (all.Count > 0) content.Children.Add(ListFilterBox(_gatewayFilter, "Name or address", f => { _gatewayFilter = f; ApplyRowFilter(rows, f); }));
            foreach (var (row, _) in rows) content.Children.Add(row);
            ApplyRowFilter(rows, _gatewayFilter);
        }
        catch (BastionException ex) { content.Children.Add(CodedErrorText("SSH", ex.Message)); }
        var add = new Button { Content = "Add Gateway…" }.Quiet("GlyphAdd", "Add gateway");
        add.Click += (_, _) => _ = EditGatewayAsync(null);
        ShowPage(null, "Gateways", content, add);
    }

    private static string GatewayAddress(GatewayDto g) => $"{(g.Username is { Length: > 0 } u ? u + "@" : "")}{g.Host}:{g.Port ?? 22}";

    private Grid GatewayRow(GatewayDto g)
    {
        var row = new Grid { ColumnSpacing = Ui.Double("Space8"), MinHeight = Ui.Double("ControlHeight") };
        row.ColumnDefinitions.Add(new ColumnDefinition());
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var used = g.UsedBy.Count == 0 ? "not used" : "used by " + string.Join(", ", g.UsedBy.Take(4)) + (g.UsedBy.Count > 4 ? $" and {g.UsedBy.Count - 4} more" : "");
        var detail = Ui.Text($"{GatewayAddress(g)} · {used}", "CaptionSecondaryTextStyle");
        detail.TextWrapping = TextWrapping.Wrap;
        row.Children.Add(new StackPanel { VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Text(g.Name, "BodyTextStyle"), detail } });
        var edit = new Button { Content = "Edit…" }.Quiet("GlyphEdit", "Edit");
        AutomationProperties.SetName(edit, "Edit " + g.Name);
        edit.Click += (_, _) => _ = EditGatewayAsync(g);
        Grid.SetColumn(edit, 1);
        row.Children.Add(edit);
        var remove = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphDelete", "IconSize"), IsEnabled = g.UsedBy.Count == 0 };
        ToolTipService.SetToolTip(remove, g.UsedBy.Count == 0 ? "Delete" : "In use: change the connections that use it first");
        AutomationProperties.SetName(remove, "Delete gateway " + g.Name);
        remove.Click += (_, _) => _ = RemoveGatewayAsync(g);
        Grid.SetColumn(remove, 2);
        row.Children.Add(remove);
        return row;
    }

    private async Task EditGatewayAsync(GatewayDto? existing)
    {
        var form = new GatewayForm(existing);
        while (await ShowModal(existing is null ? "Add gateway" : "Edit gateway", form.Body, primary: "Save", cancel: "Cancel", validate: form.Validate, focus: form.FirstField))
        {
            try
            {
                if (existing is null) _library.AddGateway(form.GatewayName, form.Host, form.PortValue, form.UserName, form.Notes);
                else _library.UpdateGateway(existing.Id, form.GatewayName, form.Host, form.PortValue, form.UserName, form.Notes);
                SaveLibrary();
                break;
            }
            catch (BastionException ex) { form.ShowError(ex.Message); }
        }
        ShowGatewayManagerPage();
    }

    private async Task RemoveGatewayAsync(GatewayDto g)
    {
        if (!await ShowModal("Delete gateway?", ErrorText($"{g.Name} ({GatewayAddress(g)}) will be removed from the library."), primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
        try
        {
            _library.RemoveGateway(g.Id);
            SaveLibrary();
        }
        catch (BastionException ex) { await ShowModal("Could not delete the gateway", CodedErrorText("SSH", ex.Message), primary: "OK", cancel: null); }
        ShowGatewayManagerPage();
    }

    /// <summary>
    /// For an RDP, VNC or web connection with a gateway: sign in to the gateway (its key verified like a jump host's) and open the
    /// route. Returns (true, null) for a direct connection, (true, route) once the route is open, and (false, null) when the user
    /// cancelled or the gateway could not be reached (already reported). A broken gateway reference never falls back to direct.
    /// </summary>
    private async Task<(bool Proceed, GatewayRoute? Route)> OpenGatewayRouteAsync(TreeItem item, string connectionId)
    {
        GatewayHopDto? hop;
        try { hop = _library.GatewayHop(connectionId); }
        catch (BastionException ex)
        {
            await ShowModal("Cannot open " + item.Name, CodedErrorText("SSH", ex.Message), primary: "OK", cancel: null);
            return (false, null);
        }
        if (hop is null) return (true, null);
        var form = new GatewayLoginForm(hop);
        string? trust = null;
        var askForLogin = true;
        try
        {
            while (true)
            {
                if (askForLogin && !await ShowModal("Sign in to gateway " + hop.Name, form.Body, primary: "Continue", cancel: "Cancel",
                        caption: $"{item.Name} via {hop.Key}", validate: form.Validate, focus: form.FirstField)) return (false, null);
                askForLogin = true;
                var (user, kind, secret, keyPath, verified) = (form.UserName, form.Kind, form.Secret, form.KeyPath, trust);
                var library = _library;
                GatewayRouteResult result;
                _connecting = true;
                UpdateConnectAction(Selected);
                try { result = await Task.Run(() => GatewayRoute.Open(Sessions, library, connectionId, user, kind, secret, keyPath, verified)); }
                catch (BastionException ex)
                {
                    await ShowModal("Could not reach gateway " + hop.Name, CodedErrorText("SSH", ex.Message), primary: "OK", cancel: null);
                    return (false, null);
                }
                finally
                {
                    _connecting = false;
                    UpdateConnectAction(Selected);
                }
                switch (result.Outcome)
                {
                    case ConnectOutcome.Ok:
                        Announce("Gateway route open " + result.Route!.Summary);
                        return (true, result.Route);
                    case ConnectOutcome.HostKeyUnknown when result.Fingerprint is { } fingerprint:
                        if (!await ShowModal("Trust this host key?", HostKeyPrompt.Body(hop.Key, fingerprint, true),
                                primary: "Connect and trust", cancel: "Cancel", focusCancel: true)) return (false, null);
                        trust = fingerprint;
                        askForLogin = false;
                        continue;
                    case ConnectOutcome.AuthFailed:
                        form.ClearSecrets();
                        form.ShowFailure("The gateway refused the login. Check the user name and the password or key.");
                        continue;
                    default:
                        await ShowModal("Could not reach gateway " + hop.Name, CodedErrorText("SSH", result.Error ?? "The connection failed."), primary: "OK", cancel: null);
                        return (false, null);
                }
            }
        }
        finally { form.ClearSecrets(); }
    }

    // ---- Snapshot mode hooks (SnapshotRunner, BASTION_SNAPSHOT_GATEWAYS) ----

    private GatewayForm? _snapshotGatewayForm;

    /// <summary>Two demo gateways, one set on the first RDP connection, so the page shows both "used by" and "not used".</summary>
    internal void SeedGatewaysForSnapshot()
    {
        if (_library.Gateways().Count > 0) return;
        var jump = _library.AddGateway("Jump", "jump.lab", 2222, "ops", "");
        _library.AddGateway("Edge", "edge.lab", null, null, "");
        var rdp = FindFirst(_roots, i => IsRdp(i));
        if (rdp?.Id is { } id) _library.SetProperty(id, "gateway_id", jump);
    }

    private static TreeItem? FindFirst(IEnumerable<TreeItem> items, Func<TreeItem, bool> match)
    {
        foreach (var i in items)
        {
            if (match(i)) return i;
            if (FindFirst(i.Children, match) is { } hit) return hit;
        }
        return null;
    }

    internal Task AddGatewayForSnapshot()
    {
        _snapshotGatewayForm = new GatewayForm(null);
        return ShowModal("Add gateway", _snapshotGatewayForm.Body, primary: "Save", cancel: "Cancel", validate: _snapshotGatewayForm.Validate, focus: _snapshotGatewayForm.FirstField);
    }

    internal void FillGatewayForSnapshot(string name, string host, string port) => _snapshotGatewayForm?.Fill(name, host, port);

    /// <summary>The gateway sign-in dialog for the first connection that uses a gateway (not submitted).</summary>
    internal void ShowGatewayLoginForSnapshot()
    {
        var item = FindFirst(_roots, i => IsRdp(i));
        if (item?.Connection is { } c) _ = OpenGatewayRouteAsync(item, c.Id);
    }

    /// <summary>
    /// Snapshot only: a VNC connection behind the gateway <paramref name="gatewayHost"/>:<paramref name="gatewayPort"/>, opened
    /// through its route without dialogs (the gateway key is trusted after the first, refused attempt, as the dialog would).
    /// </summary>
    internal async Task<RemoteDesktopView> OpenVncThroughGatewayForSnapshot(string gatewayHost, int gatewayPort, string gatewayPassword, string vncHost, int vncPort, string vncPassword)
    {
        if (!_demo) throw new InvalidOperationException("snapshot only");
        var gw = _library.AddGateway("Lab jump", gatewayHost, gatewayPort, "tester", "");
        var id = _library.AddConnection(null, "private-vnc", "vnc", vncHost, vncPort, null);
        _library.SetProperty(id, "gateway_id", gw);
        Reload(id);
        var library = _library;
        var first = await Task.Run(() => GatewayRoute.Open(Sessions, library, id, null, SshLoginKind.Password, gatewayPassword, null, null));
        if (first.Outcome != ConnectOutcome.HostKeyUnknown) throw new InvalidOperationException($"expected the gateway key prompt, got {first.Outcome}: {first.Error}");
        var result = await Task.Run(() => GatewayRoute.Open(Sessions, library, id, null, SshLoginKind.Password, gatewayPassword, null, first.Fingerprint));
        if (result.Route is not { } route) throw new InvalidOperationException($"gateway route failed: {result.Error}");
        var vnc = await Task.Run(() => VncSession.Connect("127.0.0.1", route.Port, vncPassword));
        if (vnc.Session is null)
        {
            route.Dispose();
            throw new InvalidOperationException($"VNC through the gateway failed: {vnc.Error}");
        }
        var view = new RemoteDesktopView(new RoutedDesktop(new VncDesktop(vnc.Session), route));
        AddTab($"{vncHost}:{vncPort} {route.Summary}", null, rdp: view);
        return view;
    }
}

/// <summary>A remote desktop that reaches its host through a gateway route; the route closes with the desktop.</summary>
public sealed partial class RoutedDesktop(IRemoteDesktop inner, GatewayRoute route) : IRemoteDesktop
{
    public bool IsConnected => inner.IsConnected;
    public string? CloseReason => inner.CloseReason ?? (route.IsRunning ? null : "The gateway route closed.");
    public bool Frame(ref byte[] buffer, ref ulong serial, out int width, out int height) => inner.Frame(ref buffer, ref serial, out width, out height);
    public void MouseMove(int x, int y) => inner.MouseMove(x, y);
    public void Resize(int width, int height) => inner.Resize(width, height);
    public void MouseButton(RemoteButton button, bool down) => inner.MouseButton(button, down);
    public bool Key(Windows.System.VirtualKey key, uint scanCode, bool extended, bool down) => inner.Key(key, scanCode, extended, down);
    public bool Character(char c) => inner.Character(c);

    public void Dispose()
    {
        inner.Dispose();
        route.Dispose();
    }
}

/// <summary>Name, host, port, user and notes of a gateway; the core does the real validation (no option-like hosts, unique names).</summary>
internal sealed class GatewayForm
{
    private readonly TextBox _name = new() { Header = "Name", IsSpellCheckEnabled = false };
    private readonly TextBox _host = new() { Header = "Host", PlaceholderText = "jump.example.com", IsSpellCheckEnabled = false };
    private readonly TextBox _port = new() { Header = "Port", PlaceholderText = "22", IsSpellCheckEnabled = false };
    private readonly TextBox _user = new() { Header = "User name (optional)", PlaceholderText = "The connection's user name", IsSpellCheckEnabled = false };
    private readonly TextBox _notes = new() { Header = "Notes", AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, Height = 72 };
    private readonly FieldMessage _nameError = new(), _hostError = new(), _portError = new();

    public StackPanel Body { get; }
    public Control FirstField => _name;
    public string GatewayName => _name.Text.Trim();
    public string Host => _host.Text.Trim();
    public int? PortValue => int.TryParse(_port.Text.Trim(), out var p) ? p : null;
    public string? UserName => string.IsNullOrWhiteSpace(_user.Text) ? null : _user.Text.Trim();
    public string Notes => _notes.Text;

    public GatewayForm(GatewayDto? existing)
    {
        if (existing is not null)
        {
            (_name.Text, _host.Text, _port.Text, _user.Text, _notes.Text) =
                (existing.Name, existing.Host, existing.Port?.ToString() ?? "", existing.Username ?? "", existing.Notes);
        }
        var hostRow = new Grid { ColumnSpacing = Ui.Double("Space8") };
        hostRow.ColumnDefinitions.Add(new ColumnDefinition());
        hostRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(96) });
        hostRow.Children.Add(new StackPanel { Children = { _host, _hostError.Element } });
        var portStack = new StackPanel { Children = { _port, _portError.Element } };
        Grid.SetColumn(portStack, 1);
        hostRow.Children.Add(portStack);
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { new StackPanel { Children = { _name, _nameError.Element } }, hostRow, _user, _notes } };
        _name.TextChanged += (_, _) => _nameError.Hide();
        _host.TextChanged += (_, _) => _hostError.Hide();
        _port.TextChanged += (_, _) => _portError.Hide();
    }

    internal void Fill(string name, string host, string port) => (_name.Text, _host.Text, _port.Text) = (name, host, port);

    public bool Validate()
    {
        var ok = true;
        if (GatewayName.Length == 0) { _nameError.Show("Enter a name."); ok = false; }
        if (Host.Length == 0) { _hostError.Show("Enter the gateway's host name or address."); ok = false; }
        if (_port.Text.Trim().Length > 0 && PortValue is not (>= 1 and <= 65535)) { _portError.Show("Port must be a number from 1 to 65535."); ok = false; }
        return ok;
    }

    /// <summary>A refusal from the core (duplicate name, bad host): shown under the field it is about.</summary>
    public void ShowError(string message)
    {
        if (message.Contains("name", StringComparison.OrdinalIgnoreCase) && !message.Contains("host", StringComparison.OrdinalIgnoreCase)) _nameError.Show(message);
        else _hostError.Show(message);
    }
}

/// <summary>The gateway's own login: password, SSH agent or key file. Secrets are cleared when the attempt ends.</summary>
internal sealed class GatewayLoginForm
{
    private readonly TextBox _user = new() { Header = "Gateway user name", IsSpellCheckEnabled = false };
    private readonly RadioButtons _kind = new() { Header = "Sign in with", MaxColumns = 3, Items = { "Password", "SSH agent", "Key file" }, SelectedIndex = 0 };
    private readonly PasswordBox _password = new() { Header = "Password" };
    private readonly TextBox _keyPath = new() { Header = "Private key file", PlaceholderText = @"C:\Users\you\.ssh\id_ed25519", IsSpellCheckEnabled = false, Visibility = Visibility.Collapsed };
    private readonly FieldMessage _userError = new(), _failure = new();

    public StackPanel Body { get; }
    public Control FirstField => _user.Text.Length == 0 ? _user : _password;
    public string UserName => _user.Text.Trim();
    public SshLoginKind Kind => _kind.SelectedIndex switch { 1 => SshLoginKind.Agent, 2 => SshLoginKind.KeyFile, _ => SshLoginKind.Password };
    public string? Secret => Kind == SshLoginKind.Agent ? null : _password.Password;
    public string? KeyPath => Kind == SshLoginKind.KeyFile ? _keyPath.Text.Trim() : null;

    public GatewayLoginForm(GatewayHopDto hop)
    {
        _user.Text = hop.Username ?? "";
        var note = Ui.Text($"This connection is reached through {hop.Name} ({hop.Key}). Gantry signs in there first and forwards a local port to the host; the route closes with the tab.", "CaptionSecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { note, new StackPanel { Children = { _user, _userError.Element } }, _kind, _password, _keyPath, _failure.Element } };
        _kind.SelectionChanged += (_, _) =>
        {
            _password.Visibility = Kind == SshLoginKind.Agent ? Visibility.Collapsed : Visibility.Visible;
            _password.Header = Kind == SshLoginKind.KeyFile ? "Passphrase (if the key has one)" : "Password";
            _keyPath.Visibility = Kind == SshLoginKind.KeyFile ? Visibility.Visible : Visibility.Collapsed;
            _failure.Hide();
        };
        _user.TextChanged += (_, _) => _userError.Hide();
        _password.PasswordChanged += (_, _) => _failure.Hide();
    }

    public bool Validate()
    {
        if (UserName.Length == 0) { _userError.Show("Enter the user name for the gateway."); return false; }
        if (Kind == SshLoginKind.KeyFile && string.IsNullOrEmpty(KeyPath)) { _failure.Show("Choose the private key file."); return false; }
        return true;
    }

    public void ShowFailure(string message) => _failure.Show(message);

    public void ClearSecrets() => _password.Password = "";
}
