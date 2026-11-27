using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>Name, SSH connection, kind and ports of a saved tunnel. Ports are checked here; the core checks again.</summary>
internal sealed class TunnelForm
{
    private static readonly (string Kind, string Label)[] Kinds = [("local", "Local (-L)"), ("remote", "Remote (-R)"), ("dynamic", "SOCKS (-D)")];
    private readonly IReadOnlyList<(string Id, string Name)> _vias;
    private readonly TextBox _name = new() { Header = "Name", IsSpellCheckEnabled = false };
    private readonly ComboBox _via = new() { Header = "Through SSH connection", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly RadioButtons _kind = new() { Header = "Kind", MaxColumns = 3 };
    private readonly TextBox _listen = new() { Header = "Local port", PlaceholderText = "8080", IsSpellCheckEnabled = false };
    private readonly TextBox _host = new() { Header = "Destination host", PlaceholderText = "db.internal", IsSpellCheckEnabled = false };
    private readonly TextBox _port = new() { Header = "Destination port", PlaceholderText = "5432", IsSpellCheckEnabled = false };
    private readonly Grid _dest = new() { ColumnSpacing = Ui.Double("Space8") };
    private readonly CheckBox _withConnection = new() { Content = "Start when the connection opens" };
    private readonly FieldMessage _nameError = new(), _viaError = new(), _listenError = new(), _destError = new();

    public StackPanel Body { get; }
    public Control FirstField => _name;
    private string Kind => Kinds[Math.Max(0, _kind.SelectedIndex)].Kind;

    public TunnelForm(TunnelDefDto? existing, IReadOnlyList<(string Id, string Name)> vias)
    {
        _vias = vias;
        foreach (var (_, label) in Kinds) _kind.Items.Add(label);
        foreach (var v in vias) _via.Items.Add(v.Name);
        _kind.SelectedIndex = existing is null ? 0 : Math.Max(0, Array.FindIndex(Kinds, k => k.Kind == existing.Kind));
        if (existing is not null) Fill(existing);
        else if (vias.Count == 1) _via.SelectedIndex = 0;
        _dest.ColumnDefinitions.Add(new ColumnDefinition());
        _dest.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });
        _dest.Children.Add(_host);
        Grid.SetColumn(_port, 1);
        _dest.Children.Add(_port);
        Body = new StackPanel
        {
            Spacing = Ui.Double("Space12"),
            Children =
            {
                new StackPanel { Children = { _name, _nameError.Element } },
                new StackPanel { Children = { _via, _viaError.Element } },
                _kind,
                new StackPanel { Children = { _listen, _listenError.Element } },
                new StackPanel { Children = { _dest, _destError.Element } },
                _withConnection,
            },
        };
        _kind.SelectionChanged += (_, _) => ApplyKind();
        _name.TextChanged += (_, _) => _nameError.Hide();
        _listen.TextChanged += (_, _) => _listenError.Hide();
        _host.TextChanged += (_, _) => _destError.Hide();
        _port.TextChanged += (_, _) => _destError.Hide();
        _via.SelectionChanged += (_, _) => _viaError.Hide();
        ApplyKind();
    }

    private void Fill(TunnelDefDto t)
    {
        _name.Text = t.Name;
        var (listen, dest) = t.Kind == "remote" ? (t.Port, t.LocalPort) : (t.LocalPort, t.Port);
        _listen.Text = listen > 0 ? listen.ToString() : "";
        _host.Text = t.Host;
        _port.Text = dest > 0 ? dest.ToString() : "";
        _withConnection.IsChecked = t.StartWithConnection;
        _via.SelectedIndex = _vias.ToList().FindIndex(v => v.Id == t.ViaId);
    }

    /// <summary>Labels follow the kind: -R listens on the server and forwards to this side; SOCKS has no destination.</summary>
    private void ApplyKind()
    {
        var remote = Kind == "remote";
        _listen.Header = remote ? "Port on the server" : "Local port";
        _host.Header = remote ? "Forward to host" : "Destination host";
        _host.PlaceholderText = remote ? "127.0.0.1" : "db.internal";
        _port.Header = remote ? "Forward to port" : "Destination port";
        _dest.Visibility = Kind == "dynamic" ? Visibility.Collapsed : Visibility.Visible;
        _destError.Hide();
    }

    private static int? Port(TextBox box) => int.TryParse(box.Text.Trim(), out var p) && p is >= 1 and <= 65535 ? p : null;

    public bool Validate()
    {
        var ok = true;
        if (_name.Text.Trim().Length == 0) { _nameError.Show("Enter a name."); ok = false; }
        if (_via.SelectedIndex < 0) { _viaError.Show(_vias.Count == 0 ? "Add an SSH connection first." : "Choose the SSH connection."); ok = false; }
        if (Port(_listen) is null) { _listenError.Show("Port must be a number from 1 to 65535."); ok = false; }
        if (Kind != "dynamic" && (_host.Text.Trim().Length == 0 || Port(_port) is null)) { _destError.Show("Enter the host and a port from 1 to 65535."); ok = false; }
        return ok;
    }

    public TunnelDefDto ToDto(string id)
    {
        var dynamic = Kind == "dynamic";
        var (listen, dest) = (Port(_listen) ?? 0, dynamic ? 0 : Port(_port) ?? 0);
        // The core's -R: `port` is the server's port, `localPort` the port on this side it forwards to (core-ffi tunnels.rs).
        var (localPort, port) = Kind == "remote" ? (dest, listen) : (listen, dest);
        return new TunnelDefDto(id, _name.Text.Trim(), _vias[_via.SelectedIndex].Id, "", Kind, localPort,
            dynamic ? "" : _host.Text.Trim(), port, "", _withConnection.IsChecked == true);
    }

    /// <summary>Snapshot mode: fill a local forward without typing.</summary>
    internal void FillForSnapshot(string name, int via, int listen, string host, int port)
    {
        (_name.Text, _listen.Text, _host.Text, _port.Text) = (name, listen.ToString(), host, port.ToString());
        _via.SelectedIndex = via;
    }

    /// <summary>A refusal from the core (duplicate name, bad port): shown under the field it is about.</summary>
    public void ShowError(string message)
    {
        if (message.Contains("name", StringComparison.OrdinalIgnoreCase)) _nameError.Show(message);
        else if (message.Contains("port", StringComparison.OrdinalIgnoreCase)) _listenError.Show(message);
        else _destError.Show(message);
    }
}
