using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// The "New connection" dialog body: Name across the top, then Protocol | Host and Port | User name, each message
/// under the field it is about. Built in code so the form stays next to its validation: pressing Create with a
/// missing field keeps the dialog open and says what is missing.
/// </summary>
public sealed class AddConnectionForm
{
    /// <summary>Core protocol identifiers and how the list shows them.</summary>
    internal static readonly (string Id, string Label)[] Protocols =
    [
        ("ssh", "SSH"), ("rdp", "RDP"), ("vnc", "VNC"), ("sftp", "SFTP"), ("scp", "SCP"), ("ftp", "FTP"),
        ("ftps", "FTPS"), ("web", "Web"), ("telnet", "Telnet"), ("local", "Local shell"),
    ];

    private readonly TextBox _name = new() { Header = "Name", PlaceholderText = "web-1", IsSpellCheckEnabled = false };
    private readonly ComboBox _protocol = new() { Header = "Protocol", HorizontalAlignment = HorizontalAlignment.Stretch };
    // PLUG-08-WIN: the built-in protocols, then the installed plugins' connection types (PostgreSQL, Proxmox VE, ...).
    private readonly (string Id, string Label)[] _options;
    private readonly IReadOnlyList<PluginTypeDto> _pluginTypes;
    private readonly TextBox _host = new() { Header = "Host", PlaceholderText = "host.example.com", IsSpellCheckEnabled = false };
    // A TextBox, not a NumberBox: the NumberBox template made the first sheet of a session measure for 256 ms
    // (q-kern-1), over the 80 ms sheet budget. Validate() already checks the typed text for 1-65535.
    private readonly TextBox _port = new() { Header = "Port", IsSpellCheckEnabled = false, HorizontalAlignment = HorizontalAlignment.Stretch, InputScope = NumberScope() };
    private readonly TextBox _user = new() { Header = "User name (optional)", IsSpellCheckEnabled = false };
    private readonly ComboBox _shell = new() { Header = "Shell", HorizontalAlignment = HorizontalAlignment.Stretch, Visibility = Visibility.Collapsed };
    private readonly CheckBox _showHelpers = new() { Content = "Show helper distributions (docker-desktop)", Visibility = Visibility.Collapsed };
    private readonly Lazy<IReadOnlyList<WslDistro>> _distros;
    private readonly string? _initialShell;
    private List<(string Id, string Label)> _shellOptions = [];
    private readonly FieldMessage _nameError = new();
    private readonly FieldMessage _hostError = new();
    private readonly FieldMessage _portError = new();
    // B7: Telnet's one-line warning (or why it is off). Serial is not offered on Windows (owner, 2026-11-15).
    // Created only when Telnet is chosen: an InfoBar applies its template even while closed.
    private InfoBar? _telnetBand;
    private readonly Border _telnetSlot = new();
    private readonly Func<bool> _telnetAllowed;
    private readonly Func<string?> _telnetLock;

    public Grid Body { get; }
    // Host and port with their messages; hidden together for a local shell. (FrameworkElement.Parent is null here.)
    private readonly StackPanel _hostField, _portField;
    /// <summary>The field that should have focus when the form opens.</summary>
    public Control FirstField => _name;

    public string ConnectionName => _name.Text.Trim();
    public string Protocol => _options[Math.Max(0, _protocol.SelectedIndex)].Id;
    /// <summary>The installed plugin type chosen, or null for a built-in protocol.</summary>
    public PluginTypeDto? PluginType => _pluginTypes.FirstOrDefault(t => t.Id == Protocol);
    /// <summary>Raised when the protocol changes (the dialog hides Test for plugin types, which the core cannot probe).</summary>
    public event Action? ProtocolChanged;
    public string Host => _host.Text.Trim();
    /// <summary>null = the protocol's default port.</summary>
    public int? PortValue => int.TryParse(_port.Text.Trim(), out var p) ? p : null;
    public string? UserName => IsLocal || PluginType is not null || string.IsNullOrWhiteSpace(_user.Text) ? null : _user.Text.Trim();
    private bool IsLocal => Protocol == "local";
    /// <summary>The <c>local.shell</c> to store for a local shell connection; null for other protocols.</summary>
    public string? Shell => IsLocal && _shell.SelectedIndex >= 0 ? _shellOptions[_shell.SelectedIndex].Id : null;

    /// <param name="distros">Installed WSL distributions for the Local shell picker; read only once Local shell is chosen,
    /// because detection may start <c>wsl.exe</c>.</param>
    /// <param name="protocol">Protocol to preselect, for example <c>local</c> from the terminal menu.</param>
    /// <param name="shell">Shell to preselect, for example <c>wsl:Ubuntu-24.04</c>.</param>
    /// <param name="telnetAllowed">Whether Telnet may be created now (Allow Telnet under the managed policy).</param>
    /// <param name="telnetLock">The administrator's reason when the managed policy forbids Telnet.</param>
    public AddConnectionForm(Func<IReadOnlyList<WslDistro>>? distros = null, string? protocol = null, string? shell = null,
        Func<bool>? telnetAllowed = null, Func<string?>? telnetLock = null, IReadOnlyList<PluginTypeDto>? pluginTypes = null)
    {
        _pluginTypes = pluginTypes ?? [];
        _options = [.. Protocols, .. _pluginTypes.Select(t => (t.Id, t.Name))];
        _protocol.ItemsSource = _options.Select(p => p.Label).ToList();
        _protocol.SelectedIndex = 0;
        _telnetAllowed = telnetAllowed ?? (() => false);
        _telnetLock = telnetLock ?? (() => null);
        _distros = new(distros ?? (() => []));
        _initialShell = shell;
        Body = new Grid { ColumnSpacing = Ui.Double("Space12"), RowSpacing = Ui.Double("Space12") };
        Body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Ui.Double("FieldNarrowWidth")) });
        Body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (var i = 0; i < 4; i++) Body.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        Place(new StackPanel { Children = { _name, _nameError.Element } }, row: 0, column: 0, span: 2);
        Place(_protocol, row: 1, column: 0);
        Place(_hostField = new StackPanel { Children = { _host, _hostError.Element } }, row: 1, column: 1);
        Place(_portField = new StackPanel { Children = { _port, _portError.Element } }, row: 2, column: 0);
        Place(_user, row: 2, column: 1);
        Place(new StackPanel { Spacing = Ui.Double("Space8"), Children = { _shell, _showHelpers } }, row: 1, column: 1);
        Place(_telnetSlot, row: 3, column: 0, span: 2);
        AutomationProperties.SetName(_shell, "Shell");
        AutomationProperties.SetName(_showHelpers, "Show helper distributions");
        _showHelpers.Click += (_, _) => FillShells(Shell);
        if (protocol is not null && Array.FindIndex(_options, p => p.Id == protocol) is >= 0 and var at) _protocol.SelectedIndex = at;
        if (shell is not null && _name.Text.Length == 0 && LocalShells.DistroOf(shell) is { } d) _name.Text = d;

        _protocol.SelectionChanged += (_, _) => { UpdatePortHint(); UpdateLocal(); UpdateLegacy(); ProtocolChanged?.Invoke(); };
        _name.TextChanged += (_, _) => _nameError.Hide();
        _host.TextChanged += (_, _) => _hostError.Hide();
        _port.TextChanged += (_, _) => _portError.Hide();
        UpdatePortHint();
        UpdateLocal();
        UpdateLegacy();
    }

    /// <summary>
    /// Telnet: the warning band (or why it is off).
    /// </summary>
    private void UpdateLegacy()
    {
        if (Protocol == "telnet")
        {
            if (_telnetBand is null)
            {
                _telnetBand = new InfoBar { Severity = InfoBarSeverity.Warning, IsClosable = false, IsOpen = false };
                AutomationProperties.SetName(_telnetBand, "Telnet warning");
                _telnetSlot.Child = _telnetBand;
            }
            var reason = _telnetLock();
            var allowed = _telnetAllowed();
            _telnetBand.Title = allowed ? "Not encrypted" : "Telnet is off";
            _telnetBand.Message = allowed ? "Anyone on the network can read what you type." : MainWindow.TelnetOffText(reason is not null);
            _telnetBand.Severity = allowed ? InfoBarSeverity.Warning : InfoBarSeverity.Informational;
            ToolTipService.SetToolTip(_telnetBand, reason ?? TelnetSerial.Warning);
        }
        if (_telnetBand is not null) _telnetBand.IsOpen = Protocol == "telnet";
    }

    private void FillShells(string? keep)
    {
        _shellOptions = LocalShells.Options(_distros.Value, _showHelpers.IsChecked == true, keep);
        _shell.ItemsSource = _shellOptions.Select(o => o.Label).ToList();
        _shell.SelectedIndex = Math.Max(0, _shellOptions.FindIndex(o => o.Id == keep));
    }

    /// <summary>Local shells have no host, port or user: the Shell picker takes the host's place.</summary>
    private void UpdateLocal()
    {
        var local = IsLocal;
        if (local && _shell.ItemsSource is null) FillShells(_initialShell);
        var remote = local ? Visibility.Collapsed : Visibility.Visible;
        _hostField.Visibility = _portField.Visibility = remote;
        // A plugin entry's login is a saved credential (the core releases it to the plugin), so no user name here.
        _user.Visibility = local || PluginType is not null ? Visibility.Collapsed : Visibility.Visible;
        _shell.Visibility = local ? Visibility.Visible : Visibility.Collapsed;
        _showHelpers.Visibility = local && _distros.Value.Any(d => d.Hidden) ? Visibility.Visible : Visibility.Collapsed;
        _hostError.Hide();
    }

    private void Place(FrameworkElement element, int row, int column, int span = 1)
    {
        Grid.SetRow(element, row);
        Grid.SetColumn(element, column);
        Grid.SetColumnSpan(element, span);
        element.VerticalAlignment = VerticalAlignment.Top;
        Body.Children.Add(element);
    }

    private static Microsoft.UI.Xaml.Input.InputScope NumberScope() =>
        new() { Names = { new Microsoft.UI.Xaml.Input.InputScopeName(Microsoft.UI.Xaml.Input.InputScopeNameValue.Number) } };

    private void UpdatePortHint() => _port.PlaceholderText = (PluginType is { } t ? t.DefaultPort : TreeItem.DefaultPort(Protocol))?.ToString() ?? "none";

    /// <summary>True when the form can be submitted; otherwise shows what is missing and focuses the first such field.</summary>
    public bool Validate()
    {
        var nameOk = ConnectionName.Length > 0;
        var hostOk = IsLocal || Host.Length > 0;
        if (nameOk) _nameError.Hide(); else _nameError.Show("Enter a name.");
        if (hostOk) _hostError.Hide(); else _hostError.Show("Enter a host name or IP address.");
        var portText = _port.Text.Trim();
        var portOk = IsLocal || portText.Length == 0 || PortValue is >= 1 and <= 65535;
        var telnetOk = Protocol != "telnet" || _telnetAllowed();
        if (portOk) _portError.Hide(); else _portError.Show("Port must be a number from 1 to 65535.");
        if (!nameOk) _name.Focus(FocusState.Programmatic);
        else if (!hostOk) _host.Focus(FocusState.Programmatic);
        else if (!portOk) _port.Focus(FocusState.Programmatic);
        return nameOk && hostOk && portOk && telnetOk;
    }
}
