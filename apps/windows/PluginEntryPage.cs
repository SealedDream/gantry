using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// PVE-TLS (as Native Mac PropertyEditor's plugin sections): the first page of a plugin entry's property editor, named
/// after its installed type. The type's own fields, the certificate rule with Trust Server Certificate… (the fingerprint is
/// shown inline for comparison, then pinned on Trust), and Test Connection, which runs the core's TLS check under the
/// entry's rule and never the protocol probe. Field changes go through the core on Save or Apply.
/// </summary>
internal sealed class PluginEntryPage
{
    private readonly LibraryClient _library;
    private readonly string _dataDir;
    private readonly string _id;
    private readonly int _defaultPort;
    private readonly List<(PluginFieldDto Field, Control Control, Func<string> Read)> _fields = [];
    private readonly FieldMessage _error = new();
    private readonly TextBlock _rule = Ui.Text("", "BodyTextStyle");
    private readonly StackPanel _compare = new() { Spacing = Ui.Double("Space8"), Visibility = Visibility.Collapsed };
    private readonly Button _trust = new() { Content = "Trust Server Certificate…" };
    private readonly Button _system = new() { Content = "Use System Trust" };
    private string? _offered;

    public string PageName { get; }
    public FrameworkElement Body { get; }
    /// <summary>The host and port the dialog holds now (unsaved edits included).</summary>
    public Func<(string Host, int? Port)>? Target { get; init; }

    /// <summary>PVE-AUTH: the login step's work for the dialog's host and port (read on the UI thread, run off it);
    /// null when the dialog holds an edited target, which is tested with TLS alone.</summary>
    public Func<string, int, Func<ProbeStepDto>?>? LoginTest { get; init; }

    public PluginEntryPage(LibraryClient library, string dataDir, string id, PluginTypeDto type)
    {
        _library = library;
        _dataDir = dataDir;
        _id = id;
        _defaultPort = type.DefaultPort ?? 443;
        PageName = type.Name;
        var panel = new StackPanel { Spacing = Ui.Double("Space12") };
        foreach (var f in PluginEntryClient.Fields(library, dataDir, id))
        {
            // Plugin API 1.3: a toggle field is a switch ("Allow changes", "Snapshot before connect").
            if (f.Kind == "toggle")
            {
                var sw = new ToggleSwitch { Header = f.Label, IsOn = f.Value == "true" };
                AutomationProperties.SetName(sw, f.Label);
                _fields.Add((f, sw, () => sw.IsOn ? "true" : "false"));
                panel.Children.Add(sw);
                continue;
            }
            var box = new TextBox { Header = f.Label, Text = f.Value ?? "" };
            AutomationProperties.SetName(box, f.Label);
            _fields.Add((f, box, () => box.Text.Trim()));
            panel.Children.Add(box);
        }
        panel.Children.Add(_error.Element);

        panel.Children.Add(Ui.Text("Certificate", "BodyStrongTextStyle"));
        _rule.TextWrapping = TextWrapping.Wrap;
        panel.Children.Add(_rule);
        AutomationProperties.SetName(_trust, "Trust Server Certificate");
        ToolTipService.SetToolTip(_trust, "Read the server's certificate, compare its fingerprint, then pin it");
        _trust.Click += (_, _) => _ = ReadCertificateAsync();
        AutomationProperties.SetName(_system, "Use System Trust");
        _system.Click += (_, _) => SetRule("verify-full", null);
        panel.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { _trust, _system } });
        panel.Children.Add(_compare);

        var test = new TestConnectionPanel(() =>
        {
            var (host, port) = Target?.Invoke() ?? ("", null);
            if (host.Length == 0) return null;
            var p = port ?? _defaultPort;
            return new ProbeRequest(type.Id, host, p, null, null, id, PluginTls: true, PluginPin: Pin(), PluginLogin: LoginTest?.Invoke(host, p));
        }, () => throw new InvalidOperationException("a plugin test needs no session manager"));
        panel.Children.Add(test.Element);
        Body = panel;
        ShowRule();
    }

    private string? Pin()
    {
        try { return PluginEntryClient.Tls(_library, _id) is { Mode: "pinned", PinSha256: { } pin } ? pin : null; }
        catch (BastionException) { return null; }
    }

    private void ShowRule()
    {
        PluginEntryTlsDto? tls = null;
        try { tls = PluginEntryClient.Tls(_library, _id); } catch (BastionException ex) { _rule.Text = "Cannot read: " + ex.Message; }
        var pin = tls is { Mode: "pinned" } ? tls.PinSha256 : null;
        if (tls is not null) _rule.Text = pin is not null ? "Pinned: " + MainWindow.ShortPin(pin) : tls.Damaged ? "Pin unreadable: system trust" : "System trust";
        ToolTipService.SetToolTip(_rule, pin is not null ? "SHA-256 " + pin : "The server's certificate must be valid for its name.");
        _system.Visibility = pin is not null ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Reads the certificate and shows its fingerprint inline with Trust and Cancel (no second dialog over this one).</summary>
    private async Task ReadCertificateAsync()
    {
        var (host, port) = Target?.Invoke() ?? ("", null);
        if (host.Length == 0) return;
        var p = port ?? _defaultPort;
        _trust.IsEnabled = false;
        _compare.Children.Clear();
        try { _offered = await Task.Run(() => PluginEntryClient.ProbeCertificate(host, p)); }
        catch (BastionException ex)
        {
            _compare.Children.Add(new TextBlock { Text = "Certificate not read: " + ex.Message, TextWrapping = TextWrapping.Wrap });
            _compare.Visibility = Visibility.Visible;
            return;
        }
        finally { _trust.IsEnabled = true; }
        var text = Ui.Text($"{host}:{p}\nSHA-256\n{MainWindow.GroupedPin(_offered)}\nCompare it with the server before you trust it.", "BodyTextStyle");
        text.TextWrapping = TextWrapping.Wrap;
        text.IsTextSelectionEnabled = true;
        AutomationProperties.SetName(text, "Certificate fingerprint");
        var trust = new Button { Content = "Trust", Style = Ui.Style("AccentButtonStyle") };
        AutomationProperties.SetName(trust, "Trust this certificate");
        var cancel = new Button { Content = "Cancel" };
        trust.Click += (_, _) => { if (_offered is { } pin) SetRule("pinned", pin); };
        cancel.Click += (_, _) => { _offered = null; _compare.Visibility = Visibility.Collapsed; _trust.Focus(FocusState.Programmatic); };
        _compare.Children.Add(text);
        _compare.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { cancel, trust } });
        _compare.Visibility = Visibility.Visible;
        cancel.Focus(FocusState.Programmatic);
    }

    private void SetRule(string mode, string? pin)
    {
        try
        {
            PluginEntryClient.SetTls(_library, _id, mode, pin);
            RuleChanged?.Invoke();
        }
        catch (BastionException ex) { _error.ShowCoded("APP", ex.Message); }
        _offered = null;
        _compare.Visibility = Visibility.Collapsed;
        ShowRule();
    }

    /// <summary>Set by the dialog's owner: the rule was saved (the library needs saving).</summary>
    public Action? RuleChanged { get; init; }

    /// <summary>Applies changed fields; false (with the message shown) on the first refusal.</summary>
    public bool Apply()
    {
        _error.Hide();
        for (var i = 0; i < _fields.Count; i++)
        {
            var (f, control, read) = _fields[i];
            var value = read();
            // An unset toggle reads "false": unchanged, so nothing is written for it.
            if (value == (f.Value ?? (f.Kind == "toggle" ? "false" : ""))) continue;
            try { PluginEntryClient.SetField(_library, _dataDir, _id, f.Key, value.Length == 0 ? null : value); }
            catch (BastionException ex)
            {
                _error.Show(ex.Message.StartsWith("invalid input: ", StringComparison.Ordinal) ? ex.Message["invalid input: ".Length..] : ex.Message);
                control.Focus(FocusState.Programmatic);
                return false;
            }
            _fields[i] = (f with { Value = value }, control, read);
        }
        return true;
    }
}
