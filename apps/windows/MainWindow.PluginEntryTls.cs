using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// PLUG-PVE-01-WIN (as Native Mac PluginEntryTls.swift, #1362): a plugin entry's certificate rule. System trust, or one
// pinned certificate the user compared and accepted (Proxmox hosts are mostly self-signed). The core owns the setting;
// the plugin never sees or changes it. The probe is a TLS handshake only: nothing is sent.
public sealed partial class MainWindow
{
    private const int DefaultTlsPort = 443;

    /// <summary>Certificate: the entry's TLS rule, Trust Server Certificate… and, when pinned, Use System Trust.</summary>
    private void AddPluginTlsSection(ConnectionDto c)
    {
        PluginEntryTlsDto tls;
        try { tls = PluginEntryClient.Tls(_library, c.Id); }
        catch (BastionException ex) { AddSection("Certificate", ("Rule", "Cannot read: " + ex.Message)); return; }
        var pin = tls.Mode == "pinned" ? tls.PinSha256 : null;
        var state = pin is not null ? "Pinned: " + ShortPin(pin) : tls.Damaged ? "Pin unreadable: system trust" : "System trust";
        AddSection("Certificate", ("Rule", state));
        ToolTipService.SetToolTip(InspectorBody.Children[^1], pin is not null ? "SHA-256 " + pin
            : tls.Damaged ? "The saved pin could not be read. Trust the server's certificate again." : "The server's certificate must be valid for its name.");
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Margin = Ui.Thickness("InspectorButtonMargin") };
        var trust = new Button { Content = "Trust Server Certificate…", IsEnabled = c.Host.Length > 0 };
        AutomationProperties.SetName(trust, "Trust Server Certificate");
        ToolTipService.SetToolTip(trust, "Read the server's certificate, compare its fingerprint, then pin it");
        trust.Click += (_, _) => _ = TrustCertificateAsync(c, trust);
        buttons.Children.Add(trust);
        if (pin is not null)
        {
            var system = new Button { Content = "Use System Trust" };
            AutomationProperties.SetName(system, "Use System Trust");
            system.Click += (_, _) => _ = SetPluginTlsAsync(c.Id, "verify-full", null);
            buttons.Children.Add(system);
        }
        InspectorBody.Children.Add(buttons);
    }

    private async Task TrustCertificateAsync(ConnectionDto c, Button trust)
    {
        trust.IsEnabled = false;
        try { await ConfirmAndPinAsync(c); }
        finally { trust.IsEnabled = true; }
    }

    /// <summary>Reads the server's certificate, shows its SHA-256 to compare, and pins it on Trust. True when pinned.</summary>
    private async Task<bool> ConfirmAndPinAsync(ConnectionDto c)
    {
        if (_modal is not null) return false;
        var host = c.Host;
        var port = c.Port ?? PluginTypeOf(c)?.DefaultPort ?? DefaultTlsPort;
        string pin;
        try { pin = await Task.Run(() => PluginEntryClient.ProbeCertificate(host, port)); }
        catch (BastionException ex)
        {
            await ShowModal(c.Name + ": certificate not read", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return false;
        }
        var body = Ui.Text($"{host}:{port}\nSHA-256\n{GroupedPin(pin)}\n\nCompare it with the server before you trust it.", "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        body.IsTextSelectionEnabled = true;
        AutomationProperties.SetName(body, "Certificate fingerprint");
        if (!await ShowModal($"Trust this certificate for {c.Name}?", body, primary: "Trust", cancel: "Cancel", focusCancel: true)) return false;
        await SetPluginTlsAsync(c.Id, "pinned", pin);
        try { return PluginEntryClient.Tls(_library, c.Id).PinSha256 == pin; }
        catch (BastionException) { return false; }
    }

    private async Task SetPluginTlsAsync(string id, string mode, string? pin)
    {
        try
        {
            PluginEntryClient.SetTls(_library, id, mode, pin);
            SaveLibrary();
            RefreshInspectorFor(id);
        }
        catch (BastionException ex) { await ShowModal("Could not save the certificate rule", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
    }

    /// <summary><c>ab12cd…9f0e</c>: enough to recognise; the whole value is in the tooltip.</summary>
    internal static string ShortPin(string pin) => pin.Length > 12 ? $"{pin[..6]}…{pin[^4..]}" : pin;

    /// <summary>Groups of four, for comparing with the server's own display.</summary>
    internal static string GroupedPin(string pin) =>
        string.Join(" ", Enumerable.Range(0, (pin.Length + 3) / 4).Select(i => pin.Substring(i * 4, Math.Min(4, pin.Length - i * 4))));
}
