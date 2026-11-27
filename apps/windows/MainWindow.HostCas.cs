using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Host certificate authorities (core hostcert over C ABI 20) on the Credential Manager page: each is a
// `@cert-authority <patterns> <key>` line in the app's known_hosts, the same file and rules as the macOS CA manager.
// Adding one is an explicit trust decision, so the dialog shows the fingerprint back before anything is written.
public sealed partial class MainWindow
{
    private void AddHostCaSection(StackPanel content)
    {
        content.Children.Add(SectionHeader("Host certificate authorities"));
        var note = Ui.Text("Servers whose host certificate is signed by one of these CAs connect without a fingerprint prompt, for the hosts listed. Check a CA key with its owner before you add it.", "CaptionSecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        content.Children.Add(note);
        try
        {
            var cas = Sessions.HostCas();
            if (cas.Count == 0) content.Children.Add(Ui.Text("No certificate authorities.", "BodySecondaryTextStyle"));
            foreach (var ca in cas) content.Children.Add(HostCaRow(ca));
        }
        catch (BastionException ex) { content.Children.Add(CodedErrorText("APP", ex.Message)); }
        content.Children.Add(PageButton("Add Certificate Authority…", () => _ = AddHostCaFromPageAsync()));
    }

    private Grid HostCaRow(HostCaDto ca)
    {
        var row = new Grid { ColumnSpacing = Ui.Double("Space12"), MinHeight = Ui.Double("ControlHeight") };
        row.ColumnDefinitions.Add(new ColumnDefinition());
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var detail = $"{ca.Algorithm} {ca.Fingerprint}{(ca.Comment is { Length: > 0 } c ? " · " + c : "")}";
        var fp = Ui.Text(detail, "CaptionSecondaryTextStyle");
        fp.IsTextSelectionEnabled = true;
        row.Children.Add(new StackPanel { VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Text(ca.Patterns, "BodyTextStyle"), fp } });
        var remove = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphDelete", "IconSize") };
        ToolTipService.SetToolTip(remove, "Remove");
        AutomationProperties.SetName(remove, "Remove certificate authority for " + ca.Patterns);
        remove.Click += (_, _) => _ = RemoveHostCaFromPageAsync(ca);
        Grid.SetColumn(remove, 1);
        row.Children.Add(remove);
        return row;
    }

    private async Task AddHostCaFromPageAsync()
    {
        var form = new HostCaForm();
        while (await ShowModal("Add certificate authority", form.Body, primary: "Trust", cancel: "Cancel", validate: form.Validate, focus: form.FirstField, wide: true))
        {
            try
            {
                var added = Sessions.AddHostCa(form.Patterns, form.PublicKey);
                await ShowModal("Certificate authority added", ErrorText($"{added.Algorithm} {added.Fingerprint} now signs host certificates for {added.Patterns}."), primary: "OK", cancel: null);
                break;
            }
            catch (BastionException ex) { form.ShowError(ex.Message); }
        }
        ShowCredentialManagerPage();
    }

    private async Task RemoveHostCaFromPageAsync(HostCaDto ca)
    {
        var body = ErrorText($"Host certificates signed by {ca.Fingerprint} will no longer be trusted for {ca.Patterns}. Those servers will ask for a fingerprint again.");
        if (await ShowModal("Remove certificate authority?", body, primary: "Remove", cancel: "Cancel", focusCancel: true))
        {
            try { Sessions.RemoveHostCa(ca.Patterns, ca.Fingerprint); }
            catch (BastionException ex) { await ShowModal("Could not remove the certificate authority", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        }
        ShowCredentialManagerPage();
    }

    // ---- Snapshot mode hooks (SnapshotRunner, BASTION_SNAPSHOT_HOST_CAS) ----

    private HostCaForm? _snapshotHostCaForm;

    /// <summary>The demo CA (public key only), so the page has a row to show.</summary>
    internal void SeedHostCaForSnapshot()
    {
        const string demoCa = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILF/4mdPs9Kjydpnat9r6vTUpm4Geo9KVCqLHrcPY0vz demo-ca";
        if (Sessions.HostCas().Count == 0) Sessions.AddHostCa("*.lab,[127.0.0.1]:2240", demoCa);
    }

    internal Task AddHostCaForSnapshot()
    {
        _snapshotHostCaForm = new HostCaForm();
        return ShowModal("Add certificate authority", _snapshotHostCaForm.Body, primary: "Trust", cancel: "Cancel", validate: _snapshotHostCaForm.Validate, focus: _snapshotHostCaForm.FirstField, wide: true);
    }

    internal void FillHostCaForSnapshot(string patterns, string key) => _snapshotHostCaForm?.Fill(patterns, key);
}

/// <summary>Host patterns plus one OpenSSH public key line; the core does the real validation.</summary>
internal sealed class HostCaForm
{
    private readonly TextBox _patterns = new() { Header = "Hosts", PlaceholderText = "*.example.com,[10.0.0.5]:2222", IsSpellCheckEnabled = false };
    private readonly TextBox _key = new()
    {
        Header = "CA public key", AcceptsReturn = false, TextWrapping = TextWrapping.Wrap, IsSpellCheckEnabled = false,
        Height = 96, PlaceholderText = "ssh-ed25519 AAAA… ca",
    };
    private readonly FieldMessage _patternsError = new(), _keyError = new();

    public StackPanel Body { get; }
    public Control FirstField => _patterns;
    public string Patterns => _patterns.Text.Trim();
    public string PublicKey => _key.Text.Trim();

    public HostCaForm()
    {
        AutomationProperties.SetName(_key, "CA public key");
        Body = new StackPanel { Spacing = Ui.Double("Space12") };
        Body.Children.Add(new StackPanel { Children = { _patterns, _patternsError.Element } });
        Body.Children.Add(new StackPanel { Children = { _key, _keyError.Element } });
        _patterns.TextChanged += (_, _) => _patternsError.Hide();
        _key.TextChanged += (_, _) => _keyError.Hide();
    }

    internal void Fill(string patterns, string key) => (_patterns.Text, _key.Text) = (patterns, key);

    public void ShowError(string message)
    {
        if (message.StartsWith("Host patterns", StringComparison.Ordinal)) _patternsError.Show(message); else _keyError.Show(message);
    }

    public bool Validate()
    {
        var patternsOk = Patterns.Length > 0 && !Patterns.Any(char.IsWhiteSpace);
        var keyOk = PublicKey.Length > 0 && !PublicKey.Contains("PRIVATE KEY", StringComparison.Ordinal);
        if (patternsOk) _patternsError.Hide(); else _patternsError.Show("Enter host patterns separated by commas, without spaces.");
        if (keyOk) _keyError.Hide(); else _keyError.Show(PublicKey.Contains("PRIVATE KEY", StringComparison.Ordinal) ? "That is a private key. Paste the CA's public key (.pub)." : "Paste the CA public key.");
        if (!patternsOk) _patterns.Focus(FocusState.Programmatic); else if (!keyOk) _key.Focus(FocusState.Programmatic);
        return patternsOk && keyOk;
    }
}
