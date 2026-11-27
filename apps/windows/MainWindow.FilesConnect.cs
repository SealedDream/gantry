using System;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Files-only connections (C ABI 87): SFTP and SCP connections dial through the normal SSH connect flow (ConnectAsync)
/// and FTPS signs in here; each opens the same <see cref="SftpPanel"/> the terminal Files panel uses, in its own tab.
/// FTPS uses explicit TLS with the certificate pinned on first use; plain FTP stays refused by policy in the core.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>A tab holding only a files browser; closing the tab ends the connection.</summary>
    private async Task OpenFilesTabAsync(string title, SftpSession files, string connectionId, string protocolLabel, string login)
    {
        var panel = new SftpPanel(files, PickUploadFile, protocolLabel) { EditDataDir = SessionDataDir };
        var tab = Named(AddTab(title, null, files: panel), title, login);
        TieTab(tab, connectionId);
        PaintTab(tab);
        tab.FocusContent(FocusState.Programmatic);
        await panel.StartAsync();
    }

    /// <summary>
    /// FTPS: ask for the user name and password (used for this sign-in only), show an unknown certificate's
    /// fingerprint for verification before trusting it, and open the files tab.
    /// </summary>
    private async Task ConnectFtpsAsync(TreeItem item, LibraryClient? from)
    {
        if (_modal is not null || _connecting || item.Connection is not { } c) return;
        if (!PolicyAllows("ftps", item.Name)) return;
        var where = $"{c.Host}:{c.Port ?? 21}";
        var user = new TextBox { Header = "User name", Text = c.Username ?? "" };
        var password = new PasswordBox { Header = "Password" };
        var error = new FieldMessage();
        user.TextChanged += (_, _) => error.Hide();
        password.PasswordChanged += (_, _) => error.Hide();
        var body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { user, password, error.Element } };
        bool Validate()
        {
            if (user.Text.Trim().Length > 0) return true;
            error.Show("Enter a user name.");
            return false;
        }
        // The certificate accepted for this host:port before (trust on first use); a changed one is asked about again.
        var pins = new RdpCertificatePins(SessionDataDir, "ftps_certificates.json");
        string? accepted = null;
        var ask = true;
        try
        {
            while (true)
            {
                if (ask && !await ShowModal("Connect to " + item.Name, body, primary: "Connect", cancel: "Cancel", caption: where, validate: Validate,
                        focus: user.Text.Length > 0 ? (Control)password : user)) return;
                ask = true;
                var (name, secret, verified, library, sessions) = (user.Text.Trim(), password.Password, accepted ?? pins.Pin(where), from ?? _library, Sessions);
                SshConnectResult result;
                _connecting = true;
                UpdateConnectAction(Selected);
                try { result = await Task.Run(() => sessions.ConnectFtps(library, c.Id, name, secret, verified)); }
                catch (BastionException ex)
                {
                    await ShowModal("Could not connect to " + item.Name, CodedErrorText("FILE", ex.Message), primary: "OK", cancel: null);
                    return;
                }
                finally
                {
                    _connecting = false;
                    if (!_windowClosed) UpdateConnectAction(Selected);
                }
                if (_windowClosed) { result.Files?.Dispose(); return; }
                if (result.Files is { } files)
                {
                    if (accepted is not null)
                    {
                        try { pins.Save(where, accepted); }
                        catch (Exception e) when (e is System.IO.IOException or UnauthorizedAccessException) { }
                    }
                    await OpenFilesTabAsync(c.Name, files, c.Id, "FTPS", $"{name}@{c.Host}");
                    RecordConnected(c.Id, name);
                    return;
                }
                switch (result.Outcome)
                {
                    case ConnectOutcome.HostKeyUnknown when result.Fingerprint is { } fingerprint:
                        var changed = pins.Pin(where) is not null;
                        if (!await ShowModal(changed ? "The certificate has changed" : "Trust this certificate?", HostKeyPrompt.Body(where, fingerprint, false, certificate: true),
                                primary: "Connect and trust", cancel: "Cancel", focusCancel: true)) return;
                        accepted = fingerprint;
                        ask = false; // the login is still in the form; retry with the certificate trusted
                        continue;
                    case ConnectOutcome.AuthFailed:
                        RecordFailed(c.Id, "Authentication failed");
                        password.Password = "";
                        error.Show("Authentication failed. Check the user name and password.");
                        continue;
                    default:
                        RecordFailed(c.Id, result.Error ?? "The connection failed.");
                        await ShowModal("Could not connect to " + item.Name, CodedErrorText("FILE", result.Error ?? "The connection failed."), primary: "OK", cancel: null);
                        return;
                }
            }
        }
        finally { password.Password = ""; }
    }
}
