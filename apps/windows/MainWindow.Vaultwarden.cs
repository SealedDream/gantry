using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

/// <summary>
/// Vaultwarden: unlock (with the authenticator step), the list of logins, re-sync and lock, assigning a login to a
/// connection, and handing the unlocked session to SSH connects. Network calls run off the UI thread; the master
/// password is cleared from the form as soon as an attempt ends.
/// </summary>
public sealed partial class MainWindow
{
    private VaultwardenClient? _vaultwarden;
    private bool _unlocking;

    /// <summary>One session per data directory (where <c>vaultwarden.json</c> remembers the server and e-mail).</summary>
    private VaultwardenClient Vaultwarden => _vaultwarden ??= VaultwardenClient.Open(SessionDataDir);

    private void Vaultwarden_Click(object sender, RoutedEventArgs e) => _ = VaultwardenAsync();

    private void AssignVaultwarden_Click(object sender, RoutedEventArgs e) => _ = AssignVaultwardenAsync();

    /// <summary>More → Vaultwarden…: the unlock form while locked, the logins once unlocked.</summary>
    internal async Task VaultwardenAsync()
    {
        if (_modal is not null || _unlocking) return;
        try
        {
            if (!Vaultwarden.IsUnlocked && !await UnlockVaultwardenAsync()) return;
            await ShowVaultwardenItemsAsync(Vaultwarden.Items);
        }
        catch (BastionException ex)
        {
            await ShowModal("Vaultwarden", CodedErrorText("VAULT", ex.Message), primary: "OK", cancel: null);
        }
    }

    /// <summary>Ask for the login until it succeeds or the user cancels. True when unlocked.</summary>
    private async Task<bool> UnlockVaultwardenAsync()
    {
        var form = new VaultwardenUnlockForm(Vaultwarden.Config);
        while (true)
        {
            if (!await ShowModal("Unlock Vaultwarden", form.Body, primary: "Unlock", cancel: "Cancel", validate: form.Validate, focus: form.FirstField, wide: true))
            {
                form.ClearSecrets();
                return false;
            }
            // Copy the fields out before leaving the UI thread; the blocking unlock must not touch controls.
            var (server, email, password, totp) = (form.ServerUrl, form.Email, form.MasterPassword, form.Totp);
            VaultwardenUnlockResult result;
            _unlocking = true;
            try { result = await Task.Run(() => Vaultwarden.Unlock(server, email, password, totp)); }
            finally { _unlocking = false; }

            switch (result.Outcome)
            {
                case VaultwardenOutcome.Ok:
                    form.ClearSecrets();
                    return true;
                case VaultwardenOutcome.TwoFactorRequired:
                    // The password stays in its box for the retry with the code.
                    form.AskForCode();
                    break;
                case VaultwardenOutcome.AuthFailed:
                    form.ShowFailure(totp is null ? "The e-mail or master password was not accepted." : "The master password or the code was not accepted.", passwordRefused: true);
                    break;
                default:
                    form.ShowFailure(result.Error ?? "Could not reach the server.", passwordRefused: false);
                    break;
            }
        }
    }

    private async Task ShowVaultwardenItemsAsync(VaultwardenItems items)
    {
        // Re-sync and Lock close this dialog and say what to do next; the loop reopens it with fresh data.
        while (true)
        {
            string? next = null;
            var body = new VaultwardenItemsBody(Vaultwarden.Config, items,
                resync: () => { next = "resync"; CloseModal(false); },
                lockNow: () => { next = "lock"; CloseModal(false); });
            await ShowModal("Vaultwarden", body.Body, primary: "Done", cancel: null, wide: true, focus: body.FirstButton);
            switch (next)
            {
                case "resync":
                    try { items = await Task.Run(() => Vaultwarden.Resync()); }
                    catch (BastionException ex)
                    {
                        Vaultwarden.Lock();
                        await ShowModal("Could not re-sync Vaultwarden", ErrorText(ex.Message + " Unlock it again to continue."), primary: "OK", cancel: null);
                        return;
                    }
                    break;
                case "lock":
                    // Through the session manager when it exists, so it forgets every unlocked credential at once.
                    _sessions?.LockCredentials();
                    Vaultwarden.Lock();
                    return;
                default:
                    return;
            }
        }
    }

    /// <summary>Tree menu → Assign Vaultwarden login…: unlocks first when needed, then picks one login or none.</summary>
    internal async Task AssignVaultwardenAsync()
    {
        if (_modal is not null || _unlocking || (_contextTarget ?? Selected) is not { Connection: { } conn } item) return;
        try
        {
            if (!Vaultwarden.IsUnlocked && !await UnlockVaultwardenAsync()) return;
            var form = new AssignVaultwardenForm(Vaultwarden.Items.Items, conn.VaultwardenItem);
            if (!await ShowModal("Assign Vaultwarden login", form.Body, primary: "Assign", cancel: "Cancel", caption: "for " + item.Name, focus: form.Field)) return;
            await Mutate(() =>
            {
                _library.SetVaultwardenItem(conn.Id, form.ItemId);
                return conn.Id;
            }, "Could not assign the Vaultwarden login");
        }
        catch (BastionException ex)
        {
            await ShowModal("Vaultwarden", CodedErrorText("VAULT", ex.Message), primary: "OK", cancel: null);
        }
    }

    /// <summary>The connection's Vaultwarden login, when Vaultwarden is unlocked and still has it; otherwise null.</summary>
    private VaultwardenItemDto? AssignedVaultwardenItem(ConnectionDto c)
    {
        if (c.VaultwardenItem is not { } id || _vaultwarden is null) return null;
        try { return _vaultwarden.IsUnlocked ? _vaultwarden.Items.Items.FirstOrDefault(i => i.Id == id) : null; }
        catch (BastionException) { return null; }
    }

    /// <summary>The inspector's Vaultwarden login row: the item's name while unlocked, otherwise whether one is assigned.</summary>
    private string VaultwardenLabel(ConnectionDto c)
    {
        if (c.VaultwardenItem is null) return "—";
        return AssignedVaultwardenItem(c)?.Name ?? (_vaultwarden is { IsUnlocked: true } ? "Missing from Vaultwarden" : "Assigned (Vaultwarden locked)");
    }

    // ---- Snapshot mode hooks (SnapshotRunner, BASTION_SNAPSHOT_VAULTWARDEN; a throwaway test server only) ----

    internal string ModalTitleForSnapshot => _modal is null ? "" : ModalTitle.Text;

    /// <summary>Snapshot only: type into the open dialog's password field with this header.</summary>
    internal void SetModalPasswordForSnapshot(string header, string text)
    {
        static IEnumerable<DependencyObject> All(DependencyObject d)
        {
            yield return d;
            for (var i = 0; i < Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChildrenCount(d); i++)
                foreach (var c in All(Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChild(d, i))) yield return c;
        }
        if (All(ModalBody).OfType<Microsoft.UI.Xaml.Controls.PasswordBox>().FirstOrDefault(p => p.Header as string == header) is { } box) box.Password = text;
    }

    /// <summary>
    /// Snapshot only: an SSH connection to the test server with the Vaultwarden login <paramref name="itemName"/>
    /// assigned, selected and its Connect flow started. The returned task is the whole connect flow, so a failure in
    /// it reaches the snapshot log instead of vanishing.
    /// </summary>
    internal Task OpenVaultwardenConnectForSnapshot(string itemName, string host, int port)
    {
        if (!_demo) throw new InvalidOperationException("snapshot only");
        var login = Vaultwarden.Items.Items.FirstOrDefault(i => i.Name == itemName) ?? throw new InvalidOperationException($"no Vaultwarden login named {itemName}");
        var id = _library.AddConnection(null, "lab sshd", "ssh", host, port, null);
        _library.SetVaultwardenItem(id, login.Id);
        Reload(id);
        // The tree applies a selection set from code later, so hand the new row to Connect directly.
        var row = TreeItem.Find(_roots, id) ?? throw new InvalidOperationException("the new connection is not in the tree");
        return ConnectAsync(row);
    }

    /// <summary>Snapshot only: the active tab's terminal, to type a command and read the answer.</summary>
    internal TerminalView? ActiveTerminalForSnapshot => _active?.View;
}
