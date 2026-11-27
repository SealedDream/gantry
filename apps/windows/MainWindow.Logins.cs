using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Owner point W23: one ordered list of saved logins per connection, from the core (bastion_core::logins): its default, its
// other logins, the inherited one (nearest folder, then the type default), then logins saved for other connections on the
// same host. RDP, SSH and Services/Events/Processes all use it, so a password saved over SSH is offered for RDP to that host.
// A1-NW-01 (owner decision D1): the core says which of them may be used without asking (AutoUse). A login saved for
// another connection is selected and labelled in the sheet and sent only when the user presses Connect; it becomes the
// connection's own only after a successful connect and the user's Yes. The rule is LoginRule (Interop/LoginsNative.cs).
public sealed partial class MainWindow
{
    /// <summary>The saved logins the core lists for a connection of <paramref name="library"/>, best first; empty when
    /// the vault stays shut or fails. The login the user confirmed for this connection earlier this run comes first.</summary>
    private async Task<IReadOnlyList<SavedLogin>> SavedLoginsAsync(LibraryClient library, string connectionId, bool passwordsOnly)
    {
        if (!await ConfirmVaultOpenAsync()) return [];
        try
        {
            var all = OpenCredentials().List().ToDictionary(x => x.Id);
            var logins = OpenCredentials().Logins(library, connectionId, passwordsOnly)
                .Where(l => all.ContainsKey(l.CredentialId))
                .Select(l => new SavedLogin(all[l.CredentialId], l))
                .ToList();
            return ConfirmedFirst(connectionId, logins);
        }
        catch (BastionException ex)
        {
            Announce("Saved logins could not be read: " + ex.Message);
            return [];
        }
    }

    /// <summary>Move the login confirmed this run to the front, while the core still lists it.</summary>
    private IReadOnlyList<SavedLogin> ConfirmedFirst(string connectionId, List<SavedLogin> logins)
    {
        var at = LoginRule.Preferred(Candidates(logins), ConfirmedLogin(connectionId));
        if (at <= 0) return logins;
        var first = logins[at];
        logins.RemoveAt(at);
        logins.Insert(0, first);
        return logins;
    }

    private static List<LoginCandidateDto> Candidates(IReadOnlyList<SavedLogin> logins) => logins.Select(l => l.Login).ToList();

    /// <summary>True when the first of <paramref name="logins"/> may sign in with no sheet: the core marks it auto-use
    /// (the connection's own or inherited login), or the user picked it for this connection earlier this run.</summary>
    private bool MayUseUnasked(string connectionId, IReadOnlyList<SavedLogin> logins) =>
        LoginRule.MayUseUnasked(Candidates(logins), ConfirmedLogin(connectionId));

    /// <summary>
    /// After a successful sign-in with a login saved for another connection. The user's pick in the sheet plus this
    /// success confirms the login for this connection for the rest of the run (by id, no secret), whatever is answered
    /// next. Then, once per connection per run, ask whether the connection should keep it. Yes adds it to the
    /// connection's logins, so later runs need no sheet. No, Escape and a stray Enter (the focus is on No) add nothing.
    /// Nothing is added before the connect has succeeded.
    /// </summary>
    private async Task OfferToKeepLoginAsync(TreeItem item, string connectionId, LoginCandidateDto used)
    {
        if (used.AutoUse) return; // the connection's own or inherited login: nothing to confirm or to ask
        _confirmedLogins[connectionId] = used.CredentialId;
        _confirmedLoginTimes.Started(connectionId);
        if (!LoginRule.AsksToKeep(used, _askedToKeepLogin.Contains(connectionId))) return;
        // Another dialog is open (or the window is closing): not asked now, so the question waits for a later connect.
        if (_modal is not null || _windowClosed) return;
        _askedToKeepLogin.Add(connectionId);
        var body = ErrorText($"Use this login for {item.Name} from now on?");
        // The question opens over a session the user may already be typing in: No has the focus, so Enter is No.
        if (!await ShowModal("Saved login", body, primary: "Yes", cancel: "No", caption: used.Label, focusCancel: true)) return;
        try
        {
            OpenCredentials().AddLogin(_library, connectionId, used.CredentialId);
            ReloadThenSave(item.Id);
            Announce($"{item.Name} now uses this login");
        }
        catch (BastionException ex) { Announce("The login was not added: " + ex.Message); }
    }

    /// <summary>
    /// Offer the saved password logins in the RDP sheet, the best one selected. True when the fields hold a login
    /// that may be used with no sheet. A login saved for another connection is never read here: the sheet shows
    /// it selected and labelled, and its password leaves the core when the user presses Connect.
    /// </summary>
    private async Task<bool> OfferRdpLoginsAsync(ConnectionDto c, RdpConnectForm form)
    {
        if (!await ConfirmVaultOpenAsync()) return false;
        IReadOnlyList<LoginCandidateDto> logins;
        try { logins = OpenCredentials().Logins(_library, c.Id, passwordsOnly: true); }
        catch (BastionException ex) { Announce("Saved logins could not be read: " + ex.Message); return false; }
        if (logins.Count == 0) return false;
        (string User, string Password)? Release(int i)
        {
            try { return OpenCredentials().ReleaseLogin(_library, c.Id, logins[i].CredentialId); }
            catch (BastionException ex) { Announce("The saved password could not be read: " + ex.Message); return null; }
        }
        form.OfferLogins(logins, Release);
        if (!logins[0].AutoUse) return false;
        if (form.FromSavedLogin && !logins[0].IsOwn) Announce($"Using the login {logins[0].Origin.ToLowerInvariant()}");
        return form.FromSavedLogin && form.IsComplete;
    }

    // ---- Properties › Logins… : several username/password pairs on one connection, one of them the default ----

    private async Task ShowLoginsDialogAsync(string connectionId, string name)
    {
        if (_modal is not null || !await ConfirmVaultOpenAsync()) return;
        var list = new ListView { SelectionMode = ListViewSelectionMode.Single, MaxHeight = 280, MinWidth = 320 };
        AutomationProperties.SetName(list, "Logins");
        AutomationProperties.SetAutomationId(list, "LoginsList");
        var add = new ComboBox { Header = "Add a saved credential", HorizontalAlignment = HorizontalAlignment.Stretch, PlaceholderText = "Choose…" };
        AutomationProperties.SetAutomationId(add, "LoginsAdd");
        var makeDefault = new Button { Content = "Make Default" };
        var remove = new Button { Content = "Remove" };
        AutomationProperties.SetAutomationId(makeDefault, "LoginsMakeDefault");
        AutomationProperties.SetAutomationId(remove, "LoginsRemove");
        var note = Ui.Text("", "BodySecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        AutomationProperties.SetAutomationId(note, "LoginsNote");
        List<LoginCandidateDto> rows = [];
        List<CredentialDto> addable = [];

        void Refresh()
        {
            try
            {
                rows = OpenCredentials().Logins(_library, connectionId, passwordsOnly: false).ToList();
                var taken = rows.Where(r => r.IsOwn).Select(r => r.CredentialId).ToHashSet();
                addable = OpenCredentials().List().Where(x => !taken.Contains(x.Id)).OrderBy(x => x.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
            }
            catch (BastionException ex) { note.Text = ex.Message; return; }
            list.Items.Clear();
            foreach (var r in rows) list.Items.Add(r.Label + (r.Kind == "ssh-key" ? "  ·  key" : ""));
            add.Items.Clear();
            foreach (var x in addable) add.Items.Add($"{x.Name} ({x.Username})");
            // One short line (A1-NW-01): a login saved for another connection is offered, never used on its own.
            note.Text = rows.Any(r => r.Source == "same-host") ? "A “Saved for” login is only offered in the sheet." : "";
            UpdateButtons();
        }

        void UpdateButtons()
        {
            var sel = list.SelectedIndex is >= 0 and var i && i < rows.Count ? rows[i] : null;
            makeDefault.IsEnabled = sel is not null && sel.Source != "default";
            remove.IsEnabled = sel is { IsOwn: true };
        }

        void Change(Action edit)
        {
            try
            {
                edit();
                SaveLibrary();
            }
            catch (BastionException ex) { note.Text = ex.Message; return; }
            // The login remembered from an earlier connect this run would win over the new default: forget it.
            ForgetLogin(connectionId);
            Refresh();
        }

        list.SelectionChanged += (_, _) => UpdateButtons();
        add.SelectionChanged += (_, _) =>
        {
            if (add.SelectedIndex is not (>= 0 and var i) || i >= addable.Count) return;
            var id = addable[i].Id;
            Change(() => OpenCredentials().AddLogin(_library, connectionId, id));
        };
        makeDefault.Click += (_, _) =>
        {
            if (list.SelectedIndex is not (>= 0 and var i) || i >= rows.Count) return;
            var id = rows[i].CredentialId;
            Change(() => OpenCredentials().MakeDefaultLogin(_library, connectionId, id));
        };
        remove.Click += (_, _) =>
        {
            if (list.SelectedIndex is not (>= 0 and var i) || i >= rows.Count) return;
            var id = rows[i].CredentialId;
            Change(() => OpenCredentials().RemoveLogin(_library, connectionId, id));
        };
        Refresh();
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { makeDefault, remove } };
        // A sentence, not an identifier: the one-line, trimmed modal caption clipped it (NW-LOGINS-CAPTION-CLIPPED).
        var hint = Ui.Text("The first is the default. Connects use it without asking; the others are offered in the sheet.", "BodySecondaryTextStyle");
        hint.TextWrapping = TextWrapping.Wrap;
        AutomationProperties.SetAutomationId(hint, "LoginsHint");
        var body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { hint, list, buttons, add, note } };
        await ShowModal("Logins for " + name, body, primary: "Done", cancel: null);
        Reload(connectionId);
    }

    /// <summary>Snapshot/UI tests: open the Logins dialog for a named connection.</summary>
    internal Task ShowLoginsForSnapshot(string name) =>
        LibraryItemForSnapshot(name) is { Connection: { } c } item ? ShowLoginsDialogAsync(c.Id, item.Name) : Task.CompletedTask;
}
