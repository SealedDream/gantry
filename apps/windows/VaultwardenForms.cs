using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Unlock Vaultwarden: server, e-mail and master password, plus the authenticator code once the server asked for
/// one. The master password lives only in its PasswordBox until <see cref="ClearSecrets"/>; the window hands it to
/// the core, which zeroes the buffer after the call.
/// </summary>
internal sealed class VaultwardenUnlockForm
{
    private readonly TextBox _server = new() { Header = "Server", PlaceholderText = "https://vault.example.com", IsSpellCheckEnabled = false };
    private readonly TextBox _email = new() { Header = "E-mail", IsSpellCheckEnabled = false };
    private readonly PasswordBox _password = new() { Header = "Master password" };
    private readonly TextBox _totp = new() { Header = "Authenticator code", IsSpellCheckEnabled = false, MaxLength = 10, Visibility = Visibility.Collapsed };
    private readonly FieldMessage _serverError = new(), _emailError = new(), _secretError = new();

    public StackPanel Body { get; }
    public Control FirstField => _server.Text.Trim().Length == 0 ? _server : _email.Text.Trim().Length == 0 ? _email : _password;
    public string ServerUrl => _server.Text.Trim();
    public string Email => _email.Text.Trim();
    public string MasterPassword => _password.Password;
    public string? Totp => _totp.Visibility == Visibility.Visible && _totp.Text.Trim().Length > 0 ? _totp.Text.Trim() : null;

    public VaultwardenUnlockForm(VaultwardenConfig remembered)
    {
        _server.Text = remembered.ServerUrl ?? "";
        _email.Text = remembered.Email ?? "";
        var intro = Ui.Text("Log in to read your Vaultwarden logins. Gantry keeps them in memory until you lock it or quit; the master password and item passwords are never saved.", "BodySecondaryTextStyle");
        intro.TextWrapping = TextWrapping.Wrap;
        Body = new StackPanel
        {
            Spacing = Ui.Double("Space12"),
            Children =
            {
                intro,
                new StackPanel { Children = { _server, _serverError.Element } },
                new StackPanel { Children = { _email, _emailError.Element } },
                new StackPanel { Children = { _password, _totp, _secretError.Element } },
            },
        };
        _server.TextChanged += (_, _) => _serverError.Hide();
        _email.TextChanged += (_, _) => _emailError.Hide();
        _password.PasswordChanged += (_, _) => _secretError.Hide();
        _totp.TextChanged += (_, _) => _secretError.Hide();
    }

    public bool Validate()
    {
        var server = ServerUrl.Length == 0 ? "Enter the server address."
            : !Uri.TryCreate(ServerUrl, UriKind.Absolute, out var u) || (u.Scheme != "https" && u.Scheme != "http") ? "Enter an https:// address."
            : null;
        var email = Email.Length == 0 || !Email.Contains('@') ? "Enter the account's e-mail address." : null;
        var secret = MasterPassword.Length == 0 ? "Enter the master password."
            : _totp.Visibility == Visibility.Visible && Totp is null ? "Enter the code from your authenticator app."
            : null;
        if (server is null) _serverError.Hide(); else _serverError.Show(server);
        if (email is null) _emailError.Hide(); else _emailError.Show(email);
        if (secret is null) _secretError.Hide(); else _secretError.Show(secret);
        if (server is not null) _server.Focus(FocusState.Programmatic);
        else if (email is not null) _email.Focus(FocusState.Programmatic);
        else if (secret is not null) (MasterPassword.Length == 0 ? (Control)_password : _totp).Focus(FocusState.Programmatic);
        return server is null && email is null && secret is null;
    }

    /// <summary>The server wants the authenticator code: show the field and focus it. The password stays typed.</summary>
    public void AskForCode()
    {
        _totp.Visibility = Visibility.Visible;
        _totp.Text = "";
        _secretError.Show("This account uses two-step login. Enter the current code from your authenticator app.");
        _totp.Focus(FocusState.Programmatic);
    }

    /// <summary>Show why the unlock failed and put the cursor where the fix goes.</summary>
    public void ShowFailure(string message, bool passwordRefused)
    {
        _secretError.Show(message);
        if (passwordRefused)
        {
            _password.Password = "";
            _password.Focus(FocusState.Programmatic);
        }
        else _server.Focus(FocusState.Programmatic);
    }

    /// <summary>Empty the secret fields once an attempt is over.</summary>
    public void ClearSecrets()
    {
        _password.Password = "";
        _totp.Text = "";
    }
}

/// <summary>The unlocked view: the logins Bastion can use (name and user name only), with Re-sync and Lock.</summary>
internal sealed class VaultwardenItemsBody
{
    public StackPanel Body { get; }
    public Control FirstButton { get; }

    public VaultwardenItemsBody(VaultwardenConfig config, VaultwardenItems items, Action resync, Action lockNow)
    {
        Body = new StackPanel { Spacing = Ui.Double("Space12") };
        var who = Ui.Text($"Unlocked as {config.Email} on {config.ServerUrl}. Assign a login to a connection from its menu (Assign Vaultwarden login…).", "BodySecondaryTextStyle");
        who.TextWrapping = TextWrapping.Wrap;
        Body.Children.Add(who);

        if (items.Items.Count == 0)
        {
            Body.Children.Add(Ui.Text("No personal logins in this vault.", "BodyTextStyle"));
        }
        else
        {
            var rows = new StackPanel { Spacing = Ui.Double("Space4") };
            AutomationProperties.SetName(rows, "Vaultwarden logins");
            foreach (var item in items.Items.OrderBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                var row = new StackPanel();
                row.Children.Add(Ui.Text(item.Name, "BodyTextStyle"));
                row.Children.Add(Ui.Text(item.Username is { Length: > 0 } u ? u : "No user name", "BodySecondaryTextStyle"));
                rows.Children.Add(row);
            }
            Body.Children.Add(new ScrollViewer { Content = rows, MaxHeight = 280, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        }
        if (items.Skipped > 0)
        {
            var skipped = Ui.Text($"{items.Skipped} organisation or unreadable item{(items.Skipped == 1 ? " is" : "s are")} not shown; Gantry reads personal logins only.", "BodySecondaryTextStyle");
            skipped.TextWrapping = TextWrapping.Wrap;
            Body.Children.Add(skipped);
        }

        var again = new Button { Content = Ui.IconLabel(Ui.Icon("GlyphRefresh"), "Re-sync") };
        var lockButton = new Button { Content = Ui.IconLabel(Ui.Icon("GlyphLock"), "Lock") };
        AutomationProperties.SetName(again, "Re-sync Vaultwarden");
        AutomationProperties.SetName(lockButton, "Lock Vaultwarden");
        again.Click += (_, _) => resync();
        lockButton.Click += (_, _) => lockNow();
        Body.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { again, lockButton } });
        FirstButton = again;
    }
}

/// <summary>Pick the Vaultwarden login a connection signs in with, or none.</summary>
internal sealed class AssignVaultwardenForm
{
    private readonly IReadOnlyList<VaultwardenItemDto> _items;
    private readonly ComboBox _choice;

    public StackPanel Body { get; }
    public Control Field => _choice;
    /// <summary>The chosen item id, or null for none.</summary>
    public string? ItemId => _choice.SelectedIndex <= 0 ? null : _items[_choice.SelectedIndex - 1].Id;

    public AssignVaultwardenForm(IReadOnlyList<VaultwardenItemDto> items, string? currentId)
    {
        _items = items.OrderBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        var labels = new List<string> { "None" };
        labels.AddRange(_items.Select(i => i.Label));
        _choice = new ComboBox { Header = "Vaultwarden login", ItemsSource = labels, HorizontalAlignment = HorizontalAlignment.Stretch };
        var at = _items.ToList().FindIndex(i => i.Id == currentId);
        _choice.SelectedIndex = at + 1; // -1 → 0 = None
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { _choice } };
        if (currentId is not null && at < 0)
        {
            var hint = Ui.Text("The login assigned now is not in this vault any more.", "BodySecondaryTextStyle");
            hint.TextWrapping = TextWrapping.Wrap;
            Body.Children.Add(hint);
        }
    }
}
