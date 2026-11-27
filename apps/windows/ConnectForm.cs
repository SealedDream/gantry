using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>A saved login the core lists for a connection: the vault row and where it comes from (no secret).</summary>
public sealed record SavedLogin(CredentialDto Credential, LoginCandidateDto Login);

/// <summary>
/// The "Connect" dialog body: the user name, then a password or a key file with its passphrase. Built in code
/// like the other forms so validation lives next to the fields (MainWindow.xaml.cs keeps the modal open and the
/// form says what is missing).
/// </summary>
/// <remarks>
/// Secrets: the typed values live only in the two password controls and in the <see cref="Password"/> /
/// <see cref="Passphrase"/> reads that hand them to the ABI. <see cref="ClearSecrets"/> empties the controls as
/// soon as the attempt is over, and <c>Utf8Secret</c> (Interop/SessionNative.cs) zeroes the buffer that crosses
/// the boundary. Nothing here is logged or kept on the form.
/// </remarks>
public sealed class ConnectForm
{
    private readonly TextBox _user = new() { Header = "User name", IsSpellCheckEnabled = false };
    private readonly RadioButton _usePassword = new() { Content = "Password", IsChecked = true, GroupName = "BastionConnectMethod" };
    private readonly RadioButton _useKey = new() { Content = "Key file", GroupName = "BastionConnectMethod" };
    private readonly RadioButton _useAgent = new() { Content = "SSH agent", GroupName = "BastionConnectMethod" };
    private readonly RadioButton _useVault = new() { GroupName = "BastionConnectMethod", Visibility = Visibility.Collapsed };
    private readonly RadioButton _useVaultwarden = new() { GroupName = "BastionConnectMethod", Visibility = Visibility.Collapsed };
    private readonly RadioButton _useProvider = new() { Content = "Credential provider", GroupName = "BastionConnectMethod", Visibility = Visibility.Collapsed };
    private readonly IReadOnlyList<ProviderOption> _providers;
    private readonly ComboBox _provider = new() { Header = "Provider", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly ComboBox _providerEntry = new() { Header = "Entry", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly TextBox _providerItem = new() { Header = "Item", IsSpellCheckEnabled = false };
    private readonly StackPanel _providerFields;
    private CredentialDto? _assigned;
    private SavedLogin? _chosen;
    private readonly VaultwardenItemDto? _vaultwardenItem;
    private readonly PasswordBox _password = new() { Header = "Password", PlaceholderText = "" };
    private readonly CheckBox _savePassword = new() { Content = "Save password for this connection", IsChecked = true };
    private readonly TextBox _keyPath = new() { Header = "Private key file", IsSpellCheckEnabled = false };
    private readonly PasswordBox _passphrase = new() { Header = "Key passphrase (leave empty if the key is not encrypted)" };
    private readonly StackPanel _passwordFields;
    private readonly StackPanel _keyFields;
    private readonly FieldMessage _userError = new();
    private readonly FieldMessage _secretError = new();
    private readonly List<HopLogin> _hops = [];

    public StackPanel Body { get; }

    /// <summary>The field that should have focus when the dialog opens: the secret when a user name is known.</summary>
    public Control FirstField => Kind switch
    {
        SshLoginKind.Vault => _useVault,
        SshLoginKind.Vaultwarden => _useVaultwarden,
        SshLoginKind.Provider => _useProvider,
        SshLoginKind.Agent => _user,
        _ => _user.Text.Trim().Length == 0 ? _user : _password,
    };

    public string UserName => _user.Text.Trim();

    /// <summary>The user name the session signs in as: the typed one, else the saved credential's or Vaultwarden login's.</summary>
    public string SignedInAs => UserName.Length > 0 ? UserName : Kind switch
    {
        SshLoginKind.Vault => _assigned?.Username ?? "",
        SshLoginKind.Vaultwarden => _vaultwardenItem?.Username ?? "",
        SshLoginKind.Provider => ProviderEntry?.Username ?? "",
        _ => "",
    };
    public SshLoginKind Kind =>
        _useVault.IsChecked == true ? SshLoginKind.Vault
        : _useVaultwarden.IsChecked == true ? SshLoginKind.Vaultwarden
        : _useProvider.IsChecked == true ? SshLoginKind.Provider
        : _useKey.IsChecked == true ? SshLoginKind.KeyFile
        : _useAgent.IsChecked == true ? SshLoginKind.Agent
        : SshLoginKind.Password;
    public string KeyPath => _keyPath.Text.Trim();

    /// <summary>The secret for the selected method: the password, the key's passphrase, or for a saved credential or
    /// Vaultwarden item its id (not a secret).</summary>
    public string Secret => Kind switch
    {
        SshLoginKind.KeyFile => _passphrase.Password,
        SshLoginKind.Vault => _assigned!.Id,
        SshLoginKind.Vaultwarden => _vaultwardenItem!.Id,
        SshLoginKind.Provider => ProviderReference ?? "",
        SshLoginKind.Agent => "",
        _ => _password.Password,
    };

    /// <summary>The jump hosts given their own login, keyed <c>host:port</c>; the rest reuse the target's login.</summary>
    /// <summary>The unlocked provider chosen, or null.</summary>
    private ProviderOption? ChosenProvider => _provider.SelectedIndex >= 0 && _provider.SelectedIndex < _providers.Count ? _providers[_provider.SelectedIndex] : null;

    /// <summary>The KeePass entry chosen, when the provider lists entries.</summary>
    private ProviderItemDto? ProviderEntry => ChosenProvider is { Entries.Count: > 0 } p && _providerEntry.SelectedIndex >= 0 ? p.Entries[_providerEntry.SelectedIndex] : null;

    /// <summary>The provider login, <c>"&lt;id&gt;:&lt;item&gt;"</c> (a reference, not a secret), or null while incomplete.</summary>
    public string? ProviderReference => ChosenProvider is not { } p ? null
        : p.Entries.Count > 0 ? (ProviderEntry is { } e ? $"{p.Id}:{e.Id}" : null)
        : _providerItem.Text.Trim() is { Length: > 0 } i ? $"{p.Id}:{i}" : null;

    /// <summary>Owner point 5: a typed password is saved to the vault and assigned, so the next connect opens directly.</summary>
    public bool SavePassword => Kind == SshLoginKind.Password && _savePassword.IsChecked == true && _password.Password.Length > 0;

    /// <summary>Hide "Save password" (Connect as…, Quick Connect, a connection that already has a credential).</summary>
    /// A hidden box never saves: it is unticked too.
    public void HideSavePassword()
    {
        _savePassword.Visibility = Visibility.Collapsed;
        _savePassword.IsChecked = false;
    }

    /// <summary>Fill the form with the login used last time (owner points 2, 3): a password or key file, never Vault rows.</summary>
    public void Prefill(string user, SshLoginKind kind, string? secret, string? keyPath)
    {
        if (user.Length > 0) _user.Text = user;
        // SEC-03: a reused login is not saved. A user who wanted it saved ticked the box on the first connect, which
        // already saved and assigned it; otherwise a reconnect would save it unasked and outlive the reuse time.
        _savePassword.IsChecked = false;
        // The remembered login replaces whatever was preselected (a saved credential that is only offered, A1-NW-01).
        if (kind is SshLoginKind.Password or SshLoginKind.KeyFile or SshLoginKind.Agent)
            _useVault.IsChecked = _useVaultwarden.IsChecked = _useProvider.IsChecked = false;
        switch (kind)
        {
            case SshLoginKind.Password: _usePassword.IsChecked = true; _password.Password = secret ?? ""; break;
            case SshLoginKind.KeyFile: _useKey.IsChecked = true; _keyPath.Text = keyPath ?? ""; _passphrase.Password = secret ?? ""; break;
            case SshLoginKind.Agent: _useAgent.IsChecked = true; break;
        }
        ShowMethod();
    }

    /// <summary>True when Connect could go ahead without the user touching the form.</summary>
    public bool IsComplete => Kind switch
    {
        SshLoginKind.Vault => _assigned is not null,
        SshLoginKind.Password => SignedInAs.Length > 0 && _password.Password.Length > 0,
        SshLoginKind.KeyFile => SignedInAs.Length > 0 && KeyPath.Length > 0,
        SshLoginKind.Agent => SignedInAs.Length > 0,
        _ => false,
    };

    public IReadOnlyDictionary<string, JumpLoginInput> JumpLogins =>
        _hops.Where(h => h.Kind is not null).ToDictionary(h => h.Key, h => h.Login);

    /// <param name="userName">The connection's saved user name, or null.</param>
    /// <param name="assigned">The vault credential assigned to the connection; offered first and preselected.</param>
    /// <param name="vaultwardenItem">The connection's Vaultwarden item, when Vaultwarden is unlocked and has it;
    /// preselected unless a vault credential is assigned too.</param>
    /// <param name="jumpHosts">The connection's jump hosts, each of which may sign in its own way.</param>
    public ConnectForm(string? userName, CredentialDto? assigned = null, VaultwardenItemDto? vaultwardenItem = null,
        IReadOnlyList<JumpHostDto>? jumpHosts = null, IReadOnlyList<string>? recentUsers = null,
        IReadOnlyList<ProviderOption>? providers = null, string? lastProviderReference = null)
    {
        _providers = providers ?? [];
        _assigned = assigned;
        _vaultwardenItem = vaultwardenItem;
        _user.Text = userName ?? "";
        if (vaultwardenItem is not null)
        {
            _useVaultwarden.Content = $"Vaultwarden ({vaultwardenItem.Name})";
            _useVaultwarden.Visibility = Visibility.Visible;
            _useVaultwarden.IsChecked = assigned is null;
            if (assigned is null && vaultwardenItem.Username is { Length: > 0 } vwUser) _user.PlaceholderText = vwUser;
        }
        if (assigned is not null)
        {
            _useVault.Content = $"Saved credential ({assigned.Name})";
            _useVault.Visibility = Visibility.Visible;
            _useVault.IsChecked = true;
            _user.PlaceholderText = assigned.Username;
        }
        _keyPath.PlaceholderText = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "id_ed25519");

        _providerFields = ProviderFields(lastProviderReference);

        _passwordFields = new StackPanel { Spacing = Ui.Double("Space4"), Children = { _password, _savePassword }, Visibility = assigned is null && vaultwardenItem is null ? Visibility.Visible : Visibility.Collapsed };
        _keyFields = new StackPanel { Spacing = Ui.Double("Space12"), Children = { _keyPath, _passphrase }, Visibility = Visibility.Collapsed };

        // A horizontal stack cannot wrap, so with a saved credential or Vaultwarden login beside Password and Key file
        // the row would run past the dialog: list the choices vertically then, as Windows radio groups usually are.
        var choices = 3 + (assigned is null ? 0 : 1) + (vaultwardenItem is null ? 0 : 1) + (_providers.Count == 0 ? 0 : 1);
        var method = new StackPanel
        {
            Orientation = choices > 2 ? Orientation.Vertical : Orientation.Horizontal,
            Spacing = Ui.Double(choices > 2 ? "Space4" : "Space16"),
            Children = { _useVault, _useVaultwarden, _useProvider, _usePassword, _useKey, _useAgent },
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(method, "Sign in with");

        Body = new StackPanel
        {
            Spacing = Ui.Double("Space12"),
            Children = { _user, _userError.Element, method, _providerFields, _passwordFields, _keyFields, _secretError.Element },
        };
        if (recentUsers is { Count: > 0 }) Body.Children.Insert(1, RecentRow(recentUsers));
        foreach (var hop in jumpHosts ?? [])
        {
            var row = new HopLogin(hop, _keyPath.PlaceholderText);
            _hops.Add(row);
            Body.Children.Add(row.Element);
        }

        _usePassword.Checked += (_, _) => ShowMethod();
        _useKey.Checked += (_, _) => ShowMethod();
        _useVault.Checked += (_, _) => ShowMethod();
        _useVaultwarden.Checked += (_, _) => ShowMethod();
        _useProvider.Checked += (_, _) => ShowMethod();
        _useAgent.Checked += (_, _) => ShowMethod();
        _user.TextChanged += (_, _) => _userError.Hide();
        _keyPath.TextChanged += (_, _) => _secretError.Hide();
        _password.PasswordChanged += (_, _) => _secretError.Hide();
        _passphrase.PasswordChanged += (_, _) => _secretError.Hide();
    }

    /// <summary>
    /// W23: every saved login the connection can use (its own, inherited, the same host's), best first. With more than one,
    /// a Login picker at the top switches the saved credential the form signs in with. Call only with a vault credential assigned.
    /// A1-NW-01: a login saved for another connection is only ever selected here; it is sent when the user presses Connect.
    /// </summary>
    public void OfferLogins(IReadOnlyList<SavedLogin> logins)
    {
        if (_assigned is null || logins.Count == 0) return;
        _chosen = logins[0];
        _useVault.Content = $"Saved credential ({logins[0].Login.Label})";
        if (logins.Count < 2) return;
        var picker = new ComboBox { Header = "Login", HorizontalAlignment = HorizontalAlignment.Stretch };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(picker, "LoginPicker");
        foreach (var login in logins) picker.Items.Add(login.Login.Label);
        picker.SelectedIndex = 0;
        picker.SelectionChanged += (_, _) =>
        {
            if (picker.SelectedIndex is not (>= 0 and var i) || i >= logins.Count) return;
            _chosen = logins[i];
            _assigned = logins[i].Credential;
            _useVault.Content = $"Saved credential ({logins[i].Login.Label})";
            _user.PlaceholderText = _assigned.Username;
            _useVault.IsChecked = true;
        };
        Body.Children.Insert(0, picker);
    }

    /// <summary>The saved login the form signs in with, when the saved credential is the chosen method; else null.</summary>
    public SavedLogin? ChosenLogin => Kind == SshLoginKind.Vault ? _chosen : null;

    /// <param name="recentUsers">Connect as…: user names used on this host before, newest first (no secrets).</param>
    private StackPanel RecentRow(IReadOnlyList<string> recentUsers)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space4") };
        row.Children.Add(Ui.Text("Recent:", "BodySecondaryTextStyle"));
        foreach (var name in recentUsers.Take(MaxRecentShown))
        {
            var pick = new HyperlinkButton { Content = name, Padding = new Thickness(Ui.Double("Space4"), 0, Ui.Double("Space4"), 0) };
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(pick, "Use " + name);
            pick.Click += (_, _) => { _user.Text = name; _password.Focus(FocusState.Programmatic); };
            row.Children.Add(pick);
        }
        return row;
    }

    private const int MaxRecentShown = 5;

    /// <summary>Provider, then a KeePass entry picker or a typed item (Native Mac's ProviderLoginFields).</summary>
    private StackPanel ProviderFields(string? last)
    {
        var panel = new StackPanel { Spacing = Ui.Double("Space8"), Visibility = Visibility.Collapsed, Children = { _provider, _providerEntry, _providerItem } };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(_provider, "Credential provider name");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(_providerEntry, "Provider entry");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(_providerItem, "Provider item");
        if (_providers.Count == 0) return panel;
        _useProvider.Visibility = Visibility.Visible;
        _provider.ItemsSource = _providers.Select(p => p.Title).ToList();
        var (lastId, lastItem) = last?.Split(':', 2) is [var a, var b] ? (a, b) : ("", "");
        var at = Math.Max(0, _providers.ToList().FindIndex(p => p.Id == lastId));
        _provider.SelectionChanged += (_, _) => ShowProviderItem(null);
        _providerEntry.SelectionChanged += (_, _) => _secretError.Hide();
        _providerItem.TextChanged += (_, _) => _secretError.Hide();
        _provider.SelectedIndex = at;
        ShowProviderItem(_providers[at].Id == lastId ? lastItem : null);
        return panel;
    }

    private void ShowProviderItem(string? item)
    {
        var p = ChosenProvider;
        var listed = p is { Entries.Count: > 0 };
        _providerEntry.Visibility = listed ? Visibility.Visible : Visibility.Collapsed;
        _providerItem.Visibility = listed ? Visibility.Collapsed : Visibility.Visible;
        if (p is null) return;
        _providerItem.PlaceholderText = p.ItemPrompt;
        _providerItem.Text = listed ? "" : item ?? "";
        _providerEntry.ItemsSource = p.Entries.Select(e => $"{e.Title} ({(e.Username is { Length: > 0 } u ? u : "no user")})").ToList();
        _providerEntry.SelectedIndex = listed ? p.Entries.ToList().FindIndex(e => e.Id == item) : -1;
        _secretError.Hide();
    }

    /// <summary>The login Test Connection signs in with: exactly what the form holds, kept in memory only.</summary>
    public ProbeLogin TestLogin => new((int)Kind, Secret, Kind == SshLoginKind.KeyFile ? KeyPath : null);

    /// <summary>Snapshot only: the SSH agent chosen, the first jump host set to its own password.</summary>
    internal void ShowAgentWithHopPasswordForSnapshot()
    {
        _useAgent.IsChecked = true;
        ShowMethod();
        _hops.FirstOrDefault()?.UsePasswordForSnapshot();
    }

    private void ShowMethod()
    {
        var key = Kind == SshLoginKind.KeyFile;
        var provider = Kind == SshLoginKind.Provider;
        var vault = Kind is SshLoginKind.Vault or SshLoginKind.Vaultwarden or SshLoginKind.Agent || provider;
        _passwordFields.Visibility = key || vault ? Visibility.Collapsed : Visibility.Visible;
        _providerFields.Visibility = provider ? Visibility.Visible : Visibility.Collapsed;
        _keyFields.Visibility = key ? Visibility.Visible : Visibility.Collapsed;
        _secretError.Hide();
        if (!vault) (key ? (Control)_keyPath : _password).Focus(FocusState.Programmatic);
    }

    /// <summary>True when the form can be submitted; otherwise shows what is missing and focuses that field.</summary>
    public bool Validate()
    {
        // A saved credential or Vaultwarden item brings its own user name and secret; a typed user name overrides the name only.
        if (Kind is SshLoginKind.Vault or SshLoginKind.Vaultwarden)
        {
            _userError.Hide();
            _secretError.Hide();
            return true;
        }
        if (Kind == SshLoginKind.Provider)
        {
            if (ProviderReference is null)
            {
                _secretError.Show(ChosenProvider is { Entries.Count: > 0 } ? "Choose the entry to sign in with." : "Enter the provider item, for example " + ChosenProvider?.ItemPrompt + ".");
                (_providerEntry.Visibility == Visibility.Visible ? (Control)_providerEntry : _providerItem).Focus(FocusState.Programmatic);
                return false;
            }
            _secretError.Hide();
        }
        if (SignedInAs.Length == 0)
        {
            _userError.Show("Enter the user name to sign in as.");
            _user.Focus(FocusState.Programmatic);
            return false;
        }
        _userError.Hide();

        if (Kind is SshLoginKind.Agent or SshLoginKind.Provider)
        {
            _secretError.Hide();
            return _hops.All(h => h.Validate());
        }
        if (Kind == SshLoginKind.KeyFile)
        {
            if (KeyPath.Length == 0)
            {
                _secretError.Show("Enter the path to a private key file.");
                _keyPath.Focus(FocusState.Programmatic);
                return false;
            }
            if (!File.Exists(KeyPath))
            {
                _secretError.Show("There is no file at that path.");
                _keyPath.Focus(FocusState.Programmatic);
                _keyPath.SelectAll();
                return false;
            }
        }
        else if (_password.Password.Length == 0)
        {
            _secretError.Show("Enter the password.");
            _password.Focus(FocusState.Programmatic);
            return false;
        }
        _secretError.Hide();
        return _hops.All(h => h.Validate());
    }

    /// <summary>Show why the attempt failed, so the user can correct it without retyping everything.</summary>
    public void ShowFailure(string message)
    {
        _secretError.Show(message);
        (Kind == SshLoginKind.KeyFile ? (Control)_passphrase : _password).Focus(FocusState.Programmatic);
    }

    /// <summary>Empty both secret controls. Called as soon as an attempt is finished, win or lose.</summary>
    public void ClearSecrets()
    {
        _password.Password = "";
        _passphrase.Password = "";
        foreach (var hop in _hops) hop.ClearSecrets();
    }
}

/// <summary>An unlocked credential provider offered by Connect; KeePass lists its entries, Vault takes a typed item.</summary>
public sealed record ProviderOption(string Id, string Title, string ItemPrompt, IReadOnlyList<ProviderItemDto> Entries);

/// <summary>
/// One jump host's login in the Connect dialog: by default the hop reuses the target's login, or it signs in
/// with its own password, key file or the SSH agent. Its secrets are cleared with the form's.
/// </summary>
internal sealed class HopLogin
{
    private static readonly string[] Choices = ["Same login as the target", "Password", "Key file", "SSH agent"];
    private readonly ComboBox _method = new() { ItemsSource = Choices, SelectedIndex = 0, HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly PasswordBox _password = new() { Header = "Password", Visibility = Visibility.Collapsed };
    private readonly TextBox _keyPath = new() { Header = "Private key file", IsSpellCheckEnabled = false, Visibility = Visibility.Collapsed };
    private readonly PasswordBox _passphrase = new() { Header = "Key passphrase (leave empty if the key is not encrypted)", Visibility = Visibility.Collapsed };
    private readonly FieldMessage _error = new();

    public string Key { get; }
    public StackPanel Element { get; }

    /// <summary>Null while the hop reuses the target's login.</summary>
    public SshLoginKind? Kind => _method.SelectedIndex switch
    {
        1 => SshLoginKind.Password,
        2 => SshLoginKind.KeyFile,
        3 => SshLoginKind.Agent,
        _ => null,
    };

    public JumpLoginInput Login => Kind switch
    {
        SshLoginKind.Password => new(SshLoginKind.Password, _password.Password, null),
        SshLoginKind.KeyFile => new(SshLoginKind.KeyFile, _passphrase.Password, _keyPath.Text.Trim()),
        _ => new(SshLoginKind.Agent, null, null),
    };

    public HopLogin(JumpHostDto hop, string keyPlaceholder)
    {
        Key = hop.Key;
        _method.Header = $"Jump host {hop.Username}@{hop.Key}";
        _keyPath.PlaceholderText = keyPlaceholder;
        Element = new StackPanel { Spacing = Ui.Double("Space8"), Children = { _method, _password, _keyPath, _passphrase, _error.Element } };
        _method.SelectionChanged += (_, _) =>
        {
            _password.Visibility = Kind == SshLoginKind.Password ? Visibility.Visible : Visibility.Collapsed;
            _keyPath.Visibility = _passphrase.Visibility = Kind == SshLoginKind.KeyFile ? Visibility.Visible : Visibility.Collapsed;
            _error.Hide();
        };
    }

    internal void UsePasswordForSnapshot() => _method.SelectedIndex = 1;

    public bool Validate()
    {
        var problem = Kind switch
        {
            SshLoginKind.Password when _password.Password.Length == 0 => ("Enter the jump host's password.", (Control)_password),
            SshLoginKind.KeyFile when !File.Exists(_keyPath.Text.Trim()) => ("There is no key file at that path.", _keyPath),
            _ => default((string, Control)?),
        };
        if (problem is not { } p) { _error.Hide(); return true; }
        _error.Show(p.Item1);
        p.Item2.Focus(FocusState.Programmatic);
        return false;
    }

    public void ClearSecrets()
    {
        _password.Password = "";
        _passphrase.Password = "";
    }
}

/// <summary>The second-factor prompt: one code field, not remembered anywhere.</summary>
public sealed class OneTimeCodeForm
{
    private readonly PasswordBox _code = new() { Header = "One-time code", PasswordRevealMode = PasswordRevealMode.Visible };
    private readonly FieldMessage _error = new();

    public StackPanel Body { get; }
    public Control FirstField => _code;
    public string Code => _code.Password.Trim();

    public OneTimeCodeForm(string target)
    {
        var lead = Ui.Text($"{target} asks for a second factor. Enter the code from your authenticator.", "BodyTextStyle");
        lead.TextWrapping = TextWrapping.Wrap;
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { lead, _code, _error.Element } };
        _code.PasswordChanged += (_, _) => _error.Hide();
    }

    public bool Validate()
    {
        if (Code.Length > 0) return true;
        _error.Show("Enter the code.");
        return false;
    }

    public void Clear() => _code.Password = "";
}

/// <summary>
/// The body of the host-key confirmation: what is unknown, the fingerprint on its own selectable line, and what
/// the user is expected to do about it. Trust is never offered as "connect anyway": the primary button confirms
/// a fingerprint the user is asked to compare against the server.
/// </summary>
public static class HostKeyPrompt
{
    /// <param name="testOnly">Test Connection (SEC-07): the same question, but the key is trusted for that
    /// one test and not remembered.</param>
    public static StackPanel Body(string target, string fingerprint, bool isJumpHost, bool certificate = false, bool testOnly = false)
    {
        var lead = Ui.Text(
            isJumpHost
                ? $"The jump host {target} has not been trusted before. Its key fingerprint is:"
                : certificate
                    ? $"{target} presents a certificate that has not been trusted before. Its SHA-256 fingerprint is:"
                    : $"{target} has not been trusted before. Its key fingerprint is:",
            "BodyTextStyle");
        lead.TextWrapping = TextWrapping.Wrap;

        var fp = new TextBox
        {
            Text = fingerprint,
            IsReadOnly = true,
            FontFamily = (Microsoft.UI.Xaml.Media.FontFamily)Application.Current.Resources["BastionFontFamily"],
            TextWrapping = TextWrapping.Wrap,
            IsSpellCheckEnabled = false,
            // Selectable and copyable, but out of the tab order: Enter in a focused text box submits the
            // modal, and trusting a host key should take a deliberate press of the button.
            IsTabStop = false,
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(fp, "Host key fingerprint");

        var tail = Ui.Text(
            (certificate
                ? "Compare it with the SHA-256 fingerprint of the server's certificate, read on the server itself, "
                : "Compare it with the fingerprint from the server itself (for example `ssh-keygen -lf` on its host key), ")
            + "not with anything this connection told you. "
            + (testOnly
                ? "Continue only if they match. This trusts the key for this test only: nothing is saved to known_hosts, and the first real connect asks again."
                : "Continue only if they match; the key is then remembered."),
            "BodySecondaryTextStyle");
        tail.TextWrapping = TextWrapping.Wrap;

        return new StackPanel { Spacing = Ui.Double("Space12"), Children = { lead, fp, tail } };
    }
}
