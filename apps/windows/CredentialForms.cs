using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// The Credentials dialog body: every credential in the vault (name, kind, user name; never the secret) with a
/// Remove button each, and Add password / Add SSH key underneath. The buttons hand control back to the window,
/// which opens the next dialog in place of this one.
/// </summary>
internal sealed class CredentialListBody
{
    public StackPanel Body { get; }
    public Control FirstButton { get; }

    public CredentialListBody(IReadOnlyList<CredentialDto> credentials, Action addPassword, Action addKey, Action<CredentialDto> edit, Action<CredentialDto> remove)
    {
        Body = new StackPanel { Spacing = Ui.Double("Space12") };
        var intro = Ui.Text("Saved in this PC's credential vault, encrypted with a key only your Windows account can unlock. Secrets can be replaced or removed, never shown.", "BodySecondaryTextStyle");
        intro.TextWrapping = TextWrapping.Wrap;
        Body.Children.Add(intro);

        if (credentials.Count == 0)
        {
            Body.Children.Add(Ui.Text("No credentials yet.", "BodyTextStyle"));
        }
        else
        {
            var rows = new List<UIElement>();
            foreach (var c in credentials)
            {
                var row = new Grid { ColumnSpacing = Ui.Double("Space12") };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                text.Children.Add(Ui.Text(c.Name, "BodyTextStyle"));
                var detail = $"{c.KindLabel} · {c.Username}" + (c.Folder is { Length: > 0 } f ? $" · {f}" : "");
                text.Children.Add(Ui.Text(detail, "BodySecondaryTextStyle"));
                var change = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.IconLabel(Ui.Icon("GlyphEdit"), "Edit") };
                AutomationProperties.SetName(change, "Edit " + c.Name);
                change.Click += (_, _) => edit(c);
                var del = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.IconLabel(Ui.Icon("GlyphDelete"), "Remove") };
                AutomationProperties.SetName(del, "Remove " + c.Name);
                del.Click += (_, _) => remove(c);
                var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space4"), Children = { change, del } };
                Grid.SetColumn(actions, 1);
                row.Children.Add(text);
                row.Children.Add(actions);
                rows.Add(row);
            }
            var group = GroupedRows.Group(rows);
            AutomationProperties.SetName(group, "Credentials");
            Body.Children.Add(new ScrollViewer { Content = group, MaxHeight = 280, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        }

        var addPw = new Button { Content = Ui.IconLabel(Ui.Icon("GlyphAdd"), "Add password") };
        var addK = new Button { Content = Ui.IconLabel(Ui.Icon("GlyphAdd"), "Add SSH key") };
        AutomationProperties.SetName(addPw, "Add password");
        AutomationProperties.SetName(addK, "Add SSH key");
        addPw.Click += (_, _) => addPassword();
        addK.Click += (_, _) => addKey();
        Body.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { addPw, addK } });
        FirstButton = addPw;
    }
}

/// <summary>
/// Add or edit a password or SSH key credential. The secret fields are write-only: the form never fills them in, and
/// when editing an empty secret keeps the stored one, so renaming never needs the secret again. An SSH key can be
/// pasted or imported from a file; the file is read and decrypted by the core, so its text never passes through here.
/// </summary>
internal sealed class NewCredentialForm
{
    private readonly TextBox _name = new() { Header = "Name", PlaceholderText = "db admin", IsSpellCheckEnabled = false };
    private readonly TextBox _user = new() { Header = "User name", IsSpellCheckEnabled = false };
    private readonly TextBox _folder = new() { Header = "Folder (optional)", IsSpellCheckEnabled = false };
    private readonly PasswordBox _password = new() { Header = "Password" };
    private readonly TextBox _key = new()
    {
        Header = "Private key (OpenSSH or PEM, no passphrase)", AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap,
        IsSpellCheckEnabled = false, Height = 140, FontFamily = new FontFamily("Consolas"),
        PlaceholderText = "-----BEGIN OPENSSH PRIVATE KEY-----",
    };
    private readonly PasswordBox _passphrase = new() { Header = "Key passphrase (if it has one)", Visibility = Visibility.Collapsed };
    private readonly TextBlock _fileLabel = Ui.Text("", "BodySecondaryTextStyle");
    private readonly FieldMessage _nameError = new(), _userError = new(), _secretError = new();
    private readonly bool _isEdit;

    public bool IsSshKey { get; }
    public string? ExistingId { get; }
    public StackPanel Body { get; }
    public Control FirstField => _name;
    public string CredentialName => _name.Text.Trim();
    public string UserName => _user.Text.Trim();
    public string? Folder => string.IsNullOrWhiteSpace(_folder.Text) ? null : _folder.Text.Trim();
    public string Secret => IsSshKey ? _key.Text.Replace("\r\n", "\n").Replace('\r', '\n') : _password.Password;
    /// <summary>The key file to import instead of the pasted key, or null.</summary>
    public string? KeyFile { get; private set; }
    public string Passphrase => _passphrase.Password;

    /// <param name="existing">The credential being edited (its kind decides the form), or null to add one.</param>
    /// <param name="pickKeyFile">Opens the window's file picker; null hides the import button.</param>
    public NewCredentialForm(bool sshKey, CredentialDto? existing = null, Func<Task<string?>>? pickKeyFile = null)
    {
        IsSshKey = existing is null ? sshKey : existing.Kind == "ssh-key";
        ExistingId = existing?.Id;
        _isEdit = existing is not null;
        if (existing is not null)
        {
            _name.Text = existing.Name;
            _user.Text = existing.Username;
            _folder.Text = existing.Folder ?? "";
            _password.Header = "New password (leave empty to keep the saved one)";
            _key.Header = "New private key (leave empty to keep the saved one)";
        }
        AutomationProperties.SetName(_key, "Private key");
        AutomationProperties.SetName(_passphrase, "Key passphrase");
        Body = new StackPanel { Spacing = Ui.Double("Space12") };
        var nameRow = new StackPanel { Children = { _name, _nameError.Element } };
        var userRow = new StackPanel { Children = { _user, _userError.Element } };
        var secretBox = new StackPanel { Spacing = Ui.Double("Space8"), Children = { (Control)(IsSshKey ? _key : _password) } };
        if (IsSshKey && pickKeyFile is not null)
        {
            var import = new Button { Content = Ui.IconLabel(Ui.Icon("GlyphOpenFile"), "Import key file…") };
            AutomationProperties.SetName(import, "Import key file");
            import.Click += async (_, _) =>
            {
                if (await pickKeyFile() is { } path) UseKeyFile(path);
            };
            _fileLabel.TextWrapping = TextWrapping.Wrap;
            secretBox.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space12"), Children = { import, _fileLabel } });
            secretBox.Children.Add(_passphrase);
        }
        if (!IsSshKey)
        {
            var generate = new Button { Content = "Generate…" };
            AutomationProperties.SetName(generate, "Generate password");
            var strength = Ui.Text("", "CaptionSecondaryTextStyle");
            generate.Click += (_, _) =>
            {
                try { _password.Password = PasswordGenerator.Generate(PasswordGenerator.DefaultLength); strength.Text = PasswordGeneratorPanel.StrengthText(_password.Password); }
                catch (BastionException ex) { _secretError.Show(ex.Message); }
            };
            _password.PasswordChanged += (_, _) => strength.Text = _password.Password.Length == 0 ? "" : PasswordGeneratorPanel.StrengthText(_password.Password);
            secretBox.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space12"), Children = { generate, strength } });
        }
        secretBox.Children.Add(_secretError.Element);
        // Grouped form, as on the Mac: one surface, a row per field.
        Body.Children.Add(GroupedRows.Group(nameRow, userRow, secretBox, _folder));
        _name.TextChanged += (_, _) => _nameError.Hide();
        _user.TextChanged += (_, _) => _userError.Hide();
        _password.PasswordChanged += (_, _) => _secretError.Hide();
        _passphrase.PasswordChanged += (_, _) => _secretError.Hide();
        _key.TextChanged += (_, _) => _secretError.Hide();
    }

    /// <summary>Import <paramref name="path"/> instead of a pasted key; the pasted text is cleared.</summary>
    public void UseKeyFile(string path)
    {
        KeyFile = path;
        _key.Text = "";
        _key.IsEnabled = false;
        _fileLabel.Text = System.IO.Path.GetFileName(path);
        _passphrase.Visibility = Visibility.Visible;
        _secretError.Hide();
    }

    /// <summary>Show a core error (a wrong passphrase, a file that is not a key) under the secret field.</summary>
    public void ShowSecretError(string message)
    {
        _secretError.Show(message);
        ((Control)(KeyFile is not null ? _passphrase : IsSshKey ? _key : _password)).Focus(FocusState.Programmatic);
    }

    /// <summary>Clear the secret fields once the core has them.</summary>
    public void ClearSecret()
    {
        _password.Password = "";
        _key.Text = "";
        _passphrase.Password = "";
    }

    public bool Validate()
    {
        var nameOk = CredentialName.Length > 0;
        var userOk = UserName.Length > 0;
        string? secret = null;
        if (KeyFile is not null) secret = null; // the core reads and checks the file
        else if (IsSshKey && _key.Text.Trim().Length == 0 && !_isEdit) secret = "Paste the private key or import a key file.";
        else if (IsSshKey && _key.Text.Contains("ENCRYPTED")) secret = "This key has a passphrase. Import it as a key file instead and enter the passphrase.";
        else if (!IsSshKey && _password.Password.Length == 0 && !_isEdit) secret = "Enter the password.";
        if (nameOk) _nameError.Hide(); else _nameError.Show("Enter a name.");
        if (userOk) _userError.Hide(); else _userError.Show("Enter the user name.");
        if (secret is null) _secretError.Hide(); else _secretError.Show(secret);
        if (!nameOk) _name.Focus(FocusState.Programmatic);
        else if (!userOk) _user.Focus(FocusState.Programmatic);
        else if (secret is not null) ((Control)(IsSshKey ? _key : _password)).Focus(FocusState.Programmatic);
        return nameOk && userOk && secret is null;
    }
}

/// <summary>Pick the vault credential a connection logs in with, or none.</summary>
internal sealed class AssignCredentialForm
{
    private readonly IReadOnlyList<CredentialDto> _credentials;
    private readonly ComboBox _choice;

    public StackPanel Body { get; }
    public Control Field => _choice;
    /// <summary>The chosen credential id, or null for none.</summary>
    public string? CredentialId => _choice.SelectedIndex <= 0 ? null : _credentials[_choice.SelectedIndex - 1].Id;

    public AssignCredentialForm(IReadOnlyList<CredentialDto> credentials, string? currentId)
    {
        _credentials = credentials;
        var labels = new List<string> { "None" };
        labels.AddRange(credentials.Select(c => $"{c.Name} ({c.KindLabel}, {c.Username})"));
        _choice = new ComboBox { Header = "Credential", ItemsSource = labels, HorizontalAlignment = HorizontalAlignment.Stretch };
        var at = credentials.ToList().FindIndex(c => c.Id == currentId);
        _choice.SelectedIndex = at + 1; // -1 → 0 = None
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { _choice } };
        if (credentials.Count == 0)
        {
            var hint = Ui.Text("The vault is empty. Add a credential under More → Credentials first.", "BodySecondaryTextStyle");
            hint.TextWrapping = TextWrapping.Wrap;
            Body.Children.Add(hint);
        }
    }
}
