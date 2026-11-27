using System.Runtime.InteropServices.WindowsRuntime;
using System.Text.Json;
using Bastion.Shell.Interop;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;

namespace Bastion.Shell;

/// <summary>Defaults until RDP display properties exist in the core (as RdpDefaults in RdpConnect.swift).</summary>
public static class RdpDefaults
{
    public const ushort Width = 1280, Height = 800, Port = 3389;
}

/// <summary>
/// Server certificates the user accepted, <c>host:port</c> → SHA-256 hex, in <c>&lt;data dir&gt;/rdp_certificates.json</c>
/// (the same file and format as the macOS app). Trust on first use; a changed certificate is asked about again.
/// </summary>
/// FTPS keeps its own pins the same way in <c>ftps_certificates.json</c> (pass the file name).
public sealed class RdpCertificatePins(string dataDir, string fileName = "rdp_certificates.json")
{
    private readonly string _path = Path.Combine(dataDir, fileName);

    public Dictionary<string, string> Load()
    {
        try { return JsonSerializer.Deserialize(File.ReadAllText(_path), AotJson.Options.Info<Dictionary<string, string>>()) ?? new(); }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { return new(); }
    }

    public string? Pin(string key) => Load().TryGetValue(key, out var v) ? v : null;

    public void Save(string key, string fingerprint)
    {
        var all = Load();
        all[key] = fingerprint;
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, AotJson.Write<SortedDictionary<string, string>>(new(all), new JsonSerializerOptions { TypeInfoResolver = AotJson.Resolver, WriteIndented = true }));
        File.Move(tmp, _path, overwrite: true);
    }
}

/// <summary>User, optional domain and password for one RDP connect. The password lives only in the PasswordBox.</summary>
public sealed class RdpConnectForm
{
    private readonly TextBox _user = new() { Header = "User name", IsSpellCheckEnabled = false };
    private readonly TextBox _domain = new() { Header = "Domain (optional)", IsSpellCheckEnabled = false };
    private readonly PasswordBox _password = new() { Header = "Password" };
    private readonly FieldMessage _error = new();

    public StackPanel Body { get; }
    public Control FirstField => _user.Text.Trim().Length == 0 ? _user : _password;
    public string UserName => _user.Text.Trim();
    public string? Domain => _domain.Text.Trim() is { Length: > 0 } d ? d : null;
    public string Password => _password.Password;

    /// <summary>The login used last time, so Connect / Reconnect can go ahead with no sheet (owner points 23, 26).</summary>
    /// <summary>W23: the password in the form is a saved login's (not typed), so a successful connect does not save it again.
    /// Typing in the password box clears it.</summary>
    public bool FromSavedLogin
    {
        get => _savedPassword is not null && _password.Password == _savedPassword;
        set => _savedPassword = value ? _password.Password : null;
    }
    private string? _savedPassword;

    public void Prefill(string user, string? domain, string password)
    {
        _user.Text = user;
        _domain.Text = domain ?? "";
        _password.Password = password;
    }

    public bool IsComplete => UserName.Length > 0 && Password.Length > 0;

    private IReadOnlyList<LoginCandidateDto> _logins = [];
    private Func<int, (string User, string Password)?>? _release;
    /// <summary>An offered login that is selected but not read yet: its password leaves the core at Connect.</summary>
    private int _pending = -1;

    /// <summary>The saved login whose password is in the form (see <see cref="FromSavedLogin"/>), or null.</summary>
    public LoginCandidateDto? UsedSavedLogin => FromSavedLogin && _filled >= 0 && _filled < _logins.Count ? _logins[_filled] : null;
    private int _filled = -1;

    /// <summary>
    /// W23: the saved password logins the connection can use, best first, the first one selected. A login the core
    /// marks auto-use (the connection's own or inherited) fills the fields at once (<paramref name="release"/> reads
    /// its password through the core, audited). A1-NW-01: a login saved for another connection is selected and
    /// labelled only; its password is read when the user presses Connect. The Login picker is there for a choice and
    /// for a single offered login.
    /// </summary>
    public void OfferLogins(IReadOnlyList<LoginCandidateDto> logins, Func<int, (string User, string Password)?> release)
    {
        if (logins.Count == 0) return;
        _logins = logins;
        _release = release;
        if (LoginRule.ShowsPicker(logins))
        {
            var picker = new ComboBox { Header = "Login", HorizontalAlignment = HorizontalAlignment.Stretch };
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(picker, "LoginPicker");
            foreach (var login in logins) picker.Items.Add(login.Label);
            picker.SelectedIndex = 0;
            picker.SelectionChanged += (_, _) => { if (picker.SelectedIndex is >= 0 and var i && i < _logins.Count) Choose(i); };
            Body.Children.Insert(0, picker);
        }
        Choose(0);
    }

    private void Choose(int i)
    {
        _pending = -1;
        _filled = -1;
        _savedPassword = null;
        _password.PlaceholderText = "";
        if (_logins[i].AutoUse) { Fill(i); return; }
        var (domain, user) = SplitUser(_logins[i].Username);
        if (user.Length > 0) _user.Text = user;
        _domain.Text = domain;
        _password.Password = "";
        _password.PlaceholderText = "Saved password, used when you press Connect";
        _pending = i;
        _error.Hide();
    }

    /// <summary>Read the login's password through the core and put it in the fields; false when the core refuses.</summary>
    private bool Fill(int i)
    {
        _pending = -1;
        if (_release?.Invoke(i) is not { } login) return false;
        var (domain, user) = SplitUser(login.User);
        Prefill(user.Length > 0 ? user : _user.Text, domain, login.Password);
        FromSavedLogin = true;
        _filled = i;
        _password.PlaceholderText = "";
        return true;
    }

    private static (string Domain, string User) SplitUser(string name) => name.Split('\\', 2) is [var d, var u] ? (d, u) : ("", name);

    public RdpConnectForm(string? userName)
    {
        _user.Text = userName ?? "";
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { _user, _domain, _password, _error.Element } };
        _user.TextChanged += (_, _) => _error.Hide();
        _password.PasswordChanged += (_, _) => _error.Hide();
    }

    public bool Validate()
    {
        // The user pressed Connect with an offered login selected and nothing typed over it: read its password now.
        if (Password.Length == 0 && _pending >= 0 && !Fill(_pending))
        {
            _password.PlaceholderText = "";
            ShowFailure("The saved password could not be read. Enter the password.");
            return false;
        }
        if (UserName.Length == 0) { ShowFailure("Enter the user name to sign in as."); _user.Focus(FocusState.Programmatic); return false; }
        if (Password.Length == 0) { ShowFailure("Enter the password."); return false; }
        _error.Hide();
        return true;
    }

    public void ShowFailure(string message)
    {
        _error.Show(message);
        _password.Focus(FocusState.Programmatic);
    }

    public void ClearSecrets()
    {
        _password.Password = "";
        _password.PlaceholderText = "";
        _savedPassword = null;
        _pending = -1;
        _filled = -1;
    }
}

