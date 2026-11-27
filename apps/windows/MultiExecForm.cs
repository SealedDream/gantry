using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// The plan of a multi-host run: which SSH connections, the command and how many at a time. Each host with a saved
/// credential signs in with it (core); the typed login shows only when a chosen host has none, and is used only for those.
/// The core reviews it again before anything connects; checks here only give early, field-level messages.
/// </summary>
internal sealed class MultiExecForm
{
    private const int DefaultConcurrency = 4;
    private const int MaxConcurrency = 16;
    private readonly List<(string Id, string Name, bool Saved, CheckBox Box)> _hosts = new();
    private readonly TextBox _command = new() { Header = "Command (one line)", PlaceholderText = "uptime", IsSpellCheckEnabled = false, FontFamily = new FontFamily("Consolas") };
    private readonly NumberBox _concurrency = new() { Header = "At a time", Minimum = 1, Maximum = MaxConcurrency, Value = DefaultConcurrency, SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Compact };
    private readonly TextBox _user = new() { Header = "User name (optional)", PlaceholderText = "Each connection's own", IsSpellCheckEnabled = false };
    private readonly RadioButtons _kind = new() { Header = "Sign in with", MaxColumns = 3, Items = { "Password", "SSH agent", "Key file" }, SelectedIndex = 0 };
    private readonly PasswordBox _password = new() { Header = "Password" };
    private readonly TextBox _keyPath = new() { Header = "Private key file", PlaceholderText = @"C:\Users\you\.ssh\id_ed25519", IsSpellCheckEnabled = false, Visibility = Visibility.Collapsed };
    private readonly TextBlock _savedNote = Ui.Text("Saved credentials", "BodySecondaryTextStyle");
    private readonly StackPanel _login = new() { Spacing = Ui.Double("Space12") };
    private readonly FieldMessage _hostsError = new(), _commandError = new(), _loginError = new();

    private readonly Button _saveAsTask = new() { Content = "Save as Task", IsEnabled = false };

    /// <summary>Saves a task; returns an error to show, or null when saved.</summary>
    public Func<TaskDto, string?>? SaveTask { get; set; }
    public StackPanel Body { get; }
    public Control FirstField => _command;
    public IReadOnlyList<string> HostIds => _hosts.Where(h => h.Box.IsChecked == true).Select(h => h.Id).ToList();
    /// <summary>Chosen hosts without a saved credential: only they use the typed login.</summary>
    private List<string> WithoutCredential => _hosts.Where(h => h.Box.IsChecked == true && !h.Saved).Select(h => h.Name).ToList();
    private bool NeedsLogin => WithoutCredential.Count > 0;
    public string Command => _command.Text.Trim();
    public int Concurrency => double.IsNaN(_concurrency.Value) ? DefaultConcurrency : (int)Math.Clamp(_concurrency.Value, 1, MaxConcurrency);
    public string? UserName => string.IsNullOrWhiteSpace(_user.Text) ? null : _user.Text.Trim();
    public SshLoginKind Kind => !NeedsLogin ? SshLoginKind.Agent : _kind.SelectedIndex switch { 1 => SshLoginKind.Agent, 2 => SshLoginKind.KeyFile, _ => SshLoginKind.Password };
    public string? Secret => Kind == SshLoginKind.Agent ? null : _password.Password;
    public string? KeyPath => Kind == SshLoginKind.KeyFile ? _keyPath.Text.Trim() : null;

    /// <param name="hosts">SSH connections to offer (<c>Saved</c>: has a saved credential); <paramref name="preselected"/> are ticked.</param>
    public MultiExecForm(IReadOnlyList<(string Id, string Name, string Detail, bool Saved)> hosts, ISet<string> preselected)
    {
        var list = new StackPanel();
        AutomationProperties.SetName(list, "Hosts");
        foreach (var (id, name, detail, saved) in hosts)
        {
            var box = new CheckBox { Content = $"{name}  ·  {detail}", IsChecked = preselected.Contains(id) };
            AutomationProperties.SetName(box, name);
            box.Checked += (_, _) => { _hostsError.Hide(); ApplyLogin(); };
            box.Unchecked += (_, _) => ApplyLogin();
            _hosts.Add((id, name, saved, box));
            list.Children.Add(box);
        }
        if (hosts.Count == 0) list.Children.Add(Ui.Text("No SSH connections in the library.", "BodySecondaryTextStyle"));
        var scroller = new ScrollViewer { Content = list, MaxHeight = 200 };
        var row = new Grid { ColumnSpacing = Ui.Double("Space8") };
        row.ColumnDefinitions.Add(new ColumnDefinition());
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });
        row.Children.Add(new StackPanel { Children = { _command, _commandError.Element } });
        Grid.SetColumn(_concurrency, 1);
        row.Children.Add(_concurrency);
        Body = new StackPanel
        {
            Spacing = Ui.Double("Space12"),
            Children =
            {
                Ui.Text("Hosts", "BodyStrongTextStyle"), scroller, _hostsError.Element, row, _saveAsTask,
                _savedNote, _login,
            },
        };
        foreach (var c in new UIElement[] { _user, _kind, _password, _keyPath, _loginError.Element }) _login.Children.Add(c);
        ToolTipService.SetToolTip(_savedNote, "Each chosen host signs in with its own saved credential.");
        ApplyLogin();
        _kind.SelectionChanged += (_, _) => ApplyKind();
        _command.TextChanged += (_, _) =>
        {
            _commandError.Hide();
            _saveAsTask.Content = "Save as Task";
            _saveAsTask.IsEnabled = Command.Length > 0;
        };
        AutomationProperties.SetName(_saveAsTask, "Save as Task");
        ToolTipService.SetToolTip(_saveAsTask, "Save this command as a task (runs over SSH).");
        _saveAsTask.Click += (_, _) =>
        {
            if (SaveTask is null || Command.Length == 0) return;
            if (SaveTask(AsTask()) is { } error) { _commandError.Show(error); return; }
            _saveAsTask.Content = "Saved";
            _saveAsTask.IsEnabled = false;
        };
        _password.PasswordChanged += (_, _) => _loginError.Hide();
        _keyPath.TextChanged += (_, _) => _loginError.Hide();
    }

    /// <summary>Show the typed login only when a chosen host has no saved credential; its tooltip names those hosts.</summary>
    private void ApplyLogin()
    {
        var without = WithoutCredential;
        var anyChosen = _hosts.Any(h => h.Box.IsChecked == true);
        _login.Visibility = without.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        _savedNote.Visibility = without.Count == 0 && anyChosen ? Visibility.Visible : Visibility.Collapsed;
        var help = "For hosts without a saved credential: " + string.Join(", ", without.Take(5)) + (without.Count > 5 ? $" and {without.Count - 5} more" : "");
        foreach (var c in new FrameworkElement[] { _user, _password })
        {
            ToolTipService.SetToolTip(c, without.Count > 0 ? help : null);
            AutomationProperties.SetHelpText(c, without.Count > 0 ? help : "");
        }
    }

    private void ApplyKind()
    {
        _password.Visibility = Kind == SshLoginKind.Agent ? Visibility.Collapsed : Visibility.Visible;
        _password.Header = Kind == SshLoginKind.KeyFile ? "Passphrase (if the key has one)" : "Password";
        _keyPath.Visibility = Kind == SshLoginKind.KeyFile ? Visibility.Visible : Visibility.Collapsed;
        _loginError.Hide();
    }

    public bool Validate()
    {
        var ok = true;
        if (HostIds.Count == 0) { _hostsError.Show("Choose at least one host."); ok = false; }
        if (Command.Length == 0) { _commandError.Show("Enter a command."); ok = false; }
        else if (_command.Text.Contains('\n') || _command.Text.Contains('\r')) { _commandError.Show("Use a single line."); ok = false; }
        if (NeedsLogin && Kind == SshLoginKind.KeyFile && string.IsNullOrEmpty(KeyPath)) { _loginError.Show("Choose the private key file."); ok = false; }
        return ok;
    }

    /// <summary>The command as a custom task run over SSH (<c>sh -c &lt;command&gt;</c>), as Mac Save as Task. <c>$</c> is
    /// doubled so the command stays as typed (task variables use <c>$Name$</c>).</summary>
    public TaskDto AsTask() =>
        new("", Command.Length > 60 ? Command[..60] : Command, false, false, "custom", "sh", ["-c", Command.Replace("$", "$$")], "ssh", 60);

    /// <summary>A refusal from the core review, shown under the command.</summary>
    public void ShowError(string message) => _commandError.Show(message);

    public void ClearSecrets() => _password.Password = "";

    /// <summary>Snapshot mode: fill the plan without typing.</summary>
    internal void FillForSnapshot(string command, string user, string password)
    {
        (_command.Text, _user.Text, _password.Password) = (command, user, password);
    }
}
