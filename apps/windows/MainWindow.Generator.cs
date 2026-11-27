using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace Bastion.Shell;

// Password generator and "Send text with variables…" (C ABI 26). Generation and the strength estimate are the core's;
// substitution happens in the core, which knows only plain variables (name, host, port, user, folder, custom fields) and
// refuses secret ones such as $Password$, so a typed template can never paste a stored secret into a session.
public sealed partial class MainWindow
{
    private void PasswordGenerator_Click(object sender, RoutedEventArgs e) => _ = PasswordGeneratorAsync();

    private async Task PasswordGeneratorAsync()
    {
        var panel = new PasswordGeneratorPanel();
        if (!await ShowModal("Password Generator", panel.Body, primary: "Copy and Close", cancel: "Close", focus: panel.FirstField)) return;
        if (panel.Password.Length == 0) return;
        SecretClipboard.Copy(panel.Password, SecretClipboard.ConfiguredLifetime(SettingsPath));
    }

    private void SendWithVariables_Click(object sender, RoutedEventArgs e) => _ = SendWithVariablesAsync();

    private async Task SendWithVariablesAsync()
    {
        if (_active is not { ConnectionId: { } id, Panes: { } panes }) return;
        VariablesDto vars;
        try { vars = _library.Variables(id); }
        catch (BastionException ex) { await ShowModal("Could not read the variables", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }
        var text = new TextBox
        {
            Header = "Text", AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, IsSpellCheckEnabled = false, Height = 120,
            PlaceholderText = "ssh $Username$@$Host$", FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"),
        };
        var preview = Ui.Text("", "CaptionSecondaryTextStyle");
        preview.TextWrapping = TextWrapping.Wrap;
        AutomationProperties.SetName(preview, "Preview");
        string? result = null;
        void Update()
        {
            try { result = _library.Substitute(id, text.Text); preview.Text = result.Length == 0 ? "" : "Sends: " + result; }
            catch (BastionException ex) { result = null; preview.Text = ex.Message; }
        }
        text.TextChanged += (_, _) => Update();
        var list = string.Join("\n", vars.Plain.Select(v => $"${v.Name}$  {v.Value}"));
        var help = Ui.Text(list + (vars.Secret.Count > 0 ? $"\n\nNot available (secret): {string.Join(", ", vars.Secret.Select(s => $"${s}$"))}" : "")
            + "\n$$ is a literal $.", "CaptionSecondaryTextStyle");
        help.TextWrapping = TextWrapping.Wrap;
        help.IsTextSelectionEnabled = true;
        var body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { text, preview, new ScrollViewer { Content = help, MaxHeight = 160 } } };
        if (!await ShowModal("Send Text with Variables", body, primary: "Send", cancel: "Cancel", focus: text, wide: true,
                validate: () => { Update(); return result is { Length: > 0 }; })) return;
        if (result is { Length: > 0 } send) await panes.Focused.PasteText(send);
    }
}

/// <summary>Length, the generated password with the core's strength estimate, and Generate again.</summary>
internal sealed class PasswordGeneratorPanel
{
    private readonly NumberBox _length = new()
    {
        Header = "Length", Minimum = PasswordGenerator.MinLength, Maximum = PasswordGenerator.MaxLength,
        Value = PasswordGenerator.DefaultLength, SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Inline, SmallChange = 1,
    };
    private readonly TextBox _result = new() { Header = "Password", IsReadOnly = true, IsSpellCheckEnabled = false, FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas") };
    private readonly TextBlock _strength = Ui.Text("", "CaptionSecondaryTextStyle");

    public StackPanel Body { get; }
    public Control FirstField => _length;
    public string Password => _result.Text;

    public PasswordGeneratorPanel()
    {
        AutomationProperties.SetName(_length, "Length");
        AutomationProperties.SetName(_result, "Generated password");
        AutomationProperties.SetName(_strength, "Strength");
        var again = new Button { Content = "Generate" };
        AutomationProperties.SetName(again, "Generate");
        again.Click += (_, _) => Generate();
        _length.ValueChanged += (_, _) => Generate();
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { _length, _result, _strength, again } };
        Generate();
    }

    private void Generate()
    {
        if (double.IsNaN(_length.Value)) return;
        try
        {
            _result.Text = PasswordGenerator.Generate((int)_length.Value);
            _strength.Text = StrengthText(_result.Text);
        }
        catch (BastionException ex) { _result.Text = ""; _strength.Text = ex.Message; }
    }

    internal static string StrengthText(string password)
    {
        var bits = PasswordGenerator.StrengthBits(password);
        return $"Strength: {PasswordGenerator.StrengthLabel(bits)} (about {bits:0} bits)";
    }
}
