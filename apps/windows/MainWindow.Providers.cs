using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Kind = Bastion.Shell.ExternalProviders.Kind;

namespace Bastion.Shell;

/// <summary>
/// More options → Credential providers… (Native Mac's Credential Manager provider panes, Tauri's ProvidersSheet):
/// KeePass (.kdbx + master password and/or key file, its entries listed without secrets) and HashiCorp Vault (KV 1/2,
/// namespace, token). Unlock registers the provider so a connect can sign in with "Credential provider"; "Check an
/// item" proves an item resolves without the secret leaving the core. Unlocks run off the UI thread and the secret
/// boxes are emptied as soon as an attempt ends.
/// </summary>
public sealed partial class MainWindow
{
    private ExternalProviders? _providers;

    private ExternalProviders Providers => _providers ??= new ExternalProviders(SessionDataDir);

    /// <summary>The provider login last used per connection id this app session (references only, no secrets).</summary>
    private readonly Dictionary<string, string> _providerRefs = new();

    /// <summary>The unlocked providers Connect offers; none until one is unlocked here.</summary>
    private IReadOnlyList<ProviderOption> ProviderOptions()
    {
        if (_providers is null) return [];
        return new[] { Kind.KeePass, Kind.HcVault }
            .Where(_providers.IsReady)
            .Select(k => new ProviderOption(ExternalProviders.Id(k), ProviderTitle(k), ExternalProviders.ItemPrompt(k), k == Kind.KeePass ? _providers.KeePassItems : []))
            .ToList();
    }

    private void CredentialProviders_Click(object sender, RoutedEventArgs e) => _ = ShowProvidersAsync();

    private static T Named<T>(T element, string name) where T : DependencyObject
    {
        AutomationProperties.SetName(element, name);
        return element;
    }

    /// <summary>Sets a TextBlock's text and its UIA name together (the name does not follow later Text changes).</summary>
    private static void SetLiveText(TextBlock block, string text)
    {
        block.Text = text;
        AutomationProperties.SetName(block, text);
    }

    internal async Task ShowProvidersAsync()
    {
        if (_modal is not null) return;
        var p = Providers;
        var which = Named(new ComboBox { Header = "Provider", ItemsSource = new[] { ProviderTitle(Kind.KeePass), ProviderTitle(Kind.HcVault) }, SelectedIndex = 0, HorizontalAlignment = HorizontalAlignment.Stretch }, "Provider");
        var status = new TextBlock { Style = Ui.Style("BodyStrongTextStyle"), TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetAutomationId(status, "ProviderStatus");
        var message = new TextBlock { Style = Ui.Style("CaptionTextStyle"), TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetAutomationId(message, "ProviderMessage");
        AutomationProperties.SetLiveSetting(message, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);

        // KeePass
        var kpPath = Named(new TextBox { Header = "Database (.kdbx)", Text = p.Settings.KeePassPath, PlaceholderText = @"C:\Users\you\Passwords.kdbx", IsSpellCheckEnabled = false }, "KeePass database");
        var kpBrowse = Named(new Button { Content = "Choose…" }, "Choose KeePass database");
        var kpPassword = Named(new PasswordBox { Header = "Master password" }, "KeePass master password");
        var kpKeyFile = Named(new TextBox { Header = "Key file (optional)", IsSpellCheckEnabled = false }, "KeePass key file");
        var entries = Named(new ListView { SelectionMode = ListViewSelectionMode.Single, MaxHeight = Ui.Double("DialogWidth") / 4 }, "KeePass entries");
        var keepass = new StackPanel
        {
            Spacing = Ui.Double("Space8"),
            Children = { PathRow(kpPath, kpBrowse), kpPassword, kpKeyFile, entries },
        };

        // Vault
        var vUrl = Named(new TextBox { Header = "Server", Text = p.Settings.VaultUrl, PlaceholderText = "https://vault.example.com:8200", IsSpellCheckEnabled = false }, "Vault server");
        var vKv = Named(new ComboBox { Header = "KV version", ItemsSource = new[] { "2", "1" }, SelectedIndex = p.Settings.VaultKv == 1 ? 1 : 0 }, "KV version");
        var vNs = Named(new TextBox { Header = "Namespace (optional)", Text = p.Settings.VaultNamespace, IsSpellCheckEnabled = false }, "Vault namespace");
        var vToken = Named(new PasswordBox { Header = "Token" }, "Vault token");
        // KV version beside the namespace keeps the dialog short enough for a 640x480 window.
        var kvRow = new Grid { ColumnSpacing = Ui.Double("Space8") };
        kvRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        kvRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(vNs, 1);
        kvRow.Children.Add(vKv);
        kvRow.Children.Add(vNs);
        var vault = new StackPanel { Spacing = Ui.Double("Space8"), Children = { vUrl, kvRow, vToken }, Visibility = Visibility.Collapsed };

        var unlock = Named(new Button { Content = "Unlock", Style = Ui.Style("AccentButtonStyle") }, "Unlock provider");
        var lockButton = Named(new Button { Content = "Lock" }, "Lock provider");
        var item = Named(new TextBox { Header = "Check an item", IsSpellCheckEnabled = false }, "Item to check");
        var check = Named(new Button { Content = "Check" }, "Check item");
        var checkResult = new TextBlock { Style = Ui.Style("CaptionTextStyle"), TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetAutomationId(checkResult, "ProviderCheckResult");

        Kind Current() => which.SelectedIndex == 1 ? Kind.HcVault : Kind.KeePass;
        var busy = false;

        void Refresh()
        {
            var k = Current();
            keepass.Visibility = k == Kind.KeePass ? Visibility.Visible : Visibility.Collapsed;
            vault.Visibility = k == Kind.HcVault ? Visibility.Visible : Visibility.Collapsed;
            SetLiveText(status, $"{ProviderTitle(k)}: {p.StatusText(k)}");
            var ready = p.IsReady(k);
            unlock.Content = ready ? "Reconnect" : "Unlock";
            unlock.IsEnabled = which.IsEnabled = !busy;
            lockButton.IsEnabled = ready && !busy;
            item.IsEnabled = check.IsEnabled = ready && !busy;
            item.PlaceholderText = ExternalProviders.ItemPrompt(k);
            ToolTipService.SetToolTip(item, $"Connections sign in with {ExternalProviders.Id(k)}:{ExternalProviders.ItemPrompt(k)} (Connect → Credential provider).");
            entries.Items.Clear();
            foreach (var e in k == Kind.KeePass ? p.KeePassItems : [])
            {
                var group = e.Group.Count > 0 ? "  " + string.Join("/", e.Group) : "";
                var label = $"{e.Title} ({(e.Username is { Length: > 0 } u ? u : "no user")}){group}";
                entries.Items.Add(Named(new ListViewItem { Content = label, Tag = e.Id }, label));
            }
            entries.Visibility = entries.Items.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        void Say(string? text) => SetLiveText(message, text ?? "");

        which.SelectionChanged += (_, _) => { Say(null); SetLiveText(checkResult, ""); item.Text = ""; Refresh(); };
        entries.SelectionChanged += (_, _) => { if (entries.SelectedItem is ListViewItem { Tag: string id }) item.Text = id; };
        kpBrowse.Click += async (_, _) =>
        {
            var picker = new Windows.Storage.Pickers.FileOpenPicker();
            picker.FileTypeFilter.Add(".kdbx");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            if (await picker.PickSingleFileAsync() is { } file) kpPath.Text = file.Path;
        };
        unlock.Click += async (_, _) =>
        {
            var k = Current();
            var problem = ValidateProvider(k, kpPath.Text.Trim().Trim('"'), kpPassword.Password, kpKeyFile.Text.Trim().Trim('"'), vUrl.Text.Trim(), vToken.Password);
            if (problem is not null) { Say(problem); return; }
            // Copy everything out before leaving the UI thread.
            var location = new ExternalProviders.Config(kpPath.Text.Trim().Trim('"'), vUrl.Text.Trim().TrimEnd('/'), vKv.SelectedIndex == 1 ? 1 : 2, vNs.Text.Trim());
            var secret = k == Kind.KeePass ? kpPassword.Password : vToken.Password;
            var keyFile = k == Kind.KeePass && kpKeyFile.Text.Trim().Length > 0 ? kpKeyFile.Text.Trim().Trim('"') : null;
            busy = true;
            Say("Unlocking…");
            Refresh();
            string? error;
            try { error = await Task.Run(() => p.Open(k, location, secret.Length > 0 ? secret : null, keyFile)); }
            finally { busy = false; }
            kpPassword.Password = "";
            vToken.Password = "";
            Say(error ?? $"{ProviderTitle(k)} is unlocked. Gantry reads a secret only when a connection signs in.");
            Refresh();
        };
        lockButton.Click += (_, _) =>
        {
            p.Lock(Current());
            SetLiveText(checkResult, "");
            Say($"{ProviderTitle(Current())} is locked.");
            Refresh();
        };
        check.Click += async (_, _) =>
        {
            var k = Current();
            var what = item.Text.Trim();
            if (what.Length == 0) { SetLiveText(checkResult, "Enter an item to check."); return; }
            busy = true;
            SetLiveText(checkResult, "Checking…");
            Refresh();
            string result;
            try
            {
                result = await Task.Run(() => p.Check(k, what)) switch
                {
                    ProviderCheck.Ok => "Found. The secret stays in the core.",
                    ProviderCheck.NotFound => "No such item.",
                    _ => $"{ProviderTitle(k)} refused access.",
                };
            }
            catch (BastionException ex) { result = ex.Message; }
            finally { busy = false; }
            SetLiveText(checkResult, result);
            Refresh();
        };

        Refresh();
        var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { unlock, lockButton } };
        var checkRow = PathRow(item, check);
        var body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { which, status, keepass, vault, actions, message, checkRow, checkResult } };
        await ShowModal("Credential providers", body, primary: "Done", cancel: null, focus: which, wide: true,
            caption: "Read-only. Gantry keeps where they are, never the password or token.");
        kpPassword.Password = "";
        vToken.Password = "";
    }

    private static string ProviderTitle(Kind k) => ExternalProviders.Title(k);

    /// <summary>A text field with a button on its right, the field taking the rest of the width.</summary>
    private static Grid PathRow(TextBox field, Button button)
    {
        var row = new Grid { ColumnSpacing = Ui.Double("Space8") };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        button.VerticalAlignment = VerticalAlignment.Bottom;
        Grid.SetColumn(button, 1);
        row.Children.Add(field);
        row.Children.Add(button);
        return row;
    }

    /// <summary>What is missing before an unlock can run, or null.</summary>
    private static string? ValidateProvider(Kind k, string kdbx, string password, string keyFile, string url, string token)
    {
        if (k == Kind.KeePass)
        {
            if (kdbx.Length == 0) return "Choose the .kdbx database.";
            if (!File.Exists(kdbx)) return "There is no file at that database path.";
            if (password.Length == 0 && keyFile.Length == 0) return "Enter the master password or a key file.";
            if (keyFile.Length > 0 && !File.Exists(keyFile)) return "There is no file at that key file path.";
            return null;
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "https" && u.Scheme != "http")) return "Enter the Vault address, for example https://vault.example.com:8200.";
        if (u.Scheme == "http" && !u.IsLoopback) return "Use https:// (plain http is allowed only on this PC).";
        return token.Length == 0 ? "Enter the Vault token." : null;
    }
}
