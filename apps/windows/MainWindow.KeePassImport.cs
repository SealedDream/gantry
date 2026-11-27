using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// B8 (Native Mac #1136): Bastion menu › Import KeePass File… imports a .kdbx into the credential vault. The core decrypts
// the file in memory; the preview lists titles, usernames and target folders only, never a password. Steps: master
// password and/or key file → Preview (New / Duplicate / No password) → duplicate rule → Import → result. The master
// password lives in the PasswordBox until the dialog closes and goes to the core as bytes zeroed after each call.
public sealed partial class MainWindow
{
    private void ImportKeePass_Click(object sender, RoutedEventArgs e) => _ = ImportKeePassAsync();

    internal async Task ImportKeePassAsync()
    {
        if (_modal is not null) return;
        var path = TestHooks.KeePassPath ?? await PickFileAsync(".kdbx");
        if (path is null) return;
        if (_credentials is null)
        {
            if (!await ConfirmVaultOpenAsync()) return;
            UnlockLocalVault();
            if (_vaultError is { } why) { await ShowModal("Could not unlock the vault", CodedErrorText("APP", why), primary: "OK", cancel: null); return; }
        }
        var vault = OpenCredentials();
        var name = Path.GetFileName(path);

        var password = new PasswordBox { Header = "Master password" };
        AutomationProperties.SetName(password, "KeePass master password");
        string? keyFile = null;
        var keyLabel = Ui.Text("None", "BodyTextBlockStyle");
        keyLabel.TextTrimming = TextTrimming.CharacterEllipsis;
        var chooseKey = new Button { Content = "Choose…" };
        AutomationProperties.SetName(chooseKey, "Choose key file");
        chooseKey.Click += async (_, _) =>
        {
            if (await PickFileAsync("*") is { } k) { keyFile = k; keyLabel.Text = Path.GetFileName(k); }
        };
        var keyRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { Ui.Text("Key file", "BodyStrongTextBlockStyle"), keyLabel, chooseKey } };
        var error = Ui.Text("", "CaptionTextStyle");
        bool ValidateKey()
        {
            if (password.Password.Length > 0 || keyFile is not null) return true;
            error.Text = "Enter the master password or choose a key file.";
            return false;
        }
        var keyForm = new StackPanel { Spacing = Ui.Double("Space8"), Children = { password, keyRow, error } };
        IReadOnlyList<KeePassImportRow>? rows = null;
        while (rows is null)
        {
            if (!await ShowModal("Import " + name, keyForm, primary: "Preview", cancel: "Cancel", validate: ValidateKey, focus: password)) { password.Password = ""; return; }
            var (pw, key) = (password.Password, keyFile);
            try { rows = await Task.Run(() => vault.KeePassPreview(path, pw, key)); }
            catch (BastionException ex) { error.Text = Capitalised(ex.Message); }
        }

        var rule = await KeePassPreviewAsync(name, rows);
        if (rule is null) { password.Password = ""; return; }
        KeePassImportResult result;
        try
        {
            var (pw, key) = (password.Password, keyFile);
            result = await Task.Run(() => vault.KeePassImport(path, pw, key, rule));
        }
        catch (BastionException ex)
        {
            await ShowModal("Could not import " + name, ErrorText(Capitalised(ex.Message)), primary: "OK", cancel: null);
            return;
        }
        finally { password.Password = ""; }
        ApplyFilter(keepSelection: true);
        var summary = KeePassSummary(result, Path.GetFileNameWithoutExtension(path));
        Announce(summary);
        await ShowModal("Import " + name, ErrorText(summary), primary: "Done", cancel: null);
    }

    /// <summary>The preview list and the duplicate rule; returns the rule (skip, replace, keep-both) or null on Cancel.</summary>
    private async Task<string?> KeePassPreviewAsync(string name, IReadOnlyList<KeePassImportRow> rows)
    {
        int Count(string s) => rows.Count(r => r.Status == s);
        var (fresh, dup, none) = (Count("new"), Count("duplicate"), Count("no-password"));
        var list = new StackPanel { Spacing = Ui.Double("Space4") };
        foreach (var r in rows) list.Children.Add(KeePassPreviewRow(r));
        var scroller = new ScrollViewer { Content = list, MaxHeight = 280 };
        var choice = new RadioButtons { Header = "Already in the vault", SelectedIndex = 0, IsEnabled = dup > 0 };
        foreach (var label in new[] { "Skip", "Replace", "Keep both" }) choice.Items.Add(label);
        AutomationProperties.SetName(choice, "Already in the vault");
        ToolTipService.SetToolTip(choice, "Skip keeps the saved credential. Replace overwrites its username and password. Keep both adds a second one.");
        var body = new StackPanel
        {
            Spacing = Ui.Double("Space8"),
            Children = { Ui.Text($"{fresh} new, {dup} already in the vault, {none} without a password", "CaptionTextStyle"), scroller, choice },
        };
        bool CanImport() => fresh + dup > 0;
        if (!await ShowModal("Import " + name, body, primary: "Import", cancel: "Cancel", validate: CanImport, wide: true)) return null;
        return CredentialStore.KeePassDuplicateRules[Math.Max(0, choice.SelectedIndex)];
    }

    /// <summary>One preview line: title, then username · folder; the status on the right. No secret is shown.</summary>
    private static Grid KeePassPreviewRow(KeePassImportRow r)
    {
        var detail = string.Join(" · ", new[] { r.Username, r.Folder }.Where(s => s.Length > 0));
        var title = Ui.Text(r.Title, "BodyTextBlockStyle");
        var sub = Ui.Text(detail, "CaptionTextStyle");
        foreach (var t in new[] { title, sub }) { t.TextTrimming = TextTrimming.CharacterEllipsis; t.TextWrapping = TextWrapping.NoWrap; }
        var status = Ui.Text(KeePassStatusLabel(r.Status), "CaptionTextStyle");
        var row = new Grid { ColumnSpacing = 8, ColumnDefinitions = { new ColumnDefinition(), new ColumnDefinition { Width = GridLength.Auto } } };
        Grid.SetColumn(status, 1);
        row.Children.Add(new StackPanel { Children = { title, sub } });
        row.Children.Add(status);
        AutomationProperties.SetName(row, $"{r.Title}, {KeePassStatusLabel(r.Status)}");
        return row;
    }

    internal static string KeePassStatusLabel(string status) => status switch
    {
        "new" => "New",
        "duplicate" => "Duplicate",
        _ => "No password",
    };

    /// <summary>The Mac result line, word for word.</summary>
    internal static string KeePassSummary(KeePassImportResult r, string fileStem)
    {
        var parts = new List<string> { $"Added {r.Added}" };
        if (r.Replaced > 0) parts.Add($"replaced {r.Replaced}");
        if (r.SkippedDuplicates > 0) parts.Add($"skipped {r.SkippedDuplicates} already saved");
        if (r.SkippedNoPassword > 0) parts.Add($"left out {r.SkippedNoPassword} without a password");
        return string.Join(", ", parts) + $". They are in Credentials › “KeePass {fileStem}”.";
    }

    /// <summary>A file picker for this window; null on Cancel.</summary>
    private async Task<string?> PickFileAsync(params string[] types)
    {
        var picker = new Windows.Storage.Pickers.FileOpenPicker();
        foreach (var t in types) picker.FileTypeFilter.Add(t);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        return (await picker.PickSingleFileAsync())?.Path;
    }
}
