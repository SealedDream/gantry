using System.Text.Json.Nodes;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Save as Connection (plugin API 1.6 <c>library.propose</c>; Mac PluginSaveConnectionsSheet.swift). The core checked the
/// plugin's proposals; the user picks the folder (existing or new), the protocol and host per guest and an optional saved
/// credential, linked by id. Rows whose host and protocol are already in the folder show "Already in folder" and are left
/// out. The core checks every row again and saves normal connections; the plugin learns only how many.
/// </summary>
public sealed partial class MainWindow
{
    private static readonly string[] SaveProtocols = ["ssh", "rdp", "vnc"];

    private sealed class SaveRow
    {
        public required CheckBox Include { get; init; }
        public required TextBox Name { get; init; }
        public required ComboBox Protocol { get; init; }
        public required TextBox Host { get; init; }
        public required TextBlock Mark { get; init; }
        public string Proto => SaveProtocols[Math.Max(0, Protocol.SelectedIndex)];
    }

    private static string SaveRowsJson(IEnumerable<SaveRow> rows) =>
        new JsonArray(rows.Select(r => (JsonNode)new JsonObject { ["name"] = r.Name.Text.Trim(), ["host"] = r.Host.Text.Trim(), ["protocol"] = r.Proto }).ToArray()).ToJsonString();

    /// <summary>Every folder of the library, depth first, with its depth.</summary>
    private List<(FolderDto Folder, int Depth)> SaveFolders()
    {
        var list = new List<(FolderDto, int)>();
        void Walk(FolderDto f, int depth)
        {
            list.Add((f, depth));
            foreach (var c in f.Folders) Walk(c, depth + 1);
        }
        try { foreach (var f in _library.Tree().Folders) Walk(f, 0); }
        catch (BastionException) { }
        return list;
    }

    private async Task SaveFromPluginAsync(PluginViewModel model, PluginViewModel.LibraryRequest r)
    {
        AppLog.Info($"Plugin save: {r.Items.Count} proposal(s)");
        var folders = SaveFolders();
        var creds = CredentialChoices();
        var body = new StackPanel { Spacing = Ui.Double("Space8") };
        AutomationProperties.SetAutomationId(body, "plugin-save-sheet");
        body.Children.Add(Ui.Text($"{r.Plugin} · {r.EntryName}", "BodyTextStyle"));

        var folderPick = new ComboBox { Header = "Folder", MinWidth = 240 };
        folderPick.Items.Add("Top level");
        foreach (var (f, depth) in folders) folderPick.Items.Add(new string(' ', depth * 2) + f.Name);
        folderPick.SelectedIndex = 0;
        AutomationProperties.SetAutomationId(folderPick, "plugin-save-folder");
        var newFolder = new CheckBox { Content = "New folder" };
        AutomationProperties.SetAutomationId(newFolder, "plugin-save-new-folder");
        var newName = new TextBox { PlaceholderText = "Name", MinWidth = 160, Visibility = Visibility.Collapsed };
        AutomationProperties.SetAutomationId(newName, "plugin-save-new-folder-name");
        AutomationProperties.SetName(newName, "New folder name");
        var folderRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        folderRow.Children.Add(folderPick);
        newFolder.VerticalAlignment = VerticalAlignment.Bottom;
        newName.VerticalAlignment = VerticalAlignment.Bottom;
        folderRow.Children.Add(newFolder);
        folderRow.Children.Add(newName);
        body.Children.Add(folderRow);

        var credPick = new ComboBox { Header = "Credential", MinWidth = 240 };
        credPick.Items.Add(creds.Count == 0 ? "Ask when connecting" : "None (ask when connecting)");
        foreach (var c in creds) credPick.Items.Add(c.Name);
        credPick.SelectedIndex = 0;
        credPick.IsEnabled = creds.Count > 0;
        AutomationProperties.SetAutomationId(credPick, "plugin-save-credential");
        body.Children.Add(credPick);

        var grid = new Grid { ColumnSpacing = Ui.Double("Space8"), RowSpacing = Ui.Double("Space4") };
        foreach (var w in new[] { GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto })
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        var rows = new List<SaveRow>();
        for (var i = 0; i < r.Items.Count; i++)
        {
            var p = r.Items[i];
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var row = new SaveRow
            {
                Include = new CheckBox { IsChecked = true, MinWidth = 0 },
                Name = new TextBox { Text = p.Label, MinWidth = 120 },
                Protocol = new ComboBox { ItemsSource = new[] { "SSH", "RDP", "VNC" }, SelectedIndex = Math.Max(0, Array.IndexOf(SaveProtocols, p.Protocol)), MinWidth = 90 },
                Host = new TextBox { Text = p.Host ?? "", PlaceholderText = "Host or IP", MinWidth = 140, FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas") },
                Mark = Ui.Text(p.Reported ? "Reported" : p.Host is null ? "No address" : "", "CaptionTextStyle"),
            };
            AutomationProperties.SetName(row.Include, $"Include {p.Label}");
            AutomationProperties.SetName(row.Name, $"Name of {p.Label}");
            AutomationProperties.SetName(row.Protocol, $"Protocol of {p.Label}");
            AutomationProperties.SetName(row.Host, $"Host of {p.Label}");
            AutomationProperties.SetAutomationId(row.Include, $"plugin-save-include-{i}");
            AutomationProperties.SetAutomationId(row.Name, $"plugin-save-name-{i}");
            AutomationProperties.SetAutomationId(row.Protocol, $"plugin-save-protocol-{i}");
            AutomationProperties.SetAutomationId(row.Host, $"plugin-save-host-{i}");
            AutomationProperties.SetAutomationId(row.Mark, $"plugin-save-mark-{i}");
            row.Mark.VerticalAlignment = VerticalAlignment.Center;
            if (p.Reported) ToolTipService.SetToolTip(row.Mark, $"{r.EntryName} reported this address");
            FrameworkElement[] cells = [row.Include, row.Name, row.Protocol, row.Host, row.Mark];
            for (var c = 0; c < cells.Length; c++)
            {
                Grid.SetRow(cells[c], i);
                Grid.SetColumn(cells[c], c);
                grid.Children.Add(cells[c]);
            }
            rows.Add(row);
        }
        body.Children.Add(new ScrollViewer { Content = grid, MaxHeight = 320, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        var error = Ui.Text("", "CaptionTextStyle");
        error.TextWrapping = TextWrapping.Wrap;
        error.Foreground = Ui.Brush(RootGrid, "SystemFillColorCriticalBrush");
        AutomationProperties.SetAutomationId(error, "plugin-save-error");
        body.Children.Add(error);

        string? FolderId() => folderPick.SelectedIndex <= 0 ? null : folders[folderPick.SelectedIndex - 1].Folder.Id;
        bool[] dups = [];
        void Refresh()
        {
            newName.Visibility = newFolder.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            try
            {
                // A new folder is empty: only rows that repeat each other are duplicates.
                dups = PluginEntryClient.ProposeDuplicates(_library, newFolder.IsChecked == true ? Guid.NewGuid().ToString() : FolderId(), SaveRowsJson(rows)).ToArray();
            }
            catch (BastionException) { dups = []; }
            for (var i = 0; i < rows.Count; i++)
            {
                var dup = i < dups.Length && dups[i];
                rows[i].Include.IsEnabled = !dup;
                var p = r.Items[i];
                rows[i].Mark.Text = dup ? "Already in folder" : p.Reported && rows[i].Host.Text.Trim() == p.Host ? "Reported" : rows[i].Host.Text.Trim().Length == 0 ? "No address" : "";
            }
        }
        folderPick.SelectionChanged += (_, _) => Refresh();
        newFolder.Checked += (_, _) => Refresh();
        newFolder.Unchecked += (_, _) => Refresh();
        foreach (var row in rows)
        {
            row.Host.LostFocus += (_, _) => Refresh();
            row.Protocol.SelectionChanged += (_, _) => Refresh();
        }
        Refresh();

        // A row without an address is left out (its mark says so); it never blocks the others.
        List<SaveRow> Chosen() => rows.Where((row, i) => row.Include.IsChecked == true && row.Host.Text.Trim().Length > 0 && !(i < dups.Length && dups[i])).ToList();
        List<string>? saved = null;
        bool Validate()
        {
            Refresh();
            var chosen = Chosen();
            if (newFolder.IsChecked == true && newName.Text.Trim().Length == 0) { error.Text = "Name the new folder."; return false; }
            if (chosen.Count == 0) { saved = []; return true; }
            try
            {
                var cred = credPick.SelectedIndex <= 0 ? null : creds[credPick.SelectedIndex - 1].Id;
                saved = PluginEntryClient.ProposeSave(_library, FolderId(), newFolder.IsChecked == true ? newName.Text.Trim() : null, SaveRowsJson(chosen), cred);
                return true;
            }
            catch (BastionException ex) { error.Text = ex.Message; return false; }
        }
        var title = r.Items.Count == 1 ? "Save as Connection" : $"Save {r.Items.Count} Connections";
        var ok = await ShowModal(title, body, "Save", "Cancel", caption: "Nothing secret is copied from the plugin.", validate: Validate, wide: true);
        if (!ok || saved is null)
        {
            model.AnswerLibrary(r, null, false);
            return;
        }
        if (saved.Count > 0)
        {
            // Keep the user on the plugin tab: the new connections appear in the tree, the selection stays as it was.
            ReloadThenSave(CurrentSelectionId);
        }
        AppLog.Info($"Plugin save: saved {saved.Count}");
        model.AnswerLibrary(r, saved.Count, credPick.SelectedIndex > 0);
    }
}
