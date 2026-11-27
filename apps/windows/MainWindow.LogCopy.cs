using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>Terminal tab menu → Save Selection as Log… / Save Selection as Snippet… (core log export and snippets).</summary>
public sealed partial class MainWindow
{
    /// <summary>Folder for saved log selections, beside the library (owner-only files, written by the core).</summary>
    private string LogsDir => Path.Combine(SessionDataDir, "Logs");

    private static string? SelectionOf(WorkspaceTab tab) =>
        (tab.Panes?.Focused ?? tab.View) is { } view && !view.Session.IsDisposed ? view.Session.SelectionText() : null;

    /// <summary>Adds the two entries to a terminal tab's menu; they are disabled while nothing is selected.</summary>
    private void AddLogCopyItems(MenuFlyout menu, WorkspaceTab tab)
    {
        if (tab.View is null) return;
        var log = new MenuFlyoutItem { Text = "Save Selection as Log…" };
        var snippet = new MenuFlyoutItem { Text = "Save Selection as Snippet…" };
        // The text is taken when the menu opens: the selection the user saw is what gets saved.
        string? selection = null;
        log.Click += (_, _) => { if (selection is { Length: > 0 } text) _ = SaveSelectionAsLogAsync(tab, text); };
        snippet.Click += (_, _) => { if (selection is { Length: > 0 } text) _ = SaveSelectionAsSnippetAsync(text); };
        menu.Opening += (_, _) =>
        {
            selection = SelectionOf(tab);
            log.IsEnabled = snippet.IsEnabled = !string.IsNullOrEmpty(selection);
        };
        menu.Items.Add(new MenuFlyoutSeparator());
        menu.Items.Add(log);
        menu.Items.Add(snippet);
    }

    private async Task SaveSelectionAsLogAsync(WorkspaceTab tab, string text)
    {
        var header = $"{tab.Title} — {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
        try
        {
            Directory.CreateDirectory(LogsDir);
            var path = LogExport.SaveLog(LogsDir, SafeFileName(tab.Title), header, text);
            await ShowModal("Log saved", Ui.Text(Path.GetFileName(path), "BodyStrongTextStyle"), primary: "OK", cancel: null, caption: path);
        }
        catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException) { await ShowModal("Could not save the log", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
    }

    private async Task SaveSelectionAsSnippetAsync(string text)
    {
        var name = new TextBox { Header = "Name", Text = FirstLine(text) };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(name, "Snippet name");
        var error = Ui.Text("", "CaptionTextStyle");
        var body = new StackPanel { Spacing = 8, Children = { name, error } };
        bool Validate()
        {
            if (string.IsNullOrWhiteSpace(name.Text)) { error.Text = "Enter a name."; return false; }
            try { LogExport.SaveSnippet(SessionDataDir, name.Text.Trim(), text); return true; }
            catch (BastionException ex) { error.Text = ex.Message; return false; }
        }
        await ShowModal("Save as Snippet", body, primary: "Save", cancel: "Cancel", validate: Validate, focus: name);
    }

    private const int SnippetNameMax = 40;

    private static string FirstLine(string text)
    {
        var line = text.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? "";
        return line.Length > SnippetNameMax ? line[..SnippetNameMax] : line;
    }

    private static string SafeFileName(string title)
    {
        var bad = Path.GetInvalidFileNameChars();
        var clean = new string(title.Select(c => bad.Contains(c) ? '-' : c).ToArray()).Trim();
        return clean.Length == 0 ? "terminal" : clean;
    }
}
