using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Terminal tab menu → Start or Stop Session Log and Snippets… (as Native Mac's Session menu). Logging goes through the
/// core (C ABI 58; a saved connection's log is planned by the core, C ABI 138, MainWindow.SessionLog.cs); snippets use the shared core
/// store (C ABI 64), which refuses secrets and asks for a confirmation before a multi-line send.
/// </summary>
public sealed partial class MainWindow
{
    private string SessionLogsDir => Path.Combine(SessionDataDir, "session-logs");

    private SnippetStore? _snippets;
    private SnippetStore Snippets => _snippets ??= new SnippetStore(SessionDataDir);

    private static TerminalView? PaneOf(WorkspaceTab tab) => tab.Panes?.Focused ?? tab.View;

    private void AddSessionToolItems(MenuFlyout menu, WorkspaceTab tab)
    {
        if (tab.View is null) return;
        var log = new MenuFlyoutItem { Text = "Start Session Log" };
        var snippets = new MenuFlyoutItem { Text = "Snippets…" };
        AutomationProperties.SetName(snippets, "Snippets");
        log.Click += (_, _) => _ = ToggleSessionLogAsync(tab);
        snippets.Click += (_, _) => _ = ShowSnippetsAsync(tab);
        menu.Opening += (_, _) =>
        {
            var view = PaneOf(tab);
            var alive = view is not null && !view.Session.IsDisposed;
            log.Text = alive && view!.Session.IsLogging ? "Stop Session Log" : "Start Session Log";
            AutomationProperties.SetName(log, log.Text);
            log.IsEnabled = snippets.IsEnabled = alive;
        };
        menu.Items.Add(log);
        menu.Items.Add(snippets);
    }

    private async Task ToggleSessionLogAsync(WorkspaceTab tab)
    {
        if (PaneOf(tab) is not { } view || view.Session.IsDisposed) return;
        if (view.Session.IsLogging)
        {
            try { view.Session.FinishLog("stopped by user"); }
            catch (BastionException ex) { AppLog.Warn("Session log footer not written: " + ex.Message); }
            if (ReferenceEquals(view, tab.View)) { _loggedTabs.Remove(tab); tab.Bar?.SetLog(null); }
            await ShowModal("Session log stopped", Ui.Text($"{tab.Title} is no longer logged.", "BodyTextBlockStyle"), primary: "OK", cancel: null);
            return;
        }
        try
        {
            var path = StartTabLog(tab, view);
            if (ReferenceEquals(view, tab.View)) tab.Bar?.SetLog(path);
            await ShowModal("Session log started", Ui.Text(Path.GetFileName(path), "BodyStrongTextStyle"), primary: "OK", cancel: null, caption: path);
        }
        catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException)
        {
            await ShowModal("Could not start the session log", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
        }
    }

    /// <summary>
    /// LOG-01: start the log on a saved connection's tab when its "Log session output" property is on (folder
    /// inheritance included), on open and after a reconnect swaps in a new session (each session gets a new file).
    /// No dialog: the session bar shows "Logging" with the path. A failure never stops the connection; it shows one
    /// message on the bar and is announced once.
    /// </summary>
    private void AutoStartSessionLog(WorkspaceTab tab)
    {
        if (tab.ConnectionId is not { } id || tab.View is not { } view || view.Session.IsDisposed || view.Session.IsLogging) return;
        try
        {
            if (!_library.SessionLog(id)) { tab.Bar?.SetLog(null); return; }
            tab.Bar?.SetLog(StartTabLog(tab, view));
        }
        catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException)
        {
            var problem = "Session logging did not start: " + ex.Message;
            tab.Bar?.SetLog(null, problem);
            Announce(problem);
        }
    }

    private async Task ShowSnippetsAsync(WorkspaceTab tab)
    {
        var list = new ListView { SelectionMode = ListViewSelectionMode.Single, MaxHeight = Ui.Double("DialogWidth") / 2 };
        AutomationProperties.SetName(list, "Snippet list");
        var error = Ui.Text("", "CaptionTextStyle");
        var filterText = "";
        void Reload()
        {
            list.Items.Clear();
            try
            {
                foreach (var s in Snippets.Search().Where(s => FilterMatches(filterText, s.Name, s.Text)))
                {
                    var item = new ListViewItem { Content = s.Name, Tag = s };
                    AutomationProperties.SetName(item, s.Name);
                    list.Items.Add(item);
                }
                error.Text = list.Items.Count == 0 ? "No snippets yet. Add one, or save a terminal selection as a snippet." : "";
            }
            catch (BastionException ex) { error.Text = ex.Message; }
            if (list.Items.Count > 0) list.SelectedIndex = 0;
        }
        var name = new TextBox { Header = "Name" };
        AutomationProperties.SetName(name, "New snippet name");
        var text = new TextBox { Header = "Command", AcceptsReturn = true, TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetName(text, "New snippet command");
        var add = new Button { Content = "Add" }.Quiet("GlyphAdd", "Add snippet");
        AutomationProperties.SetName(add, "Add snippet");
        var delete = new Button { Content = "Delete" }.Quiet("GlyphDelete", "Delete snippet");
        AutomationProperties.SetName(delete, "Delete snippet");
        add.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(name.Text) || string.IsNullOrEmpty(text.Text)) { error.Text = "Enter a name and a command."; return; }
            try { Snippets.Put(name.Text.Trim(), NormalizeNewlines(text.Text)); name.Text = text.Text = ""; Reload(); }
            catch (BastionException ex) { error.Text = ex.Message; }
        };
        delete.Click += (_, _) =>
        {
            if (list.SelectedItem is not ListViewItem { Tag: SnippetDto s }) return;
            try { Snippets.Remove(s.Id); Reload(); }
            catch (BastionException ex) { error.Text = ex.Message; }
        };
        Reload();
        var filter = ListFilterBox("", "Name or command", f => { filterText = f; Reload(); }); // TABBAR-WIN
        var body = new StackPanel
        {
            Spacing = Ui.Double("Space8"),
            Children = { filter, list, error, name, text, new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { add, delete } } },
        };
        bool Validate()
        {
            if (list.SelectedItem is ListViewItem { Tag: SnippetDto }) return true;
            error.Text = "Choose a snippet to send.";
            return false;
        }
        if (!await ShowModal("Snippets", body, primary: "Send", cancel: "Close", validate: Validate, focus: list, wide: true)) return;
        if (list.SelectedItem is not ListViewItem { Tag: SnippetDto chosen }) return;
        await SendSnippetAsync(tab, chosen);
    }

    private async Task SendSnippetAsync(WorkspaceTab tab, SnippetDto snippet)
    {
        if (PaneOf(tab) is not { } view || view.Session.IsDisposed) return;
        var targets = new[] { view.Session };
        try
        {
            var r = Snippets.Send(snippet.Id, targets, confirmed: false, Sessions);
            if (!r.NeedsConfirm) return;
            var ask = Ui.Text($"“{snippet.Name}” has {snippet.Lines} lines. Each line runs as it arrives.", "BodyTextBlockStyle");
            if (!await ShowModal($"Send to {tab.Title}?", ask, primary: "Send", cancel: "Cancel", focusCancel: true)) return;
            Snippets.Send(snippet.Id, targets, confirmed: true, Sessions);
        }
        catch (BastionException ex) { await ShowModal("Snippet not sent", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
    }

    /// <summary>WinUI's TextBox ends lines with a lone CR; the core store counts lines by LF.</summary>
    private static string NormalizeNewlines(string text) => text.Replace("\r\n", "\n").Replace('\r', '\n');
}
