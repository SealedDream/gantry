using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// B15 dynamic folders (core #1166, review #1126). A folder bound to a saved local task shows the items the task prints
// (Royal JSON) after the user clicks Refresh. Manual only (C11): nothing runs on open, start-up, expand or a timer.
// The first Refresh of a task shows the consent sheet; Trust and Run trusts exactly what the sheet showed (C1, H1).
// Generated rows are not in the document (C8): Enter opens Quick Connect prefilled; Make Permanent copies them in.
// A managed ban hides every control (C2). Errors are one row under the folder; the detail is its tooltip.
public sealed partial class MainWindow
{
    /// <summary>A finished Refresh, or a refusal (<see cref="Run"/> null).</summary>
    private sealed record DynamicResult(LibraryClient Library, DynamicFolderRunClient? Run, DynamicRunDto Output);

    private const string DynamicSwitchFile = "dynamic-folders-enabled";
    private const string DynamicRowPrefix = "dyn:";
    private const int DynamicSkippedShown = 20;
    private readonly Dictionary<string, DynamicResult> _dynamicResults = [];
    private readonly Dictionary<string, DynamicFolderRunClient> _dynamicRunning = [];

    /// <summary>The user's own switch (off by default), kept with this computer's session data, never in a document.</summary>
    private bool DynamicFoldersOn
    {
        get
        {
            try { return File.Exists(DynamicSwitchPath) && File.ReadAllText(DynamicSwitchPath).Trim() == "1"; }
            catch (IOException) { return false; }
        }
        set
        {
            if (value) File.WriteAllText(DynamicSwitchPath, "1");
            else File.Delete(DynamicSwitchPath);
        }
    }

    private string DynamicSwitchPath => Path.Combine(SessionDataDir, DynamicSwitchFile);

    /// <summary>The folder menu's dynamic-folder entries; none under a managed ban.</summary>
    private void AddDynamicFolderEntries(List<MenuFlyoutItemBase> result, TreeItem folder)
    {
        if (!DynamicFolderClient.Allowed()) return;
        result.Add(ExtraEntry("Dynamic Folder…", "folder", (_, _) => _ = EditDynamicFolderAsync(folder)));
        string? task;
        try { task = DynamicFolderClient.TaskId(_library, folder.Id); }
        catch (BastionException) { return; }
        if (task is null) return;
        if (_dynamicRunning.ContainsKey(folder.Id))
            result.Add(ExtraEntry("Cancel Refresh", "task", (_, _) => CancelDynamicRefresh(folder.Id)));
        else
            result.Add(ExtraEntry("Refresh", "update", (_, _) => _ = RefreshDynamicFolderAsync(folder)));
        if (_dynamicResults.TryGetValue(folder.Id, out var r) && r is { Run: not null, Output: { State: "done", Items.Count: > 0 } })
            result.Add(ExtraEntry("Make Permanent", "folder", (_, _) => _ = MakeDynamicPermanentAsync(folder)));
        result.Add(ExtraEntry("Remove Trust", "shield", (_, _) => RevokeDynamicTrust(folder)));
    }

    /// <summary>Bind a task to the folder, or make it plain. The core decides which tasks qualify (C3).</summary>
    private async Task EditDynamicFolderAsync(TreeItem folder)
    {
        if (_modal is not null) return;
        List<DynamicTaskChoiceDto> choices;
        string? current;
        try
        {
            choices = DynamicFolderClient.Choices(_library);
            current = DynamicFolderClient.TaskId(_library, folder.Id);
        }
        catch (BastionException ex) { await ShowModal("Dynamic Folder", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }

        var on = new CheckBox { Content = "Allow dynamic folders on this computer", IsChecked = DynamicFoldersOn };
        ToolTipService.SetToolTip(on, "Runs only when you click Refresh, and only after you trust the task.");
        var task = new ComboBox { Header = "Task", HorizontalAlignment = HorizontalAlignment.Stretch };
        AutomationProperties.SetName(task, "Task");
        task.Items.Add("None");
        foreach (var c in choices) task.Items.Add(c.Name);
        task.SelectedIndex = Math.Max(0, choices.FindIndex(c => c.Id == current) + 1);
        var error = Ui.Text(choices.Count == 0 ? "No eligible task: a saved custom task that runs locally." : "", "CaptionTextStyle");
        error.TextWrapping = TextWrapping.Wrap;
        var body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { Ui.Text(folder.Name, "BodyTextBlockStyle"), on, task, error } };
        string? Chosen() => task.SelectedIndex > 0 ? choices[task.SelectedIndex - 1].Id : null;
        bool Save()
        {
            var enabled = on.IsChecked == true;
            try
            {
                DynamicFoldersOn = enabled;
                // Switching off keeps the binding: the core refuses every run while the switch is off.
                if (Chosen() == current) return true;
                DynamicFolderClient.SetTask(_library, folder.Id, Chosen(), enabled);
                SaveLibrary();
                return true;
            }
            catch (BastionException ex) { error.Text = Capitalised(ex.Message); return false; }
            catch (IOException ex) { error.Text = Capitalised(ex.Message); return false; }
            catch (UnauthorizedAccessException ex) { error.Text = Capitalised(ex.Message); return false; }
        }
        if (!await ShowModal("Dynamic Folder", body, primary: "Save", cancel: "Cancel", validate: Save, focus: task)) return;
        DynTrace($"bound {folder.Name} task={(Chosen() is null ? "-" : choices[task.SelectedIndex - 1].Name)} on={on.IsChecked == true}");
        DropDynamicResult(folder.Id);
        Reload(folder.Id);
        Announce("Dynamic folder saved");
    }

    /// <summary>Refresh: consent sheet first when the task is not trusted, then a background run polled on the UI thread.</summary>
    private async Task RefreshDynamicFolderAsync(TreeItem folder)
    {
        if (_modal is not null || _dynamicRunning.ContainsKey(folder.Id)) return;
        var enabled = DynamicFoldersOn;
        try
        {
            var review = DynamicFolderClient.Review(Sessions, _library, folder.Id);
            if (!review.Trusted)
            {
                if (!await ShowModal("Trust this task?", DynamicReviewBody(review), primary: "Trust and Run", cancel: "Cancel", focusCancel: true))
                {
                    DynTrace($"trust-declined {folder.Name}");
                    return;
                }
                DynamicFolderClient.Trust(Sessions, _library, folder.Id, review.Sha256, enabled);
                DynTrace($"trusted {folder.Name}");
            }
            var run = DynamicFolderRunClient.Start(Sessions, _library, folder.Id, enabled);
            _dynamicRunning[folder.Id] = run;
            DynTrace($"run {folder.Name}");
            Announce($"Refreshing {folder.Name}");
            WatchDynamicRun(folder, run);
        }
        catch (BastionException ex)
        {
            DynTrace($"refused {folder.Name}: {ex.Message}");
            ShowDynamicError(folder, "Refresh refused", ex.Message);
        }
    }

    /// <summary>What will run, as the core reports it: program, arguments, time limit and any warnings.</summary>
    private static StackPanel DynamicReviewBody(DynamicReviewDto r)
    {
        var body = new StackPanel { Spacing = Ui.Double("Space8") };
        var lead = Ui.Text($"“{r.TaskName}” runs on this computer with your rights and fills the folder.", "BodyTextBlockStyle");
        lead.TextWrapping = TextWrapping.Wrap;
        body.Children.Add(lead);
        var lines = new List<string> { $"Program: {r.Program}", $"Arguments: {string.Join(" ", r.Args)}", $"Time limit: {r.TimeoutSecs} s" };
        lines.AddRange(r.Warnings.Select(w => $"Warning: {w}"));
        lines.Add("Any change to the task asks again.");
        foreach (var text in lines)
        {
            var line = Ui.Text(text, "CaptionTextStyle");
            line.TextWrapping = TextWrapping.Wrap;
            line.IsTextSelectionEnabled = true;
            AutomationProperties.SetName(line, text);
            body.Children.Add(line);
        }
        return body;
    }

    private void WatchDynamicRun(TreeItem folder, DynamicFolderRunClient run)
    {
        var library = _library;
        var timer = new DispatcherTimer { Interval = TaskPollInterval };
        timer.Tick += (_, _) =>
        {
            DynamicRunDto o;
            try { o = run.Output(); }
            catch (BastionException ex) { o = new DynamicRunDto(true, "failed", [], [], ex.Message, null, 0); }
            if (!o.Finished) return;
            timer.Stop();
            _dynamicRunning.Remove(folder.Id);
            DynTrace($"done {folder.Name} state={o.State} items={o.Items.Count} skipped={o.Skipped.Count}");
            if (!ReferenceEquals(library, _library)) { run.Dispose(); return; } // the document changed meanwhile
            DropDynamicResult(folder.Id);
            _dynamicResults[folder.Id] = new DynamicResult(library, run, o);
            Reload(folder.Id);
            Announce(o.State == "done" ? $"{folder.Name}: {Plural(o.Items.Count, "item")}" : $"{folder.Name}: {DynamicStateText(o)}");
        };
        timer.Start();
    }

    private void CancelDynamicRefresh(string folderId)
    {
        if (!_dynamicRunning.TryGetValue(folderId, out var run)) return;
        try { run.Cancel(); }
        catch (BastionException ex) { DynTrace($"cancel-failed {folderId}: {ex.Message}"); }
    }

    private async Task MakeDynamicPermanentAsync(TreeItem folder)
    {
        if (_modal is not null || !_dynamicResults.TryGetValue(folder.Id, out var r) || r.Run is null) return;
        var n = r.Output.Items.Count;
        var body = Ui.Text($"Add {Plural(n, "item")} to “{folder.Name}” as ordinary connections.", "BodyTextBlockStyle");
        body.TextWrapping = TextWrapping.Wrap;
        if (!await ShowModal("Make Permanent?", body, primary: "Add Connections", cancel: "Cancel")) return;
        try
        {
            var added = r.Run.MakePermanent(_library, folder.Id);
            DropDynamicResult(folder.Id);
            DynTrace($"permanent {folder.Name} added={added}");
            ReloadThenSave(folder.Id);
            Announce($"{Plural(added, "connection")} added");
        }
        catch (BastionException ex) { await ShowModal("Make Permanent", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
    }

    private void RevokeDynamicTrust(TreeItem folder)
    {
        try
        {
            var removed = DynamicFolderClient.Revoke(Sessions, _library, folder.Id);
            DynTrace($"revoked {folder.Name} removed={removed}");
            Announce(removed ? "Trust removed" : "The task was not trusted");
        }
        catch (BastionException ex) { ShowDynamicError(folder, "Remove Trust failed", ex.Message); }
    }

    /// <summary>A refusal or failure: one row under the folder, the full text in its tooltip.</summary>
    private void ShowDynamicError(TreeItem folder, string title, string detail)
    {
        DropDynamicResult(folder.Id);
        _dynamicResults[folder.Id] = new DynamicResult(_library, null, new DynamicRunDto(true, "failed", [], [], $"{title}: {detail}", null, 0));
        Reload(folder.Id);
        Announce($"{folder.Name}: {title}");
    }

    private void DropDynamicResult(string folderId)
    {
        if (_dynamicResults.Remove(folderId, out var old)) old.Run?.Dispose();
    }

    private static string DynamicStateText(DynamicRunDto o) => o.State switch
    {
        "timed_out" => "Timed out",
        "cancelled" => "Cancelled",
        _ => "Refresh failed",
    };

    /// <summary>After the tree is built: generated rows under each refreshed folder (results of another document are dropped).</summary>
    private void AddDynamicRows(List<TreeItem> roots)
    {
        foreach (var id in _dynamicResults.Where(p => !ReferenceEquals(p.Value.Library, _library)).Select(p => p.Key).ToList()) DropDynamicResult(id);
        foreach (var (folderId, r) in _dynamicResults)
        {
            if (TreeItem.Find(roots, folderId) is not { Folder: not null } folder) continue;
            folder.Children.AddRange(DynamicRows(folderId, r.Output));
        }
    }

    private List<TreeItem> DynamicRows(string folderId, DynamicRunDto o)
    {
        var rows = new List<TreeItem>();
        if (o.State != "done")
        {
            var detail = string.Join("\n", new[] { o.Error ?? "", o.Exit is { } e ? $"Exit code {e}" : "" }.Where(s => s.Length > 0));
            var title = DynamicStateText(o);
            rows.Add(AppRow($"{DynamicRowPrefix}{folderId}:status", title, FluentIcons.Object("security"), detail.Length > 0 ? detail : title, null, folderId));
            return rows;
        }
        var groups = new Dictionary<string, TreeItem>();
        foreach (var item in o.Items)
        {
            TreeItem? parent = null;
            var key = "";
            foreach (var segment in item.Path)
            {
                key += "/" + segment;
                if (!groups.TryGetValue(key, out var g))
                {
                    g = AppRow($"{DynamicRowPrefix}{folderId}:{key}", segment, FluentIcons.Object("folder"), $"Generated folder {segment}", null, parent?.Id ?? folderId);
                    groups[key] = g;
                    if (parent is null) rows.Add(g); else parent.Children.Add(g);
                }
                parent = g;
            }
            var row = AppRow($"{DynamicRowPrefix}{folderId}:{item.Id}", item.Name, FluentIcons.Object("server"),
                DynamicItemDescription(item), () => _ = QuickConnectAsync(DynamicAddress(item)), parent?.Id ?? folderId);
            if (parent is null) rows.Add(row); else parent.Children.Add(row);
        }
        if (o.Skipped.Count > 0)
            rows.Add(AppRow($"{DynamicRowPrefix}{folderId}:skipped", $"{o.Skipped.Count} skipped", FluentIcons.Object("security"),
                string.Join("\n", o.Skipped.Take(DynamicSkippedShown)), null, folderId));
        return rows;
    }

    /// <summary>One line for the tooltip. Generated, so never saved; never a secret (the core drops secret fields).</summary>
    private static string DynamicItemDescription(DynamicItemDto i) =>
        $"Generated {i.Protocol.ToUpperInvariant()}, {(i.Username is { Length: > 0 } u ? u + "@" : "")}{i.Host}{(i.Port is { } p ? ":" + p : "")}. Enter opens Quick Connect.";

    /// <summary>The Quick Connect address for a generated item: SSH as user@host:port, other types with their scheme.</summary>
    internal static string DynamicAddress(DynamicItemDto i)
    {
        if (i.Host.Contains("://", StringComparison.Ordinal)) return i.Host;
        var scheme = i.Protocol.ToLowerInvariant() switch { "ssh" => "", "web" => "https://", var p => p + "://" };
        var user = scheme.Length == 0 && i.Username is { Length: > 0 } u ? u + "@" : "";
        return $"{scheme}{user}{i.Host}{(i.Port is { } port ? ":" + port : "")}";
    }

    private static void DynTrace(string line)
    {
        if (TestHooks.DynamicTrace is not { } path) return;
        try { File.AppendAllText(path, $"{DateTime.UtcNow:O} {line}{Environment.NewLine}"); }
        catch (IOException) { } // a test trace must never break the app
    }
}
