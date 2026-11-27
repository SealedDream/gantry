using System.Text.Json;
using System.Text.Json.Serialization;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Tasks › right-click › Run on… (owner point 31, as Mac TaskRunOn.swift): run one task against every connection in a folder,
// or against hosts picked from a list. The choice is remembered per task. Each host gets its own row in the results, with
// its state and output; the core still reviews, confirms and audits every single run.
public sealed partial class MainWindow
{
    private void AttachTaskMenu(FrameworkElement row, TaskDto t)
    {
        // TABBAR-WIN: the same menu as a task row in the library tree (Run, Run on…, favourite, Edit…, Restore Default, copy).
        var menu = new MenuFlyout();
        foreach (var item in TaskMenuItems(t, withRun: true)) menu.Items.Add(item);
        row.ContextFlyout = menu;
    }

    /// <summary>
    /// Owner point W18: right-click a connection or a folder › Run Task › a task. A folder runs it on every connection
    /// inside (sub-folders included), each host with its own row in the results. Favourites first. Null without tasks.
    /// </summary>
    private MenuFlyoutSubItem? RunTaskMenu(TreeItem target)
    {
        List<TaskDto> tasks;
        try { tasks = TaskClient.List(_library); }
        catch (BastionException) { return null; }
        if (tasks.Count == 0) return null;
        var sub = new MenuFlyoutSubItem { Text = "Run Task", Icon = MenuIcon(FluentIcons.Object("task")) };
        AutomationProperties.SetAutomationId(sub, "TreeRunTask");
        foreach (var t in tasks.OrderByDescending(t => t.Favorite).ThenBy(t => t.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            var item = new MenuFlyoutItem { Text = t.Name };
            AutomationProperties.SetName(item, $"Run {t.Name} on {target.Name}");
            item.Click += (_, _) => _ = target.Connection is not null ? RunTaskAsync(t, target.Id) : RunTaskOnFolderAsync(t, target);
            sub.Items.Add(item);
        }
        return sub;
    }

    private async Task RunTaskOnFolderAsync(TaskDto t, TreeItem folder)
    {
        if (_modal is not null) return;
        var targets = AllConnections(folder.Children).ToList();
        if (targets.Count == 0)
        {
            await ShowModal("Run " + t.Name, ErrorText($"{folder.Name} has no connections."), primary: "OK", cancel: null);
            return;
        }
        await RunTaskOnTargetsAsync(t, targets);
    }

    /// <summary>Name, protocol and folder, so an RDP and an SSH connection with the same name can be told apart.</summary>
    private string HostLabel(TreeItem i)
    {
        var folder = TreeItem.FolderPath(_roots, i.ParentId);
        return $"{i.Name} · {i.Connection?.Protocol.ToUpperInvariant()}{(string.IsNullOrEmpty(folder) ? "" : " · " + folder)}";
    }

    private IEnumerable<(string Id, string Path)> TaskFolders()
    {
        IEnumerable<(string, string)> Walk(IEnumerable<TreeItem> items, string prefix) => items.Where(i => i.IsFolder && !i.IsGroup)
            .SelectMany(i => new[] { (i.Id, prefix + i.Name) }.Concat(Walk(i.Children, prefix + i.Name + " › ")));
        return Walk(_roots, "");
    }

    private TreeItem? FindFolder(string id)
    {
        TreeItem? Find(IEnumerable<TreeItem> items) => items.Select(i => i.Id == id && i.IsFolder ? i : Find(i.Children)).FirstOrDefault(i => i is not null);
        return Find(_roots);
    }

    /// <summary>Connections a Run on… choice resolves to now: a folder's connections (sub-folders included), or the picked hosts still present.</summary>
    private List<TreeItem> TaskTargets(TaskTargetChoice choice)
    {
        if (choice.FolderId is { } folderId)
            return FindFolder(folderId) is { } f ? AllConnections(f.Children).ToList() : [];
        if (choice.Tag is { } tag)
            return AllConnections().Where(i => i.Connection?.Tags?.Contains(tag) == true).ToList();
        var all = AllConnections().Where(i => i.Connection is not null).ToDictionary(i => i.Id);
        return choice.ConnectionIds.Where(all.ContainsKey).Select(id => all[id]).ToList();
    }

    private async Task RunTaskOnAsync(TaskDto t)
    {
        if (_modal is not null) return;
        var picker = new TaskRunOnPicker(TaskFolders().ToList(), TreeItem.AllTags(_roots),
            AllConnections().Where(i => i.Connection is not null).OrderBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase)
                .Select(i => (i.Id, HostLabel(i))).ToList(),
            TaskTargetStore.Load(t.Id));
        if (!await ShowModal("Run " + t.Name + " on…", picker.Body, primary: "Run", cancel: "Cancel", validate: picker.Validate, focus: picker.FirstField)) return;
        var choice = picker.Choice;
        TaskTargetStore.Save(t.Id, choice);
        var targets = TaskTargets(choice);
        if (targets.Count == 0)
        {
            await ShowModal("Run " + t.Name, ErrorText("That folder has no connections."), primary: "OK", cancel: null);
            return;
        }
        await RunTaskOnTargetsAsync(t, targets);
    }

    private async Task RunTaskOnTargetsAsync(TaskDto t, List<TreeItem> targets)
    {
        if (await AnsibleTaskBlockedAsync(t)) return;
        if (await AskTaskAnswersAsync(t) is not { } answers) return;
        var reviews = new List<(TreeItem Target, TaskReviewDto? Review, string? Error)>();
        foreach (var target in targets)
        {
            try { reviews.Add((target, TaskClient.Review(_library, t.Id, target.Id, answers), null)); }
            catch (BastionException ex) { reviews.Add((target, null, ex.Message)); }
        }
        var sensitive = reviews.Where(r => r.Review is { NeedsConfirmation: true }).Select(r => r.Target.Name).ToList();
        if (sensitive.Count > 0 && !await ShowModal("Confirm task", ErrorText($"{string.Join(", ", sensitive)} {(sensitive.Count == 1 ? "is" : "are")} marked sensitive. Run this command on {(sensitive.Count == 1 ? "it" : "them")}?"),
                primary: "Run", cancel: "Cancel", focusCancel: true)) return;
        ConnectForm? login = null;
        if (t is { Kind: "custom", RunOn: "ssh" })
        {
            login = new ConnectForm(targets[0].Connection?.Username);
            if (!await ShowModal("Sign in to run " + t.Name, login.Body, primary: "Run", cancel: "Cancel", caption: $"{targets.Count} hosts", validate: login.Validate, focus: login.FirstField))
            {
                login.ClearSecrets();
                return;
            }
        }
        var rows = new List<TaskHostRun>();
        try
        {
            foreach (var (target, review, error) in reviews)
            {
                if (review is null) { rows.Add(new TaskHostRun(target.Id, target.Name, null, error)); continue; }
                try
                {
                    var run = login is null
                        ? TaskRunClient.Start(Sessions, _library, t.Id, target.Id, null, SshLoginKind.Password, null, null, review.NeedsConfirmation, answers)
                        : TaskRunClient.Start(Sessions, _library, t.Id, target.Id, login.UserName, login.Kind, login.Secret, login.KeyPath, review.NeedsConfirmation, answers);
                    rows.Add(new TaskHostRun(target.Id, target.Name, run, null));
                }
                catch (BastionException ex) { rows.Add(new TaskHostRun(target.Id, target.Name, null, ex.Message)); }
            }
        }
        finally { login?.ClearSecrets(); }
        await ShowTaskResultsAsync(t, rows);
    }

    /// <summary>Design A grid, one row per host. Open in Terminal closes the dialog (cancelling runs still going) and
    /// connects as usual. The tally is kept as the task's last result (never its output).</summary>
    private async Task ShowTaskResultsAsync(TaskDto t, List<TaskHostRun> rows)
    {
        List<string>? openAfter = null;
        void Open(IReadOnlyList<string> ids) { openAfter = ids.ToList(); CloseModal(true); }
        var grid = new TaskResultsGrid(id => Open([id]), Open, (int)t.TimeoutSecs);
        var summary = new TextBlock { TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetAutomationId(summary, "TaskRunOnSummary");
        var body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { summary, grid.View } };
        var timer = new DispatcherTimer { Interval = TaskPollInterval };
        void Refresh()
        {
            foreach (var r in rows) r.Refresh();
            var model = rows.Select(r => r.Row).ToList();
            grid.Update(model);
            var done = model.Count(r => r.IsFinished);
            summary.Text = done == model.Count ? $"Finished on {Plural(model.Count, "host")} · {TaskGrid.Tally(model)}" : $"Running… {done} of {model.Count} finished";
            AutomationProperties.SetName(summary, summary.Text);
            if (done < model.Count) return;
            timer.Stop();
            TaskLastResultStore.Save(t.Id, TaskGrid.Tally(model));
            Announce($"{t.Name}: {summary.Text}");
        }
        // CLOSE-01: each host's run still going counts as a live session if the window is closed meanwhile.
        var counted = 0;
        void Recount() { var open = rows.Count(r => !r.Finished); _runningTaskRuns += open - counted; counted = open; }
        // A tick already queued when the dialog closes can still run after the runs are disposed (crash in layout-fit,
        // 2026-11-25: ObjectDisposedException TaskRunClient from this handler): ignore ticks once closed.
        var closed = false;
        timer.Tick += (_, _) => { if (closed) return; Refresh(); Recount(); };
        Refresh();
        Recount();
        if (rows.Any(r => !r.Finished)) timer.Start();
        try { await ShowModal($"{t.Name} · {Plural(rows.Count, "host")}", body, primary: "Close", cancel: null, wide: true); }
        finally
        {
            closed = true;
            timer.Stop();
            _runningTaskRuns -= counted;
            counted = 0;
            foreach (var r in rows) r.Dispose();
        }
        if (openAfter is not null) await OpenTaskHostsAsync(openAfter);
    }

    /// <summary>Open a terminal on each host through the normal connect (sign-in and host-key checks apply), one after another.
    /// Windows has no Broadcast Input across tabs (only across a tab's panes), so none is started.</summary>
    private async Task OpenTaskHostsAsync(IReadOnlyList<string> ids)
    {
        foreach (var id in ids)
        {
            if (FindItem(_roots, id) is not { Connection: not null } item) continue;
            await ConnectAsync(item);
        }
    }
}

/// <summary>One host's run behind a grid row.</summary>
internal sealed partial class TaskHostRun : IDisposable
{
    private readonly TaskRunClient? _run;
    private bool _disposed;

    public TaskGridRow Row { get; private set; }
    public bool Finished => Row.IsFinished;

    public TaskHostRun(string id, string host, TaskRunClient? run, string? error)
    {
        _run = run;
        Row = run is null ? new TaskGridRow(id, host, "failed", Error: error ?? "could not start") : new TaskGridRow(id, host, "starting");
    }

    public void Refresh()
    {
        if (Finished || _run is null || _disposed) return;
        try
        {
            var o = _run.Output();
            Row = Row with { State = o.State, Exit = o.Exit, Stdout = o.Stdout, Stderr = o.Stderr, Error = o.Error, Millis = o.Millis };
        }
        catch (BastionException ex) { Row = Row with { State = "failed", Error = ex.Message }; }
    }

    public void Dispose()
    {
        if (_run is null || _disposed) return;
        _disposed = true;
        if (!Finished) { try { _run.Cancel(); } catch (BastionException) { /* it ended meanwhile */ } }
        _run.Dispose();
    }
}

/// <summary>Run on… target: a folder (its connections at run time) or picked connection ids.</summary>
/// <summary>A folder, a tag (every connection with it, resolved at run time) or picked hosts.</summary>
public sealed record TaskTargetChoice(string? FolderId, List<string> ConnectionIds, string? Tag = null);

/// <summary>The folder or host picker of Run on…, opened on the task's last choice.</summary>
internal sealed class TaskRunOnPicker
{
    private readonly RadioButton _byFolder = new() { Content = "Every connection in a folder", GroupName = "BastionTaskRunOn" };
    private readonly RadioButton _byTag = new() { Content = "Every connection with a tag", GroupName = "BastionTaskRunOn" };
    private readonly RadioButton _byHosts = new() { Content = "Chosen hosts", GroupName = "BastionTaskRunOn" };
    private readonly ComboBox _tag = new() { Header = "Tag", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly IReadOnlyList<string> _tags;
    private readonly ComboBox _folder = new() { Header = "Folder", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly List<CheckBox> _hostBoxes = [];
    private readonly ScrollViewer _hosts = new() { MaxHeight = 280 };
    private readonly TextBlock _error = new() { TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed };
    private readonly List<(string Id, string Path)> _folders;
    private readonly List<(string Id, string Name)> _connections;

    public StackPanel Body { get; }
    public Control FirstField => _byFolder.IsChecked == true ? _folder : _byTag.IsChecked == true ? _tag : (Control?)_hostBoxes.FirstOrDefault() ?? _byHosts;

    public TaskRunOnPicker(List<(string Id, string Path)> folders, IReadOnlyList<string> tags, List<(string Id, string Name)> connections, TaskTargetChoice? last)
    {
        _folders = folders;
        _tags = tags;
        _tag.ItemsSource = tags.ToList();
        var tagIndex = last?.Tag is { } lt ? tags.ToList().IndexOf(lt) : -1;
        _tag.SelectedIndex = tagIndex >= 0 ? tagIndex : (tags.Count > 0 ? 0 : -1);
        _byTag.IsEnabled = tags.Count > 0;
        AutomationProperties.SetName(_tag, "Tag");
        AutomationProperties.SetAutomationId(_byTag, "TaskRunOnTag");
        _connections = connections;
        _folder.ItemsSource = folders.Select(f => f.Path).ToList();
        var picked = last?.ConnectionIds.ToHashSet() ?? [];
        var list = new StackPanel();
        foreach (var (id, label) in connections)
        {
            var box = new CheckBox { Content = label, IsChecked = picked.Contains(id) };
            AutomationProperties.SetName(box, label);
            _hostBoxes.Add(box);
            list.Children.Add(box);
        }
        _hosts.Content = list;
        AutomationProperties.SetName(_folder, "Folder");
        AutomationProperties.SetName(_hosts, "Hosts");
        AutomationProperties.SetAutomationId(_byFolder, "TaskRunOnFolder");
        AutomationProperties.SetAutomationId(_byHosts, "TaskRunOnHosts");
        var folderIndex = last?.FolderId is { } fid ? folders.FindIndex(f => f.Id == fid) : -1;
        _folder.SelectedIndex = folderIndex >= 0 ? folderIndex : (folders.Count > 0 ? 0 : -1);
        var byTag = last?.Tag is not null && tagIndex >= 0;
        var byFolder = !byTag && (last is null ? folders.Count > 0 : last.FolderId is not null && folderIndex >= 0);
        _byFolder.IsChecked = byFolder;
        _byTag.IsChecked = byTag;
        _byHosts.IsChecked = !byFolder && !byTag;
        _byFolder.IsEnabled = folders.Count > 0;
        void Sync()
        {
            _folder.Visibility = _byFolder.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            _hosts.Visibility = _byHosts.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            _tag.Visibility = _byTag.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        }
        _byTag.Checked += (_, _) => Sync();
        _byFolder.Checked += (_, _) => Sync();
        _byHosts.Checked += (_, _) => Sync();
        Sync();
        Body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { _byFolder, _byTag, _byHosts, _folder, _tag, _hosts, _error } };
    }

    public TaskTargetChoice Choice => _byFolder.IsChecked == true && _folder.SelectedIndex >= 0
        ? new TaskTargetChoice(_folders[_folder.SelectedIndex].Id, [])
        : _byTag.IsChecked == true && _tag.SelectedIndex >= 0 ? new TaskTargetChoice(null, [], _tags[_tag.SelectedIndex])
        : new TaskTargetChoice(null, _hostBoxes.Select((b, i) => (b, i)).Where(x => x.b.IsChecked == true).Select(x => _connections[x.i].Id).ToList());

    public bool Validate()
    {
        var problem = _byFolder.IsChecked == true ? (_folder.SelectedIndex < 0 ? "Choose a folder." : null)
            : _byTag.IsChecked == true ? (_tag.SelectedIndex < 0 ? "Choose a tag." : null)
            : !_hostBoxes.Any(b => b.IsChecked == true) ? "Choose at least one host." : null;
        _error.Text = problem ?? "";
        _error.Visibility = problem is null ? Visibility.Collapsed : Visibility.Visible;
        return problem is null;
    }
}

/// <summary>Each task's last Run on… choice, in %LOCALAPPDATA%\Gantry\task-targets.json (ids only, no secrets).</summary>
internal static class TaskTargetStore
{
    private static string Path => System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Gantry", "task-targets.json");

    private static Dictionary<string, TaskTargetChoice> Read()
    {
        try { return File.Exists(Path) ? JsonSerializer.Deserialize(File.ReadAllText(Path), TaskTargetJson.Default.DictionaryStringTaskTargetChoice) ?? [] : []; }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { return []; }
    }

    internal static TaskTargetChoice? Load(string taskId) => Read().GetValueOrDefault(taskId);

    internal static void Save(string taskId, TaskTargetChoice choice)
    {
        var all = new Dictionary<string, TaskTargetChoice>(Read()) { [taskId] = choice };
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            File.WriteAllText(Path, JsonSerializer.Serialize(all, TaskTargetJson.Default.DictionaryStringTaskTargetChoice));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { System.Diagnostics.Debug.WriteLine($"task targets not saved: {ex.Message}"); }
    }
}

[JsonSerializable(typeof(Dictionary<string, TaskTargetChoice>))]
internal sealed partial class TaskTargetJson : JsonSerializerContext { }
