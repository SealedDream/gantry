using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;

namespace Bastion.Shell;

// Application › Tasks (Royal TS: Tasks in the navigation tree). The library's saved tasks through the core (C ABI 92, the
// same tasks the macOS and Tauri apps run): the built-ins (Ping, Trace Route, DNS Lookup, TCP Check) and the user's own
// commands, run on this PC or over SSH against a chosen connection. The core validates, applies policy, decides when a run
// needs confirmation (custom tasks on sensitive connections) and writes the audit entry; this page only asks and shows output.
public sealed partial class MainWindow
{
    private static readonly TimeSpan TaskPollInterval = TimeSpan.FromMilliseconds(250);
    private const string TaskOutputFont = "Cascadia Mono, Consolas";

    internal void OpenTaskManager()
    {
        _pageKind = "tasks";
        ShowTaskManagerPage();
    }

    private static string TaskSummary(TaskDto t) => t.Kind switch
    {
        "ping" => "Built-in · ping the host",
        "trace_route" => "Built-in · trace the route to the host",
        "dns_lookup" => "Built-in · look up the host name",
        "tcp_check" => "Built-in · check the port is open",
        _ => $"{(t.RunOn == "ssh" ? "On the connection (SSH)" : "On this PC")} · {string.Join(' ', new[] { t.Program }.Concat(t.Args))} · {t.TimeoutSecs} s",
    };

    private void SetTaskFavorite(TaskDto t, bool favorite)
    {
        try { TaskClient.SetFavorite(_library, t.Id, favorite); }
        catch (BastionException ex) { _ = ShowModal("Could not change the favourite", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        ShowTaskManagerPage();
        RefreshApplicationSection();
    }

    /// <param name="copy">Edit a Copy…: <paramref name="existing"/> only fills the form; a new task is saved.</param>
    private async Task EditTaskAsync(TaskDto? existing, bool copy = false)
    {
        if (_modal is not null) return;
        var form = new TaskForm(existing);
        while (await ShowModal(existing is null || copy ? "Add task" : "Edit task", form.Body, primary: "Save", cancel: "Cancel", validate: form.Validate, focus: form.FirstField))
        {
            try
            {
                var id = TaskClient.Save(_library, form.Result(existing?.Id ?? "", existing?.Favorite ?? false));
                // B5 (T01): saved by the user here, so this exact content may run as a hook.
                TaskHookClient.Trust(_library, id, SessionDataDir);
                Announce("Task saved " + form.Name);
                break;
            }
            catch (BastionException ex) { form.ShowError(ex.Message); }
        }
        ShowTaskManagerPage();
        RefreshApplicationSection(); // task rows in Application > Tasks (TABBAR-WIN)
    }

    private async Task RemoveTaskAsync(TaskDto t)
    {
        if (_modal is not null) return;
        var text = Ui.Text($"Delete “{t.Name}”? Connections that run it before or after connecting stop running it.", "BodyTextStyle");
        text.TextWrapping = TextWrapping.Wrap;
        if (!await ShowModal("Delete task", text, primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
        try { TaskClient.Remove(_library, t.Id); }
        catch (BastionException ex) { await ShowModal("Could not delete the task", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        ShowTaskManagerPage();
        RefreshApplicationSection();
    }

    /// <summary>Pick the connection (the selection by default), confirm when the core asks, sign in for SSH tasks, then show the output.</summary>
    private async Task RunTaskAsync(TaskDto t, string? connectionId)
    {
        if (_modal is not null) return;
        if (await AnsibleTaskBlockedAsync(t)) return;
        var connections = AllConnections().Where(i => i.Connection is not null).OrderBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        if (connections.Count == 0)
        {
            await ShowModal("Run task " + t.Name, ErrorText("Add a connection first: a task runs against a connection's host."), primary: "OK", cancel: null);
            return;
        }
        // Owner point W18: a folder runs the task on every connection inside it, so folders follow the connections here.
        var folders = connectionId is null ? TaskFolders().ToList() : [];
        var pick = new ComboBox
        {
            Header = "Run on", HorizontalAlignment = HorizontalAlignment.Stretch,
            ItemsSource = connections.Select(c => c.Name).Concat(folders.Select(f => $"Every connection in {f.Path}")).ToList(),
        };
        AutomationProperties.SetName(pick, "Connection");
        var preferred = connectionId ?? (Selected is { Connection: not null } s ? s.Id : null);
        var selectedFolder = Selected is { IsFolder: true } sf ? folders.FindIndex(f => f.Id == sf.Id) : -1;
        pick.SelectedIndex = selectedFolder >= 0 ? connections.Count + selectedFolder : Math.Max(0, connections.FindIndex(c => c.Id == preferred));
        if (connectionId is null && !await ShowModal("Run task " + t.Name, pick, primary: "Next", cancel: "Cancel", focus: pick)) return;
        if (pick.SelectedIndex >= connections.Count && FindFolder(folders[pick.SelectedIndex - connections.Count].Id) is { } folder)
        {
            await RunTaskOnFolderAsync(t, folder);
            return;
        }
        var target = connections[Math.Max(0, pick.SelectedIndex)];

        if (await AskTaskAnswersAsync(t) is not { } answers) return;
        TaskReviewDto review;
        try { review = TaskClient.Review(_library, t.Id, target.Id, answers); }
        catch (BastionException ex) { await ShowModal("Cannot run " + t.Name, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }
        if (review.NeedsConfirmation && !await ShowModal("Confirm task", ErrorText($"{target.Name} is marked sensitive. Run this command?\n{review.Display}"),
                primary: "Run", cancel: "Cancel", focusCancel: true)) return;

        ConnectForm? login = null;
        if (t is { Kind: "custom", RunOn: "ssh" })
        {
            login = new ConnectForm(target.Connection?.Username);
            if (!await ShowModal("Sign in to run " + t.Name, login.Body, primary: "Run", cancel: "Cancel", caption: target.Name, validate: login.Validate, focus: login.FirstField))
            {
                login.ClearSecrets();
                return;
            }
        }
        TaskRunClient run;
        try
        {
            run = login is null
                ? TaskRunClient.Start(Sessions, _library, t.Id, target.Id, null, SshLoginKind.Password, null, null, review.NeedsConfirmation, answers)
                : TaskRunClient.Start(Sessions, _library, t.Id, target.Id, login.UserName, login.Kind, login.Secret, login.KeyPath, review.NeedsConfirmation, answers);
        }
        catch (BastionException ex) { await ShowModal("Could not run " + t.Name, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }
        finally { login?.ClearSecrets(); }
        await ShowTaskOutputAsync(t, target.Name, run);
    }

    private static string TaskState(TaskRunDto o) => o.State switch
    {
        "running" => $"Running… {o.Millis / 1000.0:0.0} s",
        "done" => $"Finished · exit {o.Exit?.ToString() ?? "?"} · {o.Millis} ms",
        "timed_out" => "Timed out",
        "cancelled" => "Cancelled",
        _ => "Failed: " + (o.Error ?? "unknown error"),
    };

    /// <summary>Output dialog, refreshed while the run goes on. Closing it while the task runs cancels the run.</summary>
    private async Task ShowTaskOutputAsync(TaskDto t, string target, TaskRunClient run)
    {
        var state = new TextBlock { TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetAutomationId(state, "TaskRunState");
        var output = new TextBox { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, FontFamily = new Microsoft.UI.Xaml.Media.FontFamily(TaskOutputFont), MinHeight = 160, MaxHeight = 320 };
        ScrollViewer.SetHorizontalScrollBarVisibility(output, ScrollBarVisibility.Auto);
        AutomationProperties.SetName(output, "Task output");
        var command = Ui.Text("", "CaptionSecondaryTextStyle");
        command.IsTextSelectionEnabled = true;
        command.TextWrapping = TextWrapping.Wrap;
        var body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { command, state, output } };
        var timer = new DispatcherTimer { Interval = TaskPollInterval };
        var finished = false;
        // CLOSE-01: a run still going counts as a live session if the window is closed meanwhile.
        var counted = true;
        _runningTaskRuns++;
        void Uncount() { if (!counted) return; counted = false; _runningTaskRuns--; }
        void Refresh()
        {
            TaskRunDto o;
            try { o = run.Output(); }
            catch (BastionException ex) { state.Text = "Failed: " + ex.Message; timer.Stop(); finished = true; Uncount(); return; }
            command.Text = o.Display;
            state.Text = TaskState(o);
            AutomationProperties.SetName(state, state.Text);
            var text = o.Stderr.Length == 0 ? o.Stdout : o.Stdout + (o.Stdout.Length > 0 ? "\n" : "") + o.Stderr;
            if (output.Text != text) output.Text = text;
            if (!o.Finished) return;
            finished = true;
            timer.Stop();
            Uncount();
            TaskLastResultStore.Save(t.Id, TaskGrid.Tally([new TaskGridRow(target, target, o.State, o.Exit, Millis: o.Millis)]));
            Announce($"{t.Name} on {target}: {state.Text}");
        }
        // A tick queued before Close can run after run.Dispose(): ignore ticks once the dialog has closed.
        var closed = false;
        timer.Tick += (_, _) => { if (!closed) Refresh(); };
        Refresh();
        if (!finished) timer.Start();
        try { await ShowModal($"{t.Name} · {target}", body, primary: "Close", cancel: null, wide: true); }
        finally
        {
            closed = true;
            timer.Stop();
            Uncount();
            var cancelT0 = PerfTrace.Now();
            if (!finished) { try { run.Cancel(); } catch (BastionException) { /* it ended meanwhile */ } }
            if (!finished) PerfTrace.Write("task-cancel", PerfTrace.Ms(cancelT0));
            run.Dispose();
        }
    }

    // ---- Snapshot hooks (BASTION_SNAPSHOT_ROYAL_LAYOUT) ----

    internal IReadOnlyList<string> TaskLinesForSnapshot() =>
        TaskClient.List(_library).Select(t => $"{(t.Favorite ? "★ " : "")}{t.Name} ({t.Kind}{(t.Builtin ? ", built-in" : "")})").ToList();

    internal string AddTaskForSnapshot(string name, string program)
    {
        var id = TaskClient.Save(_library, new TaskDto("", name, false, false, "custom", program, [], "local", 30));
        ShowTaskManagerPage();
        return id;
    }

    internal void RemoveTaskForSnapshot(string id)
    {
        TaskClient.Remove(_library, id);
        ShowTaskManagerPage();
    }
}

/// <summary>Add or edit a custom task: name, program, one argument per line, where it runs and the time limit.</summary>
internal sealed class TaskForm
{
    private readonly TextBox _name = new() { Header = "Name", IsSpellCheckEnabled = false };
    private readonly TextBox _program = new() { Header = "Program", PlaceholderText = "for example ping or uptime", IsSpellCheckEnabled = false };
    private readonly TextBox _args = new() { Header = "Arguments, one per line", Description = "$Host$, $Port$, $Username$, $Ask:Label$", AcceptsReturn = true, MinHeight = 72, IsSpellCheckEnabled = false };
    private readonly ComboBox _runOn = new() { Header = "Runs", HorizontalAlignment = HorizontalAlignment.Stretch, ItemsSource = new[] { "On this PC", "On the connection (SSH)" } };
    private readonly NumberBox _timeout = new() { Header = "Time limit (seconds)", Minimum = 1, Maximum = 3600, SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Compact };
    private readonly TextBlock _error = new() { TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed };

    public StackPanel Body { get; }
    public Control FirstField => _name;
    public string Name => _name.Text.Trim();

    public TaskForm(TaskDto? t)
    {
        _name.Text = t?.Name ?? "";
        _program.Text = t?.Program ?? "";
        _args.Text = string.Join("\n", t?.Args ?? []);
        _runOn.SelectedIndex = t?.RunOn == "ssh" ? 1 : 0;
        _timeout.Value = t?.TimeoutSecs ?? 60;
        foreach (var (c, n) in new (Control, string)[] { (_name, "Name"), (_program, "Program"), (_args, "Arguments"), (_runOn, "Runs"), (_timeout, "Time limit") })
            AutomationProperties.SetName(c, n);
        AutomationProperties.SetAutomationId(_error, "TaskFormError");
        ToolTipService.SetToolTip(_args, "$Ask:Label$ asks for a value each time the task runs; every host in the run gets the same answer.");
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { _name, _program, _args, _runOn, _timeout, _error } };
    }

    public bool Validate()
    {
        var problem = Name.Length == 0 ? "Enter a name." : _program.Text.Trim().Length == 0 ? "Enter the program to run." : double.IsNaN(_timeout.Value) ? "Enter a time limit." : null;
        if (problem is null) return true;
        ShowError(problem);
        return false;
    }

    public void ShowError(string message)
    {
        _error.Text = message;
        AutomationProperties.SetName(_error, message);
        _error.Visibility = Visibility.Visible;
    }

    public TaskDto Result(string id, bool favorite) => new(id, Name, favorite, false, "custom", _program.Text.Trim(),
        _args.Text.Split('\n', '\r').Select(a => a.Trim()).Where(a => a.Length > 0).ToList(), _runOn.SelectedIndex == 1 ? "ssh" : "local", (uint)Math.Clamp(_timeout.Value, 1, 3600));
}
