using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

// B5 task hooks (Native Mac #1137): tasks and snippets attached to a connection or a folder run before connect, after
// connect and after disconnect. The core orders them (outer folder first, then the connection) and applies the trust
// rule (T01): a local-program task that came in a document runs only after the user saved that exact task in Tasks on
// this computer; anything else is refused and the user is told how to allow it. A hook never asks for confirmation: a
// task that needs one (a sensitive connection) is refused. Snippet hooks send a snippet from this computer's own store to
// the new session; a multi-line one still needs its confirmation, so it is not sent. "All hosts" (folders only) runs the
// task on every connection in the folder. After-disconnect runs once per session end (tab closed, or the session's
// program ended, or a supervised link whose reconnect gave up), never for a tab that never connected, a tab replaced by a
// reconnect, or app quit. Before-connect hooks gate the connect (GateBeforeConnectAsync): the connect waits for each task,
// "Running <task>…" with Cancel shows when it takes a moment, and a task that fails, times out or is cancelled stops the
// connect with its output (HookGate). In a Connect All run (HookBatch) a multi-host hook runs once for the run.
public sealed partial class MainWindow
{
    private readonly HashSet<WorkspaceTab> _disconnectHooksFired = [];
    private readonly Queue<string> _hookNotices = new();
    private DispatcherTimer? _hookNoticeTimer;
    /// <summary>Connections opened by the running Connect All, with its batch, until their after-connect hooks ran.</summary>
    private readonly Dictionary<string, HookBatch> _hookBatches = [];
    /// <summary>A quick before-connect task finishes without the "Running …" dialog flashing up.</summary>
    private static readonly TimeSpan HookGateDialogDelay = TimeSpan.FromMilliseconds(400);

    /// <summary>Run the hooks for <paramref name="connectionId"/> at <paramref name="when"/>.</summary>
    private void RunHooks(string when, string connectionId)
    {
        if (when == "after_connect") RunAfterConnect(connectionId); // Ansible on a control host (MainWindow.AnsibleHost.cs)
        if (_library.IsQuickConnect) return;
        HookBatch? batch = null;
        if (when == "after_connect" && _hookBatches.Remove(connectionId, out var b)) batch = b;
        List<ResolvedHookDto> hooks;
        List<TaskDto> tasks;
        try
        {
            hooks = TaskHookClient.Resolved(_library, connectionId, when, SessionDataDir);
            if (hooks.Count == 0) return;
            tasks = TaskClient.List(_library);
        }
        catch (BastionException ex) { HookTrace($"error {when} {connectionId}: {ex.Message}"); return; }
        foreach (var r in hooks)
        {
            var task = tasks.FirstOrDefault(t => t.Id == r.Hook.TaskId);
            if (r.Untrusted)
            {
                HookTrace($"refused-untrusted {task?.Name} {when} {connectionId}");
                HookNotice($"“{task?.Name ?? "Task"}” came from a document and runs a local program. Open it in Tasks and save it to allow it as a hook.");
                continue;
            }
            if (r.Runnable) RunHook(r, task, connectionId, when, batch);
        }
    }

    private void RunHook(ResolvedHookDto r, TaskDto? task, string connectionId, string when, HookBatch? batch)
    {
        switch (r.Hook.TargetOrTask)
        {
            case "snippet":
                SendHookSnippet(r.Hook.SnippetId ?? "", connectionId);
                break;
            case "multi_host":
                // Set on the folder by the user: every host in it, sub-folders included.
                if (task is null || batch?.Claim(r.OwnerId, task.Id, when) == false) break;
                foreach (var host in MultiHostTargets(r)) StartHookTask(task, host, when);
                break;
            default:
                if (task is not null) StartHookTask(task, connectionId, when);
                break;
        }
    }

    private IEnumerable<string> MultiHostTargets(ResolvedHookDto r) =>
        FindItem(_roots, r.OwnerId) is { } folder
            ? AllConnections(folder.Children).Select(h => h.Id).OrderBy(id => id, StringComparer.Ordinal).ToList()
            : [];

    /// <summary>
    /// Before-connect hooks, in core order. The connect waits for each task and goes ahead only when all succeeded. A
    /// refused (untrusted) task is reported and skipped, as before; snippet hooks never run before connect.
    /// </summary>
    private async Task<bool> GateBeforeConnectAsync(TreeItem item)
    {
        if (_library.IsQuickConnect) return true;
        List<ResolvedHookDto> hooks;
        List<TaskDto> tasks;
        try
        {
            hooks = TaskHookClient.Resolved(_library, item.Id, "before_connect", SessionDataDir);
            if (hooks.Count == 0) return true;
            tasks = TaskClient.List(_library);
        }
        catch (BastionException ex) { HookTrace($"error before_connect {item.Id}: {ex.Message}"); return true; }
        _hookBatches.TryGetValue(item.Id, out var batch);
        foreach (var r in hooks)
        {
            var task = tasks.FirstOrDefault(t => t.Id == r.Hook.TaskId);
            if (r.Untrusted)
            {
                HookTrace($"refused-untrusted {task?.Name} before_connect {item.Id}");
                HookNotice($"“{task?.Name ?? "Task"}” came from a document and runs a local program. Open it in Tasks and save it to allow it as a hook.");
                continue;
            }
            if (!r.Runnable || task is null || r.Hook.TargetOrTask == "snippet") continue;
            IEnumerable<string> targets = [item.Id];
            if (r.Hook.TargetOrTask == "multi_host")
            {
                if (batch?.Claim(r.OwnerId, task.Id, "before_connect") == false) continue;
                targets = MultiHostTargets(r);
            }
            foreach (var id in targets)
            {
                if (await RunGateTaskAsync(task, id, item.Name) is not { } stop) continue;
                HookTrace($"gate-stopped {task.Name} {item.Name}");
                Announce(stop);
                await ShowModal("Not connected", ErrorText(stop), primary: "OK", cancel: null);
                return false;
            }
        }
        return true;
    }

    /// <summary>One before-connect task, awaited. Null when it succeeded, else why the connect stops.</summary>
    private async Task<string?> RunGateTaskAsync(TaskDto t, string connectionId, string connecting)
    {
        var target = FindItem(_roots, connectionId);
        var name = target?.Name ?? connectionId;
        TaskRunClient run;
        try
        {
            // A sensitive host asks first, as Run Task does; Cancel stops the connect.
            var review = TaskClient.Review(_library, t.Id, connectionId);
            if (review.NeedsConfirmation && !await ShowModal($"Run “{t.Name}” on {name}?",
                    ErrorText($"{name} is marked sensitive (for example production).\n\n{review.Display}"), primary: "Run", cancel: "Cancel"))
                return $"Not connected to {connecting}: “{t.Name}” was cancelled before connect.";
            var user = target?.Connection?.Username;
            run = target?.Connection?.EffectiveCredentialId is { } cred
                ? TaskRunClient.Start(Sessions, _library, t.Id, connectionId, user, SshLoginKind.Vault, cred, null, review.NeedsConfirmation)
                : TaskRunClient.Start(Sessions, _library, t.Id, connectionId, user, SshLoginKind.Agent, null, null, review.NeedsConfirmation);
        }
        catch (BastionException ex)
        {
            HookTrace($"failed {t.Name} before_connect {name}: {ex.Message}");
            return $"Not connected to {connecting}: before-connect task “{t.Name}” did not start.\n\n{ex.Message}";
        }
        HookTrace($"gate-run {t.Name} before_connect {name}");
        _runningTaskRuns++;
        try
        {
            var started = DateTime.UtcNow;
            Task<bool>? dialog = null;
            var cancelled = false;
            TaskRunDto o;
            while (true)
            {
                try { o = run.Output(); }
                catch (BastionException ex) { o = new TaskRunDto("", true, "failed", null, "", "", ex.Message, 0); }
                if (o.Finished) break;
                // "Running <task>…" with Cancel (Esc too) once it takes a moment; the task's own timeout bounds the wait.
                if (dialog is null && DateTime.UtcNow - started >= HookGateDialogDelay)
                    dialog = ShowModal($"Running {t.Name}…", ErrorText($"Before connecting to {connecting}."), primary: "Cancel", cancel: null);
                if (dialog is { IsCompleted: true } && !cancelled) { run.Cancel(); cancelled = true; }
                await Task.Delay(TaskPollInterval);
            }
            if (dialog is { IsCompleted: false }) CloseModal(false);
            HookTrace($"done {t.Name} {name} state={o.State} exit={o.Exit?.ToString() ?? "-"}");
            return HookGate.StopReason(t.Name, connecting, o.State, o.Exit, o.Stdout, o.Stderr, o.Error);
        }
        finally
        {
            _runningTaskRuns--;
            run.Dispose();
        }
    }

    /// <summary>One hook run in the background, signed in with the connection's credential, else the SSH agent.</summary>
    private void StartHookTask(TaskDto t, string connectionId, string when)
    {
        var target = FindItem(_roots, connectionId);
        var name = target?.Name ?? connectionId;
        try
        {
            if (TaskClient.Review(_library, t.Id, connectionId).NeedsConfirmation)
            {
                HookTrace($"refused-confirm {t.Name} {when} {name}");
                HookNotice($"{name} is marked sensitive, so “{t.Name}” does not run as a hook. Run it from Tasks.");
                return;
            }
            var user = target?.Connection?.Username;
            var run = target?.Connection?.EffectiveCredentialId is { } cred
                ? TaskRunClient.Start(Sessions, _library, t.Id, connectionId, user, SshLoginKind.Vault, cred, null, false)
                : TaskRunClient.Start(Sessions, _library, t.Id, connectionId, user, SshLoginKind.Agent, null, null, false);
            HookTrace($"run {t.Name} {when} {name}");
            WatchHookRun(t, name, run);
        }
        catch (BastionException ex)
        {
            HookTrace($"failed {t.Name} {when} {name}: {ex.Message}");
            HookNotice($"“{t.Name}” on {name}: {ex.Message}");
        }
    }

    /// <summary>Poll a hook run until it ends; a failure is shown. It counts as a live session for Quit (CLOSE-01).</summary>
    private void WatchHookRun(TaskDto t, string host, TaskRunClient run)
    {
        _runningTaskRuns++;
        var timer = new DispatcherTimer { Interval = TaskPollInterval };
        timer.Tick += (_, _) =>
        {
            TaskRunDto o;
            try { o = run.Output(); }
            catch (BastionException ex) { o = new TaskRunDto("", true, "failed", null, "", "", ex.Message, 0); }
            if (!o.Finished) return;
            timer.Stop();
            _runningTaskRuns--;
            run.Dispose();
            HookTrace($"done {t.Name} {host} state={o.State} exit={o.Exit?.ToString() ?? "-"}");
            if (o is { State: "done", Exit: 0 }) Announce($"{t.Name} on {host}: {TaskState(o)}");
            else HookNotice($"“{t.Name}” on {host}: {o.Error ?? TaskState(o)}");
        };
        timer.Start();
    }

    /// <summary>An after-connect snippet hook: sent to the connection's newest terminal tab.</summary>
    private void SendHookSnippet(string snippetId, string connectionId)
    {
        var tab = _tabs.LastOrDefault(t => t.HostColorId == connectionId && t.View is not null);
        if (tab is null || PaneOf(tab) is not { } view || view.Session.IsDisposed) return;
        try
        {
            if (Snippets.Send(snippetId, [view.Session], confirmed: false, Sessions).NeedsConfirm)
            {
                HookTrace($"snippet-needs-confirm {snippetId} {connectionId}");
                HookNotice("A multi-line snippet hook needs confirmation. Send it from Snippets.");
                return;
            }
            view.Session.Write("\r");
            HookTrace($"snippet-sent {snippetId} {connectionId}");
        }
        catch (BastionException ex) { HookNotice("Snippet hook: " + ex.Message); }
    }

    /// <summary>A session ended: run its after-disconnect hooks once. A crash-restore placeholder never connected.</summary>
    private void SessionEnded(WorkspaceTab tab)
    {
        if (tab.Waiting is not null || tab.HostColorId is not { } id || !_disconnectHooksFired.Add(tab)) return;
        RunHooks("after_disconnect", id);
    }

    /// <summary>Spoken at once; shown in a dialog as soon as no dialog or connect is in progress (never inside a connect form).</summary>
    private void HookNotice(string text)
    {
        Announce(text);
        _hookNotices.Enqueue(text);
        if (_hookNoticeTimer is not null) return;
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _hookNoticeTimer = timer;
        timer.Tick += async (_, _) =>
        {
            if (_modal is not null || _connecting || _hookNotices.Count == 0) return;
            timer.Stop();
            var body = string.Join("\n", _hookNotices);
            _hookNotices.Clear();
            await ShowModal("Attached task not run", ErrorText(body), primary: "OK", cancel: null);
            if (_hookNotices.Count > 0) timer.Start(); else _hookNoticeTimer = null;
        };
        timer.Start();
    }

    private static void HookTrace(string line)
    {
        if (TestHooks.HookTrace is not { } path) return;
        try { File.AppendAllText(path, $"{DateTime.UtcNow:O} {line}{Environment.NewLine}"); }
        catch (IOException) { } // a test trace must never break a session
    }
}
