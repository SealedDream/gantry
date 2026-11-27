using Bastion.Shell.Interop;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;

namespace Bastion.Shell;

// Multi-host exec (core multiexec over C ABI 73): one reviewed single-line command on several SSH connections, 1 to 16 at a
// time. The core refuses bad plans, asks for an acknowledgement before production hosts, checks host keys strictly (an
// unknown key fails that host, never a prompt) and audits the host count and command length, never the command.
public sealed partial class MainWindow
{
    private static readonly TimeSpan ExecPollInterval = TimeSpan.FromMilliseconds(250);
    private const int ExecOutputLines = 12;
    private MultiExecRun? _execRun;
    private DispatcherQueueTimer? _execTimer;
    private StackPanel? _execResults;

    private void MultiExec_Click(object sender, RoutedEventArgs e) => _ = MultiExecAsync();

    /// <summary>SSH connections to offer, with the ones under the tree selection ticked (a folder ticks its SSH hosts).</summary>
    private (List<(string Id, string Name, string Detail, bool Saved)> Hosts, HashSet<string> Ticked) ExecHosts()
    {
        var hosts = AllConnections().Where(IsSsh)
            .Select(i => (i.Id, i.Name, Detail: $"{i.Connection!.Host}:{i.Connection.Port ?? 22}",
                Saved: (i.Connection.EffectiveCredentialId ?? i.Connection.CredentialId) is not null))
            .OrderBy(h => h.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        var ticked = new HashSet<string>();
        if (Tree.SelectedItem is TreeItem sel)
        {
            IEnumerable<TreeItem> Walk(TreeItem i) => i.IsFolder ? i.Children.SelectMany(Walk) : [i];
            foreach (var i in Walk(sel).Where(IsSsh)) ticked.Add(i.Id);
        }
        return (hosts, ticked);
    }

    internal async Task MultiExecAsync()
    {
        if (_modal is not null) return;
        var (hosts, ticked) = ExecHosts();
        var form = new MultiExecForm(hosts, ticked) { SaveTask = SaveAsTask };
        try
        {
            while (await ShowModal("Run on several hosts", form.Body, primary: "Run", cancel: "Cancel", validate: form.Validate, focus: form.FirstField, wide: true))
            {
                if (await StartExecAsync(form)) return;
            }
        }
        finally { form.ClearSecrets(); }
    }

    /// <summary>Review, acknowledge production hosts, create and run. False keeps the plan dialog open (a refusal is shown in it).</summary>
    private async Task<bool> StartExecAsync(MultiExecForm form)
    {
        var (ids, command, n) = (form.HostIds, form.Command, form.Concurrency);
        ExecReviewDto review;
        try { review = MultiExecRun.Review(_library, ids, command, n); }
        catch (BastionException ex) { form.ShowError(ex.Message); return false; }
        if (review.NeedsProductionAck && !await ShowModal("Run on sensitive hosts?",
                ErrorText($"{string.Join(", ", review.Sensitive)} {(review.Sensitive.Count == 1 ? "is" : "are")} marked production or sensitive. The command runs there as typed."),
                primary: "Run", cancel: "Back", focusCancel: true)) return false;
        try
        {
            var run = MultiExecRun.Create(Sessions, _library, ids, command, n, form.UserName, form.Kind, form.Secret, form.KeyPath, review.NeedsProductionAck);
            ReplaceExecRun(run);
            run.Run();
        }
        catch (BastionException ex) { form.ShowError(ex.Message); return false; }
        _pageKind = "multiexec";
        ShowExecPage(command);
        return true;
    }

    private void ReplaceExecRun(MultiExecRun? run)
    {
        _execTimer?.Stop();
        _execRun?.Dispose();
        _execRun = run;
    }

    private void ShowExecPage(string command)
    {
        _execResults = new StackPanel { Spacing = Ui.Double("Space8") };
        var title = Ui.Text(command, "BodyStrongTextStyle");
        title.FontFamily = new FontFamily("Consolas");
        title.IsTextSelectionEnabled = true;
        var content = new StackPanel { Spacing = Ui.Double("Space12"), Children = { title, _execResults } };
        var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        actions.Children.Add(ExecAction("Cancel", () => _execRun?.Cancel()));
        actions.Children.Add(ExecAction("Retry Failed", () => { _execRun?.RetryFailed(); _execTimer?.Start(); }));
        actions.Children.Add(ExecAction("Copy CSV", () => CopyExport("csv")));
        actions.Children.Add(ExecAction("Copy JSON", () => CopyExport("json")));
        ShowPage(null, "Multi-host exec", content, actions);
        _execTimer ??= CreateExecTimer();
        _execTimer.Start();
        RefreshExecResults();
    }

    private DispatcherQueueTimer CreateExecTimer()
    {
        var t = DispatcherQueue.CreateTimer();
        t.Interval = ExecPollInterval;
        t.Tick += (_, _) => RefreshExecResults();
        Closed += (_, _) => ReplaceExecRun(null);
        return t;
    }

    private Button ExecAction(string label, Action click)
    {
        var b = new Button { Content = label, Style = Ui.Style("SubtleButtonStyle") };
        AutomationProperties.SetName(b, label);
        b.Click += (_, _) =>
        {
            try { click(); }
            catch (BastionException ex) { _ = ShowModal(label, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        };
        return b;
    }

    private void CopyExport(string format)
    {
        if (_execRun is null) return;
        var data = new DataPackage();
        data.SetText(_execRun.Export(format));
        Clipboard.SetContent(data);
        Announce($"Results copied as {format.ToUpperInvariant()}");
    }

    private void RefreshExecResults()
    {
        if (_pageKind != "multiexec" || _execRun is null || _execResults is null) { _execTimer?.Stop(); return; }
        ExecResultsDto r;
        try { r = _execRun.Results(); }
        catch (BastionException ex)
        {
            _execTimer?.Stop();
            _execResults.Children.Clear();
            _execResults.Children.Add(CodedErrorText("APP", ex.Message));
            return;
        }
        _execResults.Children.Clear();
        var ok = r.Hosts.Count(h => h.State == "done" && h.Exit == 0);
        _execResults.Children.Add(Ui.Text(ExecSummary(r, ok), "CaptionSecondaryTextStyle"));
        foreach (var h in r.Hosts) _execResults.Children.Add(ExecRow(h));
        if (!r.Finished) return;
        _execTimer?.Stop();
        Announce(ExecSummary(r, ok));
    }

    private static string ExecSummary(ExecResultsDto r, int ok) =>
        r.Finished ? $"Finished: {ok} of {r.Hosts.Count} succeeded" : $"Running: {r.Hosts.Count(h => h.State is "done" or "failed" or "cancelled")} of {r.Hosts.Count} finished";

    private static string ExecState(ExecHostDto h) => h.State switch
    {
        "done" => $"exit {h.Exit?.ToString() ?? "?"} · {h.Millis} ms",
        "failed" => "failed: " + (h.Error ?? "unknown error"),
        "running" => "running…",
        "cancelled" => "cancelled",
        _ => "waiting",
    };

    private static StackPanel ExecRow(ExecHostDto h)
    {
        var head = Ui.Text($"{h.Host}  ·  {ExecState(h)}", "BodyTextStyle");
        head.TextWrapping = TextWrapping.Wrap;
        var row = new StackPanel { Spacing = Ui.Double("Space4"), Children = { head } };
        AutomationProperties.SetName(row, $"{h.Host} {ExecState(h)}");
        var output = string.Join('\n', new[] { h.Stdout.TrimEnd(), h.Stderr.TrimEnd() }.Where(s => s.Length > 0));
        if (output.Length == 0) return row;
        var lines = output.Split('\n');
        var shown = lines.Length > ExecOutputLines
            ? string.Join('\n', lines.Take(ExecOutputLines)) + $"\n… {lines.Length - ExecOutputLines} more lines (Copy CSV or JSON for all)"
            : output;
        var text = Ui.Text(shown, "CaptionSecondaryTextStyle");
        text.FontFamily = new FontFamily("Consolas");
        text.IsTextSelectionEnabled = true;
        text.TextWrapping = TextWrapping.Wrap;
        row.Children.Add(text);
        return row;
    }

    // ---- Snapshot mode hooks (SnapshotRunner, BASTION_SNAPSHOT_MULTIEXEC) ----

    /// <summary>The plan dialog's inline validation, then (with a host) a live run on a trusted and an unknown-key host.</summary>
    internal async Task<List<string>> MultiExecForSnapshot(Func<string, Task> capture, string? host, int port, string user, string password)
    {
        var log = new List<string>();
        var (hosts, ticked) = ExecHosts();
        var form = new MultiExecForm(hosts, ticked);
        _ = ShowModal("Run on several hosts", form.Body, primary: "Run", cancel: "Cancel", validate: form.Validate, focus: form.FirstField, wide: true);
        await Task.Delay(400);
        PressModalPrimaryForSnapshot(); // empty command: inline validation
        await Task.Delay(300);
        await capture("multiexec-plan-");
        CancelModalForSnapshot();
        log.Add($"plan dialog: {hosts.Count} SSH hosts offered, {ticked.Count} ticked from the selection");
        if (host is null) return log;
        var trusted = _library.AddConnection(null, "mx-trusted", "ssh", host, port, user);
        var unknown = _library.AddConnection(null, "mx-unknown", "ssh", "localhost", port, user);
        // Pin the key of the first host the way a connect does; the second name has no known_hosts entry and must fail.
        var library = _library;
        var sessions = Sessions;
        var first = await Task.Run(() => sessions.ConnectSsh(library, trusted, user, SshLoginKind.Password, password, null, null, null, 80, 24));
        var pinned = await Task.Run(() => sessions.ConnectSsh(library, trusted, user, SshLoginKind.Password, password, null, first.Fingerprint, null, 80, 24));
        pinned.Session?.Dispose();
        const string command = "echo mx-$((6*7)); exit 3";
        var run = MultiExecRun.Create(Sessions, _library, [trusted, unknown], command, 2, user, SshLoginKind.Password, password, null, false);
        ReplaceExecRun(run);
        run.Run();
        _pageKind = "multiexec";
        ShowExecPage(command);
        var until = DateTime.UtcNow.AddSeconds(60);
        ExecResultsDto r;
        while (!(r = run.Results()).Finished && DateTime.UtcNow < until) await Task.Delay(200);
        RefreshExecResults();
        await capture("multiexec-results-");
        foreach (var h in r.Hosts) log.Add($"{h.Host}: {ExecState(h)}; stdout \"{h.Stdout.Trim()}\"");
        log.Add($"csv lines: {run.Export("csv").Split('\n', StringSplitOptions.RemoveEmptyEntries).Length}");
        return log;
    }
}
