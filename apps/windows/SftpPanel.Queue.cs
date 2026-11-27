using System.Runtime.InteropServices;
using System.Diagnostics;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// The transfer queue of the Files panel. Jobs live in the core queue (order, overwrite rule, conflicts, retries);
/// this side probes the target, copies with the tab's SFTP browser one job at a time and reports back. A job whose
/// target exists follows the panel's "If the file exists" rule; with "Ask" it waits in the queue until the inline
/// conflict row is answered. Failed jobs stay for Retry; queued ones can be cancelled.
/// </summary>
public sealed partial class SftpPanel
{
    private readonly TransferQueue _queue = new(1);
    /// <summary>Transfers running or queued, each a live session when the app quits (CLOSE-01).</summary>
    public int RunningTransfers
    {
        get
        {
            if (_closed) return 0;
            try { return _queue.Jobs().Count(j => !j.IsFinished); }
            catch (BastionException) { return _jobList.Count(j => !j.IsFinished); }
        }
    }
    private readonly ComboBox _rule = new() { HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly ListView _jobs = new() { SelectionMode = ListViewSelectionMode.Single, MaxHeight = 160 };
    private readonly Grid _conflictRow = new() { Visibility = Visibility.Collapsed, ColumnSpacing = 4 };
    private readonly TextBlock _conflictText = new() { TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
    private IReadOnlyList<TransferJob> _jobList = [];
    private TransferJob? _conflict;
    private bool _pumping;
    private bool _remoteChanged;

    /// <summary>The overwrite rule new jobs get ("ask", "replace", "skip", "replace_if_newer", "rename").</summary>
    public string OverwriteRule
    {
        get => TransferQueue.Rules[Math.Max(0, _rule.SelectedIndex)].Rule;
        set => _rule.SelectedIndex = Math.Max(0, Array.FindIndex(TransferQueue.Rules, r => r.Rule == value));
    }

    /// <summary>Snapshot and test mode: the jobs as the queue holds them.</summary>
    internal IReadOnlyList<TransferJob> JobsForSnapshot => _jobList;

    private UIElement BuildQueue()
    {
        foreach (var (_, label) in TransferQueue.Rules) _rule.Items.Add(label);
        _rule.SelectedIndex = 0;
        AutomationProperties.SetName(_rule, "If the file exists");
        var ruleRow = new Grid { ColumnSpacing = 8 };
        ruleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        ruleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var ruleLabel = Ui.Text("If the file exists", "CaptionSecondaryTextStyle");
        ruleLabel.VerticalAlignment = VerticalAlignment.Center;
        ruleRow.Children.Add(ruleLabel);
        Grid.SetColumn(_rule, 1);
        ruleRow.Children.Add(_rule);

        var head = new Grid();
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        head.Children.Add(Ui.Text("Transfers", "BodyStrongTextStyle"));
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 4 };
        buttons.Children.Add(QueueButton("GlyphRefresh", "Retry", () => ActOnSelectedJob("retry")));
        buttons.Children.Add(QueueButton("GlyphClose", "Cancel transfer", () => ActOnSelectedJob("cancel")));
        buttons.Children.Add(QueueButton("GlyphDelete", "Clear finished", () => { _queue.ClearFinished(); RefreshQueue(); return Task.CompletedTask; }));
        Grid.SetColumn(buttons, 1);
        head.Children.Add(buttons);

        _conflictRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        _conflictRow.Children.Add(_conflictText);
        var col = 1;
        foreach (var (rule, label) in new[] { ("replace", "Replace"), ("skip", "Skip"), ("rename", "Keep both") })
        {
            _conflictRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var b = new Button { Content = label };
            if (rule == "replace") b.Style = Ui.Style("AccentButtonStyle");
            AutomationProperties.SetName(b, $"Conflict: {label}");
            b.Click += (_, _) => _ = AnswerConflict(rule);
            Grid.SetColumn(b, col++);
            _conflictRow.Children.Add(b);
        }

        AutomationProperties.SetName(_jobs, "Transfers");
        return new StackPanel { Spacing = 6, Children = { ruleRow, head, _conflictRow, _jobs } };
    }

    private Button QueueButton(string glyph, string name, Func<Task> click)
    {
        var b = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon(glyph) };
        AutomationProperties.SetName(b, name);
        ToolTipService.SetToolTip(b, name);
        b.Click += (_, _) => _ = click();
        return b;
    }

    private async Task ActOnSelectedJob(string action)
    {
        if (_jobs.SelectedIndex < 0 || _jobs.SelectedIndex >= _jobList.Count) { Report("Select a transfer first."); return; }
        var job = _jobList[_jobs.SelectedIndex];
        try { _queue.Update(job.Id, action); }
        catch (BastionException ex) { Report(ex.Message); return; }
        RefreshQueue();
        if (action == "retry") await Pump();
    }

    /// <summary>Answer the waiting conflict with "replace", "skip" or "rename" (keep both), then carry on.</summary>
    public async Task AnswerConflict(string rule)
    {
        if (_conflict is not { } job) return;
        try { _queue.Update(job.Id, rule); }
        catch (BastionException ex) { Report(ex.Message); return; }
        _conflict = null;
        RefreshQueue();
        await Pump();
    }

    /// <summary>Add a job with the panel's overwrite rule. Null (and the reason shown) when the core refuses it.</summary>
    private ulong? Enqueue(bool upload, string source, string target, ulong total)
    {
        try { return _queue.Add(upload, source, target, total, OverwriteRule); }
        catch (BastionException ex) { Report(ex.Message); return null; }
    }

    /// <summary>Run queued jobs one at a time until none can start. Re-entrant calls return at once.</summary>
    private async Task Pump()
    {
        if (_pumping) return;
        _pumping = true;
        try
        {
            while (true)
            {
                TransferJob? job;
                try { job = _queue.StartNext(); }
                catch (BastionException ex) { Report(ex.Message); break; }
                if (job is null) break;
                RefreshQueue();
                await RunJob(job);
                RefreshQueue();
            }
        }
        finally { _pumping = false; }
        var status = _status.Text;
        if (_remoteChanged) { _remoteChanged = false; await Navigate(_dir); }
        await RefreshLocal();
        RefreshQueue();
        Report(status);
    }

    private async Task RunJob(TransferJob job)
    {
        while (_busy) await Task.Delay(50);
        if (_closed) return;
        _busy = true;
        foreach (var c in _actions) c.IsEnabled = false;
        var name = JobName(job);
        _status.Text = $"{(job.IsUpload ? "Uploading" : "Downloading")} {name}…";
        var clock = Stopwatch.StartNew();
        string outcome;
        // The core writes the bytes copied so far into this cell; poll it for the bar and the status line.
        // It is freed only after the copy has returned, so the core never writes into freed memory.
        var cell = Marshal.AllocHGlobal(sizeof(long));
        Marshal.WriteInt64(cell, 0);
        try
        {
            var copy = Task.Run(() => Copy(job, cell));
            while (await Task.WhenAny(copy, Task.Delay(ProgressPollMs)) != copy)
                if (!_closed) ShowBytes(job, (ulong)Marshal.ReadInt64(cell), clock);
            outcome = await copy;
        }
        catch (Exception ex) when (ex is BastionException or ObjectDisposedException or IOException or UnauthorizedAccessException)
        {
            outcome = "fail";
            if (!_closed)
            {
                TryUpdate(job.Id, "fail", ex.Message);
                _status.Text = $"{name}: {ex.Message}";
            }
        }
        finally
        {
            Marshal.FreeHGlobal(cell);
            _busy = false;
            if (_closed) _queue.Dispose();
            else foreach (var c in _actions) c.IsEnabled = true;
        }
        if (_closed) return;
        if (outcome == "copied")
        {
            TryProgress(job.Id, job.Total, (ulong)clock.ElapsedMilliseconds);
            TryUpdate(job.Id, "finish", null);
            if (job.IsUpload) _remoteChanged = true;
            _status.Text = $"{(job.IsUpload ? "Uploaded" : "Downloaded")} {name} ({Size(job.Total)})";
        }
        else if (outcome == "skip") _status.Text = $"Skipped {name}: it already exists.";
        else if (outcome == "ask") _status.Text = $"{name} already exists. Choose what to do.";
    }

    /// <summary>Off the UI thread: probe the target, let the core apply the rule, copy. Returns "copied", "skip" or "ask".</summary>
    private const int ProgressPollMs = 250;

    /// <summary>Snapshot mode: the byte counts the bar showed while copies ran.</summary>
    internal List<ulong> ProgressSamplesForSnapshot { get; } = [];

    /// <summary>A running copy: bytes on the bar and in the status line, and into the core queue for the job row.</summary>
    private void ShowBytes(TransferJob job, ulong done, Stopwatch clock)
    {
        if (job.Total == 0) return;
        done = Math.Min(done, job.Total);
        ProgressSamplesForSnapshot.Add(done);
        TryProgress(job.Id, done, (ulong)clock.ElapsedMilliseconds);
        _progress.Visibility = Visibility.Visible;
        _progress.Maximum = job.Total;
        _progress.Value = done;
        _status.Text = $"{(job.IsUpload ? "Uploading" : "Downloading")} {JobName(job)}: {Size(done)} of {Size(job.Total)} ({done * 100 / job.Total}%)";
    }

    private string Copy(TransferJob job, IntPtr progress)
    {
        TransferResolution r;
        if (job.IsUpload)
        {
            var dir = SftpSession.Parent(job.Target);
            var listing = _sftp.List(dir);
            var hit = listing.FirstOrDefault(e => e.Name == SftpLeaf(job.Target));
            var source = new DateTimeOffset(File.GetLastWriteTimeUtc(job.Source)).ToUnixTimeSeconds();
            r = _queue.Resolve(job.Id, hit is not null, hit?.Modified, source, listing.Select(e => SftpSession.Join(dir, e.Name)));
        }
        else
        {
            var dir = Path.GetDirectoryName(job.Target) ?? "";
            var exists = File.Exists(job.Target) || Directory.Exists(job.Target);
            long? target = exists ? new DateTimeOffset(File.GetLastWriteTimeUtc(job.Target)).ToUnixTimeSeconds() : null;
            var remote = _sftp.List(SftpSession.Parent(job.Source)).FirstOrDefault(e => e.Name == SftpLeaf(job.Source));
            var taken = Directory.Exists(dir) ? Directory.EnumerateFileSystemEntries(dir).ToList() : [];
            r = _queue.Resolve(job.Id, exists, target, remote?.Modified, taken);
        }
        if (r.Action != "copy") return r.Action;
        var to = r.Target ?? job.Target;
        if (job.IsUpload) _sftp.Upload(job.Source, to, r.Replace, progress);
        else _sftp.Download(job.Source, to, r.Replace, progress);
        return "copied";
    }

    private void TryUpdate(ulong id, string action, string? detail)
    {
        try { _queue.Update(id, action, detail); }
        catch (BastionException) { /* the job was cancelled meanwhile: nothing left to report */ }
    }

    private void TryProgress(ulong id, ulong done, ulong elapsed)
    {
        try { _queue.Progress(id, done, elapsed); }
        catch (BastionException) { /* as above */ }
    }

    private static string SftpLeaf(string path)
    {
        var t = path.TrimEnd('/');
        var i = t.LastIndexOf('/');
        return i >= 0 ? t[(i + 1)..] : t;
    }

    private void RefreshQueue()
    {
        var keep = _jobs.SelectedIndex >= 0 && _jobs.SelectedIndex < _jobList.Count ? _jobList[_jobs.SelectedIndex].Id : (ulong?)null;
        try { _jobList = _queue.Jobs(); }
        catch (BastionException ex) { Report(ex.Message); return; }
        _jobs.Items.Clear();
        foreach (var j in _jobList) _jobs.Items.Add(JobRow(j));
        if (keep is { } id && _jobList.ToList().FindIndex(j => j.Id == id) is var i and >= 0) _jobs.SelectedIndex = i;
        _conflict = _jobList.FirstOrDefault(j => j.State == "conflict");
        _conflictRow.Visibility = _conflict is null ? Visibility.Collapsed : Visibility.Visible;
        if (_conflict is { } c) _conflictText.Text = $"{JobName(c)} already exists at the target.";
        var open = _jobList.Count(j => !j.IsFinished);
        _progress.Visibility = open > 0 && _jobList.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
        _progress.Maximum = Math.Max(1, _jobList.Count);
        _progress.Value = _jobList.Count - open;
    }

    private static string JobName(TransferJob j) => j.IsUpload ? SftpLeaf(j.Target) : Path.GetFileName(j.Target);

    private static string StateText(TransferJob j) => j.State switch
    {
        "queued" => "Queued",
        "running" => "Copying",
        "paused" => "Paused",
        "conflict" => "Exists: waiting",
        "done" => $"Done, {Size(j.Total)}",
        "skipped" => "Skipped",
        "failed" => $"Failed: {j.Error}",
        "cancelled" => "Cancelled",
        _ => j.State,
    };

    private static UIElement JobRow(TransferJob j)
    {
        var g = new Grid { ColumnSpacing = 8 };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        g.Children.Add(Ui.Icon(j.IsUpload ? "GlyphUpload" : "GlyphDownload", "SmallIconSize"));
        var name = new TextBlock { Text = JobName(j), TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
        ToolTipService.SetToolTip(name, $"{j.Source} → {j.Target}");
        Grid.SetColumn(name, 1);
        g.Children.Add(name);
        var state = Ui.Text(StateText(j), "CaptionSecondaryTextStyle");
        state.VerticalAlignment = VerticalAlignment.Center;
        state.TextTrimming = TextTrimming.CharacterEllipsis;
        state.MaxWidth = 180;
        Grid.SetColumn(state, 2);
        g.Children.Add(state);
        AutomationProperties.SetName(g, $"{(j.IsUpload ? "Upload" : "Download")} {JobName(j)}, {StateText(j)}");
        return g;
    }
}
