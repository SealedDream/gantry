using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

/// <summary>
/// Session log v2 (LOG-CORE-02, C ABI 138): a saved connection's log goes where the core plans it
/// (<c>&lt;root&gt;/&lt;Folder&gt;/&lt;Connection&gt;/&lt;time&gt;_&lt;user&gt;.log</c>, header and footer, optional time
/// stamps). A log the core stopped (disk full, queue overflow) shows on the session bar and is announced once. The footer
/// gets the end reason. Retention (settings and each folder's keep-days) runs at start-up and once a day, off the UI thread.
/// </summary>
public sealed partial class MainWindow
{
    private static readonly TimeSpan LogWatchInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan LogPurgeInterval = TimeSpan.FromDays(1);

    private readonly HashSet<WorkspaceTab> _loggedTabs = [];
    private DispatcherTimer? _logWatch;
    private DispatcherTimer? _logPurge;

    private SessionLogContext SessionLogCtx =>
        new(SessionDataDir, "Gantry for Windows", typeof(MainWindow).Assembly.GetName().Version?.ToString() ?? "0");

    /// <summary>Start a log on <paramref name="view"/>: planned for a saved connection's main pane, else the plain
    /// session-logs file named after the tab (quick connect, local shells without an item, split panes).</summary>
    private string StartTabLog(WorkspaceTab tab, TerminalView view)
    {
        string path;
        if (tab.ConnectionId is { } id && ReferenceEquals(view, tab.View) && !_library.IsQuickConnect)
            path = view.Session.StartPlannedLog(_library, id, SessionLogCtx);
        else
        {
            Directory.CreateDirectory(SessionLogsDir);
            path = view.Session.StartLog(SessionLogsDir, SafeFileName(tab.Title));
        }
        if (ReferenceEquals(view, tab.View)) WatchLog(tab);
        return path;
    }

    /// <summary>Stop every pane's log with <paramref name="reason"/> in the footer. Never throws: a failed footer must
    /// not stop a tab from closing.</summary>
    private void FinishTabLogs(WorkspaceTab tab, string reason)
    {
        _loggedTabs.Remove(tab);
        foreach (var pane in tab.AllPanes.Append(tab.View).OfType<TerminalView>().Distinct())
        {
            if (pane.Session.IsDisposed) continue;
            try { if (pane.Session.FinishLog(reason) is not null) AppLog.Info("Session log finished: " + reason); }
            catch (Exception ex) { AppLog.Warn($"Session log footer not written ({ex.GetType().Name}): {ex.Message}"); } // never blocks a close
        }
    }

    private void WatchLog(WorkspaceTab tab)
    {
        _loggedTabs.Add(tab);
        if (_logWatch is null)
        {
            _logWatch = new DispatcherTimer { Interval = LogWatchInterval };
            _logWatch.Tick += (_, _) => CheckLogs();
        }
        if (!_logWatch.IsEnabled) _logWatch.Start();
    }

    /// <summary>A log the core stopped on its own: say so on the bar, once.</summary>
    private void CheckLogs()
    {
        foreach (var tab in _loggedTabs.ToList())
        {
            if (tab.View is not { } view || view.Session.IsDisposed) { _loggedTabs.Remove(tab); continue; }
            SessionLogState state;
            try { state = view.Session.LogState(); }
            catch (BastionException) { continue; }
            if (state.IsActive) continue;
            _loggedTabs.Remove(tab);
            if (!state.IsStopped) continue;
            var problem = "Logging stopped: " + (state.Reason ?? "unknown error");
            tab.Bar?.SetLogStopped(problem);
            Announce(problem);
        }
        if (_loggedTabs.Count == 0) _logWatch?.Stop();
    }

    /// <summary>Retention at start-up and then once a day.</summary>
    private void StartSessionLogPurge()
    {
        if (_demo) return;
        PurgeSessionLogs();
        _logPurge = new DispatcherTimer { Interval = LogPurgeInterval };
        _logPurge.Tick += (_, _) => PurgeSessionLogs();
        _logPurge.Start();
    }

    private void PurgeSessionLogs()
    {
        if (_library.IsQuickConnect) return;
        var lib = _library;
        var dir = SessionDataDir;
        _ = Task.Run(() =>
        {
            try
            {
                var r = lib.PurgeSessionLogs(null, dir);
                if (r.DeletedFiles > 0) AppLog.Info($"Session logs: {r.DeletedFiles} old files deleted, {r.FreedBytes} bytes freed");
            }
            catch (Exception ex) when (ex is BastionException or ObjectDisposedException or DllNotFoundException)
            {
                AppLog.Warn("Session log retention failed: " + ex.Message);
            }
        });
    }
}
