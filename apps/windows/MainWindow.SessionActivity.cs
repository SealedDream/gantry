using Bastion.Shell.Interop;

namespace Bastion.Shell;

// Activity log for the sessions the app drives itself: RDP, VNC and web tabs (#954 left them out). SSH, SFTP, SCP and
// FTPS are recorded by the core (bastion_session_connect*) and must not be begun here too. Metadata only: no secrets,
// no keystrokes, no content. Every write runs off the UI thread and a failed write never blocks or ends a session.
// Sessions still open when the app ends are closed by the core's close_orphans at the next launch.
public sealed partial class MainWindow
{
    private const string ActivityApp = "native-windows";

    /// <summary>The core session id for each recorded tab content (RemoteDesktopView or WebTabView); a pending begin.</summary>
    private readonly Dictionary<object, Task<string?>> _sessionActivity = new();

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    internal static bool IsAppRecordedProtocol(string protocol) => protocol is "rdp" or "vnc" or "web";

    /// <summary>Root-first folder ids and names above a connection, so the Activity folder filter finds it.</summary>
    private List<ActivityClient.FolderRef> ActivityFolderPath(string? parentId)
    {
        var path = new List<ActivityClient.FolderRef>();
        for (var id = parentId; id is not null && FindItem(_roots, id) is { } folder && path.Count < 64; id = folder.ParentId)
            if (folder.Folder is not null) // tree headings (favorites, credentials ...) have no library id; the core takes UUIDs only
                path.Insert(0, new ActivityClient.FolderRef(folder.Id, folder.Name));
        return path;
    }

    private ActivityClient.SessionStart? ActivityStartFor(string connectionId)
    {
        if (_library.IsQuickConnect || FindItem(_roots, connectionId) is not { Connection: { } c } item) return null;
        if (!IsAppRecordedProtocol(c.Protocol)) return null;
        var host = c.Host;
        int? port = c.Port;
        if (c.Protocol == "web" && Uri.TryCreate(c.Host, UriKind.Absolute, out var url)) { host = url.Host; port = url.IsDefaultPort ? null : url.Port; }
        var hasUsername = !string.IsNullOrWhiteSpace(c.Username);
        return new ActivityClient.SessionStart(c.Id, c.Name, ActivityFolderPath(item.ParentId), c.Protocol, host, port,
            hasUsername ? c.Username : null, [], ActivityClient.LoginSourceFor(c.Protocol, hasUsername), NowMs(), ActivityApp,
            typeof(MainWindow).Assembly.GetName().Version?.ToString() ?? "0", Environment.MachineName);
    }

    /// <summary>A tab with a connected RDP/VNC desktop or a web page opened: record its start, connected now.</summary>
    private void BeginTabActivity(object content, string? connectionId)
    {
        if (connectionId is null || _sessionActivity.ContainsKey(content) || ActivityStartFor(connectionId) is not { } start) return;
        var dir = SessionDataDir;
        _sessionActivity[content] = Task.Run(() =>
        {
            try { return (string?)ActivityClient.Begin(dir, start); }
            catch (BastionException e) { System.Diagnostics.Debug.WriteLine($"Gantry: activity begin failed: {e.Message}"); return null; }
        });
        _activityConnectedAt[content] = start.StartedAt; // the tab opens on a live session
        if (content is RemoteDesktopView rdp) rdp.Closed += (_, _) => EndTabActivity(content, "remote_closed");
    }

    private readonly Dictionary<object, long> _activityConnectedAt = new();

    /// <summary>Record the end once; later calls for the same content do nothing.</summary>
    private void EndTabActivity(object? content, string reason)
    {
        if (content is null || !_sessionActivity.Remove(content, out var begun)) return;
        long? connectedAt = _activityConnectedAt.Remove(content, out var at) ? at : null;
        var dir = SessionDataDir;
        var end = new ActivityClient.SessionEnd(connectedAt, NowMs(), reason);
        _ = Task.Run(async () =>
        {
            if (await begun is not { } id) return;
            try { ActivityClient.End(dir, id, end); }
            catch (BastionException e) { System.Diagnostics.Debug.WriteLine($"Gantry: activity end failed: {e.Message}"); }
        });
    }

    /// <summary>An RDP or VNC connect that failed before a tab opened: one record that never connected.</summary>
    private void RecordFailedActivity(string connectionId, string reason)
    {
        if (ActivityStartFor(connectionId) is not { } start) return;
        var dir = SessionDataDir;
        var end = new ActivityClient.SessionEnd(null, NowMs(), reason);
        _ = Task.Run(() =>
        {
            try { ActivityClient.End(dir, ActivityClient.Begin(dir, start), end); }
            catch (BastionException e) { System.Diagnostics.Debug.WriteLine($"Gantry: activity record failed: {e.Message}"); }
        });
    }
}
