using Windows.Graphics;
using System.Text.Json.Nodes;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Session restore (UX spec §1, core open_sessions, C ABI 80). The open SSH tabs (connection, terminal or files, split
// layout; never a secret) are saved after every tab change. A normal quit records a clean exit. After a normal quit with
// "Restore sessions on launch" on, the next launch reopens them through the normal connect flow, so a saved login
// connects with no sheet and the others ask to sign in. After a crash (owner decision D15, A2-W26) the launch plan's
// AutoReconnect is false: every remote tab comes back in its place, not connected, and nothing is sent to any host until
// the user chooses Reconnect on its session bar; that runs the normal connect flow. W26: remote desktop, VNC and web tabs
// of saved connections are kept too, and local shells (default shell, PowerShell, cmd, WSL) are kept in
// open-local-shells.txt beside the core's file and start again in both cases (they are not remote).
public sealed partial class MainWindow
{
    /// <summary>False until the launch plan has been read: saving earlier would overwrite the tabs it is about to restore.</summary>
    private bool _restoreReady;
    private string _lastSavedSessions = "";

    /// <summary>Read the launch plan once, after the first frame, and reopen its tabs.</summary>
    private void InitSessionRestore()
    {
        if (_demo) return;
        RootGrid.Loaded += OnLoadedRestore;
    }

    private void OnLoadedRestore(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        RootGrid.Loaded -= OnLoadedRestore;
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => _ = RestoreSessionsAsync());
    }

    private async Task RestoreSessionsAsync()
    {
        LaunchPlanDto plan;
        try { plan = SessionRestore.Begin(_library, SessionDataDir, SettingValue(SessionRestore.RestoreSettingId) != "false"); }
        catch (BastionException ex)
        {
            _restoreReady = true;
            Announce("Open sessions could not be read: " + ex.Message);
            return;
        }
        _restoreReady = true;
        var restoreLocal = plan.LastExit == "crash" || (plan.LastExit == "clean" && SettingValue(SessionRestore.RestoreSettingId) != "false");
        var locals = restoreLocal ? ReadLocalShells() : [];
        if ((!plan.Restore || plan.Tabs.Count == 0) && locals.Count == 0) { SaveOpenSessions(); return; }
        var all = plan.Restore ? plan.Tabs.Select(t => new WorkspaceTabDto(t.Connection, t.Mode, LayoutSteps(t.Layout))).ToList() : [];
        var count = all.Count + locals.Count;
        Announce(plan.LastExit == "crash" ? $"Restoring {Plural(count, "tab")} after an unexpected quit" : $"Restoring {Plural(count, "tab")}");
        // B12-W2d: a local shell saved in a torn-off window ("kind<TAB>x,y,w,h") reopens in a window at that frame.
        var tornLocals = new List<(WorkspaceTab Tab, RectInt32 Frame)>();
        foreach (var line in locals)
        {
            var (kind, frame) = ParseLocalShell(line);
            var before = _tabs.Count;
            OpenLocalShell(kind);
            if (frame is { } f && _tabs.Count > before) tornLocals.Add((_tabs[^1], f));
        }
        void ReopenTornLocals() { foreach (var (tab, f) in tornLocals) if (_tabs.Contains(tab) && IsDocked(tab)) TearOff(tab, null, f); }
        if (plan.Restore && !plan.AutoReconnect)
        {
            // After a crash (D15) nobody may be at the machine: put the tabs back without connecting.
            var gone = RestoreDisconnected(plan.Tabs, plan.Selected ?? 0);
            ReopenTornOffWindows(plan); // B12-W2c
            ReopenTornLocals();
            SaveOpenSessions();
            await ReportUnopenedTabs(gone + plan.Missing, 0, all.Count + plan.Missing, "from the last session");
            return;
        }
        // All saved tabs go through the workspace path in their saved order (PAR-6); SSH also gets its splits and files.
        var (missing, failedSplits) = await OpenSavedTabsAsync(all, plan.Selected ?? 0);
        ReopenTornOffWindows(plan); // B12-W2c
        ReopenTornLocals();
        SaveOpenSessions();
        await ReportUnopenedTabs(missing + plan.Missing, failedSplits, all.Count + plan.Missing, "from the last session");
    }

    private static readonly TimeSpan RestoreReconnectWait = TimeSpan.FromSeconds(30);
    private const double RestoredNoticeWidth = 480; // a comfortable line length for the two sentences of the notice

    /// <summary>Put each saved tab back in order as a tab that is not connected. Returns how many connections are gone.</summary>
    private int RestoreDisconnected(IReadOnlyList<OpenTabDto> saved, int selected)
    {
        var missing = 0;
        var opened = new List<WorkspaceTab>();
        foreach (var tab in saved)
        {
            if (FindItem(_roots, tab.Connection) is { Connection: { } c } item && CanOpen(item)) opened.Add(AddWaitingTab(item, c, tab));
            else missing++;
        }
        if (selected >= 0 && selected < opened.Count) ActivateTab(opened[selected]);
        return missing;
    }

    /// <summary>One not-connected tab: the connection's name and icon, a notice, and the session bar saying Disconnected.</summary>
    private WorkspaceTab AddWaitingTab(TreeItem item, ConnectionDto c, OpenTabDto saved)
    {
        var title = Ui.Text("Not connected", "SubtitleTextStyle");
        AutomationProperties.SetAutomationId(title, "RestoredTabNotice");
        var text = Ui.Text($"Gantry closed unexpectedly while this tab was open. Nothing has been sent to {c.Host}. Choose Reconnect to connect.", "BodyTextStyle");
        text.TextWrapping = TextWrapping.Wrap;
        // The notice sits on the session surface, so its text takes the session's colours, not the app theme's
        // (dark text on the dark terminal was unreadable, owner 2026-11-15).
        title.Foreground = Ui.Brush(RootGrid, "SessionForegroundBrush");
        text.Foreground = Ui.Brush(RootGrid, "SessionSecondaryForegroundBrush");
        var notice = new StackPanel
        {
            Spacing = Ui.Double("Space8"),
            Margin = new Thickness(Ui.Double("Space12")),
            MaxWidth = RestoredNoticeWidth,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Children = { title, text },
        };
        var glyph = IsWeb(item) ? "GlyphWeb" : IsRdp(item) || IsVnc(item) ? "GlyphDesktop" : saved.Mode == "files" || IsSshFiles(item) ? "GlyphFolder" : "GlyphTerminal";
        var tab = AddTab(item.Name, null, hostId: item.Id, waiting: saved, notice: notice, glyph: glyph);
        var address = $"{(string.IsNullOrWhiteSpace(c.Username) ? "" : c.Username + "@")}{c.Host}{(c.Port is { } port ? ":" + port : "")}";
        var bar = new SessionBar(RootGrid, $"{c.Name} ({address})", SessionBarPinned, () => _ = ConnectRestoredAsync(tab), pinned => SessionBarPinned = pinned,
            reconnectTip: "Connect this tab");
        bar.SetState(SessionBarState.Disconnected);
        Grid.SetColumnSpan(bar.Root, 2);
        tab.Body.Children.Add(bar.Root);
        tab.Bar = bar;
        PaintSessionIdentity(tab, tab.HostColorId is { } hid ? _hostColors.GetValueOrDefault(hid) : null); // UI-01
        SetTabStatus(tab, "disconnected");
        return tab;
    }

    /// <summary>Reconnect on a waiting tab: the normal connect flow (a saved login connects with no sheet: the user asked).
    /// The new session takes the tab's place, with its split panes and Files panel; a cancelled or failed connect leaves it.</summary>
    private async Task ConnectRestoredAsync(WorkspaceTab tab)
    {
        // W26: one log line per outcome (mode only, no names), so a Reconnect that opens nothing can be traced.
        void Trace(string what) => AppLog.Info($"restore reconnect ({tab.Waiting?.Mode ?? "-"}): {what}");
        if (tab.Waiting is not { } saved || !_tabs.Contains(tab)) { Trace("not a waiting tab"); return; }
        // A Reconnect pressed while a dialog (e.g. the saved-login question) or another connect is open used to be
        // dropped silently. Wait for it to clear, then connect; say so if it never does.
        if (!await WaitForConnectSlotAsync())
        {
            Trace($"still busy (dialog {_modal is not null}, connecting {_connecting})");
            Announce("Reconnect waits for the open dialog. Close it and choose Reconnect again.");
            return;
        }
        if (!_tabs.Contains(tab) || tab.Waiting is null) { Trace("tab gone while waiting"); return; }
        if (FindItem(_roots, saved.Connection) is not { } item)
        {
            Trace("connection not in the library");
            Announce("This connection is no longer in the library.");
            return;
        }
        SelectItem(item.Id);
        var before = _tabs.ToList();
        await ConnectAsync(item);
        if (IsWeb(item)) return; // AddTab gives a web page the waiting tab's place
        if (!_tabs.Contains(tab) || _tabs.Except(before).LastOrDefault() is not { } opened) { Trace("the connect opened no tab"); return; }
        await TakeRestoredPlaceAsync(tab, opened);
        if (!IsSsh(item) || opened.View is null) { Trace("connected"); return; }
        if (!ApplyLayout(opened, LayoutSteps(saved.Layout))) Announce("The split panes of this tab could not all be opened.");
        if (saved.Mode == "files" && opened.Files is null) await ToggleFilesAsync(opened);
        Trace(saved.Mode == "files" ? $"connected, Files panel {(opened.Files is null ? "not open" : "open")}" : "connected");
    }

    /// <summary>W26: ConnectAsync silently does nothing while a dialog or another connect is open. A restore that opens
    /// several tabs in a row (and Reconnect) waits for that to clear, e.g. the 'use this login from now on?' question the
    /// previous tab's connect left open. False when it is still open after <see cref="RestoreReconnectWait"/>.</summary>
    private async Task<bool> WaitForConnectSlotAsync()
    {
        var until = DateTime.UtcNow + RestoreReconnectWait;
        while ((_modal is not null || _connecting) && !_windowClosed && DateTime.UtcNow < until) await Task.Delay(200);
        return _modal is null && !_connecting && !_windowClosed;
    }

    /// <summary>Move <paramref name="opened"/> to where the waiting tab is and close the waiting tab.</summary>
    private async Task TakeRestoredPlaceAsync(WorkspaceTab waiting, WorkspaceTab opened)
    {
        if (ReferenceEquals(waiting, opened) || !_tabs.Contains(waiting)) return;
        await MoveTabAsync(opened, waiting, after: false);
        CloseTab(waiting);
        if (_tabs.Contains(opened)) ActivateTab(opened);
    }

    /// <summary>The saved layout as workspace steps ("leaf", "right:0.5", …); anything else is no split.</summary>
    private static List<string> LayoutSteps(JsonNode? layout) =>
        layout is JsonArray steps ? steps.Select(s => s?.GetValue<string>()).OfType<string>().ToList() : [];

    /// <summary>Save the open SSH tabs; skipped when nothing changed since the last save. With
    /// <paramref name="inBackground"/> the file write runs off the UI thread (a tab switch only changes the selected tab);
    /// writes stay in order, and a later save on the UI thread waits for the ones before it.</summary>
    private void SaveOpenSessions(bool inBackground = false)
    {
        if (!_restoreReady || _demo) return;
        var tabs = CurrentLayout().Select(t => new OpenTabDto(t.Connection, t.Mode, t.Layout is { Count: > 0 } l ? new JsonArray(l.Select(s => (JsonNode?)s).ToArray()) : null)).ToList();
        // W26/PAR-6: CurrentLayout covers SSH, remote desktop, VNC and web tabs of saved connections, in tab order.
        var saved = SavableTabs();
        // A2-W26: tabs still waiting after a crash stay in the set as they were saved, so a second quit does not lose them.
        foreach (var t in _tabs.Where(t => t.Waiting is not null))
        {
            tabs.Add(t.Waiting!);
            saved.Add(t);
        }
        // B12-W2c: which torn-off window each tab is in, and where those windows are.
        for (var i = 0; i < tabs.Count; i++) tabs[i] = tabs[i] with { Window = saved[i].Window?.Id.ToString() };
        var windows = SavedWindows(saved);
        SaveLocalShells();
        var selected = _active is { } a ? Math.Max(0, saved.IndexOf(a)) : 0;
        var key = string.Join("|", tabs.Select(t => $"{t.Connection}:{t.Mode}:{t.Layout?.ToJsonString()}:{t.Window}")) + "#" + selected
            + "#" + string.Join("|", windows.Select(w => $"{w.Id}:{w.X},{w.Y},{w.Width},{w.Height}"));
        if (key == _lastSavedSessions) return;
        _lastSavedSessions = key;
        var dir = SessionDataDir;
        if (inBackground)
        {
            lock (_sessionSaveLock)
                _sessionSaveChain = _sessionSaveChain.ContinueWith(_ => WriteOpenSessions(dir, tabs, selected, windows), TaskScheduler.Default);
            return;
        }
        Task pending;
        lock (_sessionSaveLock) pending = _sessionSaveChain;
        pending.Wait(); // an earlier background write must not land after this one
        WriteOpenSessions(dir, tabs, selected, windows);
    }

    private readonly object _sessionSaveLock = new();
    private Task _sessionSaveChain = Task.CompletedTask;

    private void WriteOpenSessions(string dir, List<OpenTabDto> tabs, int selected, IReadOnlyList<SavedWindowDto> windows)
    {
        try { SessionRestore.Save(dir, tabs, selected, windows: windows); }
        catch (BastionException ex)
        {
            if (DispatcherQueue.HasThreadAccess) { _lastSavedSessions = ""; Announce("Open sessions not saved: " + ex.Message); }
            else DispatcherQueue.TryEnqueue(() => { _lastSavedSessions = ""; Announce("Open sessions not saved: " + ex.Message); });
        }
    }

    private const string LocalShellsFile = "open-local-shells.txt";

    /// <summary>Kind of a local shell tab from its title: local, powershell, cmd, wsl or wsl:&lt;distro&gt;.</summary>
    private static string? LocalShellKind(WorkspaceTab tab) => tab switch
    {
        { ConnectionId: not null } or { StartLocal: null } => null,
        { DefaultTitle: "Local shell" } => "local",
        { DefaultTitle: "PowerShell" } => "powershell",
        { DefaultTitle: "Command Prompt" } => "cmd",
        { DefaultTitle: "WSL" } => "wsl",
        _ => "wsl:" + tab.DefaultTitle,
    };

    /// <summary>Restore: the tab is needed at once (a torn-off frame follows it), so the shell starts here, on the UI
    /// thread. A WSL distribution that is no longer installed opens nothing.</summary>
    private void OpenLocalShell(string kind)
    {
        if (!LocalShellInstalled(kind)) return;
        var (title, start) = LocalShellStart(kind);
        OpenTerminal(title, () => start(DefaultShellCols, DefaultShellRows));
    }

    private string _lastSavedLocals = "\0";

    private void SaveLocalShells()
    {
        var text = string.Join("\n", _tabs.Select(t => LocalShellKind(t) is { } kind
            ? t.Window is { } w ? $"{kind}\t{w.Frame.X},{w.Frame.Y},{w.Frame.Width},{w.Frame.Height}" : kind
            : null).OfType<string>());
        if (text == _lastSavedLocals) return;
        _lastSavedLocals = text;
        // Written off the UI thread, in order with the open-session saves: the write sat inside every local shell open
        // and close (WIN-STALL-USER). Quit waits for it (WaitSessionSaves). A failed write is retried at the next change.
        var path = Path.Combine(SessionDataDir, LocalShellsFile);
        lock (_sessionSaveLock)
            _sessionSaveChain = _sessionSaveChain.ContinueWith(_ =>
            {
                try { File.WriteAllText(path, text); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    DispatcherQueue.TryEnqueue(() =>
                    {
                        if (_lastSavedLocals == text) _lastSavedLocals = "\0";
                        Announce("Open local shells not saved: " + ex.Message);
                    });
                }
            }, TaskScheduler.Default);
    }

    /// <summary>Quit: the queued session and local-shell writes land before the process ends.</summary>
    private void WaitSessionSaves()
    {
        Task pending;
        lock (_sessionSaveLock) pending = _sessionSaveChain;
        try { pending.Wait(TimeSpan.FromSeconds(5)); }
        catch (AggregateException) { /* each write reports its own failure */ }
    }

    /// <summary>A line of open-local-shells.txt: the kind, and the torn-off window's frame when it had one.</summary>
    private static (string Kind, RectInt32? Frame) ParseLocalShell(string line)
    {
        var parts = line.Split('\t', 2);
        if (parts.Length < 2) return (line, null);
        var n = parts[1].Split(',');
        if (n.Length == 4 && int.TryParse(n[0], out var x) && int.TryParse(n[1], out var y) && int.TryParse(n[2], out var w) && int.TryParse(n[3], out var h) && w > 0 && h > 0)
            return (parts[0], new RectInt32(x, y, w, h));
        return (parts[0], null);
    }

    private List<string> ReadLocalShells()
    {
        try { return File.ReadAllLines(Path.Combine(SessionDataDir, LocalShellsFile)).Where(l => l.Length > 0).Take(64).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>A normal quit: the next launch restores only when the setting asks for it.</summary>
    private void MarkCleanQuit()
    {
        if (!_restoreReady || _demo) return;
        SaveOpenSessions();
        try { SessionRestore.MarkCleanQuit(SessionDataDir); }
        catch (BastionException) { /* the next launch then treats this quit as a crash and offers the tabs again */ }
    }
}
