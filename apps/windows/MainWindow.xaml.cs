using System.Runtime.InteropServices;
using Bastion.Shell.Interop;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;
using Windows.UI.Core;
using DispatcherQueuePriority = Microsoft.UI.Dispatching.DispatcherQueuePriority;
using DispatcherQueueTimer = Microsoft.UI.Dispatching.DispatcherQueueTimer;

namespace Bastion.Shell;

// Why the dialogs are an in-window modal and not ContentDialog:
// on the Windows 10 development machine (build 19045, NVIDIA GTX 1070, driver 32.0.15.8278) running composition
// animations keep the process's DirectComposition frame thread busy, and a ContentDialog never finished its close
// animation, so ShowAsync never returned and "Add" silently did nothing. The modal below completes from plain click
// and key events. Whether other machines or Windows 11 show the problem is not known (docs/TESTING.md,
// "WinUI CPU spin"). The same constraint explains the custom tab strip (TabView idles at 100% of a core there) and
// the transition-free button templates in Themes/Buttons.xaml.
public sealed partial class MainWindow : Window
{
    /// <summary>The tree on screen: the Personal library or an open document (MainWindow.Documents.cs).</summary>
    private LibraryClient _library;
    /// <summary>The Personal library; settings, the vault and session data live beside it.</summary>
    private readonly LibraryClient _personal;
    private CredentialStore? _credentials;
    private readonly AppearanceSettings _appearance;
    /// <summary>Snapshot mode: throwaway demo data that must never be written to disk.</summary>
    private readonly bool _demo;
    private readonly DispatcherQueueTimer _searchTimer;
    private readonly DispatcherQueueTimer _copiedTimer;
    /// <summary>Polls supervised SSH tabs for reconnect state while any is open.</summary>
    private readonly DispatcherQueueTimer _linkTimer;
    private readonly SolidColorBrush _transparent = new(Microsoft.UI.Colors.Transparent);

    /// <summary>The whole library, and what the tree shows (the same list unless a search is active).</summary>
    private List<TreeItem> _roots = new();
    /// <summary>Every tag in the library, made on first use after each tree load (tag suggestions, Run on › Tag).</summary>
    private IReadOnlyList<string>? _libraryTags;
    private List<TreeItem> _shown = new();

    /// <summary>The tree's ItemsSource: a copy of <see cref="_shown"/> whose single rows can be swapped (Other sessions, Application).</summary>
    private TreeChildren _shownSource = new();
    private string _query = "";
    private TreeItem? _contextTarget;

    /// <summary>Opened on the first connect: the broker, audit log and known_hosts next to the library file.</summary>
    private SessionManagerClient? _sessions;

    /// <summary>Set first thing in <c>Closed</c>: a connect that returns afterwards only frees what it opened (Codex W02).</summary>
    private bool _windowClosed;
    /// <summary>Serves `bastion ping|list|open` on the owner-only pipe; null when another instance already listens.</summary>
    private IpcListener? _ipc;
    private readonly DispatcherQueueTimer _ipcTimer;
    /// <summary>A connection the CLI asked to open while a dialog was up; opened once the window is free.</summary>
    private string? _ipcWaiting;
    /// <summary>One connect attempt at a time, so a slow server cannot stack up dialogs.</summary>
    private bool _connecting;

    // Pane state: what the user asked for, whether the window is too narrow, and an explicit "show anyway".
    private bool _navWanted = true, _inspectorWanted;
    private bool _navNarrow, _inspectorNarrow, _navForced, _inspectorForced;
    /// <summary>Collapsed for now because a session has focus and auto-hide is on; not saved.</summary>
    private bool _navAutoHidden;
    private double _navWidth, _inspectorWidth;

    /// <summary>Why the library did not open; the window then shows only this error (App decides what follows).</summary>
    internal Exception? OpenError { get; private set; }

    // CS8618: on the open-error path the constructor returns early and the window shows only the error text; none of
    // the fields set below are used then (no handlers are attached before that point except the tree's).
#pragma warning disable CS8618
    public MainWindow(Func<LibraryClient> openLibrary, bool readOnlyDemo)
#pragma warning restore CS8618
    {
        // WIN-COLD-START round 4: the Window base constructor (HWND, compositor) and the XAML need no library, so they run
        // before the library opens. On a first launch the open waits for the antivirus scan of the core DLL, which a
        // worker started at process start (ColdPrefetch.WarmCoreImage); this work now runs while that scan finishes.
        StartupProbe.Mark("window-new"); // after the Window base constructor
#if BASTION_TEST_HOOKS
        try { InitializeComponent(); } // WIN-AOT diagnostics: name the XAML parse failure on stderr (test builds only)
        catch (Exception ex) { Console.Error.WriteLine("MainWindow.InitializeComponent failed: " + ex); Console.Error.Flush(); throw; }
#else
        InitializeComponent();
#endif
        Tree.MultiSelectionChanged += Tree_MultiSelectionChanged; // MainWindow.TreeMulti.cs
        StartupProbe.Mark("xaml");
        LibraryClient library;
        try { library = openLibrary(); }
        catch (Exception e)
        {
            ShowOpenError(e);
            return;
        }
        StartupProbe.Mark("library");
        // The first tree read (core tree JSON, parse, all host colours) runs on a worker while the window is set up; the
        // core handle is shared and its reads take &self. Only the first Reload uses it; the rows are still built here.
        _firstTree = Task.Run(() => (library.Tree(), LoadHostColorsFrom(library)));
        _library = library;
        _personal = library;
        _demo = readOnlyDemo;
        BuildBeforeFirstFrame(); // snapshot runs and the BASTION_COLD_EAGER A/B only (MainWindow.LightStart.cs)
        Title = "Gantry";
        _navWidth = Ui.Double("NavPaneWidthValue");
        _inspectorWidth = Ui.Double("InspectorWidthValue");
        SizeWindow();
        StartupProbe.Mark("size");
        // The content goes into the title bar after the first frame (#145, owner: "FLASH OK"): extending costs ~170 ms
        // before the first frame on Windows 10, so the window shows a standard title bar for a moment first.
        ApplyBackdrop();
        StartupProbe.Mark("backdrop");
        // The title bar colours are applied on RootGrid.Loaded, before the first frame (Windows 10 drops them if set earlier).
        InitFullScreen();
        StartupProbe.Mark("fullscreen");


        _searchTimer = DispatcherQueue.CreateTimer();
        _searchTimer.Interval = TimeSpan.FromMilliseconds(SearchDebounceMs);
        _searchTimer.IsRepeating = false;
        _searchTimer.Tick += (_, _) => ApplyFilter(keepSelection: true, perfLabel: KeystrokePerfLabel);
        _copiedTimer = DispatcherQueue.CreateTimer();
        _copiedTimer.Interval = TimeSpan.FromSeconds(1.5);
        _copiedTimer.IsRepeating = false;
        _copiedTimer.Tick += (_, _) => { if (CopyHostLabel is { } label) label.Visibility = Visibility.Collapsed; }; // icon only, so Connect, Edit and Delete fit beside it
        _linkTimer = DispatcherQueue.CreateTimer();
        _linkTimer.Interval = TimeSpan.FromMilliseconds(500);
        _linkTimer.IsRepeating = true;
        _linkTimer.Tick += (_, _) => PollLinks();
        _ipcTimer = DispatcherQueue.CreateTimer();
        _ipcTimer.Interval = TimeSpan.FromMilliseconds(300);
        _ipcTimer.IsRepeating = true;
        _ipcTimer.Tick += (_, _) => PollIpc();

        ConfigureSplitters();
        StartupProbe.Mark("splitters");
        AppWindow.Closing += OnAppWindowClosing;
        InitRemoteAltF4();
        Closed += (_, _) =>
        {
            // BASTION_CLOSE_TRACE times each step (close-to-exit budget: under 1 s).
            CloseTrace.Begin("closed");
            static void S(string name, Action step) => CloseTrace.Step(name, step);
            // The process ends at the bottom of this handler: write the open-session list one last time (a no-op when
            // nothing changed; every other setting and library save is already written synchronously).
            S("save-open-sessions", () => SaveOpenSessions());
            S("wait-session-saves", WaitSessionSaves); // the local-shell list is written off the UI thread
            S("save-window-frame", SaveWindowFrame); // Window at launch: Remember last size and position
            S("close-torn-off", CloseTornOffWindows); // B12-W2b: before the tabs are disposed
            S("close-settings", CloseSettings);
            _closed = true;
            // The tree's ItemsSource is left alone: clearing it mid-realisation re-entered layout (0xc00000fd).
            _copiedTimer.Stop();
            // End every terminal's program and free its native handle before the library goes away. Each SSH
            // terminal owns its connection, so the session manager is released after them.
            _windowClosed = true;
            Microsoft.Windows.System.Power.PowerManager.SystemSuspendStatusChanged -= OnSuspendStatusChanged;
            S("mark-clean-quit", MarkCleanQuit);
            S("dispose-tray", DisposeTray);
            S("stop-gate-countdown", StopGateCountdown); // its tick reads a document that is disposed next
            S("dispose-documents", DisposeDocuments);
            S("stop-network-watch", StopNetworkWatch);
            _linkTimer.Stop();
            _ipcTimer.Stop();
            _idle?.Stop();
            S("ipc-dispose", () => _ipc?.Dispose());
            S("tabs-dispose", () =>
            {
                foreach (var tab in _tabs.ToList())
                {
                    tab.Link?.Dispose();
                    tab.Files?.Dispose();
                    tab.Web?.Dispose();
                    tab.Rdp?.Dispose();
                    tab.Plugin?.Dispose();
                    foreach (var pane in tab.AllPanes) pane.Dispose();
                }
            });
            S("sessions-dispose", () => _sessions?.Dispose());
            S("flush-library-saves", FlushLibrarySaves); // every queued background save is on disk before the libraries go and before Exit
            S("quick-libraries-dispose", DisposeQuickLibraries);
            S("credentials-dispose", () => _credentials?.Dispose());
            S("vaultwarden-dispose", () => _vaultwarden?.Dispose());
            S("library-dispose", _library.Dispose);
            CloseTrace.Begin("closed-done");
            // Closing the main window ends the app, and everything on disk is final here (queued saves flushed and
            // everything disposed above; the app log writes through). End the process now instead of letting WinUI release
            // the realised tree: on a 5,000-row library that took over 5 s, and mid-realisation (the start-up probe's
            // close) it overflowed the stack in combase. Snapshot runs keep their own exit path.
            if (!SnapshotRunner.Active) Environment.Exit(0);
        };
        RootGrid.PreviewKeyDown += Root_PreviewKeyDown;
        // handledEventsToo: NumberBox marks Enter handled after committing its value; the dialog still submits.
        RootGrid.AddHandler(UIElement.KeyDownEvent, new KeyEventHandler(Modal_KeyDown), true);
        RootGrid.SizeChanged += (_, _) => { UpdatePanes(); UpdateToolbarLabels(); };
        // XAML resources switch to the HighContrast dictionaries by themselves. AccessibilitySettings.HighContrastChanged
        // cannot be subscribed from a desktop app (0x80070490), so code-painted tab colours refresh on their next paint.
        RootGrid.ActualThemeChanged += (_, _) => OnThemeChanged();
        RootGrid.Loaded += (_, _) => StartupProbe.Mark("loaded");
        // Before the first frame only a dark window sets its system title bar (a light one keeps the default, already
        // light: ApplyTitleBarPreference): the colours (a dozen AppWindow calls,
        // ~90 ms on a cold start) are applied after it, with the content moved into the title bar (StartDeferredServices),
        // where they are set again anyway because colours set before the window is shown do not stick on Windows 10.
        RootGrid.Loaded += (_, _) =>
        {
            _titleBarTheme = null;
            ApplyTitleBarPreference();
            StartupProbe.Mark("titlebar-pref"); // WIN-COLD-LIGHT: splits loaded -> frame1 on slow boots
        };
        HookRecentlyDeleted();

        _appearance = AppearanceSettings.Load(library.Path);
        TermThemes.DataDir = Path.GetDirectoryName(Path.GetFullPath(library.Path));
        _navWanted = !_appearance.NavHidden;
        ApplyDock();
        UpdatePinButton();
        StartupProbe.Mark("appearance");
        InitInspectorState();
        ApplyInspectorLayout(false); // the pane is not built yet: keep its column closed until it is first shown
        StartupProbe.Mark("inspector");
        Layer.GotFocus += Layer_GotFocus;
        InitTreeState();
        InitSessionTree();
        InitTreeRightPress();
        Tree.RowPrepared += row => { ApplyRowDensity(row); HookRowDrop(row); }; // as rows are created or recycled
        Action<LibraryRow>? warm = null;
        warm = prepared => { Tree.RowPrepared -= warm; PrewarmFilterPath(); PrewarmTerminal(); PrewarmDashboard(); _ = RefreshWslMenuAsync(); }; // WIN-SPEED-NIGHT5: after the first row is painted
        Tree.RowPrepared += warm;
        if (StartupProbe.Active)
        {
            Action<LibraryRow>? firstRow = null;
            firstRow = _ => { Tree.RowPrepared -= firstRow; StartupProbe.Mark("first-row"); };
            Tree.RowPrepared += firstRow;
        }
        InitTreeInputLog();
        StartupProbe.Mark("tree-state");
        InitSettings();
        StartupProbe.Mark("settings");
        StartupProbe.Mark("init");
        Reload(selectId: null);
        StartupProbe.Mark("reload");
        // Before the first frame: the zoom and the document gate change what is painted.
        InitZoom();
        MigrateKnownDocuments(); // A1-CORE-01-FU5: before the gate or a restore opens a document
        InitDocumentGate();
        InitSessionRestore();
        InitAppIcon();
        // The screen-lock hook as soon as the window has its handle: two system calls, no disk I/O. After the first frame
        // (deferred, low priority) a lock in the first seconds of a cold start was missed (lock-reopen wave 4).
        InitScreenLock();
        InitMinimumSize();
        InitKeyFocus(); // a window activated with nothing focused still takes Ctrl+N and the other shortcuts
        // The toolbar joins the title bar after the first frame (InitTitleBar). Drawn before that, it would show under the
        // standard title bar and then jump into it: the first frames show the standard title bar alone ("FLASH OK"). It is
        // built then too (WIN-COLD-LIGHT, MainWindow.LightStart.cs), so the first frame parses none of it.
        Startup.AfterFirstFrame(this, StartDeferredServices);
#if BASTION_TEST_HOOKS
        if (TestHooks.WebFillSeed) Startup.AfterFirstFrame(this, SeedWebFillForTest);
        if (TestHooks.PveSeedPort is { } pvePort) Startup.AfterFirstFrame(this, () => SeedPveForTest(pvePort));
        if (TestHooks.K8sSeedPort is { } k8sPort) Startup.AfterFirstFrame(this, () => SeedK8sForTest(k8sPort));
        if (TestHooks.VmwSeedPort is { } vmwPort) Startup.AfterFirstFrame(this, () => SeedVmwForTest(vmwPort));
        if (TestHooks.PgSeed is { } pgSeed) Startup.AfterFirstFrame(this, () => SeedPgForTest(pgSeed));
        if (TestHooks.ExecSeed is { } execSeed) Startup.AfterFirstFrame(this, () => SeedExecForTest(execSeed));
        if (LeakProbe.DrillOn) Startup.AfterFirstFrame(this, () => _ = RunLeakDrill()); // WIN-SHELL-LEAK drill
#endif
        PerfTrace.StartStallWatch(DispatcherQueue); // test builds with BASTION_PERF_TRACE only
    }

    private bool _closed;

    /// <summary>
    /// Work that no one needs before the window is on screen (start-up budget, docs/TESTING.md): the CLI's IPC
    /// endpoint, the sleep/resume hook, the More sub-menus and the tray icon. Requests that arrive earlier wait in the pipe's queue.
    /// </summary>
    private void StartDeferredServices()
    {
        if (_closed) return;
        _firstFramesDone = true;
        BuildTitleBar(); // WIN-COLD-LIGHT: not part of the first frames; shown below once it is in the title bar
        BuildSearchBox(); // WIN-COLD-LIGHT: replaces the first frame's look-alike
        RealiseHosts();
        // WIN-STARTUP: not painted, so after the first frame: the network fingerprint and watcher, the activity-log
        // housekeeping and the Recently Deleted purge (a library read and possibly a save).
        StartAppLog();
        StartNetworkWatch();
        StartActivityHousekeeping();
        StartSessionLogPurge(); // LOG-CORE-02 retention, off the UI thread
        PurgeDeleted();
        try
        {
            InitTitleBar();
        }
        catch (Exception e) when (e is COMException or InvalidOperationException or ArgumentException)
        {
            CrashLog.Write(e); // keep the standard title bar; the rest of the deferred start still runs
        }
        // The colours (the caption buttons, or the standard title bar if extending failed): first applied here, after the
        // first frame (RootGrid.Loaded sets only the light or dark preference).
        _titleBarTheme = null;
        ApplyTitleBarTheme();
        Toolbar.Visibility = Visibility.Visible;
        ApplyToolbarTips();
        UpdateToolbarLabels(); // measured while collapsed it always fit
        PlaceStartupFocus();
        // Not painted: the temp-folder sweep (sync disk I/O) waits for the first frame too. The session-lock hook is
        // installed in the constructor.
        if (!_demo) FinishPendingUpdate();
        // Sleep drops every supervised SSH link on purpose; resume brings them back (core session supervisor).
        Microsoft.Windows.System.Power.PowerManager.SystemSuspendStatusChanged += OnSuspendStatusChanged;
        try
        {
            _ipc = IpcListener.Start(_library, SessionDataDir);
            _ipcTimer.Start();
        }
        catch (BastionException) { /* another Bastion window already serves this library; the CLI talks to that one */ }
        // Menus behind More › sub-items: nobody can open them before the first frame.
        BuildTerminalColorsMenu();
        BuildTypeDefaultsMenu();
        BuildDocumentsMenu();
        BuildFullScreenMenu();
        InitTray();
        // WIN-COLD-LIGHT: the Credentials section and Recent sessions, after a frame with the title bar in place.
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, BuildAfterFirstFrame);
    }

    /// <summary>The element a snapshot renders.</summary>
    public FrameworkElement RootElement => RootGrid;

    // ---- Window chrome ----

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hwnd);

    private IntPtr Hwnd => WinRT.Interop.WindowNative.GetWindowHandle(this);

    /// <summary>Default size in effective pixels scaled to the monitor's DPI, centred in the work area, plus a minimum size.</summary>
    private bool _launchStateApplied;

    private void SizeWindow()
    {
        var scale = Math.Max(96u, GetDpiForWindow(Hwnd)) / 96.0;
        var work = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        // Settings › General › Window at launch (MainWindow.WindowLaunch.cs); demo and snapshot runs keep the standard size.
        var frame = LaunchFrame(scale, new PixelRect(work.X, work.Y, work.Width, work.Height), out var maximize, out var fullScreen);
        AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(frame.X, frame.Y, frame.Width, frame.Height));
        if (!_launchStateApplied) { _launchStateApplied = true; ApplyLaunchState(maximize, fullScreen); }
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.PreferredMinimumWidth = (int)(Ui.Double("WindowMinWidth") * scale);
            presenter.PreferredMinimumHeight = (int)(Ui.Double("WindowMinHeight") * scale);
        }
    }

    /// <summary>Mica on Windows 11 only (build 22000+ and supported); everywhere else the solid shell background.</summary>
    private void ApplyBackdrop()
    {
        if (_demo) return; // snapshots need an opaque, deterministic background
        try
        {
            if (Environment.OSVersion.Version.Build < 22000 || !MicaController.IsSupported()) return;
            SystemBackdrop = new MicaBackdrop();
            RootGrid.Background = _transparent;
        }
        catch
        {
            // Any failure leaves the solid background from the XAML in place.
        }
    }

    /// <summary>
    /// The system title bar takes the shell colours of the current theme, so title bar and toolbar read as one header
    /// (AppWindow.TitleBar colours; Windows 10 otherwise draws a white title bar over the dark theme, and the DWM
    /// immersive-dark-mode attribute is ignored for this window there). High contrast keeps the system defaults.
    /// Content extends into the title bar (MainWindow.TitleBar.cs); only the system caption buttons are painted here.
    /// </summary>
    private void ApplyTitleBarTheme()
    {
        if (_tones is not null) { ApplyTitleBarTones(_tones); return; }
        // Before the root is loaded its ActualTheme is not resolved yet; the app theme is what it will be.
        var theme = RootGrid.IsLoaded ? RootGrid.ActualTheme
            : Application.Current.RequestedTheme == ApplicationTheme.Dark ? ElementTheme.Dark : ElementTheme.Light;
        var key = Ui.HighContrast ? "HighContrast" : theme == ElementTheme.Dark ? "Dark" : "Light";
        if (key == _titleBarTheme) return;
        _titleBarTheme = key;
        try
        {
            var bar = AppWindow.TitleBar;
            // Light or dark system title bar (App SDK 1.7+); Windows 10 ignores the colours below without it.
            bar.PreferredTheme = key switch { "Dark" => TitleBarTheme.Dark, "Light" => TitleBarTheme.Light, _ => TitleBarTheme.UseDefaultAppMode };
            if (!AppWindowTitleBar.IsCustomizationSupported()) return;
            if (key == "HighContrast")
            {
                bar.ResetToDefault();
                return;
            }
            var background = Ui.ThemeColor(key, "ShellBackgroundBrush");
            var foreground = Ui.ThemeColor(key, "TitleBarForegroundColor");
            var inactive = Ui.ThemeColor(key, "TitleBarInactiveForegroundColor");
            bar.BackgroundColor = bar.InactiveBackgroundColor = background;
            bar.ButtonBackgroundColor = bar.ButtonInactiveBackgroundColor = background;
            bar.ForegroundColor = bar.ButtonForegroundColor = bar.ButtonHoverForegroundColor = bar.ButtonPressedForegroundColor = foreground;
            bar.InactiveForegroundColor = bar.ButtonInactiveForegroundColor = inactive;
            bar.ButtonHoverBackgroundColor = Ui.ThemeColor(key, "TitleBarButtonHoverColor");
            bar.ButtonPressedBackgroundColor = Ui.ThemeColor(key, "TitleBarButtonPressedColor");
        }
        catch
        {
            // Title bar colours are cosmetic; the default title bar stays.
        }
    }

    private string? _titleBarTheme;

    /// <summary>
    /// Only the dark system title bar, for the frames before <see cref="ApplyTitleBarTheme"/> runs. A light window
    /// needs nothing here: the default (TitleBarTheme.Legacy) is already the light system title bar, and this call
    /// (the setter and the first high-contrast read) took 84-248 ms on 7 of 10 boots in q-cold-reboot6
    /// (WIN-COLD-LIGHT). ApplyTitleBarTheme sets the theme and colours right after the first frame either way.
    /// </summary>
    private void ApplyTitleBarPreference()
    {
        try
        {
            var theme = RootGrid.ActualTheme;
            if (theme != ElementTheme.Dark && !BuildsEverythingFirst) return;
            AppWindow.TitleBar.PreferredTheme = Ui.HighContrast ? TitleBarTheme.UseDefaultAppMode
                : theme == ElementTheme.Dark ? TitleBarTheme.Dark : TitleBarTheme.Light;
        }
        catch
        {
            // Cosmetic, as in ApplyTitleBarTheme: the default title bar stays until the colours are applied.
        }
    }

    private void OnThemeChanged()
    {
        ApplyTitleBarTheme();
        foreach (var tab in _tabs) { PaintTab(tab); tab.Bar?.Repaint(); }
        _iconColors = null; // the core's icon tints differ per theme
        if (_appearance.TerminalTheme == AppearanceSettings.MatchAppTheme) RepaintAppTerminalTheme(); // Match app theme follows the switch
        SyncSessionSurface(); // a non-terminal tab's surface follows the theme dictionary
        Reload(CurrentSelectionId);
    }

    // ---- Panes ----

    private void ConfigureSplitters()
    {
        NavSplitter.Column = NavColumn;
        NavSplitter.MinValue = Ui.Double("NavPaneMinWidth");
        NavSplitter.MaxValue = Ui.Double("NavPaneMaxWidth");
        NavSplitter.DefaultValue = Ui.Double("NavPaneWidthValue");
        NavSplitter.WidthCommitted += (_, _) => _navWidth = NavColumn.Width.Value;
        InspectorSplitter.Column = InspectorColumn;
        InspectorSplitter.ColumnIsAfter = true;
        InspectorSplitter.MinValue = Ui.Double("InspectorMinWidth");
        InspectorSplitter.MaxValue = Ui.Double("InspectorMaxWidth");
        InspectorSplitter.DefaultValue = Ui.Double("InspectorWidthValue");
        InspectorSplitter.WidthCommitted += (_, _) => _inspectorWidth = InspectorColumn.Width.Value;
    }

    // Logical visibility flips at once; a hiding pane stays laid out until its slide-out ends (Motion.Slide).
    private bool NavVisible => NavPane.Visibility == Visibility.Visible && !_navHiding && !_dockPeek;
    private bool InspectorVisible => Inspector is { Visibility: Visibility.Visible } && !_inspectorHiding;
    private bool _navHiding, _inspectorHiding;
    private int _navMotion, _inspectorMotion; // a newer slide makes an older slide-out's end a no-op

    /// <summary>Apply the pane choices to the current width: narrow windows hide the inspector, then the navigation pane.</summary>
    private void UpdatePanes()
    {
        var width = RootGrid.ActualWidth;
        if (width <= 0) return;
        var navNarrow = width < Ui.Double("NavAutoHideWidth");
        var inspectorNarrow = width < Ui.Double("InspectorAutoHideWidth");
        if (navNarrow != _navNarrow) { _navNarrow = navNarrow; _navForced = false; }
        if (inspectorNarrow != _inspectorNarrow) { _inspectorNarrow = inspectorNarrow; _inspectorForced = false; }
        SetNav(_navWanted && !_navAutoHidden && !_navDocked && (!_navNarrow || _navForced));
        SetInspector(InspectorShown && InspectorHasSubject && (!_inspectorNarrow || _inspectorForced));
        var workspaceMin = Ui.Double("WorkspaceMinWidth");
        NavSplitter.MaxValue = Math.Min(Ui.Double("NavPaneMaxWidth"), width - (InspectorVisible ? InspectorColumn.Width.Value : 0) - workspaceMin);
        InspectorSplitter.MaxValue = Math.Min(Ui.Double("InspectorMaxWidth"), width - (NavVisible ? NavColumn.Width.Value : 0) - workspaceMin);
    }

    private void SetNav(bool visible)
    {
        if (visible == NavVisible) return;
        if (!visible && NavColumn.Width.Value > 0) _navWidth = NavColumn.Width.Value;
        var hadFocus = !visible && Contains(NavPane, FocusedElement);
        _navHiding = !visible;
        var navMotion = ++_navMotion;
        if (visible)
        {
            // Shown: the column grows from where it is to the remembered width while the pane slides in.
            var from = NavColumn.ActualWidth;
            ApplyNavLayout(true);
            AnimateNavColumn(from, _navWidth, navMotion, () => NavColumn.MinWidth = Ui.Double("NavPaneMinWidth"));
        }
        else
        {
            // Hidden: the column narrows with the slide-out, and the pane collapses when both are done.
            AnimateNavColumn(NavColumn.ActualWidth, 0, navMotion, () => { });
        }
        Motion.Slide(NavPane, visible, edge: -1, hidden: () => { if (_navHiding && navMotion == _navMotion) { _navHiding = false; StopNavColumn(); ApplyNavLayout(false); } });
        if (hadFocus) FocusWorkspace();
    }

    /// <summary>The details pane has something to show: a selected connection (owner rule: only then). Not at start, on the
    /// Welcome page with a folder or nothing selected, nor over a full page (Documents, Workspaces, the managers) or the
    /// document gate. The remembered toggle is not changed.</summary>
    private bool InspectorHasSubject =>
        PageHost is not { Visibility: Visibility.Visible } && _gate is not { Visibility: Visibility.Visible }
        && _tabs.Count == 0 // owner rule: an open session hides it
        && _inspectorPending is { IsGroup: false, IsFolder: false };

    private void SetInspector(bool visible)
    {
        if (visible == InspectorVisible) return;
        if (!visible && InspectorColumn.Width.Value > 0) _inspectorWidth = InspectorColumn.Width.Value;
        var hadFocus = !visible && Inspector is not null && Contains(Inspector, FocusedElement);
        _inspectorHiding = !visible;
        if (visible) ApplyInspectorLayout(true);
        var inspectorMotion = ++_inspectorMotion;
        Motion.Slide(Inspector!, visible, edge: 1, hidden: () => { if (_inspectorHiding && inspectorMotion == _inspectorMotion) { _inspectorHiding = false; ApplyInspectorLayout(false); } });
        if (hadFocus) FocusWorkspace();
    }

    private void ApplyNavLayout(bool visible)
    {
        NavPane.Visibility = NavSplitter.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        NavColumn.MinWidth = visible ? Ui.Double("NavPaneMinWidth") : 0;
        NavColumn.Width = new GridLength(visible ? _navWidth : 0);
        UpdateCompactLibraryWidth();
        // ActualWidth still holds the old width until the next layout pass: measure again after it.
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, UpdateCompactLibraryWidth);
    }

    private void ApplyInspectorLayout(bool visible)
    {
        if (Inspector is null)
        {
            if (visible) EnsureInspector();
            else { InspectorSplitter.Visibility = Visibility.Collapsed; InspectorColumn.MinWidth = 0; InspectorColumn.Width = new GridLength(0); return; }
        }
        if (ApplyInspectorOverlay(visible)) return; // full screen: over the sessions (MainWindow.InspectorState.cs)
        Inspector!.Visibility = InspectorSplitter.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        InspectorColumn.MinWidth = visible ? Ui.Double("InspectorMinWidth") : 0;
        InspectorColumn.Width = new GridLength(visible ? _inspectorWidth : 0);
    }

    /// <summary>
    /// Owner point 25: the user showed the pane while a session is open, so auto-hide leaves it alone until they hide it
    /// again (before, the next click into the session hid it straight away and it could never be pinned).
    /// </summary>
    private bool _navPinned;

    private void ShowNav(bool show)
    {
        _navPinned = show && _active is not null;
        _navWanted = show;
        _navAutoHidden = false;
        _appearance.SetNav(!show, _appearance.NavAutoHide, save: !_demo);
        _navForced = show && _navNarrow;
        UpdatePanes();
        ApplyDock(); // unpinned: the pane leaves its column and the left edge reveals it (W7)
    }

    /// <summary>W7: the pin on the pane itself. Pinned keeps the pane in its column; unpinned slides it away and the
    /// pointer at the far left edge brings it back over the content.</summary>
    private void NavPin_Click(object sender, RoutedEventArgs e) => ShowNav(!_navWanted);

    private void UpdatePinButton()
    {
        var label = _navWanted ? "Unpin navigation pane" : "Pin navigation pane";
        ToolTipService.SetToolTip(NavPinButton, label + " (Ctrl+Alt+N). Unpinned, point at the left edge to show it.");
        AutomationProperties.SetName(NavPinButton, label);
        ((FontIcon)NavPinButton.Content).Glyph = Ui.String(_navWanted ? "GlyphUnpin" : "GlyphPin");
    }

    private void ShowInspector(bool show)
    {
        _inspectorWanted = show;
        RememberInspector(show);
        _inspectorForced = show && _inspectorNarrow;
        UpdatePanes();
    }

    private void NavToggle_Click(object sender, RoutedEventArgs e) => ShowNav(NavToggle.IsChecked);


    /// <summary>Ctrl+Alt+N toggles what is on screen. In a narrow window the pane is wanted but hidden for the width, so
    /// the first press shows it rather than hiding an already hidden pane (NW-NAV-01).</summary>
    private void ToggleNav()
    {
        if (_navWanted && ToggleDockPeek()) return;
        var hiddenForWidth = _navWanted && _navNarrow && !_navForced;
        ShowNav(hiddenForWidth || !_navWanted);
    }

    internal string ToggleNavForSnapshot()
    {
        ToggleNav();
        return $"visible={NavVisible} saved-hidden={_appearance.NavHidden} button=\"{AutomationProperties.GetName(NavPinButton)}\"";
    }

    private void NavAutoHideToggle_Click(object sender, RoutedEventArgs e)
    {
        _appearance.SetNav(_appearance.NavHidden, NavAutoHideToggle.IsChecked, save: !_demo);
        if (!NavAutoHideToggle.IsChecked && _navAutoHidden) { _navAutoHidden = false; UpdatePanes(); }
    }

    /// <summary>Auto-hide: focus moving into the open session collapses the navigation pane until it is shown again.</summary>
    private void Layer_GotFocus(object sender, RoutedEventArgs e)
    {
        if (!_appearance.NavAutoHide || _navPinned || _navAutoHidden || !NavVisible || _active is null) return;
        if (e.OriginalSource is not DependencyObject source || !Contains(_active.Body, source)) return;
        _navAutoHidden = true;
        UpdatePanes();
    }

    private void InspectorToggle_Click(object sender, RoutedEventArgs e) => ShowInspector(InspectorToggle.IsChecked);

    private void HideInspector_Click(object sender, RoutedEventArgs e) => ShowInspector(false);

    private void MoreMenu_Opening(object sender, object e)
    {
        NavToggle.IsChecked = NavVisible;
        NavAutoHideToggle.IsChecked = _appearance.NavAutoHide;
        // The saved choice when there is nothing to show (Welcome, a page): the pane is hidden there even when the choice
        // is on, and a check from what is on screen made the next click save it as on again.
        InspectorToggle.IsChecked = InspectorHasSubject ? InspectorVisible : _inspectorWanted;
        MoreDelete.IsEnabled = Selected is not null;
        MoreSplitRight.IsEnabled = MoreSplitDown.IsEnabled = _active is not null;
        MoreFiles.IsEnabled = _active is { ConnectionId: not null };
        MoreSendVariables.IsEnabled = _active is { ConnectionId: not null, Panes: not null };
        MoreFiles.Text = _active?.Files is null ? "Show files (SFTP)" : "Hide files";
    }

    /// <summary>The library did not open: the window shows why, as App's own error window did before round 4.</summary>
    private void ShowOpenError(Exception e)
    {
        OpenError = e;
        Title = "Gantry";
        Content = new TextBlock
        {
            Text = "Gantry could not open its library:\n\n" + e.Message,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(24),
            IsTextSelectionEnabled = true,
        };
    }

    // ---- Library tree and search ----

    private void Reload(string? selectId)
    {
        var reloadT0 = PerfTrace.Now();
        // The launch's first build is start-up (startup-budget.ps1); later ones are rebuilds the speed suite reports.
        var rebuild = _treeReloads > 0;
        if (rebuild) PerfTrace.AfterFrame("tree-reload-frame", reloadT0);
        FolderDto tree;
        if (_firstTree is { } first && ReferenceEquals(_library, _personal))
        {
            _firstTree = null;
            (tree, _hostColorsNext) = first.GetAwaiter().GetResult(); // a core error surfaces here as before
            StartupProbe.Mark("reload-tree-prefetched");
        }
        else
        {
            _firstTree = null;
            tree = _library.Tree();
            StartupProbe.Mark("reload-tree");
            LoadHostColors();
            StartupProbe.Mark("reload-colors");
        }
        var readMs = PerfTrace.Ms(reloadT0);
        LoadProduction(tree);
        MarkOpenablePluginEntries(tree);
        TreeItem.DarkNames = RootGrid.ActualTheme == ElementTheme.Dark;
        // WIN-TREE-REBUILD: unchanged rows stay the same objects, so the tree swaps only the changed ones.
        var buildT0 = PerfTrace.Now();
        var context = TreeReuse.Context();
        var reuse = ReferenceEquals(_rootsLibrary, _library) ? TreeReuse.Over(_roots, _rootsContext, context) : null;
        _roots = TreeItem.Build(tree, IconBrush, HostColorFor, reuse);
        (_rootsContext, _rootsLibrary) = (context, _library);
        var buildMs = PerfTrace.Ms(buildT0);
        if (_dynamicResults.Count > 0) AddDynamicRows(_roots);
        _libraryTags = null;
        TagTokens.LibraryTags ??= () => _libraryTags ??= TreeItem.AllTags(_roots);
        StartupProbe.Mark("reload-build");
        RepaintHostColors();
        RepaintConnectionThemes();
        var filterT0 = PerfTrace.Now();
        ApplyFilter(keepSelection: false, selectId);
        StartupProbe.Mark("reload-filter");
        UpdateWorkspace();
        if (rebuild && PerfTrace.Enabled)
        {
            PerfTrace.Write("tree-reload-work", PerfTrace.Ms(reloadT0)); // speed suite: the UI thread's own part, read to update
            PerfTrace.Line(string.Create(System.Globalization.CultureInfo.InvariantCulture,
                $"DETAIL tree-reload read={readMs:0.0} build={buildMs:0.0} filter={PerfTrace.Ms(filterT0):0.0} kept={reuse?.Kept ?? 0} made={reuse?.Made ?? -1}"));
        }
    }

    /// <summary>What the current <see cref="_roots"/> were built for (theme, plugin types) and from which library: a
    /// rebuild keeps rows only from a tree of the same library and context.</summary>
    private string? _rootsContext;
    private LibraryClient? _rootsLibrary;
    /// <summary>The <see cref="_rootsContext"/> the shown Favorites and Application sections were made in.</summary>
    private string? _sectionsContext;

    private static string Plural(int n, string noun) => $"{n} {noun}{(n == 1 ? "" : "s")}";

    /// <summary>Speed-suite label of a filter pass the user typed (search box). Other passes are rebuilds: a library reload,
    /// a session opening, a vault change. They are traced as tree-rebuild, so the keystroke budget measures keystrokes.</summary>
    private const string KeystrokePerfLabel = "filter-keystroke";
    private const string RebuildPerfLabel = "tree-rebuild";
    private const string FirstTreePerfLabel = "tree-first";

    /// <summary>Show the items matching the search (all of them when it is empty) and keep or set the selection.</summary>
    private void ApplyFilter(bool keepSelection, string? selectId = null, string perfLabel = RebuildPerfLabel)
    {
        // The launch's first pass is start-up (startup-budget.ps1), not a rebuild: its own label keeps it out of the row.
        PerfTrace.AfterLayout(DispatcherQueue, _treeReloads == 0 ? FirstTreePerfLabel : perfLabel, PerfTrace.Now());
        var filterT0 = PerfTrace.Now();
        var wanted = keepSelection ? CurrentSelectionId : selectId;
        var library = _query.Length == 0 ? _roots : TreeItem.Filter(_roots, _query);
        // WIN-TREE-REBUILD: the sections are made on every pass; an unchanged one stays the same object (and rows), when
        // the earlier one was made for the same theme and plugin types.
        var before = _shown;
        var sameContext = _sectionsContext == _rootsContext;
        _sectionsContext = _rootsContext;
        TreeItem? Previous(string id) => sameContext ? before.FirstOrDefault(i => i.Id == id) : null;
        _shown = TreeItem.Favorites(library, IconBrush) is { } favorites ? [TreeItem.KeepSection(Previous(favorites.Id), favorites), .. library] : library;
        if (ApplicationSection() is { } application) _shown = [.. _shown, TreeItem.KeepSection(Previous(application.Id), application)];
        StartupProbe.Mark("filter-sections");
        RefreshCredentialsPane();
        StartupProbe.Mark("filter-credentials");
        MarkExpanded(_shown);
        PerfTrace.Write("filter-compute", PerfTrace.Ms(filterT0)); // speed suite: filter + expand flags, no UI
        var bindT0 = PerfTrace.Now();
        _shown = ShowRows(_shown);
        StartupProbe.Mark("filter-bind");
        PerfTrace.Write("filter-bind", PerfTrace.Ms(bindT0));
        _treeReloads++; TraceSessionTree($"reload reloads={_treeReloads}");
        SyncSessionRows(); // UI-05: session rows onto the (possibly new) connection rows
        if (_query.Length == 0)
        {
            NavMessage.Text = _roots.Count == 0 ? "No connections" : "";
        }
        else
        {
            var total = TreeItem.CountConnections(_roots);
            Announce($"{TreeItem.CountConnections(_shown)} of {Plural(total, "connection")} match");
            NavMessage.Text = _shown.Count == 0 ? $"No matches for “{_query}”" : "";
        }
        NavMessage.Visibility = NavMessage.Text.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
        if (wanted is not null && TreeItem.Find(ShownLibrary, wanted) is not null) SelectItem(wanted);
        else
        {
            // A rebuild keeps unchanged rows (WIN-TREE-REBUILD), so the old selection could still be on screen: clear it
            // as the rebuilt tree did when every row was new, or the tree and the inspector would disagree.
            Tree.SelectedItem = null;
            UpdateInspector(null);
        }
        // No ExpandFolders() here: ShowRows set the tree's source, which already rebuilt the open rows.
    }

    /// <summary>
    /// WIN-FLAT-TREE: show <paramref name="desired"/>. The tree walks the open rows and rebinds only the rows in view, so
    /// a new list is one assignment however many rows a keystroke adds or removes. Returns the rows now shown.
    /// </summary>
    private List<TreeItem> ShowRows(List<TreeItem> desired)
    {
        _shownSource = new TreeChildren(desired);
        Tree.ItemsSource = _shownSource;
        return desired;
    }

    /// <summary>Show the rows' current open/closed state (the tree also follows Expanded changes on its own, coalesced).</summary>
    private void ExpandFolders() => Tree.Refresh();

    /// <summary>
    /// The selected row, or while a selection is still being applied (SelectItem sets it after layout) the item the
    /// inspector already shows, so a reload in between keeps it.
    /// </summary>
    private string? CurrentSelectionId => Selected?.Id ?? _inspectedId;

    /// <summary>A selection asked for while a page covered the tree, applied when the page closes.</summary>
    private string? _pendingSelect;

    /// <summary>Select the library row for <paramref name="id"/>, not its Favorites mirror.</summary>
    public void SelectItem(string id)
    {
        var item = TreeItem.Find(ShownLibrary, id);
        UpdateInspector(item);
        if (item is null) return;
        // A row inside a closed folder is not shown and cannot be selected. Open its folders first, remembered as if the
        // user had opened them, then select once the row is shown.
        if (RevealAncestors(item))
        {
            ApplyFilter(keepSelection: false, id);
            return;
        }
        SelectWhenShown(item, attempts: 20);
    }

    /// <summary>Open every closed folder above <paramref name="item"/>; true when one was closed.</summary>
    private bool RevealAncestors(TreeItem item)
    {
        if (_query.Length > 0) return false; // search results show every folder open
        var opened = false;
        for (var p = item.ParentId; p is not null; p = TreeItem.Find(_roots, p)?.ParentId)
        {
            if (_expanded.Contains(p)) continue;
            SaveExpanded(p, true);
            opened = true;
        }
        return opened;
    }

    /// <summary>Set the selection after layout has realised the row's open folder (a few expand passes at most).</summary>
    private void SelectWhenShown(TreeItem item, int attempts)
    {
        // The tree realizes its containers on the next layout pass.
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            if (!ReferenceEquals(TreeItem.Find(ShownLibrary, item.Id), item)) return; // the tree was rebuilt meanwhile
            // A selection asked for under a full-window page (Settings) waits until the page closes, as before.
            if (Body.Visibility != Visibility.Visible) { _pendingSelect = item.Id; return; }
            if (!Tree.IsShown(item))
            {
                if (attempts > 0) _ = Task.Delay(30).ContinueWith(_ => SelectWhenShown(item, attempts - 1), TaskScheduler.FromCurrentSynchronizationContext());
                return; // never shown open: the inspector still shows the item
            }
            Tree.SelectedItem = item;
        });
    }

    public bool SelectByName(string name)
    {
        TreeItem? Walk(IEnumerable<TreeItem> items)
        {
            foreach (var i in items)
            {
                if (i.Name == name) return i;
                var hit = Walk(i.Children);
                if (hit is not null) return hit;
            }
            return null;
        }
        var found = Walk(ShownLibrary);
        if (found is null) return false;
        SelectItem(found.Id);
        return true;
    }

    /// <summary>
    /// Read the new item from AddedItems first: when the selection is set from code while another item is selected,
    /// SelectedItem can still be null while this event runs.
    /// </summary>
    private void Tree_SelectionChanged(LibraryTree sender, LibraryTreeSelectionChangedEventArgs args)
    {
        var added = args.AddedItems.OfType<TreeItem>().FirstOrDefault();
        var chosen = added ?? sender.SelectedItem as TreeItem;
        if (chosen is { IsSession: true } row)
        {
            // UI-05: selecting a session row shows its tab and its connection's inspector; the tree keeps focus.
            UpdateInspector(Selected);
            HideFolderDashboard(); // DASH-01: a session row is not a folder
            if (TabForRow(row) is { } tab && !ReferenceEquals(tab, _active)) ActivateTab(tab, focus: false);
            return;
        }
        UpdateInspector(chosen);
        ShowFolderDashboard(chosen); // DASH-01: a folder shows its dashboard (MainWindow.FolderDashboard.cs)
        ShowLiveSession(chosen);
    }

    /// <summary>The selected folder or connection; a section heading (Favorites) is not a selection.</summary>
    /// <summary>A session row stands for its connection here (UI-05): commands act on the parent; Other sessions rows on nothing.</summary>
    private TreeItem? Selected => Tree.SelectedItem as TreeItem is { IsGroup: false } item
        ? item.IsSession ? (item.ParentId is { } p && p != TreeItem.OtherSessionsId ? TreeItem.Find(_roots, p) : null) : item
        : null;

    /// <summary>The shown rows without the Favorites section, whose rows mirror library rows.</summary>
    private IEnumerable<TreeItem> ShownLibrary => _shown.Where(i => !i.IsGroup);

    /// <summary>
    /// Focus the selected tree row (or the first). Keyboard paths pass FocusState.Keyboard so the focus rectangle shows;
    /// everything else uses Programmatic, which shows it only if the last input was the keyboard.
    /// </summary>
    private void FocusTreeSelection(FocusState how = FocusState.Programmatic)
    {
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            var target = Tree.SelectedItem as TreeItem ?? _shown.FirstOrDefault();
            if (target is not null) Tree.FocusItem(target, how);
            else if (_shown.Count == 0) SearchBox.Focus(how);
        });
    }

    private void Search_Click(object sender, RoutedEventArgs e) => FocusSearch();

    private void FocusSearch()
    {
        if (!NavVisible) ShowNav(true);
        SearchBox.Focus(FocusState.Keyboard);
        SearchBox.SelectAll();
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _query = SearchBox.Text.Trim();
        _searchTimer.Stop();
        _searchTimer.Start();
    }

    /// <summary>
    /// Esc clears the search (or, when it is empty, returns to the tree); Down goes to the results. Enter connects to the top
    /// match, or, with no match, to the typed address (SearchConnectAsync), as the Mac's "Search or connect" box does.
    /// </summary>
    private void SearchBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        switch (e.Key)
        {
            case VirtualKey.Escape when SearchBox.Text.Length > 0:
                SearchBox.Text = "";
                _query = "";
                _searchTimer.Stop();
                ApplyFilter(keepSelection: true, perfLabel: KeystrokePerfLabel);
                e.Handled = true;
                break;
            case VirtualKey.Enter when SearchBox.Text.Trim().Length > 0:
                _searchTimer.Stop();
                _query = SearchBox.Text.Trim();
                ApplyFilter(keepSelection: true, perfLabel: KeystrokePerfLabel);
                _ = SearchConnectAsync(_query);
                e.Handled = true;
                break;
            case VirtualKey.Escape:
            case VirtualKey.Enter:
            case VirtualKey.Down:
                _searchTimer.Stop();
                if (e.Key != VirtualKey.Escape) ApplyFilter(keepSelection: true, perfLabel: KeystrokePerfLabel);
                FocusTreeSelection(FocusState.Keyboard);
                e.Handled = true;
                break;
        }
    }

    // ---- Context menu ----

    // ---- Inspector ----

    /// <summary>The core's primary action for the inspected item (Connect, Show Session, New Connection…).</summary>
    private MenuItemDto? _inspectorPrimary;

    private void UpdateInspector(TreeItem? item)
    {
        SetMoreDeleteEnabled(item is not null and { IsGroup: false });
        _inspectorOverlayDismissed = false; // a new selection shows its details again (full screen)
        _inspectedId = item is { IsGroup: false } ? item.Id : null;
        _inspectorPending = item; // read by InspectorHasSubject: while this event runs Tree.SelectedItem can still be null,
        _inspectorStale = true;   // so the remembered open choice did not reopen the pane on the first selection after a restart
        UpdatePanes(); // the details pane shows only for a connection or a session; its first showing fills it
        UpdateConnectAction(item);
        SetConnectionPageFor(item); // UI-04: the session area shows the connection's page
        if (Inspector is null || !_inspectorStale) return; // not built yet (#145): EnsureInspector fills it when first shown
        FillInspector(item);
    }

    /// <summary>The pane is built on its first showing, not at start (#145: it is hidden at start, so its XAML waited).</summary>
    private TreeItem? _inspectorPending;
    private bool _inspectorStale;

    private void EnsureInspector()
    {
        if (_inspectorView is not null) return;
        BuildInspectorView(); // InspectorView.xaml, hidden; ApplyInspectorLayout shows it (WIN-COLD-LIGHT)
        if (_inspectorStale) FillInspector(_inspectorPending);
    }

    private void FillInspector(TreeItem? item)
    {
        _inspectorStale = false;
        ReleaseNotes();
        InspectorBody.Children.Clear();
        UpdateInspectorFooter(item is { IsGroup: false } ? (TreeItem.Find(_roots, item.Id) ?? item).Connection : null);
        if (item is null or { IsGroup: true })
        {
            InspectorKind.Visibility = InspectorActions.Visibility = Visibility.Collapsed;
            InspectorTitle.Text = "Details";
            var hint = Ui.Text("Select a connection or folder to see its details.", "BodySecondaryTextStyle");
            hint.TextWrapping = TextWrapping.Wrap;
            InspectorBody.Children.Add(hint);
            return;
        }
        var full = TreeItem.Find(_roots, item.Id) ?? item;
        InspectorKind.Visibility = InspectorActions.Visibility = Visibility.Visible;
        CopyHostButton.Visibility = full.Connection is null ? Visibility.Collapsed : Visibility.Visible;
        CopyHostLabel.Visibility = Visibility.Collapsed;
        ToolTipService.SetToolTip(InspectorPropertiesButton, full.IsFolder ? "Folder defaults (Alt+Enter)" : "Edit properties (Alt+Enter)");
        UpdateInspectorPrimary(full);

        InspectorTitle.Text = full.Name;
        var location = TreeItem.FolderPath(_roots, full.ParentId);
        if (full.Connection is { } c)
        {
            InspectorKind.Text = full.IconLabel + (location is null ? "" : " in " + location);
            // The values that apply, with where an inherited one comes from (folder or type defaults).
            Dictionary<string, PropertyValueDto> values;
            try { values = _library.PropertyValues(c.Id).ToDictionary(v => v.Key); }
            catch (BastionException) { values = new(); }
            string Effective(string key, string? own, string fallback = "—")
            {
                if (!values.TryGetValue(key, out var v)) return string.IsNullOrEmpty(own) ? fallback : own;
                if (v.Effective is null) return fallback;
                return v.Source switch
                {
                    "inherited" => $"{v.Effective} (from {v.From})",
                    "typedefault" => $"{v.Effective} ({v.From?.ToUpperInvariant()} default)",
                    "builtin" => $"{v.Effective} (default)",
                    _ => v.Effective,
                };
            }
            // An imported SSH host connects with its config values after the user's overrides and answers: show those.
            var imported = c.Protocol == "ssh" && c.Imported ? ImportedEffective(c) : null;
            var local = c.Protocol == "local";
            var overview = new List<(string, string)> { ("Type", full.IconLabel) };
            // A local shell has no host, port or login: its shell is what identifies it. Not checked against WSL here, so
            // selecting stays instant; opening it says when a distribution is gone.
            if (local) overview.Add(("Shell", LocalShells.Describe(values.GetValueOrDefault(LocalShells.ShellKey)?.Effective)));
            else overview.Add(("Host", Overridden(imported?.Hostname, c.Host)));
            // A web page's port is part of its address; the type default (443) would contradict an http://…:8080 URL.
            if (c.Protocol != "web" && !local) overview.Add(("Port", imported?.Port is { } port ? Overridden(port.ToString(), c.Port?.ToString() ?? "22") : Effective("port", c.Port?.ToString(), "Default")));
            overview.Add(("Folder", location ?? "Library root"));
            if (!string.IsNullOrEmpty(c.Group)) overview.Add(("Group", c.Group));
            AddSection("Overview", overview.ToArray());
            if (c.Protocol != "web" && !local)
            {
                var auth = new List<(string, string)> { ("User", imported?.User is { Length: > 0 } user ? Overridden(user, c.Username ?? "") : Effective("username", c.Username, "Ask when connecting")) };
                if (c.Protocol == "ssh")
                {
                    auth.Add(("Credential", EffectiveCredentialLabel(c)));
                    auth.Add(("Vaultwarden login", VaultwardenLabel(c)));
                }
                AddSection("Authentication", auth.ToArray());
            }
            if (c.Protocol == "ssh") AddNetworkSection(c, imported);
            if (c.Protocol == "web") AddWebTunnelSection(c);
            if (PluginTypeOf(c) is not null) AddPluginTlsSection(c);
            var open = _tabs.Count(t => IsTabOf(t, c.Id));
            AddSection("Activity", ("Session", open == 0 ? "Not connected" : open == 1 ? "Connected in 1 tab" : $"Connected in {open} tabs"),
                ("Favorite", c.Favorite ? "Yes" : "No"));
            AddHistorySection("connection", c.Id, c.Name);
            AddNotesSection(c);
            AddSection("Record",
                ("Source", c.Imported ? "Imported from SSH config" + (c.SourceStatus is { } s ? $" ({s})" : "") : "Created in Gantry"),
                ("ID", c.Id));
        }
        else if (full.Folder is { } f)
        {
            var connections = full.ConnectionCount;
            var subfolders = TreeItem.CountFolders(full.Children);
            InspectorKind.Text = $"{Plural(connections, "connection")} · {Plural(subfolders, "folder")}";
            var ids = ConnectionIdsUnder(full).ToHashSet();
            AddSection("Overview",
                ("Connections", connections.ToString()),
                ("In this folder", f.Connections.Count.ToString()),
                ("Subfolders", subfolders.ToString()),
                ("Sessions", ConnectedIds.Count(ids.Contains).ToString()),
                ("Location", location ?? "Library root"));
            AddHistorySection("folder", f.Id, full.Name);
            AddSection("Record", ("ID", f.Id));
        }
    }

    /// <summary>Rebuild the inspector when it shows <paramref name="connectionId"/>: its session state and primary action changed.</summary>
    private void RefreshInspectorFor(string connectionId)
    {
        if (Selected is { } item && item.Id == connectionId) UpdateInspector(item);
        // The connection page shows the same history ("Last result"); SetConnectionPageFor skips an unchanged page, so
        // a failed connect (no tab opened) left it at "None yet". Rebuild it on the next turn, as ApplyConnectionPage does.
        if (_pageConnectionId == connectionId) DispatcherQueue.TryEnqueue(() => FillConnectionPage(connectionId));
    }

    /// <summary>The accent button: the registry's primary action for a connection, New Connection for a folder.</summary>
    private void UpdateInspectorPrimary(TreeItem item)
    {
        List<MenuItemDto> menu;
        try { menu = _library.Menu(item.Id, Handled, ConnectedIds); }
        catch (BastionException) { menu = []; }
        _inspectorPrimary = item.IsFolder ? menu.FirstOrDefault(m => m.Id == "new-connection") : menu.FirstOrDefault(m => m.Primary);
        InspectorPrimaryButton.Visibility = _inspectorPrimary is null ? Visibility.Collapsed : Visibility.Visible;
        if (_inspectorPrimary is not { } p) return;
        InspectorPrimaryButton.Content = p.Label;
        InspectorPrimaryButton.IsEnabled = p.Enabled && !_connecting;
        AutomationProperties.SetName(InspectorPrimaryButton, p.Label.TrimEnd('…'));
        ToolTipService.SetToolTip(InspectorPrimaryButton, p.DisabledReason ?? (p.Id == "connect" ? p.Label + " (Enter)" : p.Label));
    }

    private void InspectorPrimary_Click(object sender, RoutedEventArgs e)
    {
        if (_inspectorPrimary is { } p && Selected is { } item) _ = PerformAsync(p, item);
    }

    /// <summary>Everything else the registry offers for the inspected item, without the primary action.</summary>
    private void InspectorMoreMenu_Opening(object sender, object e)
    {
        InspectorMoreMenu.Items.Clear();
        var entries = MenuEntries(Selected);
        // Drop the primary entry and any separator it leaves at the top.
        if (_inspectorPrimary is { } p) entries.RemoveAll(m => m is MenuFlyoutItem item && item.Text == p.Label);
        while (entries.Count > 0 && entries[0] is MenuFlyoutSeparator) entries.RemoveAt(0);
        foreach (var entry in entries) InspectorMoreMenu.Items.Add(entry);
    }

    /// <summary>A section heading and a two-column label/value grid. Values can be selected and copied.</summary>
    private void AddSection(string title, params (string Label, string Value)[] rows)
    {
        var header = Ui.Text(title, "SectionHeaderTextStyle");
        header.Margin = Ui.Thickness(InspectorBody.Children.Count == 0 ? "InspectorFirstSectionMargin" : "InspectorSectionMargin");
        AutomationProperties.SetHeadingLevel(header, AutomationHeadingLevel.Level3);
        InspectorBody.Children.Add(header);
        var grid = new Grid { ColumnSpacing = Ui.Double("Space12"), RowSpacing = InspectorRowSpacing };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = Ui.Length("InspectorLabelColumnWidth") });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (var i = 0; i < rows.Length; i++)
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var label = Ui.Text(rows[i].Label, "BodySecondaryTextStyle");
            var value = Ui.Text(rows[i].Value, "BodyTextStyle");
            label.TextWrapping = TextWrapping.Wrap; // the label column is fixed; a long label takes two lines, never clips
            value.IsTextSelectionEnabled = true;
            value.TextWrapping = TextWrapping.Wrap;
            Grid.SetRow(label, i);
            Grid.SetRow(value, i);
            Grid.SetColumn(value, 1);
            grid.Children.Add(label);
            grid.Children.Add(value);
        }
        InspectorBody.Children.Add(grid);
    }

    /// <summary>Copy Address: host and a non-default port, as the core formats it (falls back to the host).</summary>
    private void CopyHost_Click(object sender, RoutedEventArgs e)
    {
        if (Selected?.Connection is not { } c) return;
        string text;
        try { text = _library.CopyText(c.Id, sshCommand: false); }
        catch (BastionException) { text = c.Host; }
        var data = new DataPackage();
        data.SetText(text);
        Clipboard.SetContent(data);
        CopyHostLabel.Visibility = Visibility.Visible;
        _copiedTimer.Stop();
        _copiedTimer.Start();
        var peer = FrameworkElementAutomationPeer.FromElement(CopyHostButton) ?? FrameworkElementAutomationPeer.CreatePeerForElement(CopyHostButton);
        peer?.RaiseNotificationEvent(AutomationNotificationKind.ActionCompleted, AutomationNotificationProcessing.ImportantMostRecent, "Address copied", "BastionHostCopied");
    }

    // ---- Library commands ----

    /// <summary>New items go into the selected folder, or next to the selected connection, or at the root.</summary>
    private TreeItem? CurrentParent()
    {
        var sel = Selected;
        if (sel is null) return null;
        var full = TreeItem.Find(_roots, sel.Id) ?? sel; // the selection may be a filtered copy
        if (full.IsFolder) return full;
        return full.ParentId is null ? null : TreeItem.Find(_roots, full.ParentId);
    }

    /// <summary>Secondary caption for creation dialogs: the destination, unless it is the library root.</summary>
    private string? DestinationCaption(TreeItem? parent) => parent is null ? null : "in " + TreeItem.FolderPath(_roots, parent.Id);

    /// <summary>Preview (owner, Mac AddMenu parity): + opens a type picker anchored to the button, then the form with
    /// that type chosen. Menu items and Ctrl+N (no anchor button) go straight to the form.</summary>
    private void NewConnection_Click(object sender, RoutedEventArgs e)
    {
        // The toolbar + button, or (Mac-style header, #1075) the New item of the + ▾ menu, which anchors to that button.
        var anchor = sender as Button ?? (sender is MenuFlyoutItem { Name: "CompactNewConnectionItem" } ? VisibleNamed("TerminalProfilesButton") : null);
        if (anchor is null) { _ = NewConnectionAsync(); return; }
        var menu = new MenuFlyout { Placement = FlyoutPlacementMode.BottomEdgeAlignedLeft };
        foreach (var (id, label) in AddConnectionForm.Protocols)
        {
            var item = new MenuFlyoutItem { Text = label };
            AutomationProperties.SetName(item, "New " + label + " connection");
            item.Click += (_, _) => _ = NewConnectionAsync(id);
            menu.Items.Add(item);
        }
        menu.ShowAt(anchor);
    }
    private void NewFromTemplate_Click(object sender, RoutedEventArgs e) => _ = NewFromTemplateAsync();

    /// <summary>A1-NW-JUMPS: the jump hosts Test Connection dials: the saved chain, each hop with the login the user
    /// gave it in the sheet or else a copy of the target's (as the connect does). Null when a key cannot be read.</summary>
    private static IReadOnlyList<ProbeHop>? TestRoute(IReadOnlyList<JumpHostDto> hops, ConnectForm form)
    {
        var own = form.JumpLogins;
        var saved = hops.Select(h => new SavedHop(h.Key, h.Username,
            own.TryGetValue(h.Key, out var l) ? new ProbeLogin((int)l.Kind, l.Secret, l.KeyPath) : null)).ToList();
        return ProbeRoute.Hops(saved, form.SignedInAs, form.TestLogin);
    }

    private void NewFolder_Click(object sender, RoutedEventArgs e) => _ = NewFolderAsync();

    private void Delete_Click(object sender, RoutedEventArgs e) => _ = DeleteAsync();

    internal async Task NewConnectionAsync(string? protocol = null)
    {
        if (_modal is not null) return;
        var parent = CurrentParent();
        var form = new AddConnectionForm(LocalShells.Distros, protocol, telnetAllowed: () => TelnetAllowed, telnetLock: () => TelnetSerial.PolicyLock,
            pluginTypes: PluginTypes);
        // Test checks name lookup, port and handshake; this dialog has no login yet, so there is no sign-in step.
        // PVE-TLS: a plugin type gets the core's TLS check (system trust; a pin is set after creating the entry).
        var test = new TestConnectionPanel(() => !form.Validate() ? null
            : form.PluginType is { } pt ? new ProbeRequest(pt.Id, form.Host, form.PortValue ?? pt.DefaultPort ?? 443, null, null, PluginTls: true)
            : TreeItem.DefaultPort(form.Protocol) is { } fallback ? new ProbeRequest(form.Protocol, form.Host, form.PortValue ?? fallback, form.UserName, null) : null,
            () => Sessions);
        var body = new StackPanel { Spacing = Ui.Double("Space16"), Children = { form.Body, test.Element } };
        var created = await ShowModal("New connection", body, primary: "Create connection", cancel: "Cancel",
                caption: DestinationCaption(parent), validate: form.Validate, focus: form.FirstField, wide: true);
        test.Cancel();
        if (!created) return;
        await Mutate(() =>
        {
            if (form.PluginType is { } pluginType) return AddPluginConnection(parent?.Id, form, pluginType);
            var id = _library.AddConnection(parent?.Id, form.ConnectionName, form.Protocol, form.Host, form.PortValue, form.UserName);
            if (form.Shell is { } shell) _library.SetProperty(id, LocalShells.ShellKey, shell);
            return id;
        }, "Could not create the connection");
    }

    internal Task NewFolderAsync() => NewFolderInAsync(CurrentParent());

    /// <summary>The New folder form for <paramref name="parent"/> (null: the library root, as from empty space).</summary>
    private async Task NewFolderInAsync(TreeItem? parent)
    {
        if (_modal is not null) return;
        var siblings = (parent?.Children ?? (IEnumerable<TreeItem>)_roots).Where(i => i.IsFolder).Select(i => i.Name);
        var form = new NewFolderForm(siblings, parent?.Name);
        if (!await ShowModal("New folder", form.Body, primary: "Create folder", cancel: "Cancel",
                caption: DestinationCaption(parent), validate: form.Validate, focus: form.Field)) return;
        await Mutate(() => _library.AddFolder(parent?.Id, form.FolderName), "Could not create the folder");
    }

    private async Task DeleteAsync()
    {
        if (_modal is not null) return;
        if (TreeMultiSelection() is { } many) { await DeleteManyAsync(many); return; } // one confirm for the selection
        if (Selected is not { } selected) return;
        var item = TreeItem.Find(_roots, selected.Id) ?? selected;
        var outcome = RetentionDays() > 0 ? "moves to Recently Deleted" : "is deleted for good";
        string text;
        if (item.IsFolder)
        {
            var connections = item.ConnectionCount;
            var subfolders = TreeItem.CountFolders(item.Children);
            var contents = connections == 0 && subfolders == 0
                ? ""
                : $" and everything in it ({Plural(connections, "connection")}{(subfolders > 0 ? ", " + Plural(subfolders, "subfolder") : "")})";
            text = $"“{item.Name}”{contents} {outcome}.";
        }
        else
        {
            text = $"“{item.Name}” ({item.Connection!.Host}) {outcome}.";
        }
        var body = Ui.Text(text, "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        if (!await ShowModal(item.IsFolder ? "Delete folder?" : "Delete connection?", body, primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
        var parentId = item.ParentId;
        await Mutate(() =>
        {
            TrashItem(item.Id);
            if (item.IsFolder) PruneTreeState();
            return parentId; // keep the parent folder selected afterwards
        }, "Could not delete " + item.Name);
    }

    /// <summary>Run a library change, save it (never in demo mode), refresh the tree and select the result.</summary>
    private async Task Mutate(Func<string?> change, string errorTitle)
    {
        var treeHadFocus = Contains(Tree, FocusedElement);
        try
        {
            var selectId = change();
            ReloadThenSave(selectId);
            // A new item hidden by the search: clear the search so it shows.
            if (selectId is not null && _query.Length > 0 && TreeItem.Find(_shown, selectId) is null)
            {
                SearchBox.Text = "";
                _query = "";
                _searchTimer.Stop();
                ApplyFilter(keepSelection: false, selectId);
            }
            if (treeHadFocus || FocusedElement is null) FocusTreeSelection();
        }
        catch (BastionException ex)
        {
            Reload(selectId: null);
            await ShowModal(errorTitle, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
        }
    }

    // ---- Credentials ----

    /// <summary>
    /// The vault next to the library, opened now if it is locked (that unwraps or creates its DPAPI-wrapped key). For
    /// actions the user asked for only: a passive read (a label, a drag hover, a refresh) uses
    /// <see cref="CredentialsIfOpen"/>, or it undoes Lock Credentials and the idle and screen locks (LOCK-CREDENTIALS-REOPEN).
    /// </summary>
    /// <summary>Vault credentials for the Properties picker; empty while the vault is locked (never prompts).</summary>
    private IReadOnlyList<CredentialDto> CredentialChoices()
    {
        try { return _credentials?.List() ?? []; }
        catch (BastionException) { return []; }
    }

    private CredentialStore OpenCredentials() => _credentials ?? OpenVaultAndShow();

    /// <summary>The vault when it is open; null when it is locked. Never opens it.</summary>
    private CredentialStore? CredentialsIfOpen => _credentials;

    /// <summary>Open the vault on first use and, after this call returns, show its rows in the tree's Credentials section.</summary>
    private CredentialStore OpenVaultAndShow()
    {
        _credentials = OpenVault();
        // Test hook (BASTION_LOCK_TRACE): who opened the vault, so a lock undone by a passive read names its caller. A
        // file of its own (<trace>.open): global-lock-ui-test counts the lock lines of the trace itself.
        if (TestHooks.LockTrace is { } trace)
        {
            try { System.IO.File.AppendAllText(trace + ".open", $"open {DateTime.Now:HH:mm:ss.fff}\n{Environment.StackTrace}\n"); }
            catch (System.IO.IOException) { }
        }
        DispatcherQueue.TryEnqueue(RefreshApplicationSection);
        return _credentials;
    }

    /// <summary>
    /// Show the opened vault's rows by replacing only the Application section's row. Rebuilding the whole tree here
    /// (ApplyFilter) replaced the row under the pointer when the first selection of a connection with a credential opened
    /// the vault between a right press and its release, so no menu was asked for (WIN-MAIN-UI-FIXES, tree-input.log).
    /// </summary>
    private void RefreshApplicationSection()
    {
        RefreshCredentialsPane();
        var at = _shown.FindIndex(i => i.Id == TreeItem.ApplicationGroupId);
        if (at < 0 || at >= _shownSource.Count || ApplicationSection() is not { } made) { ApplyFilter(keepSelection: true); return; }
        var application = TreeItem.KeepSection(_shown[at], made);
        if (ReferenceEquals(application, _shown[at])) return; // nothing in it changed: no row is made again
        _shown[at] = application;
        _shownSource[at] = application;
        ExpandFolders();
    }

    private string CredentialLabel(string? id)
    {
        // A label never opens the vault: reading it through the opening getter undid Lock Credentials as soon as the
        // tree re-selected a connection (LOCK-CREDENTIALS-REOPEN). VaultLabels says "Locked" when the vault is closed.
        try { return VaultLabels.Credential(id, VaultNameLookup()); }
        catch (BastionException) { return "Vault unavailable"; }
    }

    /// <summary>A name lookup over the open vault; null while it is locked (then nothing is asked of it).</summary>
    private Func<string, string?>? VaultNameLookup()
    {
        if (CredentialsIfOpen is not { } store) return null;
        return id => store.List().FirstOrDefault(c => c.Id == id)?.Name;
    }

    private void Credentials_Click(object sender, RoutedEventArgs e) => _ = CredentialsAsync();

    private void AssignCredential_Click(object sender, RoutedEventArgs e) => _ = AssignCredentialAsync();

    /// <summary>The credential manager: list, add password, add SSH key, remove. Each step reopens the list.</summary>
    internal async Task CredentialsAsync()
    {
        if (_modal is not null) return;
        IReadOnlyList<CredentialDto> list;
        try { list = OpenCredentials().List(); }
        catch (BastionException ex)
        {
            await ShowModal("Could not open the credential vault", CodedErrorText("VAULT", ex.Message), primary: "OK", cancel: null);
            return;
        }
        Func<Task>? next = null;
        var body = new CredentialListBody(list,
            addPassword: () => { next = () => NewCredentialAsync(sshKey: false); CloseModal(true); },
            addKey: () => { next = () => NewCredentialAsync(sshKey: true); CloseModal(true); },
            edit: c => { next = () => EditCredentialAsync(c); CloseModal(true); },
            remove: c => { next = () => RemoveCredentialAsync(c); CloseModal(true); });
        await ShowModal("Credentials", body.Body, primary: "Done", cancel: null, wide: true);
        if (next is not null) await next();
    }

    private async Task NewCredentialAsync(bool sshKey)
    {
        await SaveCredentialAsync(new NewCredentialForm(sshKey, pickKeyFile: PickUploadFile));
        await CredentialsAsync();
    }

    private async Task EditCredentialAsync(CredentialDto c)
    {
        await SaveCredentialAsync(new NewCredentialForm(false, c, PickUploadFile));
        await CredentialsAsync();
    }

    /// <summary>
    /// Show the add/edit form until it saves or is cancelled. A core error about the secret (a wrong passphrase, a file
    /// that is not a key) stays on the form; anything else gets its own dialog.
    /// </summary>
    internal async Task SaveCredentialAsync(NewCredentialForm form)
    {
        var title = form.ExistingId is not null ? "Edit credential" : form.IsSshKey ? "Add SSH key" : "Add password";
        try
        {
            while (await ShowModal(title, form.Body, primary: "Save", cancel: "Cancel", validate: form.Validate, focus: form.FirstField, wide: true))
            {
                try
                {
                    if (form.KeyFile is { } file) OpenCredentials().ImportKeyFile(form.ExistingId, form.CredentialName, form.Folder, form.UserName, file, form.Passphrase);
                    else if (form.IsSshKey) OpenCredentials().SaveSshKey(form.ExistingId, form.CredentialName, form.Folder, form.UserName, form.Secret);
                    else OpenCredentials().SavePassword(form.ExistingId, form.CredentialName, form.Folder, form.UserName, form.Secret);
                    OpenCredentials().Save();
                    UpdateInspector(Selected);
                    return;
                }
                catch (BastionException ex) when (form.KeyFile is not null) { form.ShowSecretError(Capitalised(ex.Message)); }
                catch (BastionException ex) { await ShowModal("Could not save the credential", CodedErrorText("VAULT", ex.Message), primary: "OK", cancel: null); }
            }
        }
        finally { form.ClearSecret(); }
    }

    private static string Capitalised(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..] + (s.EndsWith('.') ? "" : ".");

    private async Task RemoveCredentialAsync(CredentialDto c)
    {
        var body = ErrorText($"“{c.Name}” ({c.KindLabel.ToLowerInvariant()} for {c.Username}) will be deleted from the vault. Connections that use it will have no credential.");
        if (await ShowModal("Remove credential?", body, primary: "Remove", cancel: "Cancel", focusCancel: true))
        {
            try
            {
                OpenCredentials().Remove(c.Id);
                OpenCredentials().Save();
                UpdateInspector(Selected);
            }
            catch (BastionException ex)
            {
                await ShowModal("Could not remove the credential", CodedErrorText("VAULT", ex.Message), primary: "OK", cancel: null);
            }
        }
        await CredentialsAsync();
    }

    internal async Task AssignCredentialAsync()
    {
        if (_modal is not null || (_contextTarget ?? Selected) is not { } item || (item.Connection is null && item.Folder is null)) return;
        var conn = item.Connection;
        IReadOnlyList<CredentialDto> list;
        try { list = OpenCredentials().List(); }
        catch (BastionException ex)
        {
            await ShowModal("Could not open the credential vault", CodedErrorText("VAULT", ex.Message), primary: "OK", cancel: null);
            return;
        }
        var form = new AssignCredentialForm(list, conn?.CredentialId);
        if (!await ShowModal("Assign credential", form.Body, primary: "Assign", cancel: "Cancel", caption: "for " + item.Name, focus: form.Field)) return;
        await Mutate(() =>
        {
            // Hosts and folders alike; with none chosen the item inherits again (core credtree).
            OpenCredentials().Assign(_library, item.Id, form.CredentialId);
            return item.Id;
        }, "Could not assign the credential");
    }

    // ---- OpenSSH import ----

    private void ImportSsh_Click(object sender, RoutedEventArgs e) => _ = ImportSshAsync(SshWorkflow.UserDir(SessionDataDir), SshConfigLocation.SystemFile);

    /// <summary>Scan <paramref name="userDir"/> (config, Includes, config.d) and <paramref name="systemFile"/>, let the user pick hosts, import them.</summary>
    internal async Task ImportSshAsync(string userDir, string? systemFile)
    {
        if (_modal is not null) return;
        SshScanDto scan;
        try { scan = LibraryClient.ScanSsh(userDir, systemFile); }
        catch (BastionException ex)
        {
            await ShowModal("Could not read the OpenSSH config", CodedErrorText("SSH", ex.Message), primary: "OK", cancel: null);
            return;
        }
        IReadOnlyDictionary<string, string>? answers = null;
        try { if (SshWorkflow.Settings(SessionDataDir).Placeholders) answers = SshWorkflow.Placeholders(SessionDataDir).Values; }
        catch (BastionException) { /* no workflow store: import without placeholder answers */ }
        var form = new SshImportForm(scan, answers, ticked => _library.SshForwards(userDir, systemFile, ticked));
        var any = scan.Hosts.Count > 0;
        if (!await ShowModal("Import from OpenSSH", form.Body, primary: any ? "Import" : "OK", cancel: any ? "Cancel" : null,
                caption: userDir + (systemFile is null ? "" : " and " + systemFile), validate: form.Validate, focus: any ? form.Field : null, wide: true) || !any) return;
        var chosen = form.ChosenIdentities;
        var chosenForwards = form.ChosenForwards;
        var imported = -1;
        var tunnels = 0;
        await Mutate(() =>
        {
            foreach (var (name, value) in form.Answers)
                if (answers is null || answers.GetValueOrDefault(name) != value) SshWorkflow.SetPlaceholder(SessionDataDir, name, value);
            imported = _library.ImportSsh(userDir, systemFile, chosen);
            try { SshWorkflow.ImportHosts(SessionDataDir, _library, chosen); } catch (BastionException) { /* the baseline is optional; hosts are already in */ }
            if (chosenForwards.Count > 0) tunnels = _library.ImportSshForwards(userDir, systemFile, chosenForwards);
            return null;
        }, "Could not import the hosts");
        if (imported < 0) return; // Mutate already showed the error
        var skipped = chosen.Count - imported;
        var done = Ui.Text($"Imported {imported} of {chosen.Count} host{(chosen.Count == 1 ? "" : "s")}." + (skipped > 0 ? $" {skipped} {(skipped == 1 ? "was" : "were")} already in the library." : "")
            + (tunnels > 0 ? $" Created {tunnels} tunnel{(tunnels == 1 ? "" : "s")}; {(tunnels == 1 ? "it starts" : "they start")} when you connect (Tunnel Manager)." : "")
            + (tunnels < chosenForwards.Count ? $" {chosenForwards.Count - tunnels} ticked tunnel{(chosenForwards.Count - tunnels == 1 ? " was" : "s were")} not created: the config changed or the port is now taken. Import again to see them." : ""), "BodyTextStyle");
        done.TextWrapping = TextWrapping.Wrap;
        await ShowModal("Import finished", done, primary: "OK", cancel: null);
    }

    // ---- Property editor ----

    private void Properties_Click(object sender, RoutedEventArgs e)
    {
        if ((sender is MenuFlyoutItem ? _contextTarget ?? Selected : Selected) is { } item) _ = PropertiesAsync(item);
    }

    /// <summary>⋯ › Default Settings (as on the Mac): one item per connection type, opening that type's defaults editor.</summary>
    private void BuildTypeDefaultsMenu()
    {
        foreach (var (id, label) in AddConnectionForm.Protocols)
        {
            var item = new MenuFlyoutItem { Text = label };
            AutomationProperties.SetName(item, label + " defaults");
            item.Click += (_, _) => _ = EditDefaultsAsync(new EditorTarget.Type(id, label));
            TypeDefaultsMenu.Items.Add(item);
        }
    }

    internal Task PropertiesAsync(TreeItem item)
    {
        var full = TreeItem.Find(_roots, item.Id) ?? item;
        return full.Connection is { } c
            ? EditDefaultsAsync(new EditorTarget.Connection(c.Id, c.Name, c.Protocol, c.OwnIcon))
            : EditDefaultsAsync(new EditorTarget.Folder(full.Id, full.Name));
    }

    /// <summary>Open the property editor; Save applies through the core (which validates) and saves the library.</summary>
    internal async Task EditDefaultsAsync(EditorTarget target)
    {
        if (_modal is not null) return;
        PropertyEditorForm form;
        var selectId = target switch { EditorTarget.Connection c => c.Id, EditorTarget.Folder f => f.Id, _ => Selected?.Id };
        try
        {
            AppLog.Info($"Properties: opening {target.GetType().Name}");
            var pluginType = target is EditorTarget.Connection pc && TreeItem.Find(_roots, pc.Id)?.Connection is { } pcc ? PluginTypeOf(pcc) : null;
            form = new PropertyEditorForm(_library, target, CredentialChoices(),
                pluginType is null ? null : (pluginType, SessionDataDir), () => { SaveLibrary(); RefreshInspectorFor(selectId ?? ""); },
                target is EditorTarget.Connection lc && pluginType is { } lt ? (host, port) => PluginLoginTest(lc.Id, lt, host, port) : null)
            {
                Applied = () => _ = Mutate(() => selectId, "Could not save the properties"),
                SavePassword = target is EditorTarget.Connection conn ? (user, password) => SavePropertiesPassword(conn, user, password) : null,
            };
        }
        catch (BastionException ex)
        {
            await ShowModal("Could not open the properties", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }
        catch (Exception ex)
        {
            // Never a silent no-op (q-pvetls-w2): say it and keep the details in the log.
            AppLog.Warn($"Properties: form not built ({ex.GetType().Name}): {ex.Message}");
            CrashLog.Write(ex);
            await ShowModal("Could not open the properties", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }
        AppLog.Info("Properties: form built");
        BeginInspectorTransient(); // shown while Properties… is open, the remembered choice unchanged
        var (title, caption) = target switch
        {
            EditorTarget.Connection c => (c.Name, TreeItem.Find(_roots, c.Id)?.Connection is { } cc && PluginTypeOf(cc) is { } t
                ? $"{t.Name} connection properties" : $"{c.Protocol.ToUpperInvariant()} connection properties"),
            EditorTarget.Folder f => (f.Name, "Folder default settings"),
            EditorTarget.Type t => ($"{t.Label} defaults", "Default settings for a connection type"),
            _ => ("Properties", null),
        };
        AppLog.Info("Properties: showing");
        var saved = await ShowModal(title, form.Body, primary: "Save", cancel: "Cancel", caption: caption, validate: form.Apply, focus: form.FirstField, wide: true);
        AppLog.Info($"Properties: closed, saved {saved}");
        if (!saved) return;
        await Mutate(() => selectId, "Could not save the properties");
    }

    /// <summary>An error body with its support code under it in small selectable text, written to the app log
    /// (LOG-ERRCODES, docs/ERROR-CODES.md).</summary>
    private static StackPanel CodedErrorText(string area, string message)
    {
        var code = ErrorCodes.Code(area, message);
        AppLog.Failure(code, message);
        var panel = new StackPanel { Spacing = Ui.Double("Space4") };
        panel.Children.Add(ErrorText(message));
        var codeText = Ui.Text(code, "CaptionTextStyle");
        codeText.IsTextSelectionEnabled = true;
        ToolTipService.SetToolTip(codeText, "Support code: quote it when you ask for help.");
        AutomationProperties.SetAutomationId(codeText, "error-code");
        panel.Children.Add(codeText);
        return panel;
    }

    private static TextBlock ErrorText(string message)
    {
        var text = Ui.Text(message, "BodyTextStyle");
        text.TextWrapping = TextWrapping.Wrap;
        text.IsTextSelectionEnabled = true;
        return text;
    }

    // ---- SSH sessions ----

    /// <summary>known_hosts and audit.jsonl live beside the library file, as they do on macOS.</summary>
    private string SessionDataDir => Path.GetDirectoryName(Path.GetFullPath(_personal.Path))!;

    private SessionManagerClient Sessions => _sessions ??= SessionManagerClient.Open(SessionDataDir);

    private static bool IsSsh(TreeItem? item) =>
        item?.Connection is { } c && string.Equals(c.Protocol, "ssh", StringComparison.OrdinalIgnoreCase);

    private static bool IsWeb(TreeItem? item) =>
        item?.Connection is { } c && string.Equals(c.Protocol, "web", StringComparison.OrdinalIgnoreCase);

    private static bool IsRdp(TreeItem? item) =>
        item?.Connection is { } c && string.Equals(c.Protocol, "rdp", StringComparison.OrdinalIgnoreCase);

    private static bool IsVnc(TreeItem? item) =>
        item?.Connection is { } c && string.Equals(c.Protocol, "vnc", StringComparison.OrdinalIgnoreCase);

    /// <summary>SFTP and SCP connections: dialled over SSH like a shell, opened as a files-only tab.</summary>
    private static bool IsSshFiles(TreeItem? item) =>
        item?.Connection is { } c && (string.Equals(c.Protocol, "sftp", StringComparison.OrdinalIgnoreCase) || string.Equals(c.Protocol, "scp", StringComparison.OrdinalIgnoreCase));

    private static bool IsFtps(TreeItem? item) =>
        item?.Connection is { } c && string.Equals(c.Protocol, "ftps", StringComparison.OrdinalIgnoreCase);

    /// <summary>Connections the Windows app can open: SSH, SFTP, SCP, FTPS, RDP, VNC, web and saved local shells.</summary>
    /// <summary>PLUG-03a: an entry of a type this build does not know. Never opened, but Enter on it goes to
    /// <see cref="ConnectAsync"/>, which says why (CanOpen stays false, so restore and workspaces skip it).</summary>
    private static bool IsUnavailable(TreeItem? item) => item?.Connection is { IsUnavailable: true };

    private static bool CanOpen(TreeItem? item) => IsSsh(item) || IsSshFiles(item) || IsFtps(item) || IsWeb(item) || IsRdp(item) || IsVnc(item) || IsLocal(item);

    /// <summary>
    /// Open a VNC connection: ask for the password (used only if the server asks), say plainly that RFB is not encrypted,
    /// connect off the UI thread. VNC has no server identity check here, so there is nothing to pin. Not saved in workspaces.
    /// </summary>
    private async Task ConnectVncAsync(TreeItem item)
    {
        if (_modal is not null || _connecting || item.Connection is not { } c) return;
        var port = (ushort)(c.Port ?? 5900);
        var (proceed, route) = await OpenGatewayRouteAsync(item, c.Id);
        if (!proceed) return;
        var (dialHost, dialPort) = route is null ? (c.Host, port) : ("127.0.0.1", route.Port);
        var password = new PasswordBox { Header = "Password (if the server asks for one)" };
        var error = new FieldMessage();
        var warning = Ui.Text(route is null
            ? "VNC traffic is not encrypted. Outside a trusted network, connect through an SSH tunnel."
            : $"VNC traffic is not encrypted; it is carried {route.Summary} over SSH.", "BodySecondaryTextStyle");
        warning.TextWrapping = TextWrapping.Wrap;
        var body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { password, warning, error.Element } };
        password.PasswordChanged += (_, _) => error.Hide();
        try
        {
            while (true)
            {
                if (!await ShowModal("Connect to " + item.Name, body, primary: "Connect", cancel: "Cancel", caption: $"{c.Host}:{port}", focus: password)) return;
                var secret = password.Password;
                VncConnectResult result;
                _connecting = true;
                UpdateConnectAction(Selected);
                try { result = await Task.Run(() => VncSession.Connect(dialHost, dialPort, secret)); }
                finally
                {
                    _connecting = false;
                    UpdateConnectAction(Selected);
                }
                if (result.Session is { } session)
                {
                    IRemoteDesktop desktop = new VncDesktop(session);
                    if (route is not null) desktop = new RoutedDesktop(desktop, route);
                    route = null; // the tab owns it now
                    Named(AddTab(c.Name, null, rdp: new RemoteDesktopView(desktop, DesktopFitOf(c.Id)), hostId: c.Id), c.Name, $"{c.Host}:{port}").FocusContent(FocusState.Programmatic);
                    RecordConnected(c.Id, null);
                    return;
                }
                if (result.AuthFailed)
                {
                    RecordFailed(c.Id, "Authentication failed");
                    password.Password = "";
                    error.Show("Authentication failed. Check the password.");
                    continue;
                }
                RecordFailed(c.Id, result.Error ?? "The connection failed.");
                await ShowModal("Could not connect to " + item.Name, CodedErrorText("SSH", result.Error ?? "The connection failed."), primary: "OK", cancel: null);
                return;
            }
        }
        finally
        {
            password.Password = "";
            route?.Dispose();
        }
    }

    /// <summary>Snapshot only: a VNC connection to a test server, opened in a tab without the dialog.</summary>
    internal async Task<RemoteDesktopView> OpenVncForSnapshot(string host, int port, string password)
    {
        if (!_demo) throw new InvalidOperationException("snapshot only");
        var id = _library.AddConnection(null, "lab-vnc", "vnc", host, port, null);
        Reload(id);
        var wrong = await Task.Run(() => VncSession.Connect(host, (ushort)port, "not-the-password"));
        if (!wrong.AuthFailed) throw new InvalidOperationException($"a wrong password was not refused: {wrong.Error}");
        var result = await Task.Run(() => VncSession.Connect(host, (ushort)port, password));
        if (result.Session is null) throw new InvalidOperationException($"VNC connect failed: {result.Error}");
        var view = new RemoteDesktopView(new VncDesktop(result.Session));
        AddTab($"{host}:{port}", null, rdp: view);
        return view;
    }

    /// <summary>
    /// Open an RDP connection: ask for the login, connect off the UI thread, and pin the server certificate on first use
    /// (a changed certificate is asked about again). The password is cleared from the form once the attempt is over.
    /// Like web tabs, RDP tabs are not saved in workspaces and are not reconnected automatically.
    /// </summary>
    /// <summary>
    /// The connection's shared RDP properties as session options (Codex R04): <c>rdp.color_depth</c> and
    /// <c>rdp.resolution</c> ("window" = the session area).
    /// </summary>
    private static bool RdpToggle(Dictionary<string, string?> values, string key) =>
        !string.Equals(values.GetValueOrDefault(key), "false", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// NLA-only stays on unless the connection (or a folder or type default above it) sets <c>rdp_nla_only</c> to false:
    /// the core's built-in "false" is not taken, so an untouched connection keeps NLA. A managed NLA requirement, or a
    /// policy that cannot be read, always keeps it on (fails closed).
    /// </summary>
    private static bool RdpNlaRequired(PropertyValueDto? nla)
    {
        bool policy;
        try { policy = PolicyClient.State().RequireRdpNla; }
        catch (Exception) { policy = true; }   // unreadable policy: keep NLA (fail closed)
        if (policy || nla is null || nla.Source == "builtin") return true;
        return !string.Equals(nla.Effective, "false", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A desktop tab's size in device pixels: the last one laid out, else the session area now, else the fallback.</summary>
    private (int Width, int Height) DesktopTabPixels() =>
        RemoteDesktopView.LastViewPixels ?? DesktopFitRules.TabPixels(SessionHost.ActualWidth, SessionHost.ActualHeight, SessionHost.XamlRoot?.RasterizationScale ?? 1.0);

    /// <summary>The connection's <c>display.fit</c> (RDP and VNC); Fit to tab when unset or unreadable.</summary>
    private DesktopFit DesktopFitOf(string connectionId)
    {
        try { return DesktopFitRules.Parse(_library.PropertyValues(connectionId).FirstOrDefault(v => v.Key == DesktopFitRules.PropertyKey)?.Effective); }
        catch (BastionException) { return DesktopFit.Fit; }
    }

    private (ushort Width, ushort Height, RdpOptions Options) RdpSessionOptions(string connectionId, int gatewayPort)
    {
        Dictionary<string, string?> values;
        bool nlaOnly;
        try
        {
            var props = _library.PropertyValues(connectionId);
            values = props.ToDictionary(v => v.Key, v => v.Effective);
            nlaOnly = RdpNlaRequired(props.FirstOrDefault(v => v.Key == "rdp_nla_only"));
        }
        catch (BastionException) { values = new(); nlaOnly = true; }
        var depth = uint.TryParse(values.GetValueOrDefault("rdp.color_depth"), out var d) && d is 15 or 16 or 24 or 32 ? d : 32u;
        // RDP-VNC-FIT: Fit to tab (default) connects at the tab's size; Fixed size and Scale use Desktop size (Window = the tab).
        var fit = DesktopFitRules.Parse(values.GetValueOrDefault(DesktopFitRules.PropertyKey));
        var size = DesktopFitRules.ConnectSize(fit, values.GetValueOrDefault(DesktopFitRules.ResolutionKey), DesktopTabPixels());
        var (width, height) = ((ushort)Math.Clamp(size.Width, 1, ushort.MaxValue), (ushort)Math.Clamp(size.Height, 1, ushort.MaxValue));
        TestHooks.LogDesktopFit(fit, width, height, "connect");
        // Redirection (core properties rdp_clipboard / rdp_audio default on, rdp_shared_folder default none): the shared folder is
        // passed only when it still exists as a folder here, so a stale path cannot fail the whole connect.
        var folder = values.GetValueOrDefault("rdp_shared_folder");
        return (width, height, new RdpOptions(ColorDepth: depth, NlaOnly: nlaOnly, GatewayPort: (ushort)gatewayPort,
            Clipboard: RdpToggle(values, "rdp_clipboard"), Audio: RdpToggle(values, "rdp_audio"),
            SharedFolder: !string.IsNullOrWhiteSpace(folder) && Directory.Exists(folder) ? folder : null));
    }

    private async Task ConnectRdpAsync(TreeItem item, WorkspaceTab? replacing = null, bool askLogin = false)
    {
        if (_modal is not null || _connecting || item.Connection is not { } c) return;
        if (!PolicyAllows("rdp", item.Name)) return;
        var port = (ushort)(c.Port ?? RdpDefaults.Port);
        var where = $"{c.Host}:{port}";
        var (proceed, route) = await OpenGatewayRouteAsync(item, c.Id);
        if (!proceed) return;
        // A gateway forward is dialled through the options (Codex R04), so the certificate is checked for the real host.
        var (dialHost, dialPort) = (c.Host, port);
        var (width, height, options) = RdpSessionOptions(c.Id, route?.Port ?? 0);
        var pins = new RdpCertificatePins(SessionDataDir);
        var form = new RdpConnectForm(c.Username);
        // Owner points 23, 26: the login that worked this run opens with no sheet, when the certificate is already
        // pinned and no gateway sign-in is needed; anything to ask brings the sheet back.
        var savedLogin = false;
        if (LastLogin(c.Id) is { Kind: SshLoginKind.Password, Secret: { } pw } last) form.Prefill(last.User, last.Domain, pw);
        // Else the best saved password login (W23): its own or a folder's, so a restart still opens with no sheet.
        // A1-NW-01: one saved for the same host over SSH is selected and labelled in the sheet, and used on Connect.
        else savedLogin = await OfferRdpLoginsAsync(c, form);
        // W23: the connection's own or inherited login connects straight away too; an unknown certificate still asks below.
        // B4: a Connect All one-by-one request (askLogin) always shows the sheet.
        var direct = !askLogin && route is null && form.IsComplete && (pins.Pin(where) is not null || savedLogin);
        string? accepted = null;
        var askForLogin = !direct;
        try
        {
            while (true)
            {
                if (askForLogin) direct = false;
                if (askForLogin && !await ShowModal("Connect to " + item.Name, form.Body, primary: "Connect", cancel: "Cancel",
                        caption: where, validate: form.Validate, focus: form.FirstField)) return;
                askForLogin = true;
                var (user, domain, password, trust) = (form.UserName, form.Domain, form.Password, accepted ?? pins.Pin(where));
                RdpConnectResult result;
                OpenH264.Prepare(SessionDataDir);
                _connecting = true;
                PerfTrace.Begin("rdp-open"); // speed suite: closed by the first frame (RemoteDesktopView.MarkFrame)
                UpdateConnectAction(Selected);
                if (direct) ShowConnectingCard(replacing is null ? $"Connecting to {item.Name}…" : "Reconnecting…");
                try
                {
                    var (timedOut, done) = await WithConnectTimeout(
                        () => RdpSession.Connect(dialHost, dialPort, user, domain, width, height, trust, password, options),
                        late => late.Session?.Dispose());
                    if (timedOut)
                    {
                        RecordFailed(c.Id, "Timed out");
                        HideConnectingCard();
                        form.ShowFailure(TimedOutText(item.Name));
                        continue;
                    }
                    result = done!;
                }
                catch (DllNotFoundException)
                {
                    await ShowModal("Could not connect to " + item.Name, ErrorText("bastion_rdp.dll is missing: run build-core.ps1."), primary: "OK", cancel: null);
                    return;
                }
                finally
                {
                    _connecting = false;
                    HideConnectingCard();
                    UpdateConnectAction(Selected);
                }
                switch (result.Outcome)
                {
                    case RdpConnectOutcome.Connected:
                        if (accepted is not null)
                        {
                            try { pins.Save(where, accepted); }
                            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
                        }
                        IRemoteDesktop desktop = new RdpDesktop(result.Session!);
                        if (route is not null) desktop = new RoutedDesktop(desktop, route);
                        route = null; // the tab owns it now
                        if (replacing is not null) CloseTab(replacing, endsSession: false);
                        Named(AddTab(c.Name, null, rdp: new RemoteDesktopView(desktop, DesktopFitOf(c.Id)), hostId: c.Id), c.Name, $"{user}@{c.Host}").FocusContent(FocusState.Programmatic);
                        RecordConnected(c.Id, user);
                        RememberLogin(c.Id, new RememberedLogin(user, SshLoginKind.Password, password, null, domain));
                        // Owner point 5 for RDP: a typed password is saved and assigned when none is.
                        if (c.CredentialId is null && !form.FromSavedLogin) SaveTypedPassword(item, c.Id, domain is { Length: > 0 } dn ? $"{dn}\\{user}" : user, password);
                        // A1-NW-01: the connect succeeded with a login saved for another connection; ask whether to keep it.
                        if (form.UsedSavedLogin is { } offered) await OfferToKeepLoginAsync(item, c.Id, offered);
                        return;
                    case RdpConnectOutcome.CertificateUnknown when result.Fingerprint is { } fingerprint:
                        var changed = pins.Pin(where) is not null;
                        if (!await ShowModal(changed ? "The certificate has changed" : "Trust this certificate?", HostKeyPrompt.Body(where, fingerprint, false, certificate: true),
                                primary: "Connect and trust", cancel: "Cancel", focusCancel: true)) return;
                        accepted = fingerprint;
                        askForLogin = false;
                        continue;
                    case RdpConnectOutcome.AuthFailed:
                        ForgetLogin(c.Id);
                        RecordFailed(c.Id, "Authentication failed");
                        form.ClearSecrets();
                        form.ShowFailure("Authentication failed. Check the user name and password.");
                        continue;
                    default:
                        RecordFailed(c.Id, result.Error ?? "The connection failed.");
                        await ShowModal("Could not connect to " + item.Name, CodedErrorText("RDP", result.Error ?? "The connection failed."), primary: "OK", cancel: null);
                        return;
                }
            }
        }
        finally
        {
            form.ClearSecrets();
            route?.Dispose();
        }
    }

    /// <summary>
    /// Open a web connection in its own tab (WebView2, InPrivate, throwaway profile). No login is asked for: the page
    /// handles its own. Web tabs are not saved in workspaces.
    /// </summary>
    /// <summary>The managed policy's protocol gate for paths the core does not orchestrate (RDP, web); SSH and VNC are
    /// checked in the core. A refusal (or a broken policy file) shows its reason and stops the connect.</summary>
    private bool PolicyAllows(string protocol, string name)
    {
        try { PolicyClient.CheckProtocol(protocol); return true; }
        catch (BastionException ex)
        {
            _ = ShowModal("Cannot open " + name, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return false;
        }
    }

    /// <param name="from">The library the item comes from (Quick Connect's own); W10: a quick https:// address is not in
    /// the main library, so looking its gateway or tunnel up there failed and no page opened.</param>
    internal WebTabView? OpenWeb(TreeItem item, LibraryClient? from = null)
    {
        var library = from ?? _library;
        if (_modal is not null || item.Connection is not { } c) return null;
        if (!PolicyAllows("web", item.Name)) return null;
        if (WebTarget.Url(c.Host, c.Port) is not { } url)
        {
            _ = ShowModal("Cannot open " + item.Name, ErrorText($"\"{c.Host}\" is not an http or https address."), primary: "OK", cancel: null);
            return null;
        }
        if (from is null && TryOpenWebThroughTunnel(item, c, url, out var tunnelled)) return tunnelled;
        bool viaGateway;
        try { viaGateway = library.GatewayHop(c.Id) is not null; }
        catch (BastionException ex)
        {
            _ = ShowModal("Cannot open " + item.Name, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return null;
        }
        if (viaGateway)
        {
            _ = OpenWebThroughGatewayAsync(item, c.Id, url);
            return null;
        }
        var web = new WebTabView(url);
        var connectionId = c.Id;
        web.EnableAutofill(new WebAutofillHooks(
            () => library.WebAutofillOffered(connectionId),
            (page, secure) => OpenCredentials().WebAutofill(library, connectionId, TreeItem.Find(_roots, connectionId)?.Connection?.EffectiveCredentialId, page, secure)));
        AddTab(item.Name, null, web, hostId: item.Id);
        if (from is null) RunHooks("after_connect", item.Id); // B5: a web page counts as connected when its tab opens
        return web;
    }

    /// <summary>A web connection with a gateway: the page loads over a loopback SOCKS proxy through it, keeping the real URL and TLS name.</summary>
    private async Task OpenWebThroughGatewayAsync(TreeItem item, string connectionId, Uri url)
    {
        var (proceed, route) = await OpenGatewayRouteAsync(item, connectionId);
        if (!proceed || route is null) return;
        AddTab(item.Name, null, new WebTabView(url, route), hostId: item.Id);
        RunHooks("after_connect", item.Id); // B5: as a direct web tab (main library only; RunHooks skips Quick Connect)
    }

    /// <summary>Enable the toolbar and inspector Connect actions for connections the app can open (SSH, RDP, web).</summary>
    private void UpdateConnectAction(TreeItem? item)
    {
        if (_inspectorPrimary is { } p) InspectorPrimaryButton.IsEnabled = p.Enabled && !_connecting;
        UpdateBottomBar(item);
    }

    private void Connect_Click(object sender, RoutedEventArgs e) => _ = ConnectAsync(Selected);

    /// <summary>
    /// `bastion open &lt;name&gt;`: the core already resolved the name to a saved connection id. Select it, bring the window
    /// forward and run the normal Connect dialog, so the user still sees and confirms the login and host key.
    /// </summary>
    private void PollIpc()
    {
        if (_modal is not null || _connecting) return; // keep the request until the window is free
        var id = _ipcWaiting ?? _ipc?.NextOpen();
        _ipcWaiting = null;
        if (id is null) return;
        if (!string.IsNullOrEmpty(_query)) { SearchBox.Text = ""; _query = ""; ApplyFilter(keepSelection: false); }
        SelectItem(id);
        if (FindItem(_roots, id) is not { } item) return; // removed since the request
        Activate();
        if (CanOpen(item) || IsUnavailable(item)) _ = ConnectAsync(item); // an unknown type: ConnectAsync says why
        else _ = ShowModal("Cannot open " + item.Name, ErrorText($"{item.Connection?.Protocol?.ToUpperInvariant()} sessions cannot be opened in the Windows app yet."), primary: "OK", cancel: null);
    }

    private static TreeItem? FindItem(IEnumerable<TreeItem> items, string id)
    {
        foreach (var i in items)
        {
            if (i.Id == id) return i;
            if (FindItem(i.Children, id) is { } hit) return hit;
        }
        return null;
    }

    /// <summary>Snapshot mode: the pipe name this window serves, or null when it is not listening.</summary>
    internal string? IpcEndpointForSnapshot => _ipc is null ? null : IpcListener.Endpoint(SessionDataDir);

    /// <summary>
    /// Open an SSH session for <paramref name="item"/>: collect a login, connect off the UI thread, and confirm
    /// an unknown host key before retrying with it. A failure stays inside this dialog; open tabs are untouched.
    /// </summary>
    /// <param name="from">The library <paramref name="item"/> comes from when it is not the main one (Quick Connect).</param>
    /// <param name="connectAs">Connect as…: ask for any user name (recent ones offered), a one-off login that is not saved;
    /// the tab is titled with the account.</param>
    /// <param name="replacing">Reconnect as…: the tab to close once the new session is up.</param>
    /// <param name="askLogin">Connect All's one-by-one list (no login of its own): the sign-in sheet always shows, so an
    /// offered login is used only when the user presses Connect.</param>
    private async Task ConnectAsync(TreeItem? item, LibraryClient? from = null, bool connectAs = false, WorkspaceTab? replacing = null, bool askLogin = false)
    {
        _treeLog?.Invoke($"connect {(item?.IsSession == true ? "session:" : "")}{item?.Name} selected={(Tree.SelectedItem as TreeItem)?.IsSession}");
        // PLUG-03a: an entry of a type this build does not know is never connected (the core refuses too); say why
        // instead of doing nothing. Before Wake-on-LAN, so no packet is sent for it either.
        // PLUG-08-WIN: an entry of an installed plugin's type opens that plugin in a tab instead.
        if (item?.Connection is { IsUnavailable: true } pluginEntry && await TryOpenPluginEntryAsync(pluginEntry)) return;
        if (item?.Connection is { IsUnavailable: true } unknown)
        {
            if (_modal is null) await ShowModal("Could not open " + unknown.Name, ErrorText(unknown.Unavailable!), primary: "OK", cancel: null);
            return;
        }
        // Wake-on-LAN first when the host asks for it (MainWindow.Wake.cs); Cancel drops the connect.
        if (item?.Connection is { } woken && !await WakeBeforeConnectAsync(woken, from ?? _library)) return;
        // B5: before-connect hooks of a saved connection (folder hooks first). The connect waits for them and stops when one
        // fails or is cancelled (MainWindow.TaskHooks.cs).
        if (from is null && item?.Connection is not null && !await GateBeforeConnectAsync(item)) return;
        if (IsWeb(item)) { OpenWeb(item!, from); return; }
        if (IsRdp(item)) { if (!connectAs) await ConnectRdpAsync(item!, replacing, askLogin); return; }
        if (IsVnc(item)) { await ConnectVncAsync(item!); return; }
        if (IsFtps(item)) { await ConnectFtpsAsync(item!, from); return; }
        if (IsLocal(item)) { OpenLocalConnection(item!, from); return; }
        if (IsTelnet(item)) { await ConnectTelnetAsync(item!, from); return; }
        if (IsSerial(item)) { await SerialNotSupportedAsync(item!); return; }
        if (!connectAs && IsSsh(item) && TryOpenMosh(item!, from)) return;
        if (_modal is not null || _connecting || !(IsSsh(item) || IsSshFiles(item)) || item?.Connection is not { } c) return;
        var filesOnly = IsSshFiles(item);

        // A vault credential assigned to the connection is offered first, then an assigned Vaultwarden login while
        // Vaultwarden is unlocked; a missing or unreadable vault just leaves it out.
        CredentialDto? assigned = null;
        // An assigned vault login asks Windows Hello first when the gate is on; a refusal just leaves it out.
        // W23: the best saved login (own, inherited or the same host's), with the others in a picker. Always the core's
        // list (A1-NW-01), so the id the form sends is one the core offers this connection. Connect as… takes no saved
        // login; a Quick Connect library is asked only when its connection names a credential.
        IReadOnlyList<SavedLogin> logins = [];
        if (!connectAs && (from is null || c.CredentialId is not null))
        {
            logins = await SavedLoginsAsync(from ?? _library, c.Id, passwordsOnly: false);
            assigned = logins.Count > 0 ? logins[0].Credential : null;
        }
        IReadOnlyList<JumpHostDto> hops = [];
        try { hops = Sessions.JumpHosts(from ?? _library, c.Id); }
        catch (BastionException) { } // resolved again by the connect itself, which reports the problem
        IReadOnlyList<string> recent = [];
        if (connectAs)
        {
            try { recent = RecentUsernames.For(SessionDataDir, c.Host, c.Port); }
            catch (BastionException) { } // suggestions only
        }
        var form = connectAs
            ? new ConnectForm(recent.FirstOrDefault(), jumpHosts: hops, recentUsers: recent, providers: ProviderOptions())
            : new ConnectForm(c.Username, assigned, AssignedVaultwardenItem(c), hops, providers: ProviderOptions(), lastProviderReference: _providerRefs.GetValueOrDefault(c.Id));
        form.OfferLogins(logins);
        // Owner points 2, 3, 26: the login that worked this run is filled in, so the sheet is not needed.
        var saved = !connectAs && from is null && LastLogin(c.Id) is { } last ? last : null;
        // A1-NW-01: a saved login goes straight through only when the core marks it auto-use (the connection's own or
        // inherited) or the user already picked it for this connection this run. One saved for another connection is
        // selected in the sheet and waits for Connect; a typed login that worked this run is used before it.
        var unasked = assigned is not null && MayUseUnasked(c.Id, logins);
        if (saved is not null && !unasked) form.Prefill(saved.User, saved.Kind, saved.Secret, saved.KeyPath);
        if (connectAs || from is not null || unasked || c.CredentialId is not null) form.HideSavePassword();
        // Straight through only for a plain saved SSH login; a jump host with its own login keeps the sheet.
        // A saved credential in the form goes straight through on the rule above only, whatever else is remembered.
        // B4: a Connect All one-by-one request (askLogin) always shows the sheet.
        var direct = !connectAs && !askLogin && hops.Count == 0 && form.IsComplete && (form.Kind == SshLoginKind.Vault ? unasked : saved is not null);
        var where = $"{c.Host}:{c.Port ?? 22}";
        // A1-NW-JUMPS: the test dials the saved jump chain, as the connect does, so a saved login is tested over the
        // route it may use. The core refuses a saved login over any other route.
        var test = new TestConnectionPanel(() => form.Validate() && TestRoute(hops, form) is { } jumps
            ? new ProbeRequest(c.Protocol, c.Host, c.Port ?? 22, form.SignedInAs, form.TestLogin, c.Id, jumps) : null, () =>
        {
            if (form.Kind == SshLoginKind.Vault) Sessions.SetCredentials(OpenCredentials());
            if (form.Kind == SshLoginKind.Vaultwarden) Sessions.SetVaultwarden(Vaultwarden);
            return Sessions;
        }, () => _library);
        // A chain with a key the test cannot read is left to the connect itself, which reports the problem.
        if (hops.All(h => ProbeRoute.SplitKey(h.Key) is not null)) form.Body.Children.Add(test.Element);
        // Fingerprints the user has verified during this dialog, for the retry. Never seeded from the server.
        string? trust = null;
        var jumpTrust = new Dictionary<string, string>();
        // The one-time code for a keyboard-interactive second factor; used for one attempt only.
        string? code = null;
        var askForLogin = !direct;
        try
        {
            while (true)
            {
                if (askForLogin)
                {
                    direct = false;
                    var go = await ShowModal((connectAs ? "Connect as… to " : "Connect to ") + item.Name, form.Body, primary: "Connect", cancel: "Cancel",
                        caption: where, validate: form.Validate, focus: form.FirstField);
                    test.Cancel();
                    if (!go) return;
                }
                askForLogin = true;

                SshConnectResult result;
                _connecting = true;
                PerfTrace.Begin("ssh-open"); // speed suite: closed by the first prompt (TerminalView.MarkRender)
                UpdateConnectAction(Selected);
                if (direct) ShowConnectingCard(replacing is null ? $"Connecting to {item.Name}…" : "Reconnecting…");
                try
                {
                    // Copy the fields out before leaving the UI thread; the blocking connect must not touch controls.
                    var kind = form.Kind;
                    // A KeePass entry brings its user name; the core knows only the provider reference.
                    var user = kind == SshLoginKind.Provider ? form.SignedInAs : form.UserName;
                    var secret = form.Secret;
                    if (kind == SshLoginKind.Provider) _providerRefs[c.Id] = secret;
                    var keyPath = form.KeyPath;
                    var verified = trust;
                    var hopTrust = new Dictionary<string, string>(jumpTrust);
                    var hopLogins = form.JumpLogins;
                    var oneTimeCode = code;
                    code = null;
                    if (oneTimeCode is not null && kind == SshLoginKind.Password) kind = SshLoginKind.PasswordAndCode;
                    if (kind == SshLoginKind.Vault) Sessions.SetCredentials(OpenCredentials());
                    if (kind == SshLoginKind.Vaultwarden) Sessions.SetVaultwarden(Vaultwarden);
                    var library = from ?? _library;
                    var sessions = Sessions;
                    var (timedOut, done) = await WithConnectTimeout(() => filesOnly
                        ? sessions.ConnectFiles(library, c.Id, user, kind, secret, keyPath, verified, hopTrust, oneTimeCode, hopLogins)
                        : sessions.ConnectSsh(library, c.Id, user, kind, secret, keyPath, verified, hopTrust, 80, 24, oneTimeCode, hopLogins),
                        late => { late.Session?.Dispose(); late.Files?.Dispose(); });
                    if (timedOut)
                    {
                        RecordFailed(c.Id, "Timed out");
                        HideConnectingCard();
                        form.ShowFailure(TimedOutText(item.Name));
                        continue;
                    }
                    result = done!;
                }
                catch (ObjectDisposedException) when (_windowClosed)
                {
                    // Closed before the queued connect began: the manager refused a new lease, nothing was opened.
                    return;
                }
                catch (BastionException ex)
                {
                    // The session manager itself could not start (a bad data directory, a missing DLL).
                    await ShowModal("Could not connect to " + item.Name, CodedErrorText("SSH", ex.Message), primary: "OK", cancel: null);
                    return;
                }
                finally
                {
                    _connecting = false;
                    HideConnectingCard();
                    if (!_windowClosed) UpdateConnectAction(Selected);
                }

                if (_windowClosed)
                {
                    // The window closed during the handshake: end the new connection instead of attaching it.
                    result.Session?.Dispose();
                    result.Files?.Dispose();
                    return;
                }

                // A1-NW-01: the saved login this attempt used, read before the form is cleared.
                var usedLogin = !connectAs && from is null ? form.ChosenLogin?.Login : null;

                if (result.Files is { } files)
                {
                    await OpenFilesTabAsync(c.Name, files, c.Id, c.Protocol.ToUpperInvariant(), $"{form.SignedInAs}@{c.Host}");
                    RecordConnected(c.Id, form.SignedInAs);
                    if (usedLogin is not null) await OfferToKeepLoginAsync(item, c.Id, usedLogin);
                    return;
                }

                if (result.IsConnected)
                {
                    // Owner (W21 follow-up): a saved connection's tab shows its name; user@host is in the tooltip.
                    // Quick Connect (an unsaved library) keeps user@host. Both tab buttons carry user@host as help text.
                    var login = $"{form.SignedInAs}@{c.Host}";
                    var shownBefore = _active; // PR-1289 MED: a tab the user picked while Reconnect was pending stays shown
                    var view = AttachSession(connectAs ? $"{item.Name} ({form.SignedInAs})" : from is null ? item.Name : login, result.Session!, c.Id);
                    if (_tabs.FirstOrDefault(t => ReferenceEquals(t.View, view)) is { } named)
                    {
                        if (from is null) LazyToolTip.Set(named.Select, $"{item.Name}: {login}");
                        AutomationProperties.SetHelpText(named.Select, login);
                        AutomationProperties.SetHelpText(named.Close, login);
                    }
                    if (connectAs && form.UserName.Length > 0)
                    {
                        try { RecentUsernames.Record(SessionDataDir, c.Host, c.Port, form.UserName); }
                        catch (BastionException) { } // a suggestion lost is not worth an error
                    }
                    if (replacing is not null && _tabs.FirstOrDefault(t => ReferenceEquals(t.View, view)) is { } opened) await TakeReconnectPlaceAsync(replacing, opened, shownBefore);
                    RecordConnected(c.Id, form.SignedInAs);
                    if (!connectAs && from is null)
                    {
                        RememberLogin(c.Id, new RememberedLogin(form.SignedInAs, form.Kind, form.Secret, form.KeyPath));
                        if (form.SavePassword) SaveTypedPassword(item, c.Id, form.SignedInAs, form.Secret);
                    }
                    // Reconnects reuse the target's login on every hop, so a hop with its own login is not reconnected without the user.
                    Supervise(view, c.Id, form.UserName, form.JumpLogins.Count == 0 ? form.Kind : SshLoginKind.Password, form.Secret, form.KeyPath, from);
                    // The session is up: only now may an offered login become the connection's own, and only on Yes.
                    if (usedLogin is not null) await OfferToKeepLoginAsync(item, c.Id, usedLogin);
                    return;
                }

                switch (result.Outcome)
                {
                    case ConnectOutcome.HostKeyUnknown when result.Fingerprint is { } fingerprint:
                        var isHop = result.Hop is not null;
                        if (!await ShowModal("Trust this host key?", HostKeyPrompt.Body(result.Hop ?? where, fingerprint, isHop),
                                primary: "Connect and trust", cancel: "Cancel", focusCancel: true)) return;
                        if (result.Hop is { } hop) jumpTrust[hop] = fingerprint; else trust = fingerprint;
                        askForLogin = false; // the login is still in the form; retry with the key now trusted
                        continue;

                    case ConnectOutcome.TwoFactorRequired when form.Kind == SshLoginKind.Password:
                        var codeForm = new OneTimeCodeForm(where);
                        try
                        {
                            if (!await ShowModal("Second factor", codeForm.Body, primary: "Continue", cancel: "Cancel",
                                    caption: where, validate: codeForm.Validate, focus: codeForm.FirstField)) return;
                            code = codeForm.Code;
                        }
                        finally { codeForm.Clear(); }
                        askForLogin = false; // the password is still in the form; retry with the code
                        continue;

                    case ConnectOutcome.NoCommonAlgorithm:
                        RecordFailed(c.Id, result.Error ?? "No algorithm in common with the server.");
                        if (!await OfferWeakAlgorithms(from ?? _library, c.Id, item.Name, result)) return;
                        askForLogin = false; // the login is still in the form; retry with the algorithms allowed
                        continue;

                    case ConnectOutcome.TwoFactorRequired:
                    case ConnectOutcome.AuthFailed:
                        ForgetLogin(c.Id);
                        RecordFailed(c.Id, "Authentication failed");
                        form.ClearSecrets();
                        form.ShowFailure("Authentication failed. Check the user name and the password or key.");
                        continue;

                    default:
                        RecordFailed(c.Id, result.Error ?? "The connection failed.");
                        await ShowModal("Could not connect to " + item.Name,
                            CodedErrorText("APP", result.Error ?? "The connection failed."), primary: "OK", cancel: null);
                        return;
                }
            }
        }
        finally
        {
            form.ClearSecrets();
        }
    }

    // ---- Workspace: terminal tabs ----

    private void NewLocalShell_Click(object sender, RoutedEventArgs e) => NewLocalShell();

    /// <summary>New terminal (button, Ctrl+Shift+T): the shell chosen in Settings > Terminal > New tab opens (W27). The
    /// shell starts off the UI thread (<see cref="StartTerminalInBackground"/>).</summary>
    private void NewLocalShell()
    {
        var kind = "local";
        try { kind = Settings.Get("terminal.new-tab"); }
        catch (BastionException) { /* the default shell */ }
        var (title, start) = LocalShellStart(kind);
        StartTerminalInBackground(title, start, LocalShellDistro(kind) is null ? null : () => LocalShellInstalled(kind));
    }

    private void NewPowerShell_Click(object sender, RoutedEventArgs e) => StartTerminalInBackground(LocalShellStart("powershell"));

    /// <summary>Default WSL distribution; shown only while the distro list is unavailable.</summary>
    private void NewWsl_Click(object sender, RoutedEventArgs e) => StartTerminalInBackground(LocalShellStart("wsl"));

    public TerminalView? OpenWsl(string distro) => OpenTerminal(distro, () => TerminalSession.Wsl(distro, 80, 24));

    /// <summary>One menu item per installed WSL distribution, read each time the menu opens.</summary>
    /// <summary>The WSL distributions last read for the New menu; null until the first read finishes.</summary>
    private IReadOnlyList<WslDistro>? _wslMenuDistros;
    private bool _wslMenuReading;
    private MenuFlyout? _wslMenu;

    /// <summary>
    /// The New menu shows the distributions read last time and reads them again off the UI thread: the core's WSL
    /// detection took up to 57 ms on the UI thread at every open (q-kern-1), and opening the menu was the most frequent
    /// long user stall (60-100 ms, q-steps-g). If the list changed while the menu is open, the menu is updated.
    /// </summary>
    private void TerminalProfiles_Opening(object? sender, object e)
    {
        if (sender is not MenuFlyout menu) return;
        _wslMenu = menu;
        FillWslItems(menu, _wslMenuDistros ?? []);
        _ = RefreshWslMenuAsync();
    }

    private async Task RefreshWslMenuAsync()
    {
        if (_wslMenuReading) return;
        _wslMenuReading = true;
        try
        {
            var fresh = await Task.Run(LocalShells.Distros);
            // Only what the menu shows counts: a distribution's State (Stopped/Running) changes when WSL starts, and
            // rebuilding the open menu for that replaced the item under the pointer, so the click opened nothing (q-wslmenu-r2).
            var changed = _wslMenuDistros is null || !Shown(_wslMenuDistros).SequenceEqual(Shown(fresh));
            _wslMenuDistros = fresh;
            // A read already running when the menu opened (the start-up warm-up) still updates the open menu.
            if (changed && !_windowClosed && _wslMenu is { IsOpen: true } open) FillWslItems(open, fresh);
        }
        finally { _wslMenuReading = false; }
    }

    private static IEnumerable<string> Shown(IReadOnlyList<WslDistro> all) => all.Where(d => !d.Hidden).Select(d => d.Name);

    private void FillWslItems(MenuFlyout menu, IReadOnlyList<WslDistro> all)
    {
        foreach (var old in menu.Items.Where(i => i.Tag is "wsl").ToList()) menu.Items.Remove(old);
        // docker-desktop helpers are left out; with no distribution the generic WSL item stays as the fallback.
        var distros = all.Where(d => !d.Hidden).ToList();
        WslPlaceholder.Visibility = distros.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        var at = menu.Items.IndexOf(WslSeparator) + 1;
        foreach (var d in distros)
        {
            var name = d.Name;
            var item = new MenuFlyoutItem { Text = "WSL: " + LocalShells.Label(d), Tag = "wsl" };
            AutomationProperties.SetName(item, $"WSL {name}");
            item.Click += (_, _) => StartTerminalInBackground(LocalShellStart("wsl:" + name)); // just listed: no install check
            menu.Items.Insert(at++, item);
        }
    }

    /// <summary>Open a terminal tab. A failure to start (for example WSL not installed) is reported, never thrown.</summary>
    /// <summary>More → Terminal colours: one radio item per core preset; the choice applies to every open tab and is saved.</summary>
    private void BuildTerminalColorsMenu()
    {
        TerminalColorsMenu.Items.Clear();
        List<(string Id, string Label)> themes;
        try { themes = TermThemes.List().Select(t => (t.Id, t.Name)).ToList(); }
        catch (BastionException) { themes = TerminalThemes.All.ToList(); }
        themes.Insert(0, (AppearanceSettings.MatchAppTheme, "Match app theme")); // the default: light or dark with the app
        foreach (var (id, label) in themes)
        {
            var item = new RadioMenuFlyoutItem { Text = label, GroupName = "TerminalColors", IsChecked = id == _appearance.TerminalTheme, Tag = id };
            AutomationProperties.SetName(item, label);
            item.Click += (_, _) => SetTerminalTheme(id);
            TerminalColorsMenu.Items.Add(item);
        }
    }

    internal void SetTerminalTheme(string id)
    {
        _appearance.SetTerminalTheme(id, save: !_demo);
        if (_titleBar is not null) // the menu is built after the first frame with the saved choice checked
            foreach (var item in TerminalColorsMenu.Items.OfType<RadioMenuFlyoutItem>()) item.IsChecked = (string)item.Tag == id;
        RepaintAppTerminalTheme();
    }

    public TerminalView? OpenTerminal(string title, Func<TerminalSession> start)
    {
        if (_modal is not null) return null;
        TerminalSession session;
        try { session = start(); }
        catch (BastionException ex)
        {
            _ = ShowModal("Could not start " + title, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return null;
        }
        return AttachLocal(title, session, start, startedAt: null);
    }

    /// <summary>A started local program in its own tab; <paramref name="again"/> starts another of it (split panes).
    /// <paramref name="startedAt"/> is the grid its PTY was started at, when it was sized for this tab already.</summary>
    private TerminalView AttachLocal(string title, TerminalSession session, Func<TerminalSession> again, (int Cols, int Rows)? startedAt)
    {
        var view = AttachSession(title, session, startedAt: startedAt);
        if (_tabs.FirstOrDefault(t => ReferenceEquals(t.View, view)) is { } tab)
        {
            tab.StartLocal = again;
            SaveOpenSessions(); // W26: the tab was saved before it was known to be a local shell
        }
        return view;
    }

    /// <summary>
    /// Put an already-started session (a local PTY or an SSH shell) into its own tab. The tab owns the session
    /// from here: when it ends it is marked exited (in its tooltip) and every other tab carries on untouched.
    /// </summary>
    /// <summary>Named tabs (owner): a saved connection's tab shows its name; user@host is the tooltip and the help text.</summary>
    private WorkspaceTab Named(WorkspaceTab tab, string name, string login)
    {
        LazyToolTip.Set(tab.Select, $"{name}: {login}");
        AutomationProperties.SetHelpText(tab.Select, login);
        AutomationProperties.SetHelpText(tab.Close, login);
        // W26: a saved connection's tab is online from the start, supervised or not (only a supervised link repaints it later).
        if (!tab.Exited) PaintTabDot(tab, connection: true);
        return tab;
    }

    private TerminalView AttachSession(string title, TerminalSession session, string? connectionId = null, (int Cols, int Rows)? startedAt = null)
    {
        var view = NewTerminalView(session, connectionId);
        // A PTY started off the UI thread was started at this tab's grid already (MainWindow.ShellStart.cs).
        if (startedAt is { } grid) view.StartedAt(grid.Cols, grid.Rows);
        // A new tab's terminal gets the area of the terminal shown now (same session area, same tab body): size the PTY
        // for it before the first layout, instead of 80x24 and a resize + redraw once laid out (q-gate-tabswitch3).
        else if (_active is { View: { ActualWidth: > 0, ActualHeight: > 0 } shown, Window: null } active && active.AllPanes.Count() == 1
            && shown.FontSizeForSnapshot == view.FontSizeForSnapshot && shown.FontForSnapshot == view.FontForSnapshot)
            view.FitBeforeLayout(new Windows.Foundation.Size(shown.ActualWidth, shown.ActualHeight));
        var tab = AddTab(title, view);
        // A title set before the user types is the shell's own start-up title (an .exe path, "Windows PowerShell", the
        // first prompt), not something the user ran: the tab keeps its name until the first input.
        var typed = false;
        view.KeysSent += (_, _) => typed = true;
        view.Pasted += (_, _) => typed = true;
        view.ProgramTitleChanged += (_, programTitle) => { if (typed) FollowProgramTitle(tab, programTitle); };
        view.Exited += (_, _) =>
        {
            // A supervised SSH tab shows its link state instead (PollLinks). A tab already ended by Disconnect keeps
            // saying "disconnected" (DisconnectInPlace closed its session, and this follows on the next poll).
            var first = !tab.Exited;
            tab.Exited = true;
            if (tab.Link is null && first) { SetTabStatus(tab, "exited"); FinishTabLogs(tab, "session ended"); SessionEnded(tab); }
            SyncSessionRows();
        };
        return view;
    }

    /// <summary>WIN-TAB-STATUS-DOT (Mac #1175): a tab shows its name and a link dot, not status words. The words go to
    /// the tooltip and the automation name ("name, disconnected"). Local shells have no dot. Broadcast is a mode, not a
    /// link state, so it stays a word in the label.</summary>
    private void SetTabStatus(WorkspaceTab tab, string? status)
    {
        var broadcast = status == BroadcastStatus;
        var link = broadcast ? null : status;
        var label = broadcast ? $"{tab.Title} ({status})" : tab.Title;
        if (tab.Label.Text.StartsWith(BellMark, StringComparison.Ordinal)) label = BellMark + label;
        tab.Label.Text = label;
        tab.Status = link;
        PaintTabDot(tab, tab.HostColorId is not null || tab.Link is not null || tab.Bar is not null);
        ApplyTabName(tab);
    }

    /// <summary>Show (or hide) the link dot for <see cref="WorkspaceTab.Status"/>. The dot shape has no automation peer: its
    /// state is the tab's ItemType ("" = no dot), for tests and screen readers.</summary>
    private void PaintTabDot(WorkspaceTab tab, bool connection)
    {
        var link = tab.Status;
        if (connection)
        {
            tab.Dot.Fill = Ui.Brush(RootGrid, TabDotBrush(link));
            tab.Dot.Visibility = Visibility.Visible;
        }
        else tab.Dot.Visibility = Visibility.Collapsed;
        AutomationProperties.SetItemType(tab.Select, !connection ? "" : link is null ? "link online" : TabDotBrush(link) == "SessionConnectingBrush" ? "link reconnecting" : "link offline");
    }

    /// <summary>Theme brush for a tab's link dot: amber while the core retries or the PC sleeps, red once offline.</summary>
    internal static string TabDotBrush(string? status) => status switch
    {
        null => "SessionConnectedBrush",
        _ when status.StartsWith("reconnecting", StringComparison.Ordinal) || status == "suspended" => "SessionConnectingBrush",
        _ => "CriticalBrush",
    };

    private static void ApplyTabName(WorkspaceTab tab)
    {
        var name = tab.Label.Text.StartsWith(BellMark, StringComparison.Ordinal) ? tab.Label.Text[BellMark.Length..] : tab.Label.Text;
        var text = tab.Status is null ? name : $"{name}, {tab.Status}";
        AutomationProperties.SetName(tab.Select, text);
        LazyToolTip.Set(tab.Select, text);
    }

    /// <summary>
    /// Hand an SSH tab to the core's session supervisor. Only a vault login or a key without a passphrase is
    /// reconnected automatically (the core repeats it within broker policy); a password session is never re-entered
    /// silently and shows "disconnected" instead. <paramref name="secret"/> is used only as the vault credential id.
    /// </summary>
    /// <param name="from">The library the connection lives in: a Quick Connect library is never saved, so its tab is not
    /// tied to a library connection (not in workspaces, not in the tree's session state).</param>
    private void Supervise(TerminalView view, string connectionId, string? user, SshLoginKind kind, string? secret, string? keyPath, LibraryClient? from = null)
    {
        if (_tabs.FirstOrDefault(t => ReferenceEquals(t.View, view)) is not { } tab) return;
        if (from is null)
        {
            TieTab(tab, connectionId);
            SyncSessionRows(); // UI-05: the row moves under its connection
            PaintTab(tab);
            AddSessionBar(tab, connectionId, user);
            AutoStartSessionLog(tab); // LOG-01
            RefreshInspectorFor(connectionId); // Activity: "Connected in 1 tab"
            // The tab only counts for restore once it belongs to a connection; it was added before the sign-in.
            SaveOpenSessions();
        }
        var again = SupervisedSession.CanReconnect(kind, secret) ? kind : SshLoginKind.Password;
        var value = again switch { SshLoginKind.Vault or SshLoginKind.Vaultwarden => secret, SshLoginKind.KeyFile => keyPath, _ => null };
        try
        {
            var library = from ?? _library;
            tab.Resupervise = session => SupervisedSession.Start(Sessions, library, session, connectionId, user, again, value);
            tab.Link = tab.Resupervise(view.Session);
            tab.LinkSeen = tab.Link.Link;
            _linkTimer.Start();
        }
        catch (BastionException) { /* the tab works as before, it just does not reconnect */ }
    }

    /// <summary>Show each supervised tab's link state, and swap in the new shell after a reconnect.</summary>
    private void PollLinks()
    {
        var any = false;
        foreach (var tab in _tabs)
        {
            if (tab.Link is not { } link) continue;
            any = true;
            var n = link.Link;
            if (n != tab.LinkSeen)
            {
                tab.LinkSeen = n;
                try { FinishTabLogs(tab, "connection lost, reconnected"); tab.View!.ReplaceSession(link.TakeTerminal()); ReattachTriggers(tab.View!); AutoStartSessionLog(tab); }
                catch (BastionException) { }
                // The Files panel was on the old connection: reopen it on the new one.
                if (tab.Files is not null) _ = ReopenFilesAsync(tab);
            }
            var s = link.Status;
            tab.Bar?.SetState(s.State switch
            {
                SessionLinkState.Connecting or SessionLinkState.Reconnecting or SessionLinkState.Suspended => SessionBarState.Connecting,
                SessionLinkState.Failed or SessionLinkState.Closed => SessionBarState.Disconnected,
                _ => SessionBarState.Connected,
            });
            SetTabStatus(tab, s.State switch
            {
                SessionLinkState.Reconnecting => $"reconnecting {s.Attempt}/{SupervisedSession.MaxAttempts}",
                SessionLinkState.Suspended => "suspended",
                SessionLinkState.Failed or SessionLinkState.Closed => "disconnected",
                _ => null,
            });
            // Owner point W25 (Tabby-style): a spinning status while the core keeps retrying (1 s doubling to 60 s), then
            // a red one once it gives up.
            // MAC-RECONNECT-BADGE: the badge names the connection; the attempt count is in its tooltip and accessible name.
            tab.View!.SetBanner(s.State switch
            {
                SessionLinkState.Reconnecting => $"Reconnecting to {tab.Title}",
                SessionLinkState.Suspended => $"Paused: {tab.Title}",
                SessionLinkState.Failed => $"Gave up reconnecting{(s.Reason is { } r ? ": " + r : "")}. Right-click the tab › Reconnect.",
                _ => null,
            }, warning: s.State == SessionLinkState.Failed, busy: s.State == SessionLinkState.Reconnecting, detail: s.State switch
            {
                SessionLinkState.Reconnecting => $"Connection lost. Reconnecting… attempt {s.Attempt} of {SupervisedSession.MaxAttempts}",
                SessionLinkState.Suspended => "Paused while the PC sleeps. Reconnects on resume.",
                _ => null,
            });
            if (s.State == SessionLinkState.Failed && s.Reason is { } why) LazyToolTip.Set(tab.Select, $"{tab.Title}: disconnected — {why}. Connect again from the library.");
            if (s.State == SessionLinkState.Failed) { FinishTabLogs(tab, "connection lost"); SessionEnded(tab); } // B5: the link is lost for good (runs once per tab)
        }
        if (any) SyncSessionRows(); // UI-05: dots follow the link state (no-op when nothing changed)
        if (!any) _linkTimer.Stop();
    }

    private void OnSuspendStatusChanged(object? sender, object e)
    {
        var status = Microsoft.Windows.System.Power.PowerManager.SystemSuspendStatus;
        DispatcherQueue.TryEnqueue(() =>
        {
            // Sleep always locks protected documents ("Screen lock and sleep always lock it"), remember-until-quit or not.
            if (status == Microsoft.Windows.System.Power.SystemSuspendStatus.Entering
                && DocumentLockDue(TimeSpan.Zero, screenLocked: false, asleep: true) == AutoLockReason.Sleep)
                LockDocumentsFor(AutoLockReason.Sleep);
            foreach (var tab in _tabs)
            {
                if (status == Microsoft.Windows.System.Power.SystemSuspendStatus.Entering) tab.Link?.Sleep();
                else if (status is Microsoft.Windows.System.Power.SystemSuspendStatus.AutoResume or Microsoft.Windows.System.Power.SystemSuspendStatus.ManualResume) tab.Link?.Wake();
            }
        });
    }

    /// <summary>B12-W1: the open tabs belong to the app, not to this window (SessionStore.cs), so a torn-off window can
    /// share them. <see cref="_tabs"/> is this window's live list in strip order; change it only through <see cref="TabStore"/>.</summary>
    private static SessionStore<WorkspaceTab> TabStore => AppTabs.Store;
    private IReadOnlyList<WorkspaceTab> _tabs => TabStore.TabsOf(this);
    private WorkspaceTab? _active;

    /// <summary>The tab link dot's diameter, as on the Mac (7 pt).</summary>
    private const double TabDotSize = 7;

    /// <param name="waiting">A2-W26: the saved tab a not-connected tab stands in for after a crash, shown as <paramref name="notice"/>
    /// with the icon <paramref name="glyph"/> (restore path only).</param>
    private WorkspaceTab AddTab(string title, TerminalView? view, WebTabView? web = null, RemoteDesktopView? rdp = null, SftpPanel? files = null, string? hostId = null,
        OpenTabDto? waiting = null, FrameworkElement? notice = null, string? glyph = null, PluginTabView? plugin = null)
    {
        BuildTitleBar(); // its strip takes the header; built before the tab joins the list (WIN-COLD-LIGHT)
        var label = new TextBlock { Text = title, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
        var dot = new Microsoft.UI.Xaml.Shapes.Ellipse { Width = TabDotSize, Height = TabDotSize, VerticalAlignment = VerticalAlignment.Center, Visibility = Visibility.Collapsed };
        var unread = view is null ? null : NewUnreadDot();
        var select = new Button
        {
            Style = Ui.Style("TabSelectButtonStyle"),
            Content = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { Ui.Icon(glyph ?? (web is not null ? "GlyphWeb" : rdp is not null ? "GlyphDesktop" : files is not null ? "GlyphFolder" : "GlyphTerminal"), "SmallIconSize"), label, dot } },
        };
        if (unread is not null) ((StackPanel)select.Content).Children.Add(unread);
        AutomationProperties.SetName(select, title);
        LazyToolTip.Set(select, title);
        var close = new Button { Style = Ui.Style("TabCloseButtonStyle"), Content = Ui.Icon("GlyphClose", "TabCloseGlyphSize"), VerticalAlignment = VerticalAlignment.Center };
        AutomationProperties.SetName(close, "Close " + title);
        LazyToolTip.Set(close, "Close (Ctrl+Shift+W)");
        var header = new Grid
        {
            CornerRadius = Ui.Radius("TabCornerRadius"),
            MinWidth = Ui.Double("TabMinWidth"),
            Height = Ui.Double("ControlHeight"),
            Background = _transparent,
        };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        header.Children.Add(select);
        Grid.SetColumn(close, 1);
        header.Children.Add(close);
        var hostBar = NewHostBar();
        Grid.SetColumnSpan(hostBar, 2);
        header.Children.Add(hostBar);

        var panes = view is null ? null : new SplitPanes(view);
        // Row 0 holds the session title bar of a saved SSH connection (MainWindow.SessionBar.cs); row 1 the content and Files.
        var content = (FrameworkElement?)panes ?? (FrameworkElement?)web ?? (FrameworkElement?)rdp ?? (FrameworkElement?)files ?? (FrameworkElement?)plugin ?? notice!;
        Grid.SetRow(content, 1);
        var body = new Grid
        {
            RowDefinitions = { new RowDefinition { Height = GridLength.Auto }, new RowDefinition { Height = new GridLength(1, GridUnitType.Star) } },
            ColumnDefinitions = { new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }, new ColumnDefinition { Width = GridLength.Auto } },
            Children = { content },
        };
        var tab = new WorkspaceTab { Title = title, DefaultTitle = title, View = view, Panes = panes, Web = web, Rdp = rdp, Files = files, Plugin = plugin, Body = body, Header = header, Select = select, Close = close, Label = label, Dot = dot, UnreadDot = unread, HostBar = hostBar, HostColorId = hostId, Waiting = waiting };
        LeakProbe.Track(tab, "WorkspaceTab");
        LeakProbe.Track(body, "TabBody");
        header.ContextFlyout = TabMenu(tab);
        LeakProbe.TrackNative(body, "nTabBody");
        LeakProbe.TrackNative(header, "nTabHeader");
        LeakProbe.TrackNative(header.ContextFlyout, "nTabMenu");
        EnableTabDrag(tab);
        header.PointerEntered += (_, _) => { tab.Hover = true; PaintTab(tab); };
        header.PointerExited += (_, _) => { tab.Hover = false; PaintTab(tab); };
        AttachTabPreview(tab);
        select.Click += (_, _) => PickTab(tab);
        select.DoubleTapped += (_, e) => { e.Handled = true; _ = RenameTabAsync(tab); }; // TABBAR-WIN: double-click renames
        close.Click += (_, _) => _ = RequestCloseTab(tab, close.FocusState == FocusState.Keyboard ? FocusState.Keyboard : FocusState.Pointer);
        TabStore.Add(this, tab);
        if (((object?)rdp ?? web) is { } recorded) BeginTabActivity(recorded, hostId);
        if (rdp is not null && hostId is not null) rdp.Closed += (_, _) => SessionEnded(tab); // B5: the remote desktop ended
        TabStrip.Children.Add(header);
        SessionHost.Children.Add(tab.Body);
        LayoutTabs();
        ActivateTab(tab);
        // A2-W26: a web page may open after its connect call has returned (through a gateway), so it takes a waiting tab's place here.
        if (web is not null && hostId is not null && _tabs.FirstOrDefault(t => t.Waiting?.Connection == hostId) is { } stood)
            _ = TakeRestoredPlaceAsync(stood, tab);
        return tab;
    }

    /// <summary>A tab's right-click menu. SSH tabs of a saved connection offer Reconnect as… (replaces this tab) and
    /// Connect as… in a new tab; the entries hide on other tabs.</summary>
    private MenuFlyout TabMenu(WorkspaceTab tab)
    {
        var menu = new MenuFlyout();
        // Owner points 3, 26: Reconnect reuses the login just used, behind the "Reconnecting…" card (SSH and RDP).
        var reconnect = new MenuFlyoutItem { Text = "Reconnect" };
        AutomationProperties.SetAutomationId(reconnect, "TabReconnect");
        TreeItem? Saved() => (tab.ConnectionId ?? (tab.Rdp is not null ? tab.HostColorId : null)) is { } sid
            && TreeItem.Find(_roots, sid) is { } si && (IsSsh(si) || IsRdp(si)) ? si : null;
        reconnect.Click += (_, _) => { if (tab.Waiting is not null) _ = ConnectRestoredAsync(tab); else if (Saved() is { } item) _ = ConnectAsync(item, replacing: tab); };
        var reconnectAs = new MenuFlyoutItem { Text = "Reconnect as…" };
        var connectAs = new MenuFlyoutItem { Text = "Connect as… in New Tab" };
        var close = new MenuFlyoutItem { Text = "Close Tab", KeyboardAcceleratorTextOverride = "Ctrl+Shift+W" };
        TreeItem? Target() => tab.ConnectionId is { } id && tab.View is not null && TreeItem.Find(_roots, id) is { } item && IsSsh(item) ? item : null;
        reconnectAs.Click += (_, _) => { if (Target() is { } item) _ = ConnectAsync(item, connectAs: true, replacing: tab); };
        connectAs.Click += (_, _) => { if (Target() is { } item) _ = ConnectAsync(item, connectAs: true); };
        close.Click += (_, _) => _ = RequestCloseTab(tab, FocusState.Pointer);
        // B12-W2b: the tab's content moves to a window of its own; "Move to Main Window" there brings it back.
        var tearOff = new MenuFlyoutItem { Text = "Move Tab to New Window" };
        AutomationProperties.SetAutomationId(tearOff, "TabTearOff");
        tearOff.Click += (_, _) => TearOff(tab, null);
        menu.Opening += (_, _) =>
        {
            var ssh = Target() is not null;
            reconnect.Visibility = tab.Waiting is not null || Saved() is not null ? Visibility.Visible : Visibility.Collapsed;
            reconnectAs.Visibility = connectAs.Visibility = ssh ? Visibility.Visible : Visibility.Collapsed;
        };
        // TABBAR-WIN (Mac #1277 item 4): a name for this tab's life; empty brings back the automatic one.
        var rename = new MenuFlyoutItem { Text = "Rename Tab…" };
        AutomationProperties.SetAutomationId(rename, "TabRename");
        LazyToolTip.Set(rename, "Name this tab; empty for the automatic name. Double-click the tab too.");
        rename.Click += (_, _) => _ = RenameTabAsync(tab);
        menu.Items.Add(rename);
        menu.Items.Add(new MenuFlyoutSeparator());
        menu.Items.Add(reconnect);
        menu.Items.Add(reconnectAs);
        menu.Items.Add(connectAs);
        menu.Items.Add(tearOff);
        menu.Items.Add(close);
        AddBroadcastItem(menu, tab);
        AddLogCopyItems(menu, tab);
        AddSessionToolItems(menu, tab);
        AddGroupItems(menu, tab);
        return menu;
    }

    /// <summary>
    /// The active tab takes the session surface colour, so it reads as part of the terminal below it (as in Windows
    /// Terminal); inactive tabs are quiet text with a hover fill. Plain brush changes, no transitions.
    /// </summary>
    private void PaintTab(WorkspaceTab tab)
    {
        var active = ReferenceEquals(tab, _active);
        tab.Header.Background = active ? ToneBrush(t => t.ActiveTab) ?? Ui.Brush(RootGrid, "ActiveTabBrush") : tab.Hover ? Ui.Brush(RootGrid, "SubtleHoverBrush") : GroupTint(tab) ?? _transparent;
        PaintHostColor(tab, active);
        tab.Select.Foreground = (active || tab.Hover ? ToneBrush(t => t.Text) : ToneBrush(t => t.SecondaryText))
            ?? Ui.Brush(RootGrid, active ? "ActiveTabForegroundBrush" : tab.Hover ? "TextPrimaryBrush" : "TextSecondaryBrush");
        var closeStyle = Ui.Style(active && !LightChrome ? "SessionTabCloseButtonStyle" : "TabCloseButtonStyle");
        if (!ReferenceEquals(tab.Close.Style, closeStyle)) tab.Close.Style = closeStyle;
        AutomationProperties.SetItemStatus(tab.Select, TabItemStatus(tab, active));
    }

    private void ActivateTab(WorkspaceTab tab) => ActivateTab(tab, focus: true);

    /// <param name="focus">False when the tree keeps focus (selecting a connection with a live session, owner point 18).</param>
    private void ActivateTab(WorkspaceTab tab, bool focus)
    {
        // B12-W2b: a torn-off tab is shown in its own window; bring that window forward instead.
        if (tab.Window is { } torn)
        {
            torn.Activate();
            if (focus) tab.FocusContent(FocusState.Programmatic);
            return;
        }
        _pageConnectionId = null; // picking a tab leaves the connection page (UI-04)
        LeaveHome(); // picking a tab leaves the start page (TABBAR-WIN)
        var previous = _active;
        // Speed marks: opening a tab (new terminal, first fit) and the tab shown after a close are not tab switches.
        var mark = !tab.Shown ? "tab-open" : previous is null || !_tabs.Contains(previous) ? "tab-after-close" : "tab-switch";
        tab.Shown = true;
        PerfTrace.AfterLayout(DispatcherQueue, mark, PerfTrace.Now());
        var probe = TabSwitchProbe.Begin(mark);
        _active = tab;
        SetUnread(tab, false);
        if (tab.Label.Text.StartsWith(BellMark, StringComparison.Ordinal))
        {
            tab.Label.Text = tab.Label.Text[BellMark.Length..];
            ApplyTabName(tab);
        }
        // Only the tab that was shown and the one now shown change: hiding and repainting every tab cost a tab switch
        // time in proportion to the tab count (q-night-5: 83.8 ms against 50).
        foreach (var t in _tabs)
        {
            if (t.Window is not null) continue; // shown in its own window (B12-W2b)
            var show = ReferenceEquals(t, tab);
            if (show || t.Body.Visibility == Visibility.Visible)
            {
                t.Body.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            }
        }
        if (previous is not null && !ReferenceEquals(previous, tab) && _tabs.Contains(previous)) PaintTab(previous);
        PaintTab(tab);
        SyncSessionSurface();
        RevealGroupOf(tab);
        // A switch changes neither which tabs are open nor the library, so only the selected tab is saved, off the UI
        // thread. A new or closed tab (the tab set changed since the last full update) still runs the full update.
        if (previous is null || _tabs.Count != _workspaceTabCount) UpdateWorkspace(); else SaveOpenSessions(inBackground: true);
        tab.Header.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false });
        TabSwitchProbe.End(DispatcherQueue, probe);
        // Never into a terminal while the All tabs list is open: typing meant for its search would run in the shell.
        if (!focus || AllTabsListOpen) return;
        tab.FocusContent(FocusState.Programmatic);
        // A menu flyout that opened this tab (Terminal profiles, Connect) hands focus back to its button as it closes,
        // after this call: take it back once, unless a dialog is up or another tab became active meanwhile.
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            if (ReferenceEquals(_active, tab) && ModalHost.Visibility == Visibility.Collapsed && !AllTabsListOpen) tab.FocusContent(FocusState.Programmatic);
        });
    }

    /// <summary>Close a terminal tab: its program is ended and the native session freed. <paramref name="how"/> is how
    /// focus moves on (Keyboard shows the focus rectangle, Pointer does not).</summary>
    private void CloseTab(WorkspaceTab tab, FocusState how = FocusState.Programmatic, bool endsSession = true)
    {
        // B5: after-disconnect hooks once per session end; not for a tab a reconnect replaces.
        if (endsSession) SessionEnded(tab);
        _disconnectHooksFired.Remove(tab);
        AppLog.Info("Tab closing");
        FinishTabLogs(tab, "tab closed"); // LOG-CORE-02: footer with the reason before the sessions go
        var index = TabStore.IndexOf(this, tab);
        var wasTornOff = tab.Window is not null;
        EndTabActivity((object?)tab.Rdp ?? tab.Web, "closed_by_user");
        tab.Link?.Dispose(); // cancel: no reconnect after the user closed the tab
        tab.Files?.Dispose();
        tab.Web?.Dispose();
        tab.Rdp?.Dispose();
        tab.Plugin?.Dispose();
        foreach (var pane in tab.AllPanes) pane.Dispose();
        // B12-W2b: its torn-off window goes with it, after the content is disposed: the views are disposed while they
        // are still in a live window (q958: disposing them out of any tree ended the app).
        CloseWindowOf(tab);
        TabStrip.Children.Remove(tab.Header);
        SessionHost.Children.Remove(tab.Body);
        ForgetTabPreview(tab);
        TabStore.Remove(tab);
        LeakProbe.MarkDisposed(tab);
        LeakProbe.MarkDisposed(tab.Body);
        LeakProbe.TabClosed(DispatcherQueue);
        LayoutTabs();
        if (tab.Group is not null) RenderStrip();
        if (tab.ConnectionId is { } closed) RefreshInspectorFor(closed);
        // A torn-off tab was not the strip's active tab: the main window keeps what it shows.
        if (wasTornOff && _active is not null) { UpdateWorkspace(); return; }
        var docked = _tabs.Where(IsDocked).ToList();
        if (docked.Count > 0)
        {
            ActivateTab(docked[Math.Clamp(index - 1, 0, docked.Count - 1)]);
            return;
        }
        _active = null;
        UpdateWorkspace();
        FocusWorkspace(how);
    }

    private void Files_Click(object sender, RoutedEventArgs e)
    {
        if (_active is { View: not null } tab) _ = ToggleFilesAsync(tab);
    }

    /// <summary>
    /// Show or hide an SSH tab's Files panel: an SFTP browser on the tab's own connection (no new login). Opening SFTP
    /// talks to the server, so it runs off the UI thread; a server without SFTP is reported.
    /// </summary>
    /// <summary>Widest the Files panel gets beside the terminal (DIPs).</summary>
    private const double FilesPanelWidth = 440;

    /// <summary>
    /// The Files panel's column: open, it shares the tab with the terminal (half each) up to FilesPanelWidth, so a narrow
    /// or zoomed window never pushes it past the right edge (it had a fixed 440 px width, WIN-EVEN-01 at 150% / 800 px);
    /// closed, the column takes no space.
    /// </summary>
    private static void SetFilesColumn(WorkspaceTab tab, bool open)
    {
        if (tab.Body.ColumnDefinitions.Count < 2) return; // a Files-only tab: the panel is the whole body
        var column = tab.Body.ColumnDefinitions[1];
        column.Width = open ? new GridLength(1, GridUnitType.Star) : GridLength.Auto;
        column.MaxWidth = open ? FilesPanelWidth : double.PositiveInfinity;
    }

    private async Task ToggleFilesAsync(WorkspaceTab tab)
    {
        if (tab.Files is { } open)
        {
            tab.Body.Children.Remove(open);
            open.Dispose();
            tab.Files = null;
            SetFilesColumn(tab, open: false);
            tab.FocusContent(FocusState.Programmatic);
            SaveOpenSessions();
            return;
        }
        if (tab.ConnectionId is null) return;
        var terminal = tab.View!.Session;
        SftpSession sftp;
        try { sftp = await Task.Run(() => SftpSession.Open(terminal)); }
        catch (Exception ex) when (ex is BastionException or ObjectDisposedException)
        {
            await ShowModal("Could not open files", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }
        if (!_tabs.Contains(tab) || tab.Files is not null || tab.UserDisconnected) { sftp.Dispose(); return; } // PR-1289: not after Disconnect
        var panel = new SftpPanel(sftp, PickUploadFile)
        {
            EditDataDir = SessionDataDir,
            TerminalFolder = () => (tab.Panes?.Focused ?? tab.View) is { Session: { IsDisposed: false } s } ? s.Cwd() : null,
        };
        Grid.SetColumn(panel, 1);
        Grid.SetRow(panel, 1);
        tab.Body.Children.Add(panel);
        tab.Files = panel;
        SetFilesColumn(tab, open: true);
        // A2-W26: the saved set records the Files panel now, so a crash before the next tab change still brings it back.
        SaveOpenSessions();
        await panel.StartAsync();
    }

    /// <summary>
    /// PR-1289 MED: Reconnect's new tab takes the old tab's place in the strip and its group, then the old tab closes.
    /// The new tab is shown and focused if the old one was shown when Reconnect began; a tab the user picked while it
    /// was pending stays shown.
    /// </summary>
    private async Task TakeReconnectPlaceAsync(WorkspaceTab replacing, WorkspaceTab opened, WorkspaceTab? shownBefore)
    {
        if (ReferenceEquals(replacing, opened) || !_tabs.Contains(replacing)) return;
        var group = replacing.Group;
        await MoveTabAsync(opened, replacing, after: false);
        if (group is not null && opened.Group != group)
            await RunStripOp(new System.Text.Json.Nodes.JsonObject { ["op"] = "addToGroup", ["tab"] = opened.StripId.ToString(), ["group"] = group });
        // Reconnect keeps the earlier session's text above the new prompt (C ABI 134).
        if (replacing.View?.Session is { IsDisposed: false } was && opened.View?.Session is { IsDisposed: false } now) now.CarryOver(was);
        CloseTab(replacing, endsSession: false);
        if (!_tabs.Contains(opened)) return;
        var keep = shownBefore is not null && !ReferenceEquals(shownBefore, replacing) && _tabs.Contains(shownBefore) ? shownBefore : opened;
        ActivateTab(keep);
    }

    private async Task ReopenFilesAsync(WorkspaceTab tab)
    {
        await ToggleFilesAsync(tab);
        await ToggleFilesAsync(tab);
    }

    /// <summary>The file picker for an upload, parented to this window.</summary>
    private async Task<string?> PickUploadFile()
    {
        var picker = new Windows.Storage.Pickers.FileOpenPicker();
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        var file = await picker.PickSingleFileAsync();
        return file?.Path;
    }

    private void SplitRight_Click(object sender, RoutedEventArgs e) => SplitActive(SplitAxis.Right);
    private void SplitDown_Click(object sender, RoutedEventArgs e) => SplitActive(SplitAxis.Down);

    /// <summary>
    /// Open a second shell beside the focused pane of the active tab. SSH tabs get another channel on the same
    /// connection (no new login); local tabs start their program again. The new pane is not supervised: it ends when
    /// the connection drops, and only the tab's supervised pane reconnects (the next pane takes over when it closes).
    /// </summary>
    internal TerminalView? SplitActive(SplitAxis axis)
    {
        if (_modal is not null || _active is not { Panes: { } panes } tab) return null;
        var at = panes.Focused;
        TerminalSession session;
        try
        {
            if (tab.StartLocal is { } start) session = start();
            else
            {
                var size = at.Session.Screen();
                session = at.Session.OpenSibling(axis == SplitAxis.Right ? Math.Max(2, size.Cols / 2) : size.Cols, axis == SplitAxis.Down ? Math.Max(1, size.Rows / 2) : size.Rows);
            }
        }
        catch (Exception ex) when (ex is BastionException or ObjectDisposedException)
        {
            _ = ShowModal("Could not split the pane", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return null;
        }
        var view = MakePane(session, tab.View);
        if (tab.Zoom != 0) view.SetFontSize(TabFontSize(tab));
        panes.Split(at, view, axis);
        return view;
    }

    /// <summary>
    /// Alt+arrow moves focus between panes, as in Windows Terminal (only when the tab is split, so a single terminal
    /// still gets Alt+arrow).
    /// </summary>
    private bool SplitKey(VirtualKey key, bool shift, WorkspaceTab tab)
    {
        // Splitting is the configurable Split Right / Split Down (Windows defaults Alt+Shift+= and Alt+Shift+-), run by
        // the shortcut dispatcher, so a rebinding is honoured.
        if (shift || tab.Panes is not { } panes || panes.Panes.Count < 2) return false;
        return key switch
        {
            VirtualKey.Left => panes.MoveFocus(PaneDirection.Left),
            VirtualKey.Right => panes.MoveFocus(PaneDirection.Right),
            VirtualKey.Up => panes.MoveFocus(PaneDirection.Up),
            VirtualKey.Down => panes.MoveFocus(PaneDirection.Down),
            _ => false,
        };
    }

    /// <summary>Close one pane; the last pane closes the whole tab (and cancels its supervisor).</summary>
    private void ClosePane(WorkspaceTab tab, TerminalView pane, FocusState how)
    {
        if (tab.Panes!.Panes.Count <= 1) { CloseTab(tab, how); return; }
        if (ReferenceEquals(pane, tab.View)) MoveSupervision(tab, pane);
        tab.Panes!.Remove(pane);
        pane.Dispose();
        tab.Panes.Focused.Focus(how);
        SaveOpenSessions();
    }

    /// <summary>
    /// PAR-7 (as on the Mac): the supervised pane is closing but other panes stay. Cancel its supervisor (that shell
    /// ends, no reconnect) and hand the tab to the next surviving pane, supervised with the same login settings.
    /// </summary>
    private void MoveSupervision(WorkspaceTab tab, TerminalView closing)
    {
        var survivor = tab.Panes!.Panes.First(p => !ReferenceEquals(p, closing));
        tab.Link?.Dispose();
        tab.Link = null;
        tab.View = survivor;
        if (tab.Resupervise is not { } start || survivor.Session.IsDisposed) return;
        try
        {
            tab.Link = start(survivor.Session);
            tab.LinkSeen = tab.Link.Link;
            _linkTimer.Start();
        }
        catch (BastionException) { /* the pane works as before, it just does not reconnect */ }
    }

    private void CycleTab(int direction)
    {
        if (_tabs.Count == 0) return;
        var index = _active is null ? 0 : TabStore.IndexOf(this, _active);
        PickTab(_tabs[(index + direction + _tabs.Count) % _tabs.Count]);
    }

    /// <summary>Tabs over the session, or the empty state; its wording depends on whether the library is empty.</summary>
    /// <summary>The tab count at the last <see cref="UpdateWorkspace"/>; a tab switch with the same count skips it.</summary>
    private int _workspaceTabCount = -1;

    private void UpdateWorkspace()
    {
        _workspaceTabCount = _tabs.Count;
        SaveOpenSessions();
        var hasTabs = _tabs.Any(IsDocked); // torn-off tabs show in their own windows (B12-W2b)
        if (!hasTabs && _navAutoHidden) { _navAutoHidden = false; UpdatePanes(); }
        ApplyHome(); // sessions, or the start page with no tab or while Home is picked (TABBAR-WIN)
        UpdatePanes(); // a session opened hides the details pane; the last one closed brings it back for the selection
        if (!hasTabs && (_firstFramesDone || BuildsEverythingFirst)) RefreshRecents(); // WIN-COLD-LIGHT: after the first frames (BuildAfterFirstFrame)
        RefreshFolderDashboard(); // library or session change: rows and Status follow, no polling
        UpdateSearchHint();
        var emptyLibrary = _roots.Count == 0;
        EmptyFolderIcon.Visibility = emptyLibrary ? Visibility.Visible : Visibility.Collapsed;
        EmptyTerminalIcon.Visibility = emptyLibrary ? Visibility.Collapsed : Visibility.Visible;
        EmptyTitle.Text = emptyLibrary ? "No connections yet" : _homeShown ? "Home" : "No active sessions";
        EmptyText.Text = emptyLibrary
            ? "Add a connection to get started, or open a local terminal."
            : "Open a saved connection or use Quick Connect.";
        EmptyNewConnection.Visibility = emptyLibrary ? Visibility.Visible : Visibility.Collapsed;
        EmptyQuickConnect.Visibility = emptyLibrary ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>
    /// The counts a status bar would show sit in the search box's hint (owner 2026-11-15: no status bar, as on the Mac).
    /// Runs with the start page, so on every library or session change; no polling.
    /// </summary>
    private void UpdateSearchHint()
    {
        var hint = $"Search or connect: {Plural(TreeItem.CountConnections(_roots), "connection")}, {Plural(_tabs.Count, "open session")}. "
            + "Enter connects to the top match or to a typed address (Ctrl+F, Ctrl+L)";
        SetSearchHint(hint); // the box is built after the first frame (WIN-COLD-LIGHT)
    }

    private async Task<bool> ConfirmPaste(string text)
    {
        var lines = text.TrimEnd('\r', '\n').Split('\n').Length;
        var body = Ui.Text($"The clipboard holds {lines} lines. This shell has not enabled bracketed paste, so each line runs as soon as it is pasted.", "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        return await ShowModal("Paste multiple lines?", body, primary: "Paste", cancel: "Cancel", focusCancel: true);
    }

    /// <summary>A program's OSC 52 copy under the "ask" policy: show what it wants to put on the clipboard.</summary>
    private async Task<bool> ConfirmClipboardWrite(string text)
    {
        var body = new StackPanel { Spacing = Ui.Double("Space8") };
        var note = Ui.Text("A program in this session wants to put this text on the clipboard. Programs can never read the clipboard.", "BodyTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        body.Children.Add(note);
        var preview = Ui.Text(text.Length > 2000 ? text[..2000] + "…" : text, "CaptionTextBlockStyle");
        preview.TextWrapping = TextWrapping.Wrap;
        preview.IsTextSelectionEnabled = true;
        body.Children.Add(new ScrollViewer { Content = preview, MaxHeight = Ui.Double("DialogWidth") / 2 });
        return await ShowModal("Allow clipboard copy?", body, primary: "Copy", cancel: "Don't copy", focusCancel: true);
    }

    /// <summary>The OSC 52 policy in force: "off" when the managed policy forbids clipboard writes, else the setting.</summary>
    /// <summary>A terminal view with the app's settings: font, theme, paste and clipboard confirmations, bell, copy on select.</summary>
    private bool _closeConfirmed;

    /// <summary>Closing the window while any session is live asks first (<c>terminal.confirm-close</c>, CLOSE-01).</summary>
    private async void OnAppWindowClosing(Microsoft.UI.Windowing.AppWindow sender, Microsoft.UI.Windowing.AppWindowClosingEventArgs e)
    {
        CloseTrace.Begin("appwindow-closing");
        // W22: in full screen a close request first leaves full screen; the window closes only on the next request.
        // Second line of defence: Alt+F4 meant for a remote desktop never gets here (InitRemoteAltF4), but Alt+F4 with
        // the keyboard in a terminal or the tree does, and so does a close from the taskbar.
        if (_fullScreen && !_closeConfirmed)
        {
            e.Cancel = true;
            ToggleFullScreen();
            Announce("Left full screen. Close again to quit Gantry.");
            return;
        }
        var live = _closeConfirmed ? 0 : LiveSessionCount();
        if (!QuitDecision.ShouldAsk(SettingValue("terminal.confirm-close") == "true", _closeConfirmed || _demo, live)) return;
        e.Cancel = true; // before the first await: the window stays open while the user decides
        if (!await ConfirmQuit(live)) return;
        _closeConfirmed = true;
        Close();
    }

    private const uint WM_SYSCOMMAND = 0x0112;
    private const long SC_CLOSE = 0xF060;
    private const nuint RemoteAltF4SubclassId = 0xB22F4;
    /// <summary>Kept in a field so the delegate the native side calls is never collected.</summary>
    private SubclassProc? _remoteAltF4Proc;

    /// <summary>How long after the remote desktop saw Alt+F4 the Close command Windows makes of it still counts as that key press.</summary>
    internal const long RemoteAltF4WindowMs = 1000;
    /// <summary>When the focused remote desktop last got Alt+F4 (Environment.TickCount64), or long.MinValue.</summary>
    private long _remoteAltF4At = long.MinValue;

    /// <summary>
    /// True for the Close command Windows makes out of an Alt+F4 key press (not the caption button, the taskbar or the
    /// system menu): the keys are still down, or the remote desktop got Alt+F4 within <see cref="RemoteAltF4WindowMs"/>.
    /// The command is posted, so a quick press (q-w22-xrdp-rerun3: the test's chord, a fast typist) is already released
    /// when it arrives, and the key state alone let it through: Bastion left full screen.
    /// </summary>
    internal static bool IsAltF4Close(uint msg, long wParam, bool altDown, bool f4Down, long msSinceRemoteAltF4 = long.MaxValue) =>
        msg == WM_SYSCOMMAND && (wParam & 0xFFF0) == SC_CLOSE
        && ((altDown && f4Down) || (msSinceRemoteAltF4 >= 0 && msSinceRemoteAltF4 <= RemoteAltF4WindowMs));

    /// <summary>
    /// W22: Alt+F4 with the keyboard in a connected remote desktop (RDP, VNC) belongs to the remote session. The view
    /// sends the key there, but Windows still turns the same key press into a Close command for this window (handling
    /// KeyDown does not stop that), so Bastion closed, or left full screen, together with the remote window. That
    /// command is dropped here. Every other close request is untouched; Ctrl+Alt+Home hands the keyboard back first.
    /// </summary>
    private void InitRemoteAltF4()
    {
        _remoteAltF4Proc = (hwnd, msg, wParam, lParam, _, _) =>
        {
            if (msg != WM_SYSCOMMAND || ((long)wParam & 0xFFF0) != SC_CLOSE) return DefSubclassProc(hwnd, msg, wParam, lParam);
            // W22 diagnosis (q-rdpfail): one line per Close command, whether it is kept for the remote desktop and why.
            var (alt, f4, since, remote) = (Down(VirtualKey.Menu), Down(VirtualKey.F4), SinceRemoteAltF4(), RemoteDesktopHasKeyboard);
            var drop = IsAltF4Close(msg, (long)wParam, alt, f4, since) && remote;
            AppLog.Info($"W22 close command: {(drop ? "dropped (Alt+F4 for the remote desktop)" : "passed on")}; alt {alt}, f4 {f4}, ms since remote Alt+F4 {(since == long.MaxValue ? "none" : since.ToString())}, remote has keyboard {remote}");
            return drop ? IntPtr.Zero : DefSubclassProc(hwnd, msg, wParam, lParam);
        };
        var hwnd = Hwnd;
        try
        {
            if (!SetWindowSubclass(hwnd, _remoteAltF4Proc, RemoteAltF4SubclassId, 0)) return; // the full screen guard below still applies
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return; }
        Closed += (_, _) => RemoveWindowSubclass(hwnd, _remoteAltF4Proc, RemoteAltF4SubclassId);
    }

    private long SinceRemoteAltF4() => _remoteAltF4At == long.MinValue ? long.MaxValue : Environment.TickCount64 - _remoteAltF4At;

    /// <summary>A connected remote desktop has the keyboard focus and no dialog is open.</summary>
    private bool RemoteDesktopHasKeyboard =>
        _modal is null && FindAncestor<RemoteDesktopView>(FocusedElement) is { Desktop.IsConnected: true };

    /// <summary>A saved connection's own (or folder-inherited) terminal font; none for local shells or when unreadable.</summary>
    private TerminalFontOverride ConnectionFont(string? connectionId)
    {
        if (connectionId is null) return TerminalFontOverride.None;
        try { return TerminalFontOverride.From(_library.PropertyValues(connectionId).ToDictionary(v => v.Key, v => v.Effective)); }
        catch (BastionException) { return TerminalFontOverride.None; }
    }

    /// <summary>Put before a hidden tab's title when its program rang the bell.</summary>
    private const string BellMark = "\U0001F514 ";

    private TerminalView NewTerminalView(TerminalSession session, string? connectionId = null) =>
        NewTerminalView(session, ConnectionFont(connectionId), ConnectionTheme(connectionId));

    /// <summary>A saved connection's own (or folder-inherited) <c>terminal_theme</c> id; null follows the app's colours.</summary>
    private string? ConnectionTheme(string? connectionId)
    {
        if (connectionId is null) return null;
        try
        {
            var v = _library.PropertyValues(connectionId).FirstOrDefault(p => p.Key == "terminal_theme");
            return string.IsNullOrEmpty(v?.Effective) ? null : v.Effective;
        }
        catch (BastionException) { return null; }
    }

    /// <summary>A terminal with the app settings, except where <paramref name="font"/> sets the connection's own.</summary>
    private TerminalView NewTerminalView(TerminalSession session, TerminalFontOverride font, string? themeId = null)
    {
        var view = new TerminalView(session, font.Size ?? TerminalFontSize, font.Family ?? SettingValue("terminal.font-family"))
        {
            FontOverride = font,
            Ligatures = font.Ligatures ?? SettingValue("terminal.ligatures") != "false",
            ConfirmMultiLinePaste = ConfirmPaste,
            ConfirmClipboardWrite = ConfirmClipboardWrite,
            BellMode = SettingValue("terminal.bell"),
            CopyOnSelect = SettingValue("terminal.copy-on-select") == "true",
            CursorStyle = SettingValue("terminal.cursor-style"),
        };
        ApplyScrollback(view, SettingValue("terminal.scrollback"));
        view.ApplyClipboardPolicy(ClipboardPolicy());
        view.ThemeApplied += (_, _) => SyncSessionSurface();
        try { view.ApplyTheme(themeId ?? EffectiveTerminalTheme); view.OwnTheme = themeId is not null; } catch (BastionException) { /* keep the default colours */ }
        view.BellRang += (_, _) => MarkBell(view);
        view.KeysSent += OnPaneKeys;
        view.Pasted += (from, text) => _ = OnPanePasted(from, text);
        AttachTriggers(view);
        AttachTermEvents();
        return view;
    }

    /// <summary>A bell in a tab that is not showing puts a bell mark on its header until the tab is shown.</summary>
    private void MarkBell(TerminalView view)
    {
        if (_tabs.FirstOrDefault(t => t.AllPanes.Contains(view)) is not { } tab || ReferenceEquals(tab, _active) || tab.Label.Text.StartsWith(BellMark, StringComparison.Ordinal)) return;
        tab.Label.Text = BellMark + tab.Label.Text;
        AutomationProperties.SetName(tab.Select, $"{tab.Label.Text[BellMark.Length..]}{(tab.Status is { } st ? ", " + st : "")}, bell rang");
    }

    /// <summary>
    /// Close a tab the user asked to close. With <c>terminal.confirm-close</c> on (the default), a tab whose program is
    /// still running asks first. A local shell sitting at its prompt does not count as running (per-pane check, C ABI 133).
    /// </summary>
    private async Task RequestCloseTab(WorkspaceTab tab, FocusState how)
    {
        try
        {
            if (tab.AllPanes.Any(IsPaneBusy) && !await ConfirmClose($"“{tab.Title}” is still running. Closing it ends its program.", "Close Tab")) { AppLog.Info("Tab close cancelled"); return; }
            CloseTab(tab, how);
        }
        catch (Exception ex)
        {
            // Callers discard this task, so a failure would vanish: keep it in the app log (type and message, no content).
            AppLog.Warn($"Tab close failed ({ex.GetType().Name}): {ex.Message}");
            throw;
        }
    }

    private async Task RequestClosePane(WorkspaceTab tab, TerminalView pane, FocusState how)
    {
        var closesTab = tab.Panes!.Panes.Count <= 1; // PAR-7: the first pane is a pane like the others
        var running = closesTab ? tab.AllPanes.Any(IsPaneBusy) : IsPaneBusy(pane);
        if (running && !await ConfirmClose(closesTab ? $"“{tab.Title}” is still running. Closing it ends its program." : "This pane's program is still running. Closing the pane ends it.", closesTab ? "Close Tab" : "Close Pane")) return;
        ClosePane(tab, pane, how);
    }

    /// <summary>A pane counts as running while its program is alive, except a local shell idle at its prompt.
    /// A core error counts as running (the close asks, when asking is on) instead of stopping the close.</summary>
    private static bool IsPaneBusy(TerminalView pane)
    {
        try { return !pane.Session.IsDisposed && pane.Session.IsAlive && pane.Session.ForegroundBusy() != false; }
        catch (BastionException) { return true; }
    }

    private async Task<bool> ConfirmClose(string text, string primary)
    {
        if (SettingValue("terminal.confirm-close") != "true") return true;
        var body = Ui.Text(text, "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        return await ShowModal("Close running session?", body, primary: primary, cancel: "Cancel", focusCancel: true);
    }

    private string ClipboardPolicy()
    {
        try { if (PolicyClient.State() is { Error: not null } or { ForbidOsc52Write: true }) return "off"; }
        catch (BastionException) { return "off"; }
        var v = SettingValue("terminal.osc52");
        return v is "off" or "allow" ? v : "ask";
    }

    // ---- Keyboard ----

    private static bool Down(VirtualKey key) => InputKeyboardSource.GetKeyStateForCurrentThread(key).HasFlag(CoreVirtualKeyStates.Down);

    private bool IsInModal(DependencyObject? e)
    {
        for (; e is not null; e = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(e))
            if (ReferenceEquals(e, ModalCard)) return true;
        return false;
    }

    private DependencyObject? FocusedElement => _keyFocus ?? (ModalRoom.XamlRoot is { } root ? FocusManager.GetFocusedElement(root) as DependencyObject : null);

    /// <summary>
    /// Window shortcuts, seen before the focused control (tunnelling). A focused terminal keeps Ctrl+letter (except
    /// Ctrl+F, Ctrl+V and Ctrl+C over a selection), Delete and F6 for its program; the Ctrl+Shift shortcuts, Ctrl+Tab and Ctrl+F6 work everywhere.
    /// </summary>
    private void Root_PreviewKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (_modal is null && IsGated)
        {
            GateKeyDown(e);
            return;
        }
        // Esc closes an open full page even when focus is outside it (e.g. left on the tree); inside, PageHost_KeyDown handles it.
        if (_modal is null && e.Key == VirtualKey.Escape && PageHost.Visibility == Visibility.Visible && !Contains(PageHost, FocusedElement))
        {
            ClosePage();
            e.Handled = true;
            return;
        }
        // A focused remote desktop (RDP/VNC) gets every key, app shortcuts included (Ctrl+L, Ctrl+F, Ctrl+Alt+..., as in
        // mstsc full-keyboard mode). The exceptions are Ctrl+Alt+Home, which hands the keyboard back to the app, and
        // plain F11 (W22): sent to the remote, nothing on the keyboard could leave Bastion's full screen from here.
        // Win-key chords stay with local Windows (it takes them before any app sees them).
        if (_modal is null && FindAncestor<RemoteDesktopView>(FocusedElement) is not null)
        {
            // Not handled: the view sends Alt+F4 to the remote. Remembered so the Close command it also makes is dropped.
            if (e.Key == VirtualKey.F4 && Down(VirtualKey.Menu)) _remoteAltF4At = Environment.TickCount64;
            if (e.Key == VirtualKey.Home && Down(VirtualKey.Control) && Down(VirtualKey.Menu))
            {
                CycleRegion(1); // the view's LostFocus releases every key held on the remote
                e.Handled = true;
            }
            else if (e.Key == VirtualKey.F11 && !Down(VirtualKey.Control) && !Down(VirtualKey.Menu) && !Down(VirtualKey.Shift))
            {
                ToggleFullScreen();
                e.Handled = true;
            }
            return;
        }
        // Find bar options (W11): Alt+C Match case, Alt+R Regular expression.
        if (_modal is null && Down(VirtualKey.Menu) && !Down(VirtualKey.Control) && !Down(VirtualKey.Shift)
            && FindAncestor<TerminalView>(FocusedElement) is { } findPane && findPane.ToggleFindOption(e.Key, FocusedElement as DependencyObject))
        {
            e.Handled = true;
            return;
        }
        if (_modal is null && e.Key == VirtualKey.Enter && Down(VirtualKey.Menu) && Selected is not null && FindAncestor<TerminalView>(FocusedElement) is null)
        {
            // Opened after this key event: the dialog takes focus at once, and the same Enter must not reach it as
            // Save (PVE-TLS: Alt+Enter on a plugin entry opened Properties and closed it in one go).
            var target = Selected;
            DispatcherQueue.TryEnqueue(() => _ = PropertiesAsync(target));
            e.Handled = true;
            return;
        }
        if (_modal is null && _active is { Panes: not null } splitTab && Down(VirtualKey.Menu) && !Down(VirtualKey.Control) && SplitKey(e.Key, Down(VirtualKey.Shift), splitTab))
        {
            e.Handled = true;
            return;
        }
        // Configurable shortcuts first (Settings › Keyboard). Not while a page is open: its Keyboard page records keys.
        if (_modal is null && PageHost?.Visibility != Visibility.Visible
            && DispatchShortcut(e.Key, Down(VirtualKey.Control), Down(VirtualKey.Menu), Down(VirtualKey.Shift), FindAncestor<TerminalView>(FocusedElement) is not null))
        {
            e.Handled = true;
            return;
        }
        // F11: full screen (MainWindow.FullScreen.cs).
        if (_modal is null && e.Key == VirtualKey.F11 && !Down(VirtualKey.Control) && !Down(VirtualKey.Menu) && !Down(VirtualKey.Shift))
        {
            ToggleFullScreen();
            e.Handled = true;
            return;
        }
        // Ctrl+Alt+N (show/hide the library) is the core "toggle-library" shortcut, rebindable in Settings › Keyboard.
        if (_modal is not null || Down(VirtualKey.Menu)) return;
        var ctrl = Down(VirtualKey.Control);
        var shift = Down(VirtualKey.Shift);
        var focused = FocusedElement;
        var inTerminal = FindAncestor<TerminalView>(focused) is not null;
        var handled = true;
        switch (e.Key)
        {
            case VirtualKey.T when ctrl && shift: NewLocalShell(); break;
            // Ctrl+, opens Settings or brings its window forward (the Mac's Cmd+,); not a core shortcut, as on the Mac.
            case (VirtualKey)188 when ctrl && !shift: OpenSettings(null); break;
            // Select All has no rebindable chord in the core table; Ctrl+Shift+A as in Windows Terminal.
            case VirtualKey.A when ctrl && shift && inTerminal: RunCommand("select-all"); break;
            case VirtualKey.A when ctrl && shift && !inTerminal: ShowAllTabs(); break;
            // TABBAR-WIN: Home (start page) with tabs open, as the Mac's Cmd+Shift+H; not a core chord, as on the Mac.
            case VirtualKey.H when ctrl && shift: ShowHome(); break;
            case VirtualKey.W when ctrl && shift && _active is not null: _ = _active.Panes is { } p ? RequestClosePane(_active, p.Focused, FocusState.Keyboard) : RequestCloseTab(_active, FocusState.Keyboard); break;
            case VirtualKey.F6 when ctrl || !inTerminal: CycleRegion(shift ? -1 : 1); break;
            case VirtualKey.F when ctrl && !shift && !inTerminal: FocusSearch(); break;
            // Owner point W11: Ctrl+F finds in the terminal too (Ctrl+Shift+F, the rebindable chord, still works); Ctrl+C
            // copies when text is selected and is ^C otherwise; Ctrl+V pastes. As in Windows Terminal and Tabby.
            case VirtualKey.F when ctrl && !shift && inTerminal: RunCommand("find"); break;
            case VirtualKey.C when ctrl && !shift && focused is TerminalView && RunCommand("copy"): break;
            case VirtualKey.V when ctrl && !shift && focused is TerminalView: RunCommand("paste"); break;
            // Ctrl+Insert copies and Shift+Insert pastes in a terminal, the older Windows and PuTTY keys.
            case VirtualKey.Insert when ctrl && !shift && focused is TerminalView && RunCommand("copy"): break;
            case VirtualKey.Insert when shift && !ctrl && focused is TerminalView: RunCommand("paste"); break;
            // UI-05: Delete on a session row never deletes its connection.
            case VirtualKey.Delete when !ctrl && !shift && FindAncestor<LibraryTree>(focused) is not null && Tree.SelectedItem is not TreeItem { IsSession: true }: _ = DeleteAsync(); break;
            case VirtualKey.F2 when !ctrl && !shift && FindAncestor<LibraryTree>(focused) is not null && Selected is { } renamed: _ = RenameAsync(TreeItem.Find(_roots, renamed.Id) ?? renamed); break;
            // Enter on an SSH or web row connects. A folder or another protocol falls through to the tree's own handling.
            // UI-05: Enter on a session row focuses its tab (ItemInvoked); it never connects the parent again.
            case VirtualKey.Enter when !ctrl && !shift && FindAncestor<LibraryTree>(focused) is not null && Tree.SelectedItem is not TreeItem { IsSession: true } && FindAncestor<LibraryRow>(focused)?.Item is not { IsSession: true } && (CanOpen(Selected) || IsUnavailable(Selected)): _ = ConnectAsync(Selected); break;
            default: handled = false; break;
        }
        if (handled) e.Handled = true;
    }

    /// <summary>F6 / Shift+F6: toolbar, navigation pane, workspace, inspector (visible ones only).</summary>
    private void CycleRegion(int direction)
    {
        var regions = new List<(UIElement Region, Action Focus)> { (Toolbar, () => CompactLibraryButton.Focus(FocusState.Keyboard)) };
        if (NavVisible) regions.Add((NavPane, () => { if (_shown.Count == 0) SearchBox.Focus(FocusState.Keyboard); else FocusTreeSelection(FocusState.Keyboard); }));
        regions.Add((Workspace, () => FocusWorkspace(FocusState.Keyboard)));
        if (InspectorVisible) regions.Add((Inspector!, FocusInspector));
        var focused = FocusedElement;
        var current = regions.FindIndex(r => Contains(r.Region, focused));
        var next = current < 0 ? 0 : (current + direction + regions.Count) % regions.Count;
        regions[next].Focus();
    }

    /// <summary>
    /// Start-up focus is placed, not left to WinUI's first tab stop: since WIN-HEADER-MAC that stop is the "Search or connect"
    /// box (top of the sidebar), and a focused search box at start-up is against the library rule (library-ui-test). The
    /// tree's selection when it has rows, else the start page. A box someone already typed into keeps the focus.
    /// </summary>
    private void PlaceStartupFocus()
    {
        if (FocusedElement is not null && FocusedElement != SearchBox) return;
        if (SearchBox.Text.Length > 0) return;
        if (NavVisible && _shown.Count > 0) FocusTreeSelection();
        else FocusWorkspace();
    }

    private void FocusWorkspace(FocusState how = FocusState.Programmatic)
    {
        if (AllTabsListOpen) return; // the list keeps focus (a close from it lands here)
        if (_active is not null) { _active.FocusContent(how); return; }
        (EmptyNewConnection.Visibility == Visibility.Visible ? EmptyNewConnection : EmptyLocalShell).Focus(how);
    }

    private void FocusInspector()
    {
        Control target = InspectorActions.Visibility != Visibility.Visible ? HideInspectorButton
            : InspectorPrimaryButton.Visibility == Visibility.Visible ? InspectorPrimaryButton : InspectorMoreButton;
        target.Focus(FocusState.Keyboard);
    }

    private static T? FindAncestor<T>(DependencyObject? element) where T : DependencyObject
    {
        for (var e = element; e is not null; e = VisualTreeHelper.GetParent(e))
            if (e is T match) return match;
        return null;
    }

    private static bool Contains(UIElement ancestor, DependencyObject? element)
    {
        for (var e = element; e is not null; e = VisualTreeHelper.GetParent(e))
            if (ReferenceEquals(e, ancestor)) return true;
        return false;
    }

    // ---- In-window modal (replaces ContentDialog; see the note at the top of this file) ----

    private TaskCompletionSource<bool>? _modal;
    private Func<bool>? _modalValidate;
    private Control? _modalReturnFocus;

    /// <summary>
    /// Show <paramref name="body"/> in the modal and complete with true when the primary button is pressed (and
    /// <paramref name="validate"/>, if given, accepts), false for Cancel or Esc. Buttons read "Cancel | primary";
    /// a null <paramref name="cancel"/> shows the primary button alone. Focus returns to the invoking control.
    /// </summary>
    /// <summary>
    /// The footer: "Cancel | primary" in two equal columns, or with <paramref name="extra"/> (an action that keeps the dialog
    /// open, such as Save as Task) "extra … Cancel primary", every button as wide as its label so none is clipped.
    /// </summary>
    private void SetModalFooterExtra(Button? extra)
    {
        foreach (var old in ModalFooter.Children.Where(c => c != ModalCancel && c != ModalPrimary).ToList()) ModalFooter.Children.Remove(old);
        ModalFooter.ColumnDefinitions.Clear();
        if (extra is null)
        {
            ModalFooter.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            ModalFooter.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            Grid.SetColumn(ModalCancel, 0);
            Grid.SetColumn(ModalPrimary, 1);
            return;
        }
        foreach (var w in new[] { GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto, GridLength.Auto })
            ModalFooter.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        extra.MinWidth = Ui.Double("DialogButtonMinWidth");
        Grid.SetColumn(extra, 0);
        ModalFooter.Children.Add(extra);
        Grid.SetColumn(ModalCancel, 2);
        Grid.SetColumn(ModalPrimary, 3);
    }

    private Task<bool> ShowModal(string title, UIElement body, string primary, string? cancel, string? caption = null,
        Func<bool>? validate = null, Control? focus = null, bool focusCancel = false, bool wide = false, Button? extra = null)
    {
        PerfTrace.AfterLayout(DispatcherQueue, "dialog-open", PerfTrace.Now());
        RealiseHosts();
        if (_modal is null) _modalReturnFocus = FocusedElement as Control;
        DismissInspectorOverlay(null); // full screen: a dialog never sits under the overlaid details pane
        _modal?.TrySetResult(false); // only one modal at a time; a new one replaces an old one
        _modal = new TaskCompletionSource<bool>();
        _modalValidate = validate;
        ModalTitle.Text = title;
        AutomationProperties.SetName(ModalHost, title);
        AutomationProperties.SetName(ModalCard, title);
        ModalCaption.Text = caption ?? "";
        ModalCaption.Visibility = caption is null ? Visibility.Collapsed : Visibility.Visible;
        // Never wider than the window (150 % at 640 px): the card shrinks and its stretched fields with it.
        var room = ModalRoom.ActualWidth - 2 * Ui.Double("Space16");
        ModalCard.MinWidth = room > 0 ? Math.Min(Ui.Double("DialogMinWidth"), room) : Ui.Double("DialogMinWidth");
        ModalCard.Width = room > 0 ? Math.Min(Ui.Double(wide ? "DialogWideWidth" : "DialogWidth"), room) : Ui.Double(wide ? "DialogWideWidth" : "DialogWidth");
        ModalBody.Content = body;
        ModalPrimary.Content = primary;
        ModalCancel.Content = cancel ?? "";
        ModalCancel.Visibility = cancel is null ? Visibility.Collapsed : Visibility.Visible;
        SetModalFooterExtra(extra);
        var presenting = ModalHost.Visibility == Visibility.Collapsed;
        ModalHost.Visibility = Visibility.Visible;
        ModalHost.UpdateLayout(); // a control must be in the laid-out tree before it can take focus
        // A dialog replacing another one does not bounce. While a session tab is in view the dialog appears without its
        // entrance (WIN-SHELL-LEAK): every animation started on the card (rounded, stroked corners) over a session left a
        // Direct2D path geometry and its composition objects in WinUI's compositor for good, and closing a running tab
        // goes through this dialog. Over the start page it still plays.
        if (presenting && SessionHost.Visibility != Visibility.Visible) Motion.Present(ModalCard);
        BringForwardForDialog(); // never left behind another window or in a minimised one
        var target = focus ?? (focusCancel && cancel is not null ? ModalCancel : ModalPrimary);
        target.Focus(FocusState.Programmatic);
        // A menu flyout that opened this dialog hands focus back to its button as it closes, after this call;
        // take it back once, unless focus is already inside the dialog.
        var shown = _modal;
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            if (_modal != shown || IsInModal(FocusedElement)) return;
            target.Focus(FocusState.Programmatic);
        });
        return _modal.Task;
    }

    /// <summary>Show <paramref name="decision"/> between the scrolled body and the buttons, always on screen.</summary>
    internal void PinModal(UIElement decision)
    {
        ModalPinned.Content = decision;
        ModalPinned.Visibility = Visibility.Visible;
        ModalPinned.UpdateLayout(); // a control must be in the laid-out tree before it can take focus
    }

    /// <summary>Remove the pinned element; with <paramref name="only"/>, only when that element is the one shown.</summary>
    internal void UnpinModal(UIElement? only = null)
    {
        if (only is not null && !ReferenceEquals(ModalPinned.Content, only)) return;
        ModalPinned.Content = null;
        ModalPinned.Visibility = Visibility.Collapsed;
    }

    // PageHost and ModalHost are built with the window: realised later through x:Load, their named children
    // (ModalTitle, ModalBody, ...) stayed null and every dialog threw (#145). They are collapsed, so they cost little.
    private static void RealiseHosts() { }

    private void CloseModal(bool result, FocusState how = FocusState.Programmatic)
    {
        if (ModalHost is null) return;
        ModalHost.Visibility = Visibility.Collapsed;
        SetModalFooterExtra(null);
        ModalBody.Content = null;
        UnpinModal();
        var pending = _modal;
        _modal = null;
        _modalCancelPressed = null;
        EndInspectorTransient(); // Properties… / Test Connection opened it for this dialog only
        _modalValidate = null;
        var back = _modalReturnFocus;
        _modalReturnFocus = null;
        if (back is not null && back.IsLoaded && back.IsEnabled && back.Visibility == Visibility.Visible) back.Focus(how);
        else if (NavVisible && _shown.Count > 0) FocusTreeSelection(how);
        else SearchBox.Focus(how);
        pending?.TrySetResult(result);
    }

    private void ModalPrimary_Click(object sender, RoutedEventArgs e) => SubmitModal(InputState(ModalPrimary));

    /// <summary>Run when the Cancel button itself is pressed (not Escape); cleared when the modal closes.</summary>
    private Action? _modalCancelPressed;

    private void ModalCancel_Click(object sender, RoutedEventArgs e)
    {
        _modalCancelPressed?.Invoke();
        CloseModal(false, InputState(ModalCancel));
    }

    /// <summary>Keyboard if the button was used from the keyboard, otherwise Pointer (no focus rectangle afterwards).</summary>
    private static FocusState InputState(Control button) => button.FocusState == FocusState.Keyboard ? FocusState.Keyboard : FocusState.Pointer;

    private void SubmitModal(FocusState how)
    {
        if (_modalValidate is not null && !_modalValidate()) return; // stay open; the form says what is missing
        CloseModal(true, how);
    }

    /// <summary>Esc cancels and Enter (in a text field) confirms, whichever element has focus while a modal is open.</summary>
    private void Modal_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (_modal is null) return;
        switch (e.Key)
        {
            case VirtualKey.Escape:
                // An open host-key question of Test Connection is answered "Cancel" first; the dialog stays (SEC-07).
                if (!TestConnectionPanel.CancelOpenPrompt()) CloseModal(false, FocusState.Keyboard);
                e.Handled = true;
                break;
            // PasswordBox too: the connect sheet's main field is one, and Enter there should connect.
            // Single-line fields only: Enter in a multi-line field (Notes) is a new line, not Save.
            case VirtualKey.Enter when e.OriginalSource is PasswordBox or TextBox { AcceptsReturn: false }:
                SubmitModal(FocusState.Keyboard);
                e.Handled = true;
                break;
        }
    }

    // ---- Snapshot mode hooks (SnapshotRunner; demo data only) ----

    internal void PressModalPrimaryForSnapshot() => SubmitModal(FocusState.Pointer);

    internal void CancelModalForSnapshot() => CloseModal(false, FocusState.Pointer);

    /// <summary>Snapshot only: two credentials in the throwaway vault next to the demo library (placeholder secrets,
    /// never real ones), the password assigned to the selected connection in memory.</summary>
    internal void SeedCredentialsForSnapshot()
    {
        if (OpenCredentials().List().Count == 0)
        {
            OpenCredentials().SavePassword(null, "db admin", "Acme Corp", "root", "snapshot-placeholder");
            OpenCredentials().SaveSshKey(null, "deploy key", null, "deploy", "-----BEGIN OPENSSH PRIVATE KEY-----\nsnapshot-placeholder\n-----END OPENSSH PRIVATE KEY-----\n");
            OpenCredentials().Save();
        }
        if (Selected?.Connection is { } c) _library.SetCredential(c.Id, OpenCredentials().List().First(x => x.Name == "db admin").Id);
        Reload(Selected?.Id);
    }

    internal Task NewCredentialForSnapshot() => NewCredentialAsync(sshKey: false);

    private NewCredentialForm? _snapshotCredentialForm;

    /// <summary>Snapshot only: edit the seeded SSH key, importing <paramref name="keyFile"/> (an encrypted test key).</summary>
    internal Task EditKeyCredentialForSnapshot(string keyFile)
    {
        var key = OpenCredentials().List().First(c => c.Kind == "ssh-key");
        _snapshotCredentialForm = new NewCredentialForm(false, key, PickUploadFile);
        _snapshotCredentialForm.UseKeyFile(keyFile);
        return SaveCredentialAsync(_snapshotCredentialForm);
    }

    /// <summary>Snapshot only: the Connect dialog signing in with the SSH agent, its jump host with its own password
    /// (placeholder hop, nothing is dialled).</summary>
    internal Task ConnectFormForSnapshot()
    {
        var form = new ConnectForm("ops", jumpHosts: [new JumpHostDto("gw.example.test:22", "jump")]);
        form.ShowAgentWithHopPasswordForSnapshot();
        return ShowModal("Connect to db-1", form.Body, primary: "Connect", cancel: "Cancel", caption: "db-1.example.test:22", validate: form.Validate);
    }

    /// <summary>Snapshot only: the second-factor prompt.</summary>
    internal Task OneTimeCodeForSnapshot()
    {
        var form = new OneTimeCodeForm("db-1.example.test:22");
        return ShowModal("Second factor", form.Body, primary: "Continue", cancel: "Cancel", caption: "db-1.example.test:22", validate: form.Validate);
    }

    internal TreeItem? SelectedForSnapshot => Selected;

    /// <summary>Snapshot only: type into the open dialog's text field with this header.</summary>
    internal void SetModalFieldForSnapshot(string header, string text)
    {
        static IEnumerable<DependencyObject> All(DependencyObject d)
        {
            yield return d;
            for (var i = 0; i < VisualTreeHelper.GetChildrenCount(d); i++)
                foreach (var c in All(VisualTreeHelper.GetChild(d, i))) yield return c;
        }
        if (All(ModalBody).OfType<TextBox>().FirstOrDefault(t => t.Header as string == header) is { } box) box.Text = text;
    }

    /// <summary>Snapshot only: demo defaults so the editor shows every kind of source (in memory, never saved).</summary>
    /// <summary>
    /// Snapshot only: give the "Acme Corp" folder its own terminal font (Consolas, 16, no ligatures), add a connection
    /// inside it and open a local shell with that connection's font, as an SSH tab of it would get.
    /// </summary>
    internal TerminalView OpenFolderFontTerminalForSnapshot()
    {
        if (!_demo) throw new InvalidOperationException("snapshot only");
        var acme = _roots.First(r => r.Name == "Acme Corp");
        _library.SetProperty(acme.Id, TerminalFontOverride.FamilyKey, "consolas");
        _library.SetProperty(acme.Id, TerminalFontOverride.SizeKey, "16");
        _library.SetProperty(acme.Id, TerminalFontOverride.LigaturesKey, "false");
        var id = _library.AddConnection(acme.Id, "font-box", "ssh", "font-box.test", 22, "tester");
        var view = NewTerminalView(TerminalSession.Spawn("powershell.exe", ["-NoLogo", "-NoProfile", "-NoExit", "-Command", "'-> != => ==='"], 100, 30), id);
        AddTab("font-box", view);
        return view;
    }

    internal void SeedPropertiesForSnapshot()
    {
        _library.SetTypeDefault("ssh", "keepalive_secs", "30");
        if (_roots.FirstOrDefault(r => r.Name == "Acme Corp") is { } acme) _library.SetProperty(acme.Id, "port", "2200");
        Reload(Selected?.Id);
    }

    /// <summary>
    /// Snapshot mode: supervise a local terminal tab as if it were an SSH shell of the selected connection, logging in
    /// again with a key file that does not exist, so the tab shows the reconnect and give-up states without a server.
    /// </summary>
    /// <summary>
    /// Snapshot only: connect a throwaway loopback test server (BASTION_SNAPSHOT_SFTP) with a password, trusting its
    /// key on first use as no user is there to verify it, then open the tab's Files panel.
    /// </summary>
    internal async Task<SftpPanel> OpenSftpForSnapshot(string host, int port, string user, string password)
    {
        if (!_demo) throw new InvalidOperationException("snapshot only");
        var id = _library.AddConnection(null, "lab-sftp", "ssh", host, port, user);
        var sessions = Sessions;
        var first = await Task.Run(() => sessions.ConnectSsh(_library, id, user, SshLoginKind.Password, password, null, null, null, 100, 30));
        var result = first.Outcome == ConnectOutcome.HostKeyUnknown
            ? await Task.Run(() => sessions.ConnectSsh(_library, id, user, SshLoginKind.Password, password, null, first.Fingerprint, null, 100, 30))
            : first;
        if (result.Session is null) throw new InvalidOperationException($"test connect failed: {result.Outcome} {result.Error}");
        var view = AttachSession($"{user}@lab-sftp", result.Session);
        var tab = _tabs.First(t => ReferenceEquals(t.View, view));
        TieTab(tab, id);
        await ToggleFilesAsync(tab);
        return tab.Files ?? throw new InvalidOperationException("the Files panel did not open");
    }

    /// <summary>
    /// Snapshot only: an RDP connection to a test server. The first attempt must report an unknown certificate; the
    /// prompt is shown and <paramref name="capture"/> runs over it, then the certificate is accepted and the tab opens.
    /// </summary>
    internal async Task<RemoteDesktopView> OpenRdpForSnapshot(string host, int port, string user, string password, Func<Task> capture)
    {
        if (!_demo) throw new InvalidOperationException("snapshot only");
        var id = _library.AddConnection(null, "lab-desktop", "rdp", host, port, user);
        Reload(id);
        var where = $"{host}:{port}";
        var first = await Task.Run(() => RdpSession.Connect(host, (ushort)port, user, null, RdpDefaults.Width, RdpDefaults.Height, null, password));
        if (first.Outcome != RdpConnectOutcome.CertificateUnknown) throw new InvalidOperationException($"expected an unknown certificate, got {first.Outcome} {first.Error}");
        var prompt = ShowModal("Trust this certificate?", HostKeyPrompt.Body(where, first.Fingerprint!, false, certificate: true), primary: "Connect and trust", cancel: "Cancel", focusCancel: true);
        await Task.Delay(400);
        await capture();
        CloseModal(true);
        await prompt;
        new RdpCertificatePins(SessionDataDir).Save(where, first.Fingerprint!);
        var pinned = new RdpCertificatePins(SessionDataDir).Pin(where);
        var result = await Task.Run(() => RdpSession.Connect(host, (ushort)port, user, null, RdpDefaults.Width, RdpDefaults.Height, pinned, password));
        if (result.Session is null) throw new InvalidOperationException($"pinned connect failed: {result.Outcome} {result.Error}");
        var view = new RemoteDesktopView(new RdpDesktop(result.Session));
        AddTab($"{user}@lab-desktop", null, rdp: view);
        return view;
    }

    private string? _webSnapshotId;

    /// <summary>Snapshot only: add a web connection to the throwaway library (once) and open it in a new tab.</summary>
    internal WebTabView? OpenWebForSnapshot(string name, string url)
    {
        if (!_demo) throw new InvalidOperationException("snapshot only");
        var id = _webSnapshotId ??= _library.AddConnection(null, name, "web", url, null, null);
        Reload(id);
        return FindItem(_roots, id) is { } item ? OpenWeb(item) : null;
    }

    internal void SuperviseForSnapshot(TerminalView view, string missingKeyPath)
    {
        if (Selected?.Connection is { } c) Supervise(view, c.Id, c.Username, SshLoginKind.KeyFile, null, missingKeyPath);
    }

    internal string ActiveTabLabelForSnapshot() => _active is { } t ? AutomationProperties.GetName(t.Select) : "";
    internal bool ModalOpenForSnapshot => _modal is not null;

    internal IReadOnlyList<WorkspaceDto> WorkspacesForSnapshot() => Workspaces.List();

    internal void CloseAllTabsForSnapshot()
    {
        foreach (var tab in _tabs.ToList()) CloseTab(tab, FocusState.Pointer);
    }

    /// <summary>Empty the in-memory demo library (never saved) to render the first-run state.</summary>
    internal void ClearDemoLibraryForSnapshot()
    {
        if (!_demo) throw new InvalidOperationException("only the snapshot demo library can be cleared");
        foreach (var item in _roots.ToList()) _library.Remove(item.Id);
        Reload(selectId: null);
    }
}
