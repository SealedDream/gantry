using System.Runtime.InteropServices;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.System;

namespace Bastion.Shell;

// Settings (core/src/settings.rs over C ABI 16): categories, rows and search come from the core registry, the values from
// settings.json next to the library, the same file and rules as the macOS Settings window. The page shows only what the
// Windows app honours (NotOnWindows lists the rest, FEATURE_MATRIX.md says why). Also here: the Credential Manager page,
// Lock Credentials and idle auto-lock, and the configurable shortcuts (shortcuts.json) with their dispatcher.
public sealed partial class MainWindow
{
    /// <summary>Settings the core lists that Windows does not apply yet; hidden rather than shown and ignored.</summary>
    // ui.tips: Windows has no panel tips line (the Mac's TipsLine), so the toggle would do nothing.
    private static readonly HashSet<string> NotOnWindows = ["ui.tips"];

    /// <summary>Settings whose core text names a macOS feature, worded for Windows.</summary>
    private static readonly Dictionary<string, (string Label, string Help)> WindowsWording = new()
    {
        ["terminal.osc52"] = ("Remote clipboard copy (OSC 52)", "Programs on a server may put text on this PC's clipboard; they can never read it. A managed policy can turn this off."),
    };

    private static SettingDefDto ForWindows(SettingDefDto d) => WindowsWording.TryGetValue(d.Id, out var w) ? d with { Label = w.Label, Help = w.Help } : d;

    /// <summary>Commands the dispatcher below runs; the Keyboard page lists only these.</summary>
    private static readonly HashSet<string> WindowsCommands =
    [
        "add", "new-folder", "local-shell", "focus-search", "toggle-library", "toggle-inspector", "credential-manager", "lock-credentials", "activity", "audit-log",
        "default-action", "split-right", "split-down", "next-tab", "previous-tab", "tab-overview", "focus-pane-left", "focus-pane-right",
        "focus-pane-up", "focus-pane-down", "next-pane", "previous-pane", "save-workspace", "workspace-manager", "quick-connect", "palette",
        "ui-zoom-in", "ui-zoom-out", "ui-zoom-reset", "zoom-in", "zoom-out", "zoom-reset", "find", "find-next", "find-previous", "copy", "paste", "clear-scrollback", "previous-prompt", "next-prompt",
        "close-pane", "send-break",
        "tab:1", "tab:2", "tab:3", "tab:4", "tab:5", "tab:6", "tab:7", "tab:8", "tab:9",
    ];

    private SettingsClient? _settings;
    private ShortcutsClient? _shortcuts;
    /// <summary>Command id → Windows chord (<c>ctrl+shift+p</c>), for the dispatcher and the tooltips.</summary>
    private Dictionary<string, string> _keys = new();
    private DispatcherQueueTimerHolder? _idle;
    private string _settingsQuery = "";
    private string _settingsCategory = "general";
    private string _pageKind = "";

    private string ConfigDir => Path.GetDirectoryName(Path.GetFullPath(_personal.Path))!;

    private string SettingsPath => Path.Combine(ConfigDir, "settings.json");
    private SettingsClient Settings => _settings ??= SettingsClient.Open(SettingsPath);

    private ShortcutsClient Shortcuts => _shortcuts ??= ShortcutsClient.Open(Path.Combine(ConfigDir, "shortcuts.json"));

    /// <summary>Read the settings and shortcuts at startup and apply what Windows honours. A damaged file is reported once.</summary>
    private void InitSettings()
    {
        try
        {
            if (!_demo) ApplyAppearanceMode(Settings.Get("appearance.mode"));
            ApplyAppearance();
            _idle = new DispatcherQueueTimerHolder(DispatcherQueue, TimeSpan.FromSeconds(30), CheckIdleLock);
        }
        catch (BastionException ex)
        {
            ApplyHeader(); // unreadable settings: the header still needs its first layout
            LogStartupError("settings", ex);
            DispatcherQueue.TryEnqueue(() => _ = ShowModal("Settings could not be read", ErrorText(ex.Message + " Defaults are used until the file is fixed or removed."), primary: "OK", cancel: null));
        }
        ReloadShortcuts();
    }

    /// <summary>
    /// Write a start-up error to startup-errors.log beside the settings file (and the start-up probe), so a caught
    /// error is never silent. Only the error's type and message: settings errors carry no secrets.
    /// </summary>
    private void LogStartupError(string where, Exception ex)
    {
        StartupProbe.Mark($"error-{where}");
        try { File.AppendAllText(Path.Combine(ConfigDir, "startup-errors.log"), $"{DateTime.Now:O} {where}: {ex.GetType().Name}: {ex.Message}{Environment.NewLine}"); }
        catch (Exception io) when (io is IOException or UnauthorizedAccessException) { /* the dialog still reports it */ }
    }

    private void ReloadShortcuts()
    {
        try { _keys = Shortcuts.List().Where(s => s.Chord is not null && WindowsCommands.Contains(s.Id)).ToDictionary(s => s.Id, s => s.Chord!); }
        catch (BastionException) { _keys = new(); }
        // WIN-STARTUP: the toolbar is collapsed until after the first frame, so its tooltips are set then
        // (StartDeferredServices); a later shortcut change sets them again here.
        if (_toolbarTipsReady) ApplyToolbarTips();
        // The empty state's hints show the keys as configured; a command without a shortcut drops its line.
        foreach (var (label, keys, id) in new[] { (HintNewConnection, HintNewConnectionKeys, "add"), (HintQuickConnect, HintQuickConnectKeys, "quick-connect"), (HintPalette, HintPaletteKeys, "palette"), (HintNewFolder, HintNewFolderKeys, "new-folder") })
        {
            keys.Text = ShortcutText(id) ?? "";
            label.Visibility = keys.Visibility = keys.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private bool _toolbarTipsReady;

    /// <summary>Toolbar tooltips and accelerator names with the keys as configured.</summary>
    private void ApplyToolbarTips()
    {
        _toolbarTipsReady = true;
        void Tip(Button b, string label, string id)
        {
            var keys = ShortcutText(id);
            var tip = keys is null ? label : $"{label} ({keys})";
            ToolTipService.SetToolTip(b, tip);
            AutomationProperties.SetHelpText(b, tip); // screen readers and UI tests read the tip without a hover popup
            AutomationProperties.SetAcceleratorKey(b, keys?.Replace("Ctrl", "Control") ?? "");
        }
        Tip(NewTerminalButton, "New terminal: local shell", "local-shell");
    }

    /// <summary>
    /// Toolbar labels: shown while every button fits with its label, icons only (with tooltips) once the window is too
    /// narrow, so the toolbar never runs under More options.
    /// </summary>
    private bool _toolbarFitPending;

    /// <summary>
    /// Called from SizeChanged and LayoutUpdated: the fit pass changes visibility and moves the tab bar, which inside the
    /// same layout pass can feed back (LayoutCycleException at some window widths). Run it once, after this pass.
    /// </summary>
    private void UpdateToolbarLabels()
    {
        if (_toolbarFitPending) return;
        _toolbarFitPending = true;
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
        {
            _toolbarFitPending = false;
            if (!_windowClosed) UpdateToolbarLabelsNow();
        });
    }

    private void UpdateToolbarLabelsNow()
    {
        if (_titleBar is null) return; // built after the first frame, which runs this again (WIN-COLD-LIGHT)
        Toolbar.Measure(new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity));
        // The tab bar shares the title bar: labels show only while the actions still leave it TabBarMinWidth.
        // What the tab bar needs in the title bar: its own buttons plus one tab (never less than TabBarMinWidth). The
        // same rule as CheckTabBarRoom, so the two never disagree and bounce the tab bar between rows.
        // Labels give way to tabs: room for the open tabs as they are (up to three tab widths), not just one, so a few
        // short tabs and a group chip never scroll off at 1280 px while labels are shown.
        TabStrip.Measure(new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity));
        var tabsWanted = Math.Max(Ui.Double("TabMinWidth"), Math.Min(TabStrip.DesiredSize.Width, 3 * Ui.Double("TabMaxWidth")));
        var tabBarNeed = Math.Max(Ui.Double("TabBarMinWidth"), TabBarFixedWidth() + tabsWanted);
        var fits = ToolbarActionsWidth() + tabBarNeed <= RootGrid.ActualWidth;
        // Icons only: the tab bar stays in the title bar while its buttons and one tab still fit beside them, and
        // never moves back up until the window is wider than where it last had to drop (the post-layout check).
        var tabsFit = (fits || ToolbarActionsWidth() + TabBarFixedWidth() + ActiveTabRoom() <= RootGrid.ActualWidth) && RootGrid.ActualWidth > _tabBarDroppedAt;
        PlaceTabBar(tabsFit);
        if (tabsFit) _tabBarDroppedAt = 0;
        MoreQuickConnect.Visibility = Visibility.Collapsed; // W20: Quick Connect lives in Go to… (and its shortcut)
        MorePalette.Visibility = Visibility.Visible; // no Commands button in the title bar (owner 2026-11-15); Ctrl+Shift+P too
    }

    private double _tabBarDroppedAt;

    private bool _tabBarDropPending;

    /// <summary>
    /// After layout: if the tabs really got less than one tab's width (fonts, zoom or a long caption inset the measure
    /// missed), drop the tab bar to its own row and remember the width, so it does not bounce back on the next pass.
    /// </summary>
    /// <summary>
    /// Room the title-bar tab area needs: one tab, plus the active tab's group chip (arranged width only, so safe on
    /// LayoutUpdated). Without the chip the strip kept one tab in the title row and scrolled its chip out of view at 800 px
    /// (WIN-MAC-LAYOUT, runner 1); now the tab bar takes its own row instead and the chip stays whole.
    /// </summary>
    private double ActiveTabRoom() =>
        Ui.Double("TabMinWidth") + (_active?.Group is { } g && _chips.TryGetValue(g, out var chip) ? chip.ActualWidth : 0);

    private void CheckTabBarRoom()
    {
        if (_tabBarDropPending || !_tabBarInTitleRow || VerticalTabs || TabBar.ActualWidth <= 0) return;
        // Runs on LayoutUpdated: read arranged sizes only. Measuring the live tab bar here (as TabBarFixedWidth does)
        // flips the tab scroller's desired size every pass and WinUI throws LayoutCycleException (found with
        // BASTION_LAYOUT_TRACE=1 at 640-1024 px). TabArea is what is left for the tabs after the tab bar's buttons.
        if (_tabs.Count == 0 || TabAreaAvailableWidth() + 0.5 >= ActiveTabRoom()) return;
        _tabBarDroppedAt = RootGrid.ActualWidth;
        _tabBarDropPending = true;
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
        {
            _tabBarDropPending = false;
            if (!_windowClosed && _tabBarInTitleRow) PlaceTabBar(inTitleBar: false);
        });
    }

    /// <summary>"Ctrl+Shift+P" for a command, or null when it has no shortcut.</summary>
    private string? ShortcutText(string id) => _keys.TryGetValue(id, out var c) ? Chords.Display(c) : null;

    // ---- Shortcut dispatcher ----

    /// <summary>
    /// Run the command whose configured chord this key press is. In a focused terminal, Ctrl with a letter, [, \ or ] and
    /// nothing else stays with the program (Ctrl+D, Ctrl+L, Ctrl+] mean something to shells and telnet), as in Windows
    /// Terminal; Ctrl with a digit, = or - is free for tabs and zoom.
    /// </summary>
    private bool DispatchShortcut(VirtualKey key, bool ctrl, bool alt, bool shift, bool inTerminal)
    {
        if (ZoomKeypadKey(key, ctrl, alt, shift)) return true;
        if (inTerminal && ctrl && !alt && !shift && Chords.KeyName(key) is { Length: 1 } k && (char.IsAsciiLetter(k[0]) || k is "[" or "\\" or "]")) return false;
        var id = _keys.FirstOrDefault(k => Chords.Matches(k.Value, key, ctrl, alt, shift)).Key;
        return id is not null && RunCommand(id);
    }

    private bool RunCommand(string id)
    {
        var panes = _active?.Panes;
        switch (id)
        {
            case "add": _ = NewConnectionAsync(); return true;
            case "new-folder": _ = NewFolderAsync(); return true;
            case "local-shell": NewLocalShell(); return true;
            case "focus-search": FocusSearch(); return true;
            case "toggle-library": ToggleNav(); return true; // Ctrl+Alt+N (Windows default); docked in full screen it pins the pane
            case "toggle-inspector": ToggleInspector(); return true;
            case "credential-manager": OpenCredentialManager(); return true;
            case "lock-credentials": LockCredentials(); return true;
            case "activity": OpenActivity(); return true;
            case "audit-log": OpenAuditLog(); return true;
            // A plugin tab keeps Ctrl+Enter (its SQL editor runs the query); the library's Connect would re-open the tab
            // and take the focus (PLUG-PG-REDO-WIN, q-pgredo-win4).
            case "default-action" when FindAncestor<PluginTabView>(FocusedElement) is not null: return false;
            case "default-action" when Selected is { } item: _ = DefaultActionAsync(item); return true;
            case "split-right": return SplitActive(SplitAxis.Right) is not null;
            case "split-down": return SplitActive(SplitAxis.Down) is not null;
            case "tab-overview": ToggleTabOverview(); return true;
            case "next-tab" or "next-tab-alt" when _tabs.Count > 0: CycleTab(1); return true;
            case "previous-tab" or "previous-tab-alt" when _tabs.Count > 0: CycleTab(-1); return true;
            case "focus-pane-left" when panes is not null: return panes.MoveFocus(PaneDirection.Left);
            case "focus-pane-right" when panes is not null: return panes.MoveFocus(PaneDirection.Right);
            case "focus-pane-up" when panes is not null: return panes.MoveFocus(PaneDirection.Up);
            case "focus-pane-down" when panes is not null: return panes.MoveFocus(PaneDirection.Down);
            case "next-pane" or "previous-pane" when panes is { Panes.Count: > 1 }:
                var at = panes.Panes.ToList().IndexOf(panes.Focused);
                panes.Panes[(at + (id == "next-pane" ? 1 : -1) + panes.Panes.Count) % panes.Panes.Count].Focus(FocusState.Keyboard);
                return true;
            case "save-workspace": _ = SaveWorkspaceAsync(); return true;
            case "workspace-manager": OpenWorkspaceManager(); return true;
            // Ctrl+L focuses "Search or connect" (owner 2026-11-15, as on the Mac); the Quick Connect dialog stays in menus and Go to.
            case "quick-connect": FocusSearch(); return true;
            case "palette": _ = PaletteAsync(); return true;
            // Owner point 13: Ctrl+= / Ctrl+- / Ctrl+0 size the terminal text only; app UI zoom is the Appearance setting.
            case "ui-zoom-in": return Zoom(+1);
            case "ui-zoom-out": return Zoom(-1);
            case "ui-zoom-reset": return Zoom(0);
            case "zoom-in": return Zoom(+1);
            case "zoom-out": return Zoom(-1);
            case "zoom-reset": return Zoom(0);
            case "find" when FocusedPane is { } pane: pane.ShowFind(); return true;
            case "copy" when FocusedPane is { } pane: return pane.CopySelection();
            case "paste" when FocusedPane is { } pane: _ = pane.PasteFromClipboard(); return true;
            case "clear-scrollback" when FocusedPane is { } pane: pane.ClearScrollback(); return true;
            case "previous-prompt" when FocusedPane is { } pane: pane.JumpPrompt(forward: false); return true;
            case "next-prompt" when FocusedPane is { } pane: pane.JumpPrompt(forward: true); return true;
            case "find-next" when FocusedPane is { } pane: pane.FindAgain(forward: true); return true;
            case "find-previous" when FocusedPane is { } pane: pane.FindAgain(forward: false); return true;
            case "select-all" when FocusedPane is { } pane: pane.SelectAll(); return true;
            case "send-break" when FocusedPane is { } pane: pane.SendBreak(); return true;
            case "close-pane" when _active is { Panes: { } closing } tab: _ = RequestClosePane(tab, closing.Focused, FocusState.Keyboard); return true;
            case { } tab when tab.StartsWith("tab:", StringComparison.Ordinal) && int.TryParse(tab[4..], out var n) && n <= _tabs.Count:
                PickTab(_tabs[n - 1]);
                return true;
            default: return false;
        }
    }

    /// <summary>Snapshot mode: a setting's current value.</summary>
    internal string SettingValueForSnapshot(string id) => SettingValue(id);

    /// <summary>Snapshot mode: run a shortcut command as its key would.</summary>
    internal bool RunCommandForSnapshot(string id) => RunCommand(id);

    /// <summary>Snapshot mode: the font size of each tab's first pane, in tab order.</summary>
    internal IReadOnlyList<double> TabFontSizesForSnapshot() => _tabs.Select(t => t.View?.FontSizeForSnapshot ?? 0).ToList();

    /// <summary>The terminal pane of the shown tab that has (or last had) focus.</summary>
    private TerminalView? FocusedPane => _active?.Panes?.Focused;

    /// <summary>
    /// Zoom the shown tab's terminals by one point (0 resets to <c>terminal.font-size</c>). Zoom is per tab and never
    /// saved, as on macOS: other tabs and the setting keep their size.
    /// </summary>
    private bool Zoom(int step)
    {
        if (_active is not { Panes: not null } tab) return false;
        var def = SettingsClient.Definitions().FirstOrDefault(d => d.Id == "terminal.font-size");
        var size = step == 0 ? BaseFontSize(tab) : Math.Clamp(TabFontSize(tab) + step, (double)(def?.Min ?? 9), (double)(def?.Max ?? 24));
        tab.Zoom = size - BaseFontSize(tab);
        foreach (var pane in tab.AllPanes) pane.SetFontSize(size);
        Announce(tab.Zoom == 0 ? "Actual size" : $"Text size {size}");
        return true;
    }

    /// <summary>The setting plus the tab's own zoom.</summary>
    private double TabFontSize(WorkspaceTab tab) => BaseFontSize(tab) + tab.Zoom;

    /// <summary>The connection's <c>terminal_font_size</c>, else the setting.</summary>
    private double BaseFontSize(WorkspaceTab tab) => tab.View?.FontOverride.Size ?? TerminalFontSize;

    /// <summary>The tree's default action: the core's primary entry (Connect / Show Session), or Properties when Settings says so.</summary>
    private async Task DefaultActionAsync(TreeItem item)
    {
        var full = TreeItem.Find(_roots, item.Id) ?? item;
        if (full.Connection is not null && SettingValue("tree.double-click") == "properties") { await PropertiesAsync(full); return; }
        // PLUG-03a: the core's menu has no primary action for a type this build does not know, so Enter and a double
        // click would do nothing. ConnectAsync says why it cannot open.
        if (full.Connection is { IsUnavailable: true }) { await ConnectAsync(full); return; }
        List<MenuItemDto> menu;
        try { menu = _library.Menu(full.Id, Handled, ConnectedIds); }
        catch (BastionException) { return; }
        if (menu.FirstOrDefault(m => m.Primary) is { } primary) await PerformAsync(primary, full);
    }

    private void Tree_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        // Folders keep the tree's own double-click (open and close); a connection runs the default action.
        // UI-05: a session row does what a single click does (focus its tab), never connects again.
        if (Tree.SelectedItem is TreeItem { IsSession: true } session) { e.Handled = true; InvokeSessionRow(session); return; }
        // PLUG-API-13: a row of a plugin's tree sends its "open" item (Connect); a branch without one opens and closes.
        if (Tree.SelectedItem is TreeItem { IsPluginRow: true } plugin) { if (ActivatePluginRow(plugin)) e.Handled = true; return; }
        if (FindAncestor<LibraryRow>(e.OriginalSource as DependencyObject) is null || Selected is not { Connection: not null } item) return;
        e.Handled = true;
        _ = DefaultActionAsync(item);
    }

    private string SettingValue(string id)
    {
        try { return Settings.Get(id); }
        catch (BastionException) { return ""; }
    }

    // ---- Appearance and Lock Credentials ----

    private void ApplyAppearanceMode(string mode)
    {
        RootGrid.RequestedTheme = mode switch { "light" => ElementTheme.Light, "dark" => ElementTheme.Dark, _ => ElementTheme.Default };
        _settingsWindow?.SetTheme(RootGrid.RequestedTheme);
    }

    /// <summary>
    /// Lock Credentials (menu, palette, idle, screen lock): the session manager first forgets its vault and revokes its
    /// broker leases (credential epoch bump), then Vaultwarden locks and the local vault's key leaves memory (Windows
    /// unwraps it again on next use). Live, already authenticated sessions keep running.
    /// </summary>
    internal void LockCredentials()
    {
        LockTrace(RevokeManagerCredentials());
        _vaultwarden?.Lock();
        _providers?.LockAll();
        _credentials?.Dispose();
        _credentials = null;
        _helloConfirmed = false;
        ForgetAllLogins(); // a remembered password must not outlive Lock (owner points 2, 3)
        ClearTabPreviews(); // no remote screen in a preview while locked (B11)
        LockDocuments();
        ApplyFilter(keepSelection: true);
        Announce("Credentials locked");
        if (_pageKind == "credentials") ShowCredentialManagerPage();
    }

    /// <summary>Revoke the core's credentials and leases. "absent" when no manager was ever opened (nothing to revoke).</summary>
    private string RevokeManagerCredentials()
    {
        if (_sessions is null) return "absent";
        try
        {
            _sessions.LockCredentials();
            return "revoked";
        }
        catch (BastionException ex)
        {
            Announce("Could not lock the session manager's credentials: " + ex.Message);
            return "failed";
        }
    }

    /// <summary>Test seam: BASTION_LOCK_TRACE names a file that records each global lock's manager outcome.</summary>
    private static void LockTrace(string managerOutcome)
    {
        if (TestHooks.LockTrace is not { } path) return;
        try { System.IO.File.AppendAllText(path, $"lock manager={managerOutcome}\n"); }
        catch (System.IO.IOException) { }
    }

    /// <summary>Why the last unlock failed, shown on the Credential Manager page.</summary>
    private string? _vaultError;

    /// <summary>Load the vault key (DPAPI); a failure is kept for the Credential Manager page.</summary>
    private void UnlockLocalVault()
    {
        try
        {
            _ = OpenCredentials();
            _vaultError = null;
        }
        catch (BastionException ex) { _vaultError = ex.Message; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);

    /// <summary>
    /// Idle auto-lock (Settings › Security), two independent limits: no input for <c>security.auto-lock</c> locks both
    /// credential stores (and documents); no input for the document limit — <c>document.auto-lock-minutes</c> capped by
    /// the managed policy, skipped while "Remember unlock until I quit" is on — locks every protected document even
    /// when neither credential store was opened (Codex W03).
    /// </summary>
    private void CheckIdleLock()
    {
        var credentialsOpen = _vaultwarden is { IsUnlocked: true } || _credentials is not null;
        if (!credentialsOpen && !HasUnlockedProtectedDocument()) return;
        var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref info)) return;
        var idle = TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - info.Time));
        var due = credentialsOpen && SettingsClient.AutoLockDue(SettingValue("security.auto-lock"), idle);
        // Test seam: each check with credentials open, so a run can tell "no idle time reached" (input from elsewhere
        // on the machine) from "idle reached and not locked".
        if (credentialsOpen && TestHooks.LockTrace is { } trace)
        {
            try { System.IO.File.AppendAllText(trace, $"idle check idle={(int)idle.TotalSeconds}s due={due}\n"); }
            catch (System.IO.IOException) { }
        }
        if (due)
        {
            LockCredentials();
            return;
        }
        if (DocumentLockDue(idle, screenLocked: false, asleep: false) == AutoLockReason.Idle) LockDocumentsFor(AutoLockReason.Idle);
    }

    /// <summary>The core's document lock rule for this idle time and OS state, with the policy-capped idle limit.</summary>
    private AutoLockReason DocumentLockDue(TimeSpan idle, bool screenLocked, bool asleep)
    {
        var userMinutes = uint.TryParse(SettingValue(DocumentClient.AutoLockSettingId), out var m) ? m : 0;
        var minutes = DocumentClient.PolicyAutoLockMinutes(userMinutes);
        // "Keep unlocked until screen locks" (start window) holds off the idle lock only.
        var remember = SettingValue("document.remember-unlock") == "true" || (_keepUnlockedUntilScreenLock && !screenLocked && !asleep);
        return DocumentClient.AutoLockDue(minutes, (ulong)Math.Max(0, idle.TotalSeconds), screenLocked, asleep, remember);
    }

    // ---- The page host: Settings and the Credential Manager over the main window ----

    /// <summary>
    /// From the Bastion menu: open once the menu has closed. The closing flyout hands the focus back to the main
    /// window, which would otherwise land on top of (or fight) the Settings window activating in the same pass.
    /// </summary>
    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuFlyoutItem) DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => OpenSettings(null));
        else OpenSettings(null);
    }

    private void CredentialManager_Click(object sender, RoutedEventArgs e) => OpenCredentialManager();

    internal void OpenSettings(string? category)
    {
        if (category is not null)
        {
            _settingsCategory = category;
            _settingsQuery = "";
        }
        ShowSettingsPage();
    }

    internal void OpenCredentialManager()
    {
        // Opening the page is a use of the vault; a lock while it is open stays locked until Unlock.
        UnlockLocalVault();
        _pageKind = "credentials";
        ShowCredentialManagerPage();
    }

    internal void ClosePage()
    {
        if (PageHost is null) return;
        if (_pageKind == "sysview") CloseSystemView();
        CloseTranscript();
        PageHost.Visibility = Visibility.Collapsed;
        PageSidebar.Content = PageContent.Content = PageActions.Content = null;
        _pageKind = "";
        Body.Visibility = Visibility.Visible;
        UpdatePanes();
        if (_pendingSelect is { } id)
        {
            _pendingSelect = null;
            SelectItem(id);
        }
        FocusTreeSelection();
    }

    private void PageHost_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != VirtualKey.Escape || _modal is not null) return;
        e.Handled = true;
        ClosePage();
    }

    private void PageClose_Click(object sender, RoutedEventArgs e) => ClosePage();

    /// <summary>Show a full-window page (frame in MainWindow.xaml): a sidebar (may be null), a title, actions and content.</summary>
    private void ShowPage(UIElement? sidebar, string title, UIElement content, FrameworkElement? actions = null)
    {
        RealiseHosts();
        if (_pageKind != "transcript") CloseTranscript(); // another page replaced the viewer: stop its read
        PageSidebar.Content = sidebar;
        // A third of the page, never wider than the navigation pane: at 640 px and 150 % the content keeps two thirds.
        PageSidebarColumn.Width = sidebar is null ? new GridLength(0) : new GridLength(1, GridUnitType.Star);
        PageSidebarColumn.MaxWidth = Ui.Length("NavPaneWidth").Value;
        PageTitle.Text = title;
        PageActions.Content = actions;
        AutomationProperties.SetName(PageClose, "Close " + title);
        PageContent.Content = content;
        Body.Visibility = Visibility.Collapsed;
        PageHost.Visibility = Visibility.Visible;
        UpdatePanes(); // no details pane over a page
    }

    // ---- Settings window (owner preview: Mac look) ----

    private SettingsWindow? _settingsWindow;

    /// <summary>
    /// Settings opens in its own window with a category sidebar, as on the Mac (SettingsView.swift); one at a time, so a
    /// second open (menu, Ctrl+,, palette) brings the open one forward with the page asked for.
    /// </summary>
    private void ShowSettingsWindow(UIElement sidebar, string title, UIElement content)
    {
        var w = _settingsWindow;
        if (w is null)
        {
            w = _settingsWindow = new SettingsWindow(RootGrid.RequestedTheme, Modal_KeyDown, () =>
            {
                if (_modal is not null) return false;
                CloseSettings();
                return true;
            });
            w.SetZoom(ZoomPercent / (double)ActualSizePercent);
            var scale = Math.Max(96u, GetDpiForWindow(Hwnd)) / 96.0;
            w.PlaceOver(new Windows.Graphics.RectInt32(AppWindow.Position.X, AppWindow.Position.Y, AppWindow.Size.Width, AppWindow.Size.Height), scale);
            w.Closed += (_, _) => { if (ReferenceEquals(_settingsWindow, w)) _settingsWindow = null; };
        }
        w.Show(sidebar, title, content);
        if (_demo) w.AppWindow.Show(activateWindow: false); // snapshot runs never take the shared desktop's foreground
        else w.Activate();
    }

    internal void CloseSettings()
    {
        var w = _settingsWindow;
        _settingsWindow = null;
        w?.Close();
    }

    private bool SettingsOpen => _settingsWindow is not null;

    /// <summary>
    /// Show a dialog opened from Settings over the Settings window, as the Mac's sheets attach to it: the main window's
    /// dialog surface moves there while the dialog is up and comes back after. Without the window, the main window shows it.
    /// </summary>
    private async Task OverSettingsAsync(Func<Task> show)
    {
        if (_settingsWindow is not { } w || _modal is not null) { await show(); return; }
        var index = RootGrid.Children.IndexOf(ModalHost);
        RootGrid.Children.Remove(ModalHost);
        w.HostModal(ModalHost);
        _modalOverSettings = true;
        try { await show(); }
        finally
        {
            _modalOverSettings = false;
            w.ReleaseModal(ModalHost);
            RootGrid.Children.Insert(Math.Min(Math.Max(0, index), RootGrid.Children.Count), ModalHost);
        }
    }

    private bool _modalOverSettings;

    /// <summary>A Settings page's question (the Keyboard page's Replace) over the Settings window, not behind it.</summary>
    private async Task<bool> ModalOverSettingsAsync(Func<Task<bool>> show)
    {
        var answer = false;
        await OverSettingsAsync(async () => answer = await show());
        return answer;
    }

    /// <summary>The element the open dialog sizes itself to: the Settings window while it hosts the dialog.</summary>
    private FrameworkElement ModalRoom => _modalOverSettings && _settingsWindow is { } w ? w.Root : RootGrid;

    /// <summary>A page of the main window opened from Settings (Credential Manager, Workspaces): bring the main window forward.</summary>
    private void FrontMainFromSettings()
    {
        if (SettingsOpen && !_demo) Activate();
    }

    internal bool SettingsOpenForSnapshot => SettingsOpen;

    internal FrameworkElement? SettingsRootForSnapshot => _settingsWindow?.Root;

    /// <summary>Snapshot only: resize the Settings window, let the layout settle, then report whether the page's controls fit.</summary>
    internal async Task<string> SettingsFitForSnapshot(int width, int height)
    {
        if (_settingsWindow is not { } w) return "settings window not open";
        var scale = Math.Max(96u, GetDpiForWindow(Hwnd)) / 96.0;
        w.AppWindow.Resize(new Windows.Graphics.SizeInt32((int)(width * scale), (int)(height * scale)));
        await Task.Delay(700);
        var root = w.Root;
        root.UpdateLayout();
        var page = new Windows.Foundation.Rect(0, 0, root.ActualWidth, root.ActualHeight);
        var bad = new List<string>();
        foreach (var c in SettingsDescendants(w.PageContent).OfType<Control>().Where(c => c.Visibility == Visibility.Visible && c.ActualWidth > 0))
        {
            var r = c.TransformToVisual(root).TransformBounds(new Windows.Foundation.Rect(0, 0, c.ActualWidth, c.ActualHeight));
            if (r.X < page.X - 0.5 || r.Right > page.Right + 0.5) bad.Add($"{(AutomationProperties.GetName(c) is { Length: > 0 } n ? n : c.GetType().Name)} {r.X:0}..{r.Right:0}");
            if (bad.Count > 8) break;
        }
        return (bad.Count == 0 ? "fits" : "CLIPPED " + string.Join("; ", bad)) + $": window {page.Width:0}x{page.Height:0}";
    }

    private static IEnumerable<DependencyObject> SettingsDescendants(DependencyObject parent)
    {
        var n = VisualTreeHelper.GetChildrenCount(parent);
        for (var i = 0; i < n; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            yield return child;
            foreach (var d in SettingsDescendants(child)) yield return d;
        }
    }

    // ---- Settings page ----

    /// <summary>W28: one colour per settings category icon, in sidebar order (readable on light and dark).</summary>
    private static readonly Windows.UI.Color[] SettingsIconColors =
    [
        Windows.UI.Color.FromArgb(255, 0x3B, 0x82, 0xF6), // blue
        Windows.UI.Color.FromArgb(255, 0xA8, 0x55, 0xF7), // purple
        Windows.UI.Color.FromArgb(255, 0xF5, 0x9E, 0x0B), // amber
        Windows.UI.Color.FromArgb(255, 0x10, 0xB9, 0x81), // green
        Windows.UI.Color.FromArgb(255, 0xEC, 0x48, 0x99), // pink
        Windows.UI.Color.FromArgb(255, 0x06, 0xB6, 0xD4), // cyan
        Windows.UI.Color.FromArgb(255, 0xEF, 0x44, 0x44), // red
        Windows.UI.Color.FromArgb(255, 0x84, 0xCC, 0x16), // lime
    ];

    private void ShowSettingsPage()
    {
        List<SettingCategoryDto> categories;
        List<SettingDefDto> defs;
        try { (categories, defs) = (SettingsClient.Categories(), SettingsClient.Definitions().Where(d => !NotOnWindows.Contains(d.Id)).Select(ForWindows).ToList()); }
        catch (BastionException ex) { _ = ShowModal("Settings", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }
        categories = categories.Where(c => c.Id == "about" || defs.Any(d => d.Category == c.Id)).ToList();
        // Not a core settings category: the administrator's managed policy, read-only (as on macOS).
        categories.Insert(Math.Max(0, categories.FindIndex(c => c.Id == "about")), new SettingCategoryDto(PolicyCategory, "Managed Policy", "security"));
        // Not a core settings category either: Plugins (install, catalogue, updates), as on the Mac.
        categories.Insert(categories.FindIndex(c => c.Id == PolicyCategory), new SettingCategoryDto(PluginsCategory, "Plugins", "app-plugins"));
        if (categories.All(c => c.Id != _settingsCategory)) _settingsCategory = categories.FirstOrDefault()?.Id ?? "about";

        var search = new TextBox { PlaceholderText = "Search settings", Text = _settingsQuery, IsSpellCheckEnabled = false, Margin = Ui.Thickness("NavSearchMargin") };
        AutomationProperties.SetName(search, "Search settings");
        var list = new ListView { SelectionMode = ListViewSelectionMode.Single, ItemContainerTransitions = new Microsoft.UI.Xaml.Media.Animation.TransitionCollection() };
        AutomationProperties.SetName(list, "Settings categories");
        // W28 (Tabby-inspired): each category has its own icon colour. The open one uses the list's own selection (a
        // pale fill and the accent bar) with normal text: an accent background under white text was painted over by
        // that selection, leaving white text on a pale row (contrast bug, 2026-11-21).
        for (var n = 0; n < categories.Count; n++)
        {
            var c = categories[n];
            var icon = new FontIcon
            {
                Glyph = FluentIcons.Object(c.Icon),
                FontFamily = (FontFamily)Application.Current.Resources["SymbolFontFamily"],
                FontSize = Ui.Double("IconSize"),
                Foreground = new SolidColorBrush(SettingsIconColors[n % SettingsIconColors.Length]),
            };
            var row = Ui.IconLabel(icon, c.Label);
            row.Spacing = Ui.Double("Space12");
            row.Padding = new Thickness(0, Ui.Double("Space4"), 0, Ui.Double("Space4"));
            AutomationProperties.SetName(row, c.Label);
            var item = new ListViewItem { Content = row, Tag = c.Id, CornerRadius = new CornerRadius(Ui.Double("Space4")) };
            list.Items.Add(item);
        }
        list.SelectedIndex = _settingsQuery.Length > 0 ? -1 : categories.FindIndex(c => c.Id == _settingsCategory);
        var sidebar = new Grid { RowDefinitions = { new RowDefinition { Height = GridLength.Auto }, new RowDefinition() } };
        sidebar.Children.Add(search);
        Grid.SetRow(list, 1);
        sidebar.Children.Add(list);

        var content = new StackPanel { Spacing = Ui.Double("Space12") };
        var title = _settingsQuery.Length > 0 ? "Search results" : categories.FirstOrDefault(c => c.Id == _settingsCategory)?.Label ?? "Settings";
        FillSettings(content, categories, defs);
        list.SelectionChanged += (_, _) =>
        {
            if (list.SelectedItem is not ListViewItem { Tag: string id } || (id == _settingsCategory && _settingsQuery.Length == 0)) return;
            _settingsCategory = id;
            _settingsQuery = "";
            ShowSettingsPage();
        };
        search.TextChanged += (_, _) =>
        {
            _settingsQuery = search.Text.Trim();
            content.Children.Clear();
            FillSettings(content, categories, defs);
        };
        ShowSettingsWindow(sidebar, title, content);
        if (_settingsQuery.Length > 0) search.Focus(FocusState.Programmatic);
        else list.Focus(FocusState.Programmatic);
    }

    private void FillSettings(StackPanel content, List<SettingCategoryDto> categories, List<SettingDefDto> defs)
    {
        if (_settingsQuery.Length > 0)
        {
            List<string> hits;
            try { hits = SettingsClient.Search(_settingsQuery); }
            catch (BastionException) { hits = []; }
            var found = hits.Select(id => defs.FirstOrDefault(d => d.Id == id)).OfType<SettingDefDto>().ToList();
            foreach (var group in found.GroupBy(d => d.Category))
            {
                content.Children.Add(SectionHeader(categories.FirstOrDefault(c => c.Id == group.Key)?.Label ?? group.Key));
                content.Children.Add(GroupedRows.Group(group.Select(d => (UIElement)SettingRow(d))));
            }
            // Shortcuts match by command name too, as on macOS.
            List<string> keys;
            try { keys = ShortcutsClient.Search(_settingsQuery).Where(WindowsCommands.Contains).ToList(); }
            catch (BastionException) { keys = []; }
            if (keys.Count > 0)
            {
                content.Children.Add(SectionHeader("Keyboard shortcuts"));
                var page = NewKeyboardPage();
                page.Filter(_settingsQuery);
                content.Children.Add(page.Body);
            }
            if (found.Count == 0 && keys.Count == 0) content.Children.Add(Ui.Text($"No settings match “{_settingsQuery}”.", "BodySecondaryTextStyle"));
            return;
        }
        switch (_settingsCategory)
        {
            case "keyboard":
                content.Children.Add(NewKeyboardPage().Body);
                return;
            case PolicyCategory:
                FillPolicyPage(content);
                return;
            case PluginsCategory:
                content.Children.Add(SettingsAction("Manage Plugins…", "Installed plugins, the catalogue and updates.", (_, _) => OpenPlugins()));
                return;
            case "about":
                content.Children.Add(GroupedRows.Group(new[] { ("Version", typeof(MainWindow).Assembly.GetName().Version?.ToString() ?? "—"), ("Library", _library.Path), ("Settings", Path.Combine(ConfigDir, "settings.json")), ("Shortcuts", Path.Combine(ConfigDir, "shortcuts.json")) }
                    .Select(p => (UIElement)LabelValue(p.Item1, p.Item2))));
                content.Children.Add(SettingsAction("Check for Updates…", "Looks for a newer Gantry now.", CheckForUpdates_Click));
                content.Children.Add(SettingsAction("Export Diagnostics…", "A zip of the app log and settings, without secrets or names.", ExportDiagnostics_Click));
                // LOG-ERRCODES: the About page is hand-built, so its core settings (Detailed logging) are added here.
                var aboutRows = defs.Where(d => d.Category == "about").Select(d => (UIElement)SettingRow(d)).ToList();
                if (aboutRows.Count > 0) content.Children.Add(GroupedRows.Group(aboutRows));
                return;
        }
        var rows = defs.Where(d => d.Category == _settingsCategory).Select(d => (UIElement)SettingRow(d)).ToList();
        if (rows.Count > 0) content.Children.Add(GroupedRows.Group(rows));
        // W6: what used to sit in the "…" menu lives with its settings.
        switch (_settingsCategory)
        {
            case "general":
                content.Children.Add(SectionHeader("Library"));
                content.Children.Add(SettingsAction("Export Connections to a File…",
                    "Saves the open library's folders and connections to a portable file, without passwords, to keep as a backup or import on another computer.",
                    ExportLibrary_Click));
                break;
            case "updates":
                content.Children.Add(SettingsAction("Check for Updates…", "Looks for a newer Gantry now.", CheckForUpdates_Click));
                break;
            case "terminal":
                content.Children.Add(Ui.Text("Ctrl+= and Ctrl+- change the text size of the open session only; Ctrl+0 resets it.", "CaptionTextStyle"));
                break;
            case "connection-defaults":
                content.Children.Add(SectionHeader("Defaults for each connection type"));
                content.Children.Add(GroupedRows.Group(AddConnectionForm.Protocols.Select(p =>
                    SettingsAction(p.Item2 + " defaults…", null, (_, _) => _ = EditDefaultsAsync(new EditorTarget.Type(p.Item1, p.Item2))))));
                break;
        }
    }

    private static UIElement SettingsAction(string text, string? help, RoutedEventHandler click)
    {
        var button = new Button { Content = text, HorizontalAlignment = HorizontalAlignment.Left };
        AutomationProperties.SetName(button, text.TrimEnd('…'));
        if (help is not null) AutomationProperties.SetHelpText(button, help);
        button.Click += click;
        if (help is null) return button;
        var stack = new StackPanel { Spacing = Ui.Double("Space4") };
        stack.Children.Add(button);
        stack.Children.Add(Ui.Text(help, "CaptionTextStyle"));
        return stack;
    }

    private const string PolicyCategory = "managed-policy";
    private const string PluginsCategory = "plugins";

    /// <summary>What the managed policy enforces. Nothing here can change it: an administrator owns the file.</summary>
    private static void FillPolicyPage(StackPanel content)
    {
        PolicyStateDto p;
        try { p = PolicyClient.State(); }
        catch (BastionException ex) { content.Children.Add(CodedErrorText("APP", ex.Message)); return; }
        if (p.Error is { } error) content.Children.Add(ErrorText(error));
        else if (p.Source is null) content.Children.Add(Ui.Text("No managed policy is installed; Gantry's defaults apply.", "BodySecondaryTextStyle"));
        content.Children.Add(LabelValue("Policy file", p.ManagedPath));
        if (p.Source is null || p.Error is not null) return;
        static string YesNo(bool b) => b ? "Yes" : "No";
        static string List(List<string> l) => l.Count == 0 ? "None" : string.Join(", ", l);
        content.Children.Add(SectionHeader("Enforced"));
        content.Children.Add(GroupedRows.Group(new[]
        {
            ("Blocked protocols", List(p.DeniedProtocols)),
            ("Legacy protocols", p.ForbidLegacy ? "Forbidden" : List(p.AllowedLegacy)),
            ("Credentials across customers", p.AllowCrossCustomerCredentials ? "Allowed" : "Refused"),
            ("Confirm bulk actions from", p.BulkConfirmThreshold.ToString(System.Globalization.CultureInfo.CurrentCulture) + " items"),
            ("Lock after inactivity", p.InactivityLockSecs is { } secs ? $"{secs / 60} min" : "Not required"),
            ("Lock on screen lock", YesNo(p.LockCredentialsOnOsLock)),
            ("Session recording", p.AllowSessionRecording ? "Allowed" : "Refused"),
            ("Clipboard writes from programs (OSC 52)", p.ForbidOsc52Write ? "Refused" : "Allowed"),
            ("RDP requires NLA", YesNo(p.RequireRdpNla)),
            ("Document auto-lock maximum", p.DocumentAutoLockMaxMinutes is { } max ? $"{max} min" : "Not required"),
            ("Document unlock", p.PasswordOnlyDocumentUnlock ? "Password only" : "Password or Windows Hello"),
        }.Select(r => (UIElement)LabelValue(r.Item1, r.Item2))));
    }

    internal static string PolicyLinesForSnapshot()
    {
        var p = PolicyClient.State();
        return $"source={p.Source ?? "none"} error={p.Error ?? "none"} denied=[{string.Join(",", p.DeniedProtocols)}] osc52={(p.ForbidOsc52Write ? "refused" : "allowed")} docAutoLockMax={p.DocumentAutoLockMaxMinutes?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "none"} passwordOnlyDocs={p.PasswordOnlyDocumentUnlock}";
    }

    internal void OpenPolicyPageForSnapshot()
    {
        _settingsCategory = PolicyCategory;
        _settingsQuery = "";
        ShowSettingsPage();
    }

    private KeyboardPage NewKeyboardPage() => new(Shortcuts, WindowsCommands,
        confirm: (title, text) => ModalOverSettingsAsync(() => ShowModal(title, ErrorText(text), primary: "Replace", cancel: "Cancel", focusCancel: true)),
        refuse: why => _ = ModalOverSettingsAsync(() => ShowModal("Shortcut not changed", CodedErrorText("APP", why), primary: "OK", cancel: null)),
        changed: ReloadShortcuts);

    private static TextBlock SectionHeader(string text)
    {
        var header = Ui.Text(text, "SectionHeaderTextStyle");
        header.Margin = Ui.Thickness("InspectorSectionMargin");
        AutomationProperties.SetHeadingLevel(header, AutomationHeadingLevel.Level2);
        return header;
    }

    private static Grid LabelValue(string label, string value)
    {
        var grid = new Grid { ColumnSpacing = Ui.Double("Space12") };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = Ui.Length("InspectorLabelColumnWidth") });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        var l = Ui.Text(label, "BodySecondaryTextStyle");
        l.TextWrapping = TextWrapping.Wrap;
        grid.Children.Add(l);
        var v = Ui.Text(value, "BodyTextStyle");
        v.IsTextSelectionEnabled = true;
        v.TextWrapping = TextWrapping.Wrap;
        Grid.SetColumn(v, 1);
        grid.Children.Add(v);
        return grid;
    }

    /// <summary>One setting: label and help on the left, its control on the right; every change saves at once.</summary>
    private Grid SettingRow(SettingDefDto d)
    {
        var row = new Grid { ColumnSpacing = Ui.Double("Space16"), MinHeight = Ui.Double("ControlHeight") };
        row.ColumnDefinitions.Add(new ColumnDefinition());
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
        var help = Ui.Text(d.Help, "CaptionSecondaryTextStyle");
        help.TextWrapping = TextWrapping.Wrap;
        row.Children.Add(new StackPanel { VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Text(d.Label, "BodyTextStyle"), help } });
        FrameworkElement control;
        var current = d.Id == "terminal.theme" ? _appearance.TerminalTheme : SettingValue(d.Id);
        switch (d.Kind)
        {
            case "choice":
                // High contrast is a Windows setting that apps follow, not one they can switch on.
                var options = d.Options.Where(o => !(d.Id == "appearance.mode" && o.Id == "high-contrast")).ToList();
                var combo = new ComboBox { ItemsSource = options.Select(o => o.Label).ToList(), SelectedIndex = options.FindIndex(o => o.Id == current), HorizontalAlignment = HorizontalAlignment.Stretch };
                combo.SelectionChanged += (_, _) => { if (combo.SelectedIndex >= 0) SetSetting(d.Id, options[combo.SelectedIndex].Id); };
                // Scrolled into view (keyboard focus, UI Automation), a drop-down lands in the middle of the page, not on its
                // bottom edge: its list opens over the drop-down with the chosen row on it, so at the bottom edge of a short
                // window the rows below the chosen one ran past the window (layout fit, 800 px, B4-WIN round 2). The request's
                // ratio is read-only, so the plain request is replaced by one that asks for the middle (that one passes through).
                combo.BringIntoViewRequested += (_, e) =>
                {
                    if (e.VerticalAlignmentRatio == 0.5) return;
                    e.Handled = true;
                    combo.StartBringIntoView(new BringIntoViewOptions { VerticalAlignmentRatio = 0.5, AnimationDesired = false });
                };
                control = combo;
                break;
            case "toggle" when d.Id == TelnetSerial.AllowSetting:
                control = AllowTelnetSwitch(current);
                break;
            case "toggle":
                var toggle = new ToggleSwitch { IsOn = current == "true", OnContent = "On", OffContent = "Off", MinHeight = Ui.Double("ControlHeight") };
                toggle.Toggled += (_, _) => SetSetting(d.Id, toggle.IsOn ? "true" : "false");
                control = toggle;
                break;
            case "integer" when d.Id == DocumentClient.AutoLockSettingId && DocumentAutoLockCap() is { } cap:
                control = CappedAutoLockBox(d, current, cap, help);
                break;
            case "integer":
                var number = new NumberBox { Minimum = d.Min, Maximum = d.Max, Value = double.TryParse(current, out var v) ? v : d.Min, SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Inline };
                number.ValueChanged += (_, _) => { if (!double.IsNaN(number.Value)) SetSetting(d.Id, ((long)number.Value).ToString()); };
                control = number;
                break;
            case "text" or "multiline":
                control = TextSettingBox(d, current);
                break;
            default:
                var open = new Button { Content = LinkLabel(d), HorizontalAlignment = HorizontalAlignment.Stretch };
                open.Click += (_, _) => _ = OpenLinkAsync(d.Link ?? "");
                control = open;
                break;
        }
        AutomationProperties.SetName(control, d.Label);
        AutomationProperties.SetHelpText(control, help.Text);
        control.VerticalAlignment = VerticalAlignment.Center;
        Grid.SetColumn(control, 1);
        row.Children.Add(control);
        return row;
    }

    /// <summary>A free-text setting (session log folder, redaction patterns): saved when focus leaves the box, so a
    /// half-typed path or pattern is never checked. The core refuses an invalid value and the box goes back.</summary>
    private TextBox TextSettingBox(SettingDefDto d, string current)
    {
        var multi = d.Kind == "multiline";
        var box = new TextBox { Text = current, AcceptsReturn = multi, TextWrapping = multi ? TextWrapping.Wrap : TextWrapping.NoWrap, HorizontalAlignment = HorizontalAlignment.Stretch };
        if (d.Max > 0) box.MaxLength = (int)Math.Min(d.Max, int.MaxValue);
        if (multi) box.MinHeight = Ui.Double("ControlHeight") * 3;
        ToolTipService.SetToolTip(box, d.Help);
        var saved = current;
        box.LostFocus += (_, _) =>
        {
            if (box.Text == saved) return;
            SetSetting(d.Id, box.Text);
            saved = SettingValue(d.Id);
            if (box.Text.Trim() != saved) box.Text = saved; // refused: show what is in force
        };
        return box;
    }

    /// <summary>The managed policy's document auto-lock maximum in minutes, or null when none is set.</summary>
    private static uint? DocumentAutoLockCap()
    {
        try { return PolicyClient.State().DocumentAutoLockMaxMinutes is { } max and > 0 ? max : null; }
        catch (BastionException) { return null; } // the core still applies the policy when it locks
    }

    /// <summary>
    /// Document auto-lock under a policy maximum: 1 to <paramref name="cap"/> minutes ("never" is not allowed), showing the
    /// limit in force (the core's stricter value), and a stored value above the cap is saved down to it.
    /// </summary>
    private NumberBox CappedAutoLockBox(SettingDefDto d, string current, uint cap, TextBlock help)
    {
        var user = uint.TryParse(current, out var u) ? u : 0;
        var effective = DocumentClient.PolicyAutoLockMinutes(user);
        help.Text = $"{d.Help} Your administrator's policy caps this at {cap} min.";
        var number = new NumberBox { Minimum = 1, Maximum = cap, Value = effective, SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Inline };
        AutomationProperties.SetAutomationId(number, "DocumentAutoLockMinutes");
        if (effective != user) SetSetting(d.Id, effective.ToString(System.Globalization.CultureInfo.InvariantCulture));
        number.ValueChanged += (_, _) =>
        {
            if (double.IsNaN(number.Value)) return;
            var clamped = DocumentClient.PolicyAutoLockMinutes((uint)Math.Clamp(number.Value, 1, cap));
            if (number.Value != clamped) number.Value = clamped;
            else SetSetting(d.Id, clamped.ToString(System.Globalization.CultureInfo.InvariantCulture));
        };
        return number;
    }

    private static string LinkLabel(SettingDefDto d) => d.Link switch
    {
        "lock-credentials" => "Lock Now",
        "ssh-import" => "Import…",
        "ssh-sources" => "Configure…",
        "keyboard-shortcuts" => "Change Shortcuts",
        "workspace-manager" => "Manage…",
        { } l when l.StartsWith("defaults:", StringComparison.Ordinal) => "Edit Defaults…",
        _ => "Open…",
    };

    /// <summary>Snapshot mode: change a setting as the Settings page does.</summary>
    internal void SetSettingForSnapshot(string id, string value) => SetSetting(id, value);

    private void SetSetting(string id, string value)
    {
        // B10: Off deletes what Recently Deleted keeps, so it asks first (MainWindow.RecentlyDeleted.cs).
        if (id == RetentionSetting && value == "0" && Settings.Get(RetentionSetting) != "0") { _ = SetRetentionOffAsync(); return; }
        try
        {
            if (id == "terminal.theme") SetTerminalTheme(value);
            Settings.Set(id, value);
            switch (id)
            {
                case "appearance.mode": ApplyAppearanceMode(value); break;
                case "appearance.accent": ApplyAccent(value); SyncSessionSurface(); break;
                case WindowTonesSetting: SyncSessionSurface(); break;
                case "appearance.density": ApplyDensity(value); break;
                case "tabs.vertical": ApplyTabOrientation(value == "true"); break;
                case "appearance.zoom": ApplyZoom(); break; // app UI zoom: a setting only (owner point 13)
                case "terminal.font-size": ApplyTerminalFontSize(TerminalFontSize); break;
                case "terminal.font-family": foreach (var pane in _tabs.SelectMany(t => t.AllPanes).Where(p => p.FontOverride.Family is null)) pane.SetFont(value); break;
                case "terminal.ligatures": foreach (var pane in _tabs.SelectMany(t => t.AllPanes).Where(p => p.FontOverride.Ligatures is null)) pane.Ligatures = value != "false"; break;
                case "terminal.bell": foreach (var pane in _tabs.SelectMany(t => t.AllPanes)) pane.BellMode = value; break;
                case SessionBarSetting: ApplySessionBarSetting(value); break;
                case "terminal.copy-on-select": foreach (var pane in _tabs.SelectMany(t => t.AllPanes)) pane.CopyOnSelect = value == "true"; break;
                case "terminal.cursor-style": foreach (var pane in _tabs.SelectMany(t => t.AllPanes)) pane.CursorStyle = value; break;
                case "terminal.scrollback": foreach (var pane in _tabs.SelectMany(t => t.AllPanes)) ApplyScrollback(pane, value); break;
                case "terminal.osc52": foreach (var pane in _tabs.SelectMany(t => t.AllPanes)) pane.ApplyClipboardPolicy(ClipboardPolicy()); break;
                case DetailedLogSetting: DetailedLogChanged(value); break;
            }
        }
        catch (BastionException ex)
        {
            _ = ShowModal("Setting not changed", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
        }
    }

    /// <summary>Settings › Terminal › Edit themes. Changes reach open tabs and the colours menu when the editor closes.</summary>
    internal ThemeEditorForm? ThemeEditorForSnapshot { get; private set; }
    internal Task EditThemesForSnapshot() => EditThemesAsync();

    private async Task EditThemesAsync()
    {
        if (_modal is not null) return;
        var dirty = false;
        var form = new ThemeEditorForm(() => dirty = true, _appearance.TerminalTheme);
        ThemeEditorForSnapshot = form;
        await ShowModal("Terminal themes", form.Body, primary: "Close", cancel: null, focus: form.Field, wide: true);
        if (!dirty) return;
        BuildTerminalColorsMenu();
        SetTerminalTheme(_appearance.TerminalTheme);
    }

    /// <summary>Settings › SSH › SSH config sources: sources, placeholders, change preview and refresh.</summary>
    internal SshSourcesForm? SshSourcesForSnapshot { get; private set; }
    internal Task EditSshSourcesForSnapshot() => EditSshSourcesAsync();

    private async Task EditSshSourcesAsync()
    {
        if (_modal is not null) return;
        var form = SshSourcesForSnapshot = new SshSourcesForm(SessionDataDir, _library, () => ReloadThenSave(null));
        await ShowModal("SSH config sources", form.Body, primary: "Close", cancel: null, focus: form.Field, wide: true);
    }

    /// <summary>The settings' links, each to the Windows page that does it (SettingsClient.HandledLinks lists them).</summary>
    private async Task OpenLinkAsync(string link)
    {
        switch (link)
        {
            case "credential-manager": OpenCredentialManager(); FrontMainFromSettings(); break;
            case "vaultwarden": await OverSettingsAsync(VaultwardenAsync); break;
            case "lock-credentials": LockCredentials(); break;
            case "keyboard-shortcuts": OpenSettings("keyboard"); break;
            case "window-current-size": UseCurrentWindowSize(); break;
            case "workspace-manager": OpenWorkspaceManager(); FrontMainFromSettings(); break;
            case "terminal-themes": await OverSettingsAsync(EditThemesAsync); break;
            case "ssh-sources": await OverSettingsAsync(EditSshSourcesAsync); break;
            case "ssh-import": await OverSettingsAsync(() => ImportSshAsync(SshWorkflow.UserDir(SessionDataDir), SshConfigLocation.SystemFile)); break;
            case { } d when d.StartsWith("defaults:", StringComparison.Ordinal):
                var protocol = d["defaults:".Length..];
                // The same label as More › Type defaults ("Web defaults", not "WEB defaults").
                var label = AddConnectionForm.Protocols.FirstOrDefault(p => p.Id == protocol).Label ?? protocol.ToUpperInvariant();
                await OverSettingsAsync(() => EditDefaultsAsync(new EditorTarget.Type(protocol, label)));
                break;
        }
    }

    // ---- Credential Manager page: the local vault and Vaultwarden in one place ----

    private void ShowCredentialManagerPage()
    {
        var content = new StackPanel { Spacing = Ui.Double("Space12") };
        content.Children.Add(SectionHeader("Local vault"));
        var vaultNote = Ui.Text("Passwords and SSH keys saved on this PC. The vault key is protected by Windows for your account (DPAPI).", "CaptionSecondaryTextStyle");
        vaultNote.TextWrapping = TextWrapping.Wrap;
        content.Children.Add(vaultNote);
        var add = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        if (_credentials is null)
        {
            // Locked: listing would open the vault again, so a lock (by hand or after idle) would undo itself here.
            content.Children.Add(Ui.Text("Locked. The key is not in memory; Windows unwraps it again when a credential is used.", "BodyTextStyle"));
            if (_vaultError is { } why) content.Children.Add(CodedErrorText("APP", why));
            add.Children.Add(PageButton("Unlock", async () =>
            {
                if (await ConfirmVaultOpenAsync()) UnlockLocalVault();
                ShowCredentialManagerPage();
            }));
        }
        else
        {
            try
            {
                var list = OpenCredentials().List();
                if (list.Count == 0) content.Children.Add(Ui.Text("No saved credentials yet.", "BodySecondaryTextStyle"));
                foreach (var c in list) content.Children.Add(CredentialRow(c));
            }
            catch (BastionException ex)
            {
                content.Children.Add(CodedErrorText("APP", ex.Message));
            }
        }
        add.Children.Add(PageButton("Add Password…", () => _ = NewCredentialFromPageAsync(sshKey: false)));
        add.Children.Add(PageButton("Add SSH Key…", () => _ = NewCredentialFromPageAsync(sshKey: true)));
        content.Children.Add(add);

        content.Children.Add(SectionHeader("Vaultwarden"));
        var unlocked = _vaultwarden is { IsUnlocked: true };
        var setUp = false;
        string status;
        try
        {
            var config = Vaultwarden.Config;
            setUp = config.ServerUrl is { Length: > 0 };
            status = unlocked ? $"Unlocked as {config.Email} on {config.ServerUrl}"
                : config.ServerUrl is { Length: > 0 } ? $"Locked ({config.Email} on {config.ServerUrl})" : "Not set up";
        }
        catch (BastionException ex) { status = ex.Message; }
        content.Children.Add(Ui.Text(status, "BodyTextStyle"));
        if (unlocked)
        {
            try
            {
                var items = Vaultwarden.Items.Items;
                content.Children.Add(Ui.Text($"{items.Count} login{(items.Count == 1 ? "" : "s")}", "CaptionSecondaryTextStyle"));
                foreach (var i in items.Take(50)) content.Children.Add(LabelValue(i.Name, i.Username ?? "—"));
            }
            catch (BastionException ex) { content.Children.Add(CodedErrorText("APP", ex.Message)); }
        }
        var vw = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        vw.Children.Add(PageButton(unlocked ? "Logins and Re-sync…" : setUp ? "Unlock…" : "Set Up…", () => _ = VaultwardenFromPageAsync()));
        if (unlocked) vw.Children.Add(PageButton("Lock Vaultwarden", () => { _vaultwarden?.Lock(); ShowCredentialManagerPage(); }));
        content.Children.Add(vw);

        AddHostCaSection(content);

        var lockAll = new Button { Content = ShortcutText("lock-credentials") is { } k ? $"Lock Credentials ({k})" : "Lock Credentials", Style = Ui.Style("SubtleButtonStyle") };
        AutomationProperties.SetName(lockAll, "Lock Credentials");
        lockAll.Click += (_, _) => LockCredentials();
        ShowPage(null, "Credential Manager", content, lockAll);
    }

    /// <summary><c>terminal.scrollback</c> on one pane; the core validated the value when it was saved.</summary>
    private static void ApplyScrollback(TerminalView pane, string value)
    {
        if (!int.TryParse(value, out var lines)) return;
        try { pane.SetScrollback(lines); }
        catch (BastionException) { /* the pane keeps its current history size */ }
    }

    private static Button PageButton(string label, Action click)
    {
        var b = new Button { Content = label };
        b.Click += (_, _) => click();
        return b;
    }

    private Grid CredentialRow(CredentialDto c)
    {
        var row = new Grid { ColumnSpacing = Ui.Double("Space12"), MinHeight = Ui.Double("ControlHeight") };
        row.ColumnDefinitions.Add(new ColumnDefinition());
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var detail = $"{c.KindLabel} for {c.Username}{(c.Folder is { Length: > 0 } f ? " · " + f : "")}";
        row.Children.Add(new StackPanel { VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Text(c.Name, "BodyTextStyle"), Ui.Text(detail, "CaptionSecondaryTextStyle") } });
        var edit = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphEdit", "IconSize") };
        ToolTipService.SetToolTip(edit, "Edit");
        AutomationProperties.SetName(edit, "Edit " + c.Name);
        edit.Click += (_, _) => _ = EditCredentialFromPageAsync(c);
        var remove = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphDelete", "IconSize") };
        ToolTipService.SetToolTip(remove, "Remove");
        AutomationProperties.SetName(remove, "Remove " + c.Name);
        remove.Click += (_, _) => _ = RemoveCredentialFromPageAsync(c);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space4"), Children = { edit, remove } };
        Grid.SetColumn(actions, 1);
        row.Children.Add(actions);
        return row;
    }

    private async Task NewCredentialFromPageAsync(bool sshKey)
    {
        await SaveCredentialAsync(new NewCredentialForm(sshKey, pickKeyFile: PickUploadFile));
        ShowCredentialManagerPage();
    }

    private async Task EditCredentialFromPageAsync(CredentialDto c)
    {
        await SaveCredentialAsync(new NewCredentialForm(false, c, PickUploadFile));
        ShowCredentialManagerPage();
    }

    private async Task RemoveCredentialFromPageAsync(CredentialDto c)
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
            catch (BastionException ex) { await ShowModal("Could not remove the credential", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        }
        ShowCredentialManagerPage();
    }

    private async Task VaultwardenFromPageAsync()
    {
        await VaultwardenAsync();
        if (_pageKind == "credentials") ShowCredentialManagerPage();
    }

    // ---- Snapshot mode hooks (SnapshotRunner, BASTION_SNAPSHOT_SETTINGS) ----

    internal void SearchSettingsForSnapshot(string query)
    {
        _settingsQuery = query;
        ShowSettingsPage();
    }

    /// <summary>Snapshot only: record a chord on the Keyboard page as a key press would.</summary>
    internal Task RecordShortcutForSnapshot(string id, string chord) => NewKeyboardPage().RecordForSnapshot(id, chord);

    internal IReadOnlyList<string> ShortcutLinesForSnapshot() =>
        Shortcuts.List().Where(s => WindowsCommands.Contains(s.Id)).Select(s => $"{s.Label}: {(s.Chord is null ? "none" : Chords.Display(s.Chord))}{(s.IsDefault ? "" : " (changed)")}").ToList();

    internal bool DispatchForSnapshot(VirtualKey key, bool ctrl, bool alt, bool shift, bool inTerminal) => DispatchShortcut(key, ctrl, alt, shift, inTerminal);

    internal bool PageOpenForSnapshot => PageHost?.Visibility == Visibility.Visible;

    internal int TabCountForSnapshot => _tabs.Count;

    /// <summary>Snapshot only: pick an option in the open dialog's list with this header and scroll it into view.</summary>
    internal string ChooseModalOptionForSnapshot(string header, string option)
    {
        static IEnumerable<DependencyObject> All(DependencyObject d)
        {
            yield return d;
            for (var i = 0; i < VisualTreeHelper.GetChildrenCount(d); i++)
                foreach (var c in All(VisualTreeHelper.GetChild(d, i))) yield return c;
        }
        var combos = All(ModalBody).OfType<ComboBox>().ToList();
        if (combos.FirstOrDefault(c => c.Header as string == header) is not { } combo) return $"no list {header} among {combos.Count}";
        combo.SelectedItem = option;
        if (FindAncestor<ScrollViewer>(combo) is not { Content: UIElement list } scroller) return "no scroller";
        var y = combo.TransformToVisual(list).TransformPoint(new Windows.Foundation.Point(0, 0)).Y;
        combo.Focus(FocusState.Programmatic); // the focused first field would scroll itself back into view
        var moved = scroller.ChangeView(null, Math.Max(0, y - 40), null, disableAnimation: true);
        return $"scroll to {y:F0} of {scroller.ScrollableHeight:F0}: {moved}";
    }
}

/// <summary>A repeating UI-thread timer that lives as long as the window.</summary>
internal sealed class DispatcherQueueTimerHolder
{
    private readonly Microsoft.UI.Dispatching.DispatcherQueueTimer _timer;

    public DispatcherQueueTimerHolder(Microsoft.UI.Dispatching.DispatcherQueue queue, TimeSpan interval, Action tick)
    {
        _timer = queue.CreateTimer();
        _timer.Interval = interval;
        _timer.IsRepeating = true;
        _timer.Tick += (_, _) => tick();
        _timer.Start();
    }

    public void Stop() => _timer.Stop();
}
