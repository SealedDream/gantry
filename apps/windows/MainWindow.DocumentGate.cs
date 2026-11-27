using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Windows.Foundation;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Spec §5 (docs/specs/session-restore-and-tab-bar.md): document-first launch. Until a document is unlocked the window body
// is covered by the Unlock screen (the last document) or the Welcome screen (no last document, or its file is gone).
// Locking the shown document (by hand, idle, screen lock) brings the Unlock screen back; sessions keep running underneath.
// The core enforces the password back-off (C ABI 81) and the managed password-only policy (ABI 82); this file presents them.
public sealed partial class MainWindow
{
    /// <summary>Shown where Windows Hello would be when the managed policy requires the document password (as the core's reason).</summary>
    private const string PasswordOnlyNote = "Your organisation requires the document password; Windows Hello is off.";

    private const int GateRecentLimit = 8;
    private Grid? _gate;
    private DispatcherTimer? _gateCountdown;

    /// <summary>On for real launches and always in an owner build. A UI test (test library set, test builds only) keeps
    /// the Personal-first launch unless it opts in, so the existing tests are unchanged.</summary>
    private bool GateEnabled => !_demo && (TestHooks.LibraryOverride is null || TestHooks.DocumentGateOptIn);

    /// <summary>
    /// Called once at start-up (owner spec §5): the Unlock screen for the most recent document; Welcome when there is
    /// none or that one is missing — never an older document instead (Codex Y08). Welcome lists the missing one with Locate.
    /// </summary>
    private void InitDocumentGate()
    {
        if (!GateEnabled) return;
        RecentDocumentDto? last = null;
        try { last = DocumentClient.RecentDetails(SessionDataDir).FirstOrDefault(); }
        catch (BastionException ex) { ShowWelcome("Recent documents could not be read: " + ex.Message); return; }
        // W2, W4: Personal.bastion opens with the device key, so it never needs the gate. With Personal there and no
        // other document last used, Personal shows straight away (owner point 1).
        if (App.Personal is not null && (last is null || IsPersonalPath(last.Path))) return;
        if (last is null) ShowWelcome(null);
        else if (!last.Present) ShowMissingPane(last);
        else GateOpen(last.Path);
    }

    // ---- Overlay ----

    private void ShowGate(UIElement card, string title, UIElement? pinned = null)
    {
        if (_gate is null)
        {
            _gate = new Grid();
            AutomationProperties.SetAutomationId(_gate, "DocumentGate");
            // Tab and Shift+Tab stay on the start window: nothing behind the gate is reachable by keyboard (Codex W05).
            _gate.TabFocusNavigation = Microsoft.UI.Xaml.Input.KeyboardNavigationMode.Cycle;
            Grid.SetRow(_gate, 1);
            Grid.SetRowSpan(_gate, 2);
            // Under ModalHost, so the Open dialog opens on top of the gate.
            RootGrid.Children.Insert(RootGrid.Children.IndexOf(ModalHost), _gate);
        }
        AutomationProperties.SetName(_gate, title);
        SetTornOffCovered(true); // B12-W2b: torn-off windows hide their sessions too
        HideBehindGate(true);
        BuildStartWindow(card, pinned);
        _gate.Visibility = Visibility.Visible;
        UpdatePanes();
        // Nothing of the library is reachable until a document is open.
        SetToolbarEnabled(false);
        Title = title + " — Gantry";
        // A terminal that had focus before the lock must not keep receiving keys behind the card.
        DispatcherQueue.TryEnqueue(() => { if (IsGated && _modal is null && !Contains(_gate!, FocusedElement)) FocusGate(); });
    }

    /// <summary>The Welcome or Unlock overlay is up: the library, tabs and sessions behind it take no commands.</summary>
    private bool IsGated => _gate is { Visibility: Visibility.Visible };

    /// <summary>
    /// The root key handler while gated and no dialog is open (Codex W05): no shortcut runs — configurable or built in,
    /// F6/pane focus and the palette included — so only the card's own Open/Create/Unlock controls act. A key that
    /// arrives with focus behind the gate (a session that had it before the lock) moves focus onto the card instead.
    /// Alt+F4 still closes the window (the system handles it).
    /// </summary>
    private void GateKeyDown(Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
    {
        if (!Contains(_gate!, FocusedElement))
        {
            e.Handled = true;
            FocusGate();
            return;
        }
        if (StartWindowKey(e)) { e.Handled = true; return; }
        // Tab is moved here, wrapping on the card, rather than left to the framework's tab order across the window.
        if (e.Key == Windows.System.VirtualKey.Tab && !Down(Windows.System.VirtualKey.Control) && !Down(Windows.System.VirtualKey.Menu))
        {
            e.Handled = true;
            MoveGateFocus(Down(Windows.System.VirtualKey.Shift));
        }
    }

    private void MoveGateFocus(bool backwards)
    {
        var stops = GateTabStops();
        if (stops.Count == 0) return;
        var current = stops.FindIndex(c => Contains(c, FocusedElement));
        var next = current < 0 ? (backwards ? stops.Count - 1 : 0) : (current + (backwards ? stops.Count - 1 : 1)) % stops.Count;
        stops[next].Focus(FocusState.Keyboard);
    }

    /// <summary>The card's keyboard stops in tree order: enabled, visible controls that take Tab.</summary>
    private List<Control> GateTabStops()
    {
        var stops = new List<Control>();
        void Walk(DependencyObject node)
        {
            if (node is UIElement { Visibility: not Visibility.Visible }) return;
            if (node is Control { IsTabStop: true, IsEnabled: true } c && c is not ScrollViewer) { stops.Add(c); return; }
            for (var k = 0; k < Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChildrenCount(node); k++)
                Walk(Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChild(node, k));
        }
        if (_gate is not null) Walk(_gate);
        return stops;
    }

    private void FocusGate()
    {
        if (_gate is null) return;
        if (GateTabStops() is [var first, ..]) first.Focus(FocusState.Keyboard);
    }

    private void HideGate()
    {
        StopGateCountdown();
        if (_gate is not null) { _gate.Visibility = Visibility.Collapsed; _gate.Children.Clear(); _startPane = null; UpdatePanes(); }
        _startCreating = false;
        SetTornOffCovered(false);
        HideBehindGate(false);
        SetToolbarEnabled(true);
    }

    /// <summary>A Grid has no IsEnabled: the toolbar's controls are switched one by one (keyboard included).</summary>
    private void SetToolbarEnabled(bool on)
    {
        // The start window shows no library chrome: every title-bar item is disabled and hidden; the bar itself stays
        // as the drag area, with the system caption buttons.
        foreach (var child in Toolbar.Children)
        {
            if (child is Control c) c.IsEnabled = on;
            if (on) { if (_hiddenByGate.Remove(child, out var v)) child.Visibility = v; }
            else if (!_hiddenByGate.ContainsKey(child)) { _hiddenByGate[child] = child.Visibility; child.Visibility = Visibility.Collapsed; }
        }
    }

    private static Button GateButton(string text, RoutedEventHandler click, bool accent = false)
    {
        var b = new Button { Content = text, HorizontalAlignment = HorizontalAlignment.Stretch };
        if (accent) b.Style = Ui.Style("AccentButtonStyle");
        AutomationProperties.SetName(b, text.TrimEnd('…'));
        b.Click += click;
        return b;
    }


    // ---- Unlock (the start window's right half) ----

    /// <summary>Open <paramref name="path"/> (locked) and show its Unlock half; an unprotected document just opens.</summary>
    private void GateOpen(string path)
    {
        var full = Path.GetFullPath(path);
        if (IsPersonalPath(full)) { HideGate(); _ = ShowDocumentAsync(null); return; }
        var doc = _documents.FirstOrDefault(d => d.Info.Path is { } p && string.Equals(Path.GetFullPath(p), full, StringComparison.OrdinalIgnoreCase));
        if (doc is null)
        {
            try { doc = DocumentClient.Open(full, SessionDataDir); }
            catch (BastionException ex) { ShowWelcome($"{Path.GetFileName(full)} could not be opened: {ex.Message}"); return; }
            _documents.Add(doc);
        }
        if (doc.Info.Locked) ShowUnlock(doc, askHello: true);
        else _ = FinishGateAsync(doc);
    }

    private void ShowUnlock(DocumentClient doc, bool askHello)
    {
        var info = doc.Info;
        _startCreating = false;
        _startSelected = info.Path;
        var hello = info.Biometric && DocumentClient.BiometricUnlockAllowed;
        var password = new PasswordBox { PlaceholderText = "Password", HorizontalAlignment = HorizontalAlignment.Stretch };
        AutomationProperties.SetName(password, "Document password");
        var error = DocError();
        var wait = Ui.Text("", "CaptionTextStyle");
        wait.Visibility = Visibility.Collapsed;
        AutomationProperties.SetAutomationId(wait, "UnlockWait");
        var unlock = new Button { Content = Glyph(""), MinWidth = 40, VerticalAlignment = VerticalAlignment.Stretch };
        AutomationProperties.SetName(unlock, "Unlock");
        ToolTipService.SetToolTip(unlock, "Unlock (Enter)");
        unlock.Click += (_, _) => GateUnlockPassword(doc, password, error);
        password.KeyDown += (_, e) =>
        {
            if (e.Key != Windows.System.VirtualKey.Enter) return;
            e.Handled = true;
            GateUnlockPassword(doc, password, error);
        };
        var field = new Grid { ColumnSpacing = Ui.Double("Space8") };
        field.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        field.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetColumn(unlock, 1);
        field.Children.Add(password);
        field.Children.Add(unlock);

        var keep = new CheckBox { Content = "Keep unlocked until screen locks", IsChecked = _keepUnlockedUntilScreenLock };
        ToolTipService.SetToolTip(keep, "No idle lock until Gantry quits. Screen lock and sleep still lock.");
        keep.Checked += (_, _) => _keepUnlockedUntilScreenLock = true;
        keep.Unchecked += (_, _) => _keepUnlockedUntilScreenLock = false;

        var pane = Stack(StartTitle(info.Name, Join("Encrypted", RecentConnections(info.Path), LastOpened(info.Path))));
        pane.Spacing = Ui.Double("Space16");
        if (hello)
        {
            var b = GateButton("Unlock with Windows Hello", (_, _) => _ = GateUnlockHelloAsync(doc, error), accent: true);
            b.MinHeight = 36;
            pane.Children.Add(b);
            pane.Children.Add(OrDivider("or password"));
        }
        pane.Children.Add(Stack(field, wait, error));
        pane.Children.Add(keep);
        if (!DocumentClient.BiometricUnlockAllowed) pane.Children.Add(PolicyNote());
        ShowGate(pane, $"Unlock {info.Name}");
        StartGateCountdown(doc, wait, unlock, password);
        password.Loaded += (_, _) => password.Focus(FocusState.Programmatic);
        // Windows Hello first; Cancel or a failure leaves the password field.
        if (hello && askHello) WhenShown(() => { if (doc.Info.Locked) _ = GateUnlockHelloAsync(doc, error); });
    }

    /// <summary>The window has been activated at least once (it is on screen and has a visible owner HWND).</summary>
    private bool _everActivated;

    /// <summary>
    /// Run <paramref name="action"/> now when the window is already on screen, otherwise on its first activation.
    /// The launch gate is built in the constructor, before App activates the window: a Windows Hello request made then
    /// has no visible owner window and Windows shows no prompt (live run on Win10, 2026-11-26).
    /// </summary>
    private void WhenShown(Action action)
    {
        if (_everActivated) { action(); return; }
        TypedEventHandler<object, WindowActivatedEventArgs>? once = null;
        TypedEventHandler<object, WindowEventArgs>? closed = null;
        void Unhook() { Activated -= once; Closed -= closed; }
        closed = (_, _) => Unhook(); // closed before it was ever shown: nothing stays subscribed
        once = (_, e) =>
        {
            if (e.WindowActivationState == WindowActivationState.Deactivated || _closed) return;
            Unhook();
            _everActivated = true;
            // After the activation finishes, so the prompt is owned by a painted, foreground window.
            DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => { if (!_closed) action(); });
        };
        Activated += once;
        Closed += closed;
    }

    private static TextBlock PolicyNote()
    {
        var note = Ui.Text(PasswordOnlyNote, "CaptionSecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        AutomationProperties.SetAutomationId(note, "DocumentPolicyNote");
        return note;
    }

    private string? LastOpened(string? path)
    {
        long? at = null;
        try { at = DocumentClient.RecentDetails(SessionDataDir).FirstOrDefault(r => string.Equals(r.Path, path, StringComparison.OrdinalIgnoreCase))?.LastOpenedAt; }
        catch (BastionException) { /* shown as unknown */ }
        return at is { } s ? "last opened " + Ago(s) : null;
    }

    private string? RecentConnections(string? path)
    {
        try { return Connections(DocumentClient.RecentDetails(SessionDataDir).FirstOrDefault(r => string.Equals(r.Path, path, StringComparison.OrdinalIgnoreCase))?.ConnectionCount); }
        catch (BastionException) { return null; }
    }

    private void GateUnlockPassword(DocumentClient doc, PasswordBox password, TextBlock error)
    {
        if (password.Password.Length == 0) { Fail(error, "Type the document password."); return; }
        try
        {
            doc.Unlock(password.Password);
            _ = FinishGateAsync(doc, signIn: true);
        }
        catch (BastionException ex) { Fail(error, ex.Message); }
        finally { password.Password = ""; }
    }

    private async Task GateUnlockHelloAsync(DocumentClient doc, TextBlock error)
    {
        string? why;
        try
        {
            why = await UnlockDocumentWithHelloAsync(doc);
            if (why is null) { await FinishGateAsync(doc, signIn: true); return; }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Started fire-and-forget: without this an unexpected error would vanish and leave the card waiting.
            TestHooks.TraceHello($"hello-gate {ex.GetType().Name} 0x{ex.HResult:X8}");
            System.Diagnostics.Debug.WriteLine($"hello gate: {ex}");
            why = "Windows Hello did not unlock it. Type the password instead.";
        }
        // Cancel leaves the same pane, password focused, without an error; any other refusal says why.
        if (why.Length > 0) Fail(error, why);
        else error.Visibility = Visibility.Collapsed;
        FocusGate();
    }

    /// <summary>While the core's back-off runs, Unlock is disabled and the wait counts down.</summary>
    private void StartGateCountdown(DocumentClient doc, TextBlock wait, Button unlock, PasswordBox password)
    {
        StopGateCountdown();
        void Tick()
        {
            UnlockStatusDto status;
            try { status = doc.UnlockStatus(); }
            catch (BastionException) { status = new(0, 0); }
            catch (ObjectDisposedException)
            {
                // The document was closed (or the window is closing) while a tick was already queued.
                StopGateCountdown();
                return;
            }
            var waiting = status.WaitSecs > 0;
            unlock.IsEnabled = password.IsEnabled = !waiting;
            wait.Text = waiting ? $"{status.Failures} wrong passwords. Try again in {status.WaitSecs} s." : "";
            wait.Visibility = waiting ? Visibility.Visible : Visibility.Collapsed;
        }
        _gateCountdown = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _gateCountdown.Tick += (_, _) => Tick();
        _gateCountdown.Start();
        Tick();
    }

    private void StopGateCountdown()
    {
        _gateCountdown?.Stop();
        _gateCountdown = null;
    }

    /// <param name="signIn">A password or Windows Hello sign-in: show Personal (owner point 1). Creating or opening an
    /// unprotected document from the start window shows that document.</param>
    private async Task FinishGateAsync(DocumentClient doc, bool signIn = false)
    {
        HideGate();
        // Owner point 1: sign-in unlocks the document and shows Personal; the document stays unlocked in the
        // Documents menu (as on Native Mac #698).
        await ShowDocumentAsync(signIn ? null : doc);
    }

    /// <summary>After a lock: the Unlock half covers the window again for the document that was shown.</summary>
    private void GateAfterLock(DocumentClient? doc)
    {
        if (!GateEnabled || doc is null || !doc.Info.Locked) return;
        ShowUnlock(doc, askHello: false);
    }

    // ---- Welcome, Open, Missing ----

    /// <summary>No document picked: first run (no recents) welcomes with New document; otherwise asks for a pick.
    /// The gate's accessible name is "Welcome" in both, as before.</summary>
    private void ShowWelcome(string? problem)
    {
        StopGateCountdown();
        _startCreating = false;
        _startSelected = null;
        var error = DocError();
        if (problem is not null) Fail(error, problem);
        var first = StartRecents().Count == 0;
        var newDoc = GateButton("New document", (_, _) => ShowCreate(), accent: true);
        newDoc.MinHeight = 36;
        AutomationProperties.SetName(newDoc, "New document");
        var pane = Stack(
            first ? StartTitle("Welcome to Gantry", "A document holds folders, connections and credentials, encrypted.")
                  : StartTitle("No document selected", "Pick one on the left, or start another."),
            newDoc,
            error);
        pane.Spacing = Ui.Double("Space16");
        ShowGate(pane, "Welcome");
    }

    /// <summary>An unprotected recent: no password, so Open is the one action.</summary>
    private void ShowOpenPane(RecentDocumentDto r)
    {
        StopGateCountdown();
        _startCreating = false;
        _startSelected = r.Path;
        var name = RecentName(r);
        var open = GateButton("Open", (_, _) => GateOpen(r.Path), accent: true);
        open.MinHeight = 36;
        AutomationProperties.SetName(open, "Open " + name);
        var pane = Stack(StartTitle(name, Join("No password", Connections(r.ConnectionCount), r.LastOpenedAt is { } s ? "last opened " + Ago(s) : null)), open);
        pane.Spacing = Ui.Double("Space16");
        ShowGate(pane, "Welcome");
    }

    /// <summary>A recent whose file moved, was deleted or cannot be read: say which, offer Locate and Remove.</summary>
    private void ShowMissingPane(RecentDocumentDto r)
    {
        StopGateCountdown();
        _startCreating = false;
        _startSelected = r.Path;
        var name = RecentName(r);
        var file = Path.GetFileName(r.Path);
        var what = Ui.Text(File.Exists(r.Path) ? $"“{file}” can’t be read: damaged or not a Gantry document." : $"“{file}” was moved or deleted.", "BodyTextStyle");
        what.TextWrapping = TextWrapping.Wrap;
        what.Foreground = Ui.Brush(RootGrid, "SystemFillColorCautionBrush");
        var locate = GateButton("Locate…", (_, _) => _ = GateOpenAsync(Path.GetDirectoryName(r.Path)), accent: true);
        AutomationProperties.SetName(locate, "Locate " + name);
        var remove = GateButton("Remove from Recents", (_, _) => RemoveRecent(r));
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        locate.HorizontalAlignment = remove.HorizontalAlignment = HorizontalAlignment.Left;
        buttons.Children.Add(locate);
        buttons.Children.Add(remove);
        var pane = Stack(StartTitle(name, r.Path), what, buttons);
        pane.Spacing = Ui.Double("Space16");
        ShowGate(pane, "Welcome");
    }

    /// <summary>Forget a document in Recents (the file stays), then the welcome half.</summary>
    private void RemoveRecent(RecentDocumentDto r)
    {
        try { DocumentClient.ForgetRecent(SessionDataDir, r.Path); }
        catch (BastionException ex) { ShowWelcome(ex.Message); return; }
        ShowWelcome(null);
    }

    private async Task GateOpenAsync(string? folder)
    {
        var start = folder is not null && Directory.Exists(folder) ? folder : DocumentsFolder;
        var path = PathBox(start + Path.DirectorySeparatorChar);
        var error = DocError();
        if (!await ShowModal("Open document", Stack(path.Row, error), primary: "Open", cancel: "Cancel", focus: path.Box,
                validate: () => File.Exists(path.Box.Text) || Fail(error, "No file at that path."))) return;
        GateOpen(path.Box.Text);
    }

    // ---- New document, in place of the right half ----

    /// <summary>Name, file, password + confirm with strength, and Windows Hello (policy note when it is off).</summary>
    private void ShowCreate()
    {
        StopGateCountdown();
        _startCreating = true;
        var name = new TextBox { Header = "Name", Text = "My Connections" };
        AutomationProperties.SetName(name, "Document name");
        var path = PathBox(Path.Combine(DocumentsFolder, "My Connections." + DocumentExtension));
        name.TextChanged += (_, _) => path.Box.Text = Path.Combine(Path.GetDirectoryName(path.Box.Text) ?? DocumentsFolder, name.Text.Trim() + "." + DocumentExtension);
        var location = Stack(Ui.Text("Location", "BodyTextStyle"), path.Row);
        location.Spacing = Ui.Double("Space4");
        var password = new PasswordBox { Header = "Password" };
        AutomationProperties.SetName(password, "Document password");
        var confirm = new PasswordBox { Header = "Confirm password" };
        AutomationProperties.SetName(confirm, "Confirm document password");
        var meter = new ProgressBar { Maximum = 3, Value = 0, MinHeight = 3 };
        AutomationProperties.SetName(meter, "Password strength");
        var strength = Ui.Text(PasswordStrength(""), "CaptionSecondaryTextStyle");
        AutomationProperties.SetAutomationId(strength, "PasswordStrength");
        password.PasswordChanged += (_, _) => { strength.Text = PasswordStrength(password.Password); meter.Value = StrengthScore(password.Password); };
        var hello = new CheckBox { Content = "Unlock with Windows Hello", Visibility = DocumentClient.BiometricUnlockAllowed ? Visibility.Visible : Visibility.Collapsed };
        AutomationProperties.SetName(hello, "Unlock with Windows Hello");
        var policyNote = PolicyNote();
        policyNote.Visibility = DocumentClient.BiometricUnlockAllowed ? Visibility.Collapsed : Visibility.Visible;
        var error = DocError();
        var cancel = new Button { Content = "Cancel" };
        cancel.Click += (_, _) => LeaveCreate();
        var create = new Button { Content = "Create", Style = Ui.Style("AccentButtonStyle") };
        AutomationProperties.SetName(create, "Create");
        create.Click += (_, _) => _ = GateCreateAsync(name, path.Box, password, confirm, hello, error);
        confirm.KeyDown += (_, e) => { if (e.Key == Windows.System.VirtualKey.Enter) { e.Handled = true; _ = GateCreateAsync(name, path.Box, password, confirm, hello, error); } };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(cancel);
        buttons.Children.Add(create);
        var strengthRow = Stack(meter, strength);
        strengthRow.Spacing = Ui.Double("Space4");
        // Cancel / Create stay pinned under the scroller, so a short window scrolls the fields, never the actions.
        var pane = Stack(StartTitle("New document", "Encrypted with its own password."), name, location, password, strengthRow, confirm, hello, policyNote, error);
        ShowGate(pane, "New document", buttons);
        name.Loaded += (_, _) => { name.Focus(FocusState.Programmatic); name.SelectAll(); };
    }

    /// <summary>The create form's Cancel (Esc): back to the selected document's unlock, or the welcome.</summary>
    private void LeaveCreate()
    {
        _startCreating = false;
        var last = StartRecents().FirstOrDefault(r => r.Present);
        if (last is not null) GateOpen(last.Path); else ShowWelcome(null);
    }

    private Task GateCreateAsync(TextBox name, TextBox path, PasswordBox password, PasswordBox confirm, CheckBox hello, TextBlock error)
    {
        if (name.Text.Trim().Length == 0) { Fail(error, "Give the document a name."); return Task.CompletedTask; }
        if (File.Exists(path.Text)) { Fail(error, "A file with that name already exists."); return Task.CompletedTask; }
        if (password.Password.Length == 0) { Fail(error, "Choose a password."); return Task.CompletedTask; }
        if (password.Password != confirm.Password) { Fail(error, "Passwords do not match."); return Task.CompletedTask; }
        DocumentClient? created = null;
        try
        {
            created = DocumentClient.Create(name.Text.Trim(), SessionDataDir);
            created.SetPassword(password.Password);
            if (hello.IsChecked == true) created.SetHello(true);
            created.Save(path.Text);
        }
        catch (BastionException ex) { created?.Dispose(); Fail(error, ex.Message); return Task.CompletedTask; }
        finally { password.Password = ""; confirm.Password = ""; }
        _documents.Add(created);
        return FinishGateAsync(created);
    }

    private static int StrengthScore(string pw)
    {
        if (pw.Length == 0) return 0;
        var classes = new[] { pw.Any(char.IsLower), pw.Any(char.IsUpper), pw.Any(char.IsDigit), pw.Any(c => !char.IsLetterOrDigit(c)) }.Count(b => b);
        return Math.Min(3, (pw.Length >= 16 ? 2 : pw.Length >= 10 ? 1 : 0) + (classes >= 3 ? 1 : 0));
    }

    /// <summary>The document file extension (one place, so the product rename changes it once).</summary>
    private const string DocumentExtension = "bastion";

    /// <summary>A rough hint from length and character classes; nothing is enforced from it.</summary>
    internal static string PasswordStrength(string pw)
    {
        if (pw.Length == 0) return "Strength: —";
        var classes = new[] { pw.Any(char.IsLower), pw.Any(char.IsUpper), pw.Any(char.IsDigit), pw.Any(c => !char.IsLetterOrDigit(c)) }.Count(b => b);
        var score = (pw.Length >= 16 ? 2 : pw.Length >= 10 ? 1 : 0) + (classes >= 3 ? 1 : 0);
        return "Strength: " + score switch { >= 3 => "strong", 2 => "good", 1 => "fair", _ => "weak" };
    }
}
