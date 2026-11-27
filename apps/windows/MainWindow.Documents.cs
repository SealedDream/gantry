using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Royal TS-style documents (`.bastion`, core C ABI 27). More › Documents lists the Personal library and every open
// document; picking one shows its tree, and every existing tree action then edits that document (the core saves each
// change into its file). Password-protected documents open locked; Windows Hello unlock is offered when the document
// has it on. Lock Credentials, idle lock and screen lock also lock every protected document and go back to Personal.
public sealed partial class MainWindow
{
    private readonly List<DocumentClient> _documents = [];
    private DocumentClient? _shownDocument;

    /// <summary>Folder the Open/Save As boxes start in.</summary>
    private static string DocumentsFolder => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

    private void BuildDocumentsMenu()
    {
        FillDocumentsMenu(DocumentsMenu.Items);
        if (CompactLibraryFlyout is not null) FillDocumentsMenu(CompactLibraryFlyout.Items, switcherFirst: true);
        UpdateDocumentSwitcher();
    }

    /// <summary>
    /// Owner points 28, W1-W4: one kind of library. Personal is Personal.bastion opened with the device key; it is listed
    /// once (by its own name) next to the other open documents, never also as a locked document of its own.
    /// </summary>
    private void FillDocumentsMenu(IList<MenuFlyoutItemBase> items, bool switcherFirst = false)
    {
        items.Clear();
        if (switcherFirst) { AddShowItems(items); items.Add(new MenuFlyoutSeparator()); }
        items.Add(DocItem("New Document…", (_, _) => _ = NewDocumentAsync(), enabled: !_demo));
        items.Add(DocItem("Open Document…", (_, _) => _ = OpenDocumentAsync(null), enabled: !_demo));
        var recent = new MenuFlyoutSubItem { Text = "Open Recent" };
        AutomationProperties.SetName(recent, "Open Recent");
        IReadOnlyList<string> paths = [];
        try { paths = _demo ? [] : DocumentClient.Recent(SessionDataDir); }
        catch (BastionException) { /* an unreadable list shows as empty */ }
        foreach (var path in paths.Where(p => !IsPersonalPath(p)).Take(10))
        {
            var p = path;
            recent.Items.Add(DocItem(Path.GetFileName(p), (_, _) => _ = OpenDocumentAsync(p), tooltip: p));
        }
        if (recent.Items.Count == 0) recent.Items.Add(new MenuFlyoutItem { Text = "No recent documents", IsEnabled = false });
        items.Add(recent);
        if (!switcherFirst) { items.Add(new MenuFlyoutSeparator()); AddShowItems(items); }

        var shown = _shownDocument;
        items.Add(new MenuFlyoutSeparator());
        items.Add(DocItem("Save Document As…", (_, _) => _ = SaveDocumentAsAsync(shown!), enabled: shown is not null));
        items.Add(DocItem("Document Properties…", (_, _) => _ = DocumentPropertiesAsync(shown!), enabled: shown is not null));
        items.Add(DocItem("Lock Document", (_, _) => LockDocument(shown!), enabled: shown?.Info.Protected == true));
        items.Add(DocItem("Close Document", (_, _) => _ = CloseDocumentAsync(shown!), enabled: shown is not null));
        items.Add(new MenuFlyoutSeparator());
        items.Add(DocItem($"Import Document into {PersonalName}…", (_, _) => _ = ImportDocumentAsync(), enabled: !_demo));
    }

    private void AddShowItems(IList<MenuFlyoutItemBase> items)
    {
        items.Add(ShowItem(PersonalName, null, _shownDocument is null));
        foreach (var doc in _documents.Where(d => !IsPersonalPath(d.Info.Path))) items.Add(ShowItem(Label(doc), doc, doc == _shownDocument));
        if (_shownDocument is null && App.Personal is not null && !_demo)
            items.Add(DocItem($"Rename {PersonalName}…", (_, _) => _ = RenamePersonalAsync()));
    }

    /// <summary>Owner point 33: Personal can be renamed (the name inside the document; the file keeps its name).</summary>
    private async Task RenamePersonalAsync()
    {
        if (App.Personal is not { } personal) return;
        var name = new TextBox { Header = "Name", Text = PersonalName };
        AutomationProperties.SetName(name, "Library name");
        var error = DocError();
        if (!await ShowModal("Rename library", Stack(name, error), primary: "Rename", cancel: "Cancel", focus: name, validate: () =>
            {
                if (name.Text.Trim().Length == 0) return Fail(error, "Give the library a name.");
                try { personal.Rename(name.Text.Trim()); return true; }
                catch (BastionException ex) { return Fail(error, ex.Message); }
            })) return;
        BuildDocumentsMenu();
        Announce($"Renamed to {PersonalName}");
    }

    /// <summary>Personal's own name (it can be renamed, owner point 33).</summary>
    private static string PersonalName
    {
        get
        {
            try { return App.Personal?.Info().Name is { Length: > 0 } n ? n : "Personal"; }
            catch (BastionException) { return "Personal"; }
        }
    }

    /// <summary>The file is Personal.bastion: it opens with the device key through <see cref="App.Personal"/>, never
    /// as a password document (W2, W4).</summary>
    private static bool IsPersonalPath(string? path)
    {
        if (App.Personal is null || string.IsNullOrEmpty(path)) return false;
        try { return string.Equals(Path.GetFullPath(path), Path.GetFullPath(PersonalDocument.DefaultPath), StringComparison.OrdinalIgnoreCase); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }

    /// <summary>The title-bar switcher names the library that is open (W1, W3); its menu switches.</summary>
    private void UpdateDocumentSwitcher() => UpdateCompactLibrary(_shownDocument is { } d ? Label(d) : PersonalName);

    private static MenuFlyoutItem DocItem(string text, RoutedEventHandler click, bool enabled = true, string? tooltip = null)
    {
        var item = new MenuFlyoutItem { Text = text, IsEnabled = enabled };
        AutomationProperties.SetName(item, text.TrimEnd('…'));
        if (tooltip is not null) ToolTipService.SetToolTip(item, tooltip);
        item.Click += click;
        return item;
    }

    private RadioMenuFlyoutItem ShowItem(string text, DocumentClient? doc, bool current)
    {
        var item = new RadioMenuFlyoutItem { Text = text, GroupName = "shown-document", IsChecked = current };
        AutomationProperties.SetName(item, "Show " + text);
        item.Click += (_, _) => _ = ShowByHandAsync(doc);
        return item;
    }

    /// <summary>LIB-01: a library shown from the switcher heads Recents, so a restart opens it. Lock, idle and screen
    /// lock go through <see cref="ShowDocumentAsync"/> directly and never count.</summary>
    private async Task ShowByHandAsync(DocumentClient? doc)
    {
        await ShowDocumentAsync(doc);
        if (_shownDocument != doc || _demo) return; // the unlock was cancelled or failed
        try
        {
            if (doc is null) App.Personal?.NoteShown();
            else doc.NoteOpened();
        }
        catch (BastionException ex) { Announce("Recent documents could not be updated: " + ex.Message); }
    }

    private static string Label(DocumentClient doc)
    {
        var info = doc.Info;
        return info.Locked ? info.Name + " (locked)" : info.Name;
    }

    /// <summary>
    /// Where the shown library's connection history and recents live (owner spec §5, Codex Y02): the open document's own
    /// state folder, so two documents never share last-use, errors or removals even when their connection ids match
    /// (a copied file). Personal keeps the folder next to its library; existing history stays with Personal.
    /// </summary>
    private string? _historyDir;

    private string HistoryDir => _historyDir ?? SessionDataDir;

    private string? DocumentStateDir(DocumentClient doc)
    {
        try { return doc.StateDir(); }
        catch (BastionException ex)
        {
            Announce("This document's history could not be opened: " + ex.Message);
            return null;
        }
    }

    /// <summary>Show <paramref name="doc"/>'s tree (null = Personal), unlocking it first when needed.</summary>
    private async Task ShowDocumentAsync(DocumentClient? doc)
    {
        if (doc is not null && doc.Info.Locked && !await UnlockDocumentAsync(doc)) { BuildDocumentsMenu(); return; }
        var library = doc is null ? _personal : doc.Library;
        if (library is null) { Announce("The document is locked"); BuildDocumentsMenu(); return; }
        if (doc is not null) await AskDocumentOriginAsync(doc); // A1-CORE-01-FU5: before the tree is shown
        _shownDocument = doc;
        _library = library;
        _historyDir = doc is null ? null : DocumentStateDir(doc);
        var name = doc?.Info.Name;
        Title = name is null ? "Gantry" : $"{name} — Gantry";
        Reload(selectId: null);
        PurgeDeleted();
        BuildDocumentsMenu();
        Announce($"Showing {name ?? PersonalName}");
    }

    private async Task NewDocumentAsync()
    {
        var name = new TextBox { Header = "Name", Text = "New Document" };
        AutomationProperties.SetName(name, "Document name");
        var path = PathBox(Path.Combine(DocumentsFolder, "New Document.gantry"));
        var password = new PasswordBox { Header = "Password (empty = not protected)" };
        AutomationProperties.SetName(password, "Document password");
        var error = DocError();
        name.TextChanged += (_, _) => path.Box.Text = Path.Combine(Path.GetDirectoryName(path.Box.Text) ?? DocumentsFolder, name.Text.Trim() + ".gantry");
        var body = Stack(name, path.Row, password, Ui.Text("Credentials can only be saved in a protected document.", "CaptionTextStyle"), error);
        DocumentClient? created = null;
        var ok = await ShowModal("New document", body, primary: "Create", cancel: "Cancel", focus: name, validate: () =>
        {
            if (name.Text.Trim().Length == 0) return Fail(error, "Give the document a name.");
            if (File.Exists(path.Box.Text)) return Fail(error, "A file with that name already exists.");
            try
            {
                created = DocumentClient.Create(name.Text.Trim(), SessionDataDir);
                if (password.Password.Length > 0) created.SetPassword(password.Password);
                created.Save(path.Box.Text);
                return true;
            }
            catch (BastionException ex) { created?.Dispose(); created = null; return Fail(error, ex.Message); }
            finally { password.Password = ""; }
        });
        if (!ok || created is null) return;
        _documents.Add(created);
        await ShowDocumentAsync(created);
    }

    private async Task OpenDocumentAsync(string? known)
    {
        var target = known;
        if (target is null)
        {
            var path = PathBox(DocumentsFolder + Path.DirectorySeparatorChar);
            var error = DocError();
            if (!await ShowModal("Open document", Stack(path.Row, error), primary: "Open", cancel: "Cancel", focus: path.Box,
                    validate: () => File.Exists(path.Box.Text) || Fail(error, "No file at that path."))) return;
            target = path.Box.Text;
        }
        var full = Path.GetFullPath(target);
        if (IsPersonalPath(full)) { await ShowDocumentAsync(null); return; }
        if (_documents.FirstOrDefault(d => d.Info.Path is { } p && string.Equals(Path.GetFullPath(p), full, StringComparison.OrdinalIgnoreCase)) is { } open)
        {
            await ShowDocumentAsync(open);
            return;
        }
        DocumentClient doc;
        try { doc = DocumentClient.Open(full, SessionDataDir); }
        catch (BastionException ex)
        {
            await ShowModal("Could not open the document", Ui.Text(ex.Message, "BodyTextStyle"), primary: "OK", cancel: null);
            return;
        }
        _documents.Add(doc);
        await ShowDocumentAsync(doc);
    }

    /// <summary>
    /// WIN-SINGLE-UNLOCK: one sheet offering Windows Hello (when the document has it and policy allows) and the password.
    /// Windows Hello is asked once as the sheet opens; Cancel or a refusal leaves the same sheet, never a second prompt.
    /// </summary>
    private async Task<bool> UnlockDocumentAsync(DocumentClient doc)
    {
        var info = doc.Info;
        // A password-only managed policy hides Windows Hello; the core refuses it anyway (ABI 82).
        var hello = info.Biometric && DocumentClient.BiometricUnlockAllowed;
        var password = new PasswordBox { Header = "Password" };
        AutomationProperties.SetName(password, "Document password");
        var error = DocError();
        var body = Stack(password, error);
        if (hello)
        {
            var helloButton = new Button { Content = "Unlock with Windows Hello", HorizontalAlignment = HorizontalAlignment.Stretch };
            AutomationProperties.SetName(helloButton, "Unlock with Windows Hello");
            helloButton.Click += (_, _) => _ = SheetHelloAsync(doc, error, password);
            body.Children.Insert(0, helloButton);
        }
        var shown = ShowModal($"Unlock {info.Name}", body, primary: "Unlock", cancel: "Cancel", focus: password, validate: () =>
        {
            try { doc.Unlock(password.Password); return true; }
            catch (BastionException ex) { return Fail(error, ex.Message); }
            finally { password.Password = ""; }
        });
        if (hello) _ = SheetHelloAsync(doc, error, password);
        return await shown || !doc.Info.Locked;
    }

    /// <summary>The unlock sheet's Windows Hello: success closes the sheet; Cancel keeps it quietly; a refusal says why.</summary>
    private async Task SheetHelloAsync(DocumentClient doc, TextBlock error, PasswordBox password)
    {
        var sheet = _modal;
        var confirmedBefore = _helloConfirmed;
        var why = await UnlockDocumentWithHelloAsync(doc);
        if (_modal != sheet)
        {
            // The user cancelled the sheet while Windows Hello was up: a late Verified must not unlock anything.
            if (why is null)
            {
                _helloConfirmed = confirmedBefore;
                try { doc.Lock(); } catch (BastionException ex) { Announce(ex.Message); }
            }
            return;
        }
        if (why is null) { CloseModal(true); return; }
        if (why.Length > 0) Fail(error, why);
        password.Focus(FocusState.Programmatic);
    }

    private async Task SaveDocumentAsAsync(DocumentClient doc)
    {
        var info = doc.Info;
        var path = PathBox(info.Path ?? Path.Combine(DocumentsFolder, info.Name + ".gantry"));
        var error = DocError();
        if (!await ShowModal("Save document as", Stack(path.Row, error), primary: "Save", cancel: "Cancel", focus: path.Box, validate: () =>
            {
                try { doc.Save(path.Box.Text); return true; }
                catch (BastionException ex) { return Fail(error, ex.Message); }
            })) return;
        if (doc == _shownDocument) await ShowDocumentAsync(doc); // the tree now reads from the new file
    }

    private async Task DocumentPropertiesAsync(DocumentClient doc)
    {
        var info = doc.Info;
        var name = new TextBox { Header = "Name", Text = info.Name };
        AutomationProperties.SetName(name, "Document name");
        var password = new PasswordBox { Header = info.Protected ? "New password (empty = keep)" : "Password (empty = not protected)" };
        AutomationProperties.SetName(password, "Document password");
        var removePassword = new CheckBox { Content = "Remove the password", Visibility = info.Protected ? Visibility.Visible : Visibility.Collapsed };
        var helloAllowed = DocumentClient.BiometricUnlockAllowed;
        var hello = new ToggleSwitch { Header = "Unlock with Windows Hello", IsOn = info.Biometric && helloAllowed, IsEnabled = info.Protected && helloAllowed };
        AutomationProperties.SetName(hello, "Unlock with Windows Hello");
        if (!helloAllowed) AutomationProperties.SetHelpText(hello, PasswordOnlyNote);
        var facts = Ui.Text($"{(info.Protected ? "Protected" : "Not protected")} · {Count(info.Credentials, "credential")} · {info.Path ?? "not saved"}", "CaptionTextStyle");
        var error = DocError();
        var ok = await ShowModal("Document properties", Stack(name, password, removePassword, hello, facts, error), primary: "Save", cancel: "Cancel", focus: name, validate: () =>
        {
            if (name.Text.Trim().Length == 0) return Fail(error, "Give the document a name.");
            if (removePassword.IsChecked == true && info.Credentials > 0) return Fail(error, "Remove its credentials first: they may only live in a protected document.");
            try
            {
                if (name.Text.Trim() != info.Name) doc.Rename(name.Text.Trim());
                if (removePassword.IsChecked == true) doc.SetPassword(null);
                else if (password.Password.Length > 0) doc.SetPassword(password.Password);
                if (helloAllowed && hello.IsOn != info.Biometric && doc.Info.Protected) doc.SetHello(hello.IsOn);
                if (doc.Info.Path is not null) doc.Save();
                return true;
            }
            catch (BastionException ex) { return Fail(error, ex.Message); }
            finally { password.Password = ""; }
        });
        if (!ok) return;
        if (doc == _shownDocument) Title = $"{doc.Info.Name} — Gantry";
        BuildDocumentsMenu();
    }

    private void LockDocument(DocumentClient doc)
    {
        var shown = doc == _shownDocument;
        if (shown && !GateEnabled) _ = ShowDocumentAsync(null);
        try { doc.Lock(); Announce($"{doc.Info.Name} locked"); }
        catch (BastionException ex) { Announce(ex.Message); }
        CloseSessionsIfSet();
        if (shown) GateAfterLock(doc);
        BuildDocumentsMenu();
    }

    /// <summary>
    /// Close sessions on lock (Security setting, off by default): as on the Mac, every session tab closes when a document
    /// locks; off keeps them running behind the unlock screen.
    /// </summary>
    private void CloseSessionsIfSet()
    {
        if (SettingValue(DocumentClient.CloseSessionsOnLockSettingId) != "true") return;
        var count = _tabs.Count;
        foreach (var tab in _tabs.ToList()) CloseTab(tab);
        if (TestHooks.LockTrace is { } path)
        {
            try { File.AppendAllText(path, $"sessions closed count={count} left={_tabs.Count}\n"); }
            catch (IOException) { }
        }
    }

    private bool HasUnlockedProtectedDocument() => _documents.Any(d => d.Info is { Protected: true, Locked: false });

    /// <summary>A document-only lock (idle limit, sleep, screen lock) with its reason, for the BASTION_LOCK_TRACE seam.</summary>
    private void LockDocumentsFor(AutoLockReason reason)
    {
        var count = _documents.Count(d => d.Info is { Protected: true, Locked: false });
        LockDocuments();
        if (TestHooks.LockTrace is { } path)
        {
            try { File.AppendAllText(path, $"documents reason={reason} count={count}\n"); }
            catch (IOException) { }
        }
    }

    /// <summary>Lock Credentials, idle and screen lock: every protected document locks and Personal shows.</summary>
    private void LockDocuments()
    {
        var unlocked = _documents.Where(d => d.Info is { Protected: true, Locked: false }).ToList();
        if (unlocked.Count == 0) return;
        var shown = _shownDocument is { } s && unlocked.Contains(s) ? s : null;
        if (shown is not null && !GateEnabled) _ = ShowDocumentAsync(null);
        foreach (var doc in unlocked)
        {
            try { doc.Lock(); }
            catch (BastionException ex) { Announce(ex.Message); }
        }
        CloseSessionsIfSet();
        GateAfterLock(shown);
        BuildDocumentsMenu();
    }

    private async Task CloseDocumentAsync(DocumentClient doc)
    {
        var info = doc.Info;
        if (info.Path is null && info.Dirty &&
            !await ShowModal($"Close {info.Name}?", Ui.Text("It was never saved; its connections will be lost.", "BodyTextStyle"),
                primary: "Close without saving", cancel: "Cancel", focusCancel: true)) return;
        if (doc == _shownDocument) await ShowDocumentAsync(null);
        _documents.Remove(doc);
        doc.Dispose();
        BuildDocumentsMenu();
        Announce($"{info.Name} closed");
        // Document-first: with no document shown, Welcome covers the window rather than Personal.
        if (GateEnabled && _shownDocument is null) ShowWelcome(null);
    }

    private async Task ImportDocumentAsync()
    {
        var path = PathBox(DocumentsFolder + Path.DirectorySeparatorChar);
        var password = new PasswordBox { Header = "Password (if the document has one)" };
        AutomationProperties.SetName(password, "Document password");
        var error = DocError();
        DocumentImportDto? preview = null;
        try
        {
            if (!await ShowModal($"Import document into {PersonalName}", Stack(path.Row, password, Ui.Text("Secrets never come along.", "CaptionTextStyle"), error),
                    primary: "Preview", cancel: "Cancel", focus: path.Box, validate: () =>
                    {
                        try { preview = DocumentClient.ImportIntoLibrary(_personal, path.Box.Text, password.Password, apply: false, SessionDataDir); return true; }
                        catch (BastionException ex) { return Fail(error, ex.Message); }
                        catch (Exception ex) when (ex is not OutOfMemoryException)
                        {
                            CrashLog.Write(ex); // not a core error: keep the detail, still say what went wrong
                            return Fail(error, $"Could not read the document ({ex.GetType().Name}: {ex.Message})");
                        }
                    })) return;
            var p = preview!;
            var summary = $"{Count(p.Connections, "connection")} from {p.SourceName}" +
                          (p.Duplicates.Count > 0 ? $", {p.Duplicates.Count} already here (skipped)" : "") +
                          (p.CredentialsDropped > 0 ? $", {Count(p.CredentialsDropped, "credential")} left out" : "");
            if (!await ShowModal("Import?", Ui.Text(summary, "BodyTextStyle"), primary: "Import", cancel: "Cancel")) return;
            var done = DocumentClient.ImportIntoLibrary(_personal, path.Box.Text, password.Password, apply: true, SessionDataDir);
            if (_shownDocument is null) Reload(selectId: null);
            Announce($"Imported {Count(done.Connections, "connection")}" + (done.Folder is { } f ? $" into {f}" : ""));
        }
        catch (BastionException ex) { await ShowModal("Import failed", Ui.Text(ex.Message, "BodyTextStyle"), primary: "OK", cancel: null); }
        finally { password.Password = ""; }
    }

    private void DisposeDocuments()
    {
        foreach (var doc in _documents) doc.Dispose();
        _documents.Clear();
    }

    private static string Count(int n, string noun) => $"{n} {noun}{(n == 1 ? "" : "s")}";

    // ---- small form helpers ----

    /// <summary>A path box with Browse…; the box is typeable so UI tests never need the file picker.</summary>
    private (TextBox Box, Grid Row) PathBox(string initial)
    {
        var box = new TextBox { Header = "File", Text = initial };
        AutomationProperties.SetName(box, "Document file");
        var browse = new Button { Content = "Browse…", VerticalAlignment = VerticalAlignment.Bottom };
        browse.Click += async (_, _) =>
        {
            var picker = new Windows.Storage.Pickers.FileOpenPicker();
            picker.FileTypeFilter.Add(".gantry");
            picker.FileTypeFilter.Add(".bastion"); // documents made before the rename
            WinRT.Interop.InitializeWithWindow.Initialize(picker, Hwnd);
            if (await picker.PickSingleFileAsync() is { } file) box.Text = file.Path;
        };
        var row = new Grid { ColumnSpacing = Ui.Double("Space8") };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.Children.Add(box);
        Grid.SetColumn(browse, 1);
        row.Children.Add(browse);
        return (box, row);
    }

    private static TextBlock DocError()
    {
        var t = Ui.Text("", "BodyTextStyle");
        t.TextWrapping = TextWrapping.Wrap;
        t.Visibility = Visibility.Collapsed;
        AutomationProperties.SetLiveSetting(t, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Assertive);
        return t;
    }

    private static bool Fail(TextBlock error, string message)
    {
        error.Text = string.IsNullOrWhiteSpace(message) ? "Something went wrong. Check the file and password." : message;
        error.Visibility = Visibility.Visible;
        return false;
    }

    private static StackPanel Stack(params UIElement[] children)
    {
        var s = new StackPanel { Spacing = Ui.Double("Space12") };
        foreach (var c in children) s.Children.Add(c);
        return s;
    }
}
