using System.Globalization;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Windows.System;

namespace Bastion.Shell;

// Workspaces with split layouts (core/src/workspace.rs over C ABI 10 and 16), the Workspace Manager page, Quick Connect
// (an unsaved one-connection library from the core) and the command palette ranked by the core (core/src/palette.rs).
// Reopening a workspace goes through the normal Connect dialog per tab: nothing logs in on its own.
public sealed partial class MainWindow
{
    private WorkspaceStore Workspaces => new(SessionDataDir);
    /// <summary>Quick Connect libraries behind open tabs; in memory only, released with the window.</summary>
    private readonly List<LibraryClient> _quickLibraries = new();
    /// <summary>The workspace last opened or saved, offered as the name for Save Current Layout.</summary>
    private string? _currentWorkspace;

    /// <summary>
    /// The saved connection a tab reopens: an SSH tab's connection, or the library connection a web, RDP or VNC tab opened
    /// (PAR-6, as on the Mac). Null for local shells and unsaved (Quick Connect, direct) tabs.
    /// </summary>
    private string? SavedConnectionOf(WorkspaceTab t) =>
        t.ConnectionId ?? ((t.Rdp is not null || t.Web is not null) && t.HostColorId is { } id && FindItem(_roots, id) is not null ? id : null);

    /// <summary>The tabs of saved connections that a workspace or session restore reopens, in tab order.</summary>
    private List<WorkspaceTab> SavableTabs() => _tabs.Where(t => SavedConnectionOf(t) is not null).ToList();

    /// <summary>The open tabs of saved connections (SSH with split layouts; web, RDP and VNC as one tab each). Local shells are not saved.</summary>
    private List<WorkspaceTabDto> CurrentLayout() =>
        SavableTabs()
            .Select(t => new WorkspaceTabDto(SavedConnectionOf(t)!, t.Files is null ? "terminal" : "files", t.Panes?.Layout() ?? [], t.Group))
            .ToList();

    /// <summary>Definitions of the tab groups that <paramref name="tabs"/> use, as the grouped save expects (Codex Y03).</summary>
    private string GroupsJsonFor(IEnumerable<WorkspaceTabDto> tabs)
    {
        var used = tabs.Select(t => t.Group).Where(g => g is not null).ToHashSet();
        return new System.Text.Json.Nodes.JsonArray(_groups.OfType<System.Text.Json.Nodes.JsonObject>()
            .Where(g => used.Contains((string?)g["id"])).Select(g => (System.Text.Json.Nodes.JsonNode)g.DeepClone()).ToArray()).ToJsonString();
    }

    /// <summary>Save Current Layout: the open tabs of saved connections with their split panes and ratios; the same name updates that workspace.</summary>
    internal async Task SaveWorkspaceAsync()
    {
        var tabs = CurrentLayout();
        if (_modal is not null || tabs.Count == 0) return;
        var name = new TextBox { Header = "Workspace name", Text = _currentWorkspace ?? "", PlaceholderText = "For example: Acme on-call", IsSpellCheckEnabled = false };
        var error = new FieldMessage();
        name.TextChanged += (_, _) => error.Hide();
        var splits = tabs.Count(t => t.Layout is { Count: > 0 });
        var note = Ui.Text($"Saves the {Plural(tabs.Count, "open tab")}{(splits > 0 ? $", {splits} with split panes," : "")} by connection only: no passwords or keys. Reopening asks to connect each one. Local shells are not saved. An existing workspace with this name is updated.", "CaptionTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        var body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { name, error.Element, note } };
        var withConnection = SavableTabs();
        var selected = _active is { } a ? Math.Max(0, withConnection.IndexOf(a)) : 0;
        bool Validate()
        {
            try
            {
                _currentWorkspace = Workspaces.SaveLayout(name.Text, tabs, selected, GroupsJsonFor(tabs)).Name;
                return true;
            }
            catch (BastionException ex)
            {
                error.Show(ex.Message);
                return false;
            }
        }
        await ShowModal("Save Current Layout", body, primary: "Save", cancel: "Cancel", validate: Validate, focus: name);
    }

    /// <summary>
    /// Reopen each tab of <paramref name="ws"/> through the normal Connect dialog, one after another, then rebuild its split
    /// panes (each a new shell on the same connection) with the saved ratios. Connections deleted since are reported.
    /// </summary>
    internal async Task OpenWorkspaceAsync(WorkspaceDto ws)
    {
        if (_modal is not null || _connecting) return;
        var (missing, failedSplits) = await OpenSavedTabsAsync(ws.Tabs, ws.Selected, ws.Groups);
        _currentWorkspace = ws.Name;
        try { Workspaces.MarkUsed(ws.Id); } catch (BastionException) { /* only the manager's order depends on it */ }
        await ReportUnopenedTabs(missing, failedSplits, ws.Tabs.Count, $"in “{ws.Name}”");
    }

    /// <summary>
    /// Open saved tabs (SSH, web, RDP, VNC) one after another through the normal connect flow (each may ask to sign in), rebuild their
    /// splits and file panels, and show the selected one. Shared by workspaces and session restore.
    /// </summary>
    private async Task<(int Missing, int FailedSplits)> OpenSavedTabsAsync(IReadOnlyList<WorkspaceTabDto> tabs, int selected,
        System.Text.Json.Nodes.JsonArray? groups = null)
    {
        var grouped = new List<(WorkspaceTab Tab, string Group)>();
        var missing = 0;
        var failedSplits = 0;
        var opened = new List<WorkspaceTab>();
        foreach (var saved in tabs)
        {
            if (FindItem(_roots, saved.Connection) is not { } item || !CanOpen(item) || IsLocal(item)) { missing++; continue; }
            // The previous tab's connect can leave a dialog open (W26: the saved-login question); ConnectAsync would
            // then skip this tab without a word.
            if (!await WaitForConnectSlotAsync()) Announce($"{item.Name} waits for the open dialog.");
            SelectItem(item.Id);
            var before = _tabs.Count;
            // PAR-6: web, RDP and VNC tabs reopen through their own connect, as on the Mac; only SSH has splits and files.
            if (IsSsh(item)) await ConnectAsync(item);
            else await RunAsync("connect", item);
            if (_tabs.Count <= before) continue;
            var tab = _tabs[^1];
            opened.Add(tab);
            if (saved.Group is { } g) grouped.Add((tab, g));
            if (!ApplyLayout(tab, saved.Layout ?? [])) failedSplits++;
            if (saved.Mode == "files") await ToggleFilesAsync(tab);
        }
        RestoreTabGroups(grouped, groups);
        if (selected >= 0 && selected < opened.Count) ActivateTab(opened[selected]);
        return (missing, failedSplits);
    }

    private async Task ReportUnopenedTabs(int missing, int failedSplits, int total, string where)
    {
        var problems = new List<string>();
        if (missing > 0) problems.Add($"{missing} of {total} connections {where} no longer exist in the library.");
        if (failedSplits > 0) problems.Add($"The split panes of {Plural(failedSplits, "tab")} could not all be opened.");
        if (problems.Count > 0) await ShowModal("Some tabs were not opened", ErrorText(string.Join(" ", problems)), primary: "OK", cancel: null);
    }

    /// <summary>Rebuild a tab's split panes from layout steps (pre-order). False when a pane could not be opened.</summary>
    private bool ApplyLayout(WorkspaceTab tab, IReadOnlyList<string> steps)
    {
        if (steps.Count == 0 || tab is not { Panes: { } panes, View: { } first }) return true;
        var at = 0;
        bool Build(TerminalView pane)
        {
            if (at >= steps.Count) return false;
            var step = steps[at++];
            if (step == "leaf") return true;
            var (axisName, ratioText) = step.Split(':') is [var a, var r] ? (a, r) : (step, "0.5");
            var axis = axisName == "right" ? SplitAxis.Right : SplitAxis.Down;
            var share = double.TryParse(ratioText, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : 0.5;
            TerminalView added;
            try
            {
                var size = pane.Session.Screen();
                added = MakePane(tab.StartLocal is { } start ? start() : pane.Session.OpenSibling(size.Cols, size.Rows), pane);
            }
            catch (Exception ex) when (ex is BastionException or ObjectDisposedException)
            {
                return false;
            }
            panes.Split(pane, added, axis, share);
            return Build(pane) & Build(added);
        }
        var ok = Build(first);
        first.Focus(FocusState.Programmatic);
        return ok;
    }

    /// <summary>A terminal pane with the app's paste confirmation, colour theme and exit banner.</summary>
    /// <remarks>A split of <paramref name="beside"/> keeps that pane's connection font.</remarks>
    private TerminalView MakePane(TerminalSession session, TerminalView? beside = null)
    {
        var view = NewTerminalView(session, beside?.FontOverride ?? TerminalFontOverride.None);
        view.Exited += (_, _) => view.SetBanner("Exited. Ctrl+Shift+W closes this pane.");
        return view;
    }

    // ---- Workspace Manager page ----

    internal void OpenWorkspaceManager()
    {
        _pageKind = "workspaces";
        ShowWorkspaceManagerPage();
    }

    private void ShowWorkspaceManagerPage()
    {
        var content = new StackPanel { Spacing = Ui.Double("Space8") };
        IReadOnlyList<WorkspaceDto> all;
        try { all = Workspaces.List(); }
        catch (BastionException ex) { all = []; content.Children.Add(CodedErrorText("APP", ex.Message)); }
        if (all.Count == 0)
        {
            var empty = Ui.Text("No saved workspaces. Open the tabs you work with, then use Workspaces › Save Current Layout, or Add to Workspace on a connection.", "BodySecondaryTextStyle");
            empty.TextWrapping = TextWrapping.Wrap;
            content.Children.Add(empty);
        }
        if (all.Count > 0)
            content.Children.Add(GroupedRows.Group(all.OrderByDescending(w => w.LastUsed ?? 0).ThenBy(w => w.Name, StringComparer.CurrentCultureIgnoreCase)
                .Select(ws => (UIElement)WorkspaceRow(ws))));
        var save = new Button { Content = "Save Current Layout…", IsEnabled = CurrentLayout().Count > 0 }.Quiet("GlyphAdd", "Save current layout");
        save.Click += (_, _) => _ = SaveFromManagerAsync();
        ShowPage(null, "Workspaces", content, save);
    }

    private Grid WorkspaceRow(WorkspaceDto ws)
    {
        var row = new Grid { ColumnSpacing = Ui.Double("Space8"), MinHeight = Ui.Double("ControlHeight") };
        row.ColumnDefinitions.Add(new ColumnDefinition());
        for (var i = 0; i < 4; i++) row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var splits = ws.Tabs.Count(t => t.Layout is { Count: > 0 });
        var used = ws.LastUsed is { } t ? "opened " + DateTimeOffset.FromUnixTimeSeconds(t).ToLocalTime().ToString("g", CultureInfo.CurrentCulture) : "never opened";
        var detail = $"{Plural(ws.Tabs.Count, "tab")}{(splits > 0 ? $", {splits} split" : "")} · {used}";
        row.Children.Add(new StackPanel { VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Text(ws.Name, "BodyTextStyle"), Ui.Text(detail, "CaptionSecondaryTextStyle") } });
        void Add(int column, Button b, string name)
        {
            AutomationProperties.SetName(b, $"{name} {ws.Name}");
            Grid.SetColumn(b, column);
            row.Children.Add(b);
        }
        var open = new Button { Content = "Open", Style = Ui.Style("AccentButtonStyle") };
        open.Click += (_, _) => { ClosePage(); _ = OpenWorkspaceAsync(ws); };
        Add(1, open, "Open");
        var rename = new Button { Content = "Rename…" }.Quiet("GlyphEdit", "Rename");
        rename.Click += (_, _) => _ = RenameWorkspaceAsync(ws);
        Add(2, rename, "Rename");
        var duplicate = new Button { Content = "Duplicate" }.Quiet("GlyphCopy", "Duplicate");
        duplicate.Click += (_, _) => WorkspaceChange(() => Workspaces.Duplicate(ws.Id), "Could not duplicate the workspace");
        Add(3, duplicate, "Duplicate");
        var delete = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphDelete", "IconSize") };
        ToolTipService.SetToolTip(delete, "Delete");
        delete.Click += (_, _) => _ = DeleteWorkspaceAsync(ws);
        Add(4, delete, "Delete");
        return row;
    }

    private void WorkspaceChange(Action change, string errorTitle)
    {
        try { change(); }
        catch (BastionException ex) { _ = ShowModal(errorTitle, CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); }
        if (_pageKind == "workspaces") ShowWorkspaceManagerPage();
    }

    private async Task SaveFromManagerAsync()
    {
        await SaveWorkspaceAsync();
        if (_pageKind == "workspaces") ShowWorkspaceManagerPage();
    }

    private async Task RenameWorkspaceAsync(WorkspaceDto ws)
    {
        var form = new RenameForm(ws.Name);
        if (!await ShowModal("Rename workspace", form.Body, primary: "Rename", cancel: "Cancel", validate: form.Validate, focus: form.Field) || form.NewName == ws.Name) return;
        WorkspaceChange(() =>
        {
            Workspaces.Rename(ws.Id, form.NewName);
            if (_currentWorkspace == ws.Name) _currentWorkspace = form.NewName;
        }, "Could not rename the workspace");
    }

    private async Task DeleteWorkspaceAsync(WorkspaceDto ws)
    {
        if (!await ShowModal($"Delete workspace “{ws.Name}”?", ErrorText("The connections and their settings stay in the library."), primary: "Delete", cancel: "Cancel", focusCancel: true)) return;
        WorkspaceChange(() =>
        {
            Workspaces.Remove(ws.Id);
            if (_currentWorkspace == ws.Name) _currentWorkspace = null;
        }, "Could not delete the workspace");
    }

    // ---- Quick Connect ----

    private void QuickConnect_Click(object sender, RoutedEventArgs e) => ShowQuickConnectFlyout();

    /// <summary>
    /// Preview (owner, Mac parity): Quick Connect as a small popover under the toolbar, as on the Mac
    /// (QuickConnect.swift), instead of a modal dialog. Enter connects; Esc or a click outside closes it.
    /// </summary>
    internal void ShowQuickConnectFlyout(string? prefill = null)
    {
        if (_modal is not null || _connecting) return;
        var address = new TextBox
        {
            Text = prefill ?? "", PlaceholderText = "user@host, rdp://host or https://…", IsSpellCheckEnabled = false,
            Width = Ui.Double("QuickConnectFieldWidth"),
        };
        AutomationProperties.SetName(address, "Quick Connect address");
        var error = new FieldMessage();
        var note = Ui.Text("Not saved to the library", "CaptionTextStyle");
        var flyout = new Flyout
        {
            Placement = FlyoutPlacementMode.Bottom,
            Content = new StackPanel { Spacing = Ui.Double("Space8"), Children = { address, error.Element, note } },
        };
        address.TextChanged += (_, _) => error.Hide();
        address.KeyDown += (_, e) =>
        {
            if (e.Key != VirtualKey.Enter) return;
            e.Handled = true;
            try
            {
                var quick = LibraryClient.QuickConnect(address.Text.Trim());
                flyout.Hide();
                _ = ConnectQuickAsync(quick);
            }
            catch (BastionException ex)
            {
                error.Show(ex.Message.StartsWith("invalid input: ", StringComparison.Ordinal) ? ex.Message["invalid input: ".Length..] : ex.Message);
            }
        };
        flyout.Opened += (_, _) => address.Focus(FocusState.Programmatic);
        // By name, so this works before and after the Mac-style header (#1075), which keeps only the sidebar SearchBox.
        // The search box is built in code after the first frame (WIN-COLD-LIGHT), so it is not looked up by name.
        var anchor = (_searchBox is { Visibility: Visibility.Visible, ActualWidth: > 0 } ? _searchBox : null)
            ?? VisibleNamed("ConnectButton", "SearchConnectButton") ?? (FrameworkElement)Content;
        flyout.ShowAt(anchor);
    }

    private FrameworkElement? VisibleNamed(params string[] names) =>
        names.Select(n => (Content as FrameworkElement)?.FindName(n) as FrameworkElement)
             .FirstOrDefault(e => e is { Visibility: Visibility.Visible, ActualWidth: > 0 });

    private async Task ConnectQuickAsync(LibraryClient quick)
    {
        if (TreeItem.Build(quick.Tree(), IconBrush).FirstOrDefault() is not { Connection: not null } item)
        {
            quick.Dispose();
            return;
        }
        _quickLibraries.Add(quick);
        if (!CanOpen(item))
        {
            await ShowModal("Cannot open " + item.Name, ErrorText($"{item.Connection.Protocol.ToUpperInvariant()} sessions cannot be opened in the Windows app yet."), primary: "OK", cancel: null);
            return;
        }
        await ConnectAsync(item, quick);
    }

    /// <summary>
    /// Quick Connect: an address the core parses into an unsaved, in-memory connection (nothing is added to the library),
    /// then the normal Connect flow, so the login prompt and host-key check still apply.
    /// </summary>
    internal async Task QuickConnectAsync(string? prefill = null)
    {
        if (_modal is not null || _connecting) return;
        var address = new TextBox { Header = "Address", Text = prefill ?? "", PlaceholderText = "user@host:port, rdp://host, https://example.com", IsSpellCheckEnabled = false };
        var error = new FieldMessage();
        address.TextChanged += (_, _) => error.Hide();
        var note = Ui.Text("Not saved to the library. SSH by default; rdp://, vnc:// and https:// pick the type.", "CaptionTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        LibraryClient? quick = null;
        bool Validate()
        {
            try
            {
                quick?.Dispose();
                quick = LibraryClient.QuickConnect(address.Text.Trim());
                return true;
            }
            catch (BastionException ex)
            {
                quick = null;
                error.Show(ex.Message.StartsWith("invalid input: ", StringComparison.Ordinal) ? ex.Message["invalid input: ".Length..] : ex.Message);
                return false;
            }
        }
        if (!await ShowModal("Quick Connect", new StackPanel { Spacing = Ui.Double("Space8"), Children = { address, error.Element, note } },
                primary: "Connect", cancel: "Cancel", validate: Validate, focus: address) || quick is null)
        {
            quick?.Dispose();
            return;
        }
        await ConnectQuickAsync(quick);
    }

    /// <summary>
    /// Enter in "Search or connect": the first connection the filter shows (tree order, Favorites and Application left out),
    /// or, when nothing matches, the text as a Quick Connect address. An address the core refuses opens the Quick Connect
    /// pop-over with the text, which shows the core's message on Enter, so nothing connects to a half-typed host.
    /// </summary>
    private async Task SearchConnectAsync(string text)
    {
        if (_modal is not null || _connecting) return;
        if (AllConnections(ShownLibrary).FirstOrDefault() is { } top)
        {
            await ConnectAsync(top);
            return;
        }
        LibraryClient quick;
        try { quick = LibraryClient.QuickConnect(text); }
        catch (BastionException) { ShowQuickConnectFlyout(text); return; }
        await ConnectQuickAsync(quick);
    }

    // ---- Command palette ----

    private sealed record PaletteEntry(PaletteEntryDto Entry, string Glyph, Func<Task> Run);

    private void Palette_Click(object sender, RoutedEventArgs e) => _ = PaletteAsync();

    /// <summary>Everything the palette can run: commands with their keys, connections, workspaces, settings pages.</summary>
    private List<PaletteEntry> PaletteEntries()
    {
        var entries = new List<PaletteEntry>();
        void Command(string title, string id, string glyph, Func<Task> run) =>
            entries.Add(new PaletteEntry(new PaletteEntryDto("command", title, ShortcutText(id) ?? ""), glyph, run));
        Command("Quick Connect…", "quick-connect", FluentIcons.Action("connect"), () => { ShowQuickConnectFlyout(); return Task.CompletedTask; });
        Command("New Connection…", "add", FluentIcons.Action("add"), () => NewConnectionAsync());
        Command("New Folder…", "new-folder", FluentIcons.Action("folder-add"), NewFolderAsync);
        Command("New from Template…", "new-from-template", FluentIcons.Action("template"), NewFromTemplateAsync);
        Command("Templates…", "templates", FluentIcons.Action("template"), ManageTemplatesAsync);
        Command("New Local Shell", "local-shell", FluentIcons.Object("local-terminal"), () => { NewLocalShell(); return Task.CompletedTask; });
        Command("Save Current Layout…", "save-workspace", FluentIcons.Object("workspace"), SaveWorkspaceAsync);
        Command("Manage Workspaces…", "workspace-manager", FluentIcons.Object("workspace"), () => { OpenWorkspaceManager(); return Task.CompletedTask; });
        Command("Credential Manager", "credential-manager", FluentIcons.Object("credential"), () => { OpenCredentialManager(); return Task.CompletedTask; });
        Command("Tunnel Manager", "tunnel-manager", FluentIcons.Action("connect"), () => { OpenTunnelManager(); return Task.CompletedTask; });
        Command("Recently Deleted", "recently-deleted", FluentIcons.Action("trash"), () => { OpenRecentlyDeleted(); return Task.CompletedTask; });
        // Parity with the Mac palette (Commands.swift "expand-all" / "collapse-all"): the whole library.
        Command("Expand All Folders", "expand-all", FluentIcons.Action("expand"), () => { SetSubtree(null, true); return Task.CompletedTask; });
        Command("Collapse All Folders", "collapse-all", FluentIcons.Action("collapse"), () => { SetSubtree(null, false); return Task.CompletedTask; });
        Command("Run on Several Hosts…", "multi-exec", FluentIcons.Action("connect"), MultiExecAsync);
        Command("Select All", "select-all", FluentIcons.Object("local-terminal"), () => { RunCommand("select-all"); return Task.CompletedTask; });
        entries.Add(new PaletteEntry(new PaletteEntryDto("command", "Home", "Ctrl+Shift+H"), FluentIcons.Object("home"), () => { ShowHome(); return Task.CompletedTask; }));
        Command("Send Interrupt (Ctrl+C)", "send-break", FluentIcons.Object("local-terminal"), () => { RunCommand("send-break"); return Task.CompletedTask; });
        Command("Lock Credentials", "lock-credentials", FluentIcons.Object("vault"), () => { LockCredentials(); return Task.CompletedTask; });
        Command("Settings", "settings", FluentIcons.Object("settings"), () => { OpenSettings(null); return Task.CompletedTask; });
        Command("Import Connections…", "import-file", FluentIcons.Action("import"), ImportConnectionsAsync);
        Command("Refresh SSH Config…", "ssh-sources", FluentIcons.Action("import"), EditSshSourcesAsync);
        Command("Import SSH Config…", "ssh-import", FluentIcons.Action("import"), () => ImportSshAsync(SshWorkflow.UserDir(SessionDataDir), SshConfigLocation.SystemFile));
        // Default Settings per type (owner 2026-11-15, as on the Mac's palette); no shortcut ids, so no keys shown.
        // After the commands; ActionNameFirst ranks New Local Shell above these for "local shell".
        foreach (var (typeId, typeLabel) in AddConnectionForm.Protocols)
            entries.Add(new PaletteEntry(new PaletteEntryDto("command", $"Default Settings: {typeLabel}…", ""), FluentIcons.Object("defaults"),
                () => EditDefaultsAsync(new EditorTarget.Type(typeId, typeLabel))));
        foreach (var item in AllConnections())
            entries.Add(new PaletteEntry(new PaletteEntryDto("connection", item.Name, item.Description, item.Connection?.Host ?? ""), item.Glyph, () => RunAsync("connect", item)));
        IReadOnlyList<WorkspaceDto> workspaces;
        try { workspaces = Workspaces.List(); }
        catch (BastionException) { workspaces = []; }
        foreach (var ws in workspaces)
            entries.Add(new PaletteEntry(new PaletteEntryDto("workspace", "Open Workspace " + ws.Name, Plural(ws.Tabs.Count, "tab")), FluentIcons.Object("workspace"), () => OpenWorkspaceAsync(ws)));
        // Add to Workspace for the selected SSH connection, one entry per workspace, as on macOS.
        if (Selected is { Connection: { Protocol: "ssh" } c })
            foreach (var ws in workspaces.Where(w => !w.Tabs.Any(t => t.Connection == c.Id && t.Mode == "terminal")))
                entries.Add(new PaletteEntry(new PaletteEntryDto("action", $"Add {c.Name} to {ws.Name}", "Add to Workspace"), FluentIcons.Object("workspace"), () => AddToWorkspaceAsync(c, ws)));
        try
        {
            foreach (var cat in SettingsClient.Categories().Where(x => x.Id != "about"))
                entries.Add(new PaletteEntry(new PaletteEntryDto("setting", "Settings: " + cat.Label, ""), FluentIcons.Object(cat.Icon), () => { OpenSettings(cat.Id); return Task.CompletedTask; }));
        }
        catch (BastionException) { /* the palette works without the settings pages */ }
        return entries;
    }

    /// <summary>An exact action-name match ranks first (owner 2026-11-17): "local shell" puts New Local Shell above
    /// "Default Settings: Local shell…", whose action name is "Default Settings". Otherwise the core's order stays.</summary>
    private static List<int> ActionNameFirst(List<int> ranked, IReadOnlyList<PaletteEntry> entries, string query)
    {
        if (query.Length == 0) return ranked;
        var pattern = new System.Text.RegularExpressions.Regex(@"(?<!\w)" + System.Text.RegularExpressions.Regex.Escape(query) + @"(?!\w)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
        bool InActionName(int i)
        {
            var title = entries[i].Entry.Title;
            var colon = title.IndexOf(": ", StringComparison.Ordinal);
            return pattern.IsMatch(colon < 0 ? title : title[..colon]);
        }
        return [.. ranked.Where(InActionName), .. ranked.Where(i => !InActionName(i))];
    }

    private IEnumerable<TreeItem> AllConnections()
    {
        IEnumerable<TreeItem> Walk(IEnumerable<TreeItem> items) => items.SelectMany(i => i.IsFolder ? Walk(i.Children) : [i]);
        return Walk(_roots);
    }

    /// <summary>The command palette: type to filter (ranked by the core), Up and Down to choose, Enter to run.</summary>
    internal async Task PaletteAsync(string? query = null)
    {
        if (_modal is not null) return;
        var entries = PaletteEntries();
        using var ranker = new PaletteRanker(entries.Select(e => e.Entry).ToList());
        var box = new TextBox { PlaceholderText = "Type a command, connection, workspace or setting", Text = query ?? "", IsSpellCheckEnabled = false };
        AutomationProperties.SetName(box, "Command palette");
        var list = new ListView { SelectionMode = ListViewSelectionMode.Single, MaxHeight = 360, ItemContainerTransitions = new Microsoft.UI.Xaml.Media.Animation.TransitionCollection() };
        AutomationProperties.SetName(list, "Results");
        var none = Ui.Text("No matches.", "BodySecondaryTextStyle");
        List<int> shown = [];
        var closed = false;
        void Fill()
        {
            if (closed) return; // TextChanged can still arrive after the dialog closed and the index is gone
            try { shown = ActionNameFirst(ranker.Rank(box.Text.Trim(), 50), entries, box.Text.Trim()); }
            catch (BastionException) { shown = []; }
            list.Items.Clear();
            foreach (var i in shown)
            {
                var e = entries[i];
                var row = new Grid { ColumnSpacing = Ui.Double("Space8") };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                row.ColumnDefinitions.Add(new ColumnDefinition());
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                row.Children.Add(new FontIcon { Glyph = e.Glyph, FontFamily = (Microsoft.UI.Xaml.Media.FontFamily)Application.Current.Resources["SymbolFontFamily"], FontSize = Ui.Double("IconSize") });
                var title = new TextBlock { Text = e.Entry.Title, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
                Grid.SetColumn(title, 1);
                row.Children.Add(title);
                var detail = Ui.Text(e.Entry.Detail, "CaptionSecondaryTextStyle");
                detail.VerticalAlignment = VerticalAlignment.Center;
                Grid.SetColumn(detail, 2);
                row.Children.Add(detail);
                AutomationProperties.SetName(row, e.Entry.Detail.Length > 0 ? $"{e.Entry.Title}, {e.Entry.Detail}" : e.Entry.Title);
                list.Items.Add(new ListViewItem { Content = row, Tag = i });
            }
            list.SelectedIndex = shown.Count > 0 ? 0 : -1;
            none.Visibility = shown.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        box.TextChanged += (_, _) => Fill();
        box.PreviewKeyDown += (_, e) =>
        {
            if (list.Items.Count == 0) return;
            if (e.Key == VirtualKey.Down) { list.SelectedIndex = Math.Min(list.Items.Count - 1, list.SelectedIndex + 1); list.ScrollIntoView(list.SelectedItem); e.Handled = true; }
            else if (e.Key == VirtualKey.Up) { list.SelectedIndex = Math.Max(0, list.SelectedIndex - 1); list.ScrollIntoView(list.SelectedItem); e.Handled = true; }
        };
        PaletteEntry? chosen = null;
        list.IsItemClickEnabled = true;
        list.ItemClick += (_, e) =>
        {
            if (e.ClickedItem is ListViewItem { Tag: int i }) { chosen = entries[i]; CloseModal(true); }
        };
        Fill();
        _paletteForSnapshot = (box, list, Fill);
        bool Validate()
        {
            if (list.SelectedItem is ListViewItem { Tag: int i }) chosen = entries[i];
            return chosen is not null;
        }
        var body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { box, none, list } };
        var ok = await ShowModal("Go to", body, primary: "Go", cancel: "Cancel", validate: Validate, focus: box, wide: true);
        closed = true;
        _paletteForSnapshot = null;
        if ((ok || chosen is not null) && chosen is not null) await chosen.Run();
    }

    private (TextBox Box, ListView List, Action Fill)? _paletteForSnapshot;

    // ---- Snapshot mode hooks (SnapshotRunner, BASTION_SNAPSHOT_WORKSPACES) ----

    /// <summary>Snapshot only: type into the open palette and return the titles in rank order.</summary>
    internal IReadOnlyList<string> PaletteTypeForSnapshot(string text)
    {
        if (_paletteForSnapshot is not { } p) return [];
        p.Box.Text = text;
        p.Fill(); // TextChanged runs later; rank now so the result belongs to this text
        return p.List.Items.OfType<ListViewItem>().Select(i => AutomationProperties.GetName((UIElement)i.Content)).ToList();
    }

    /// <summary>Snapshot only: the open SSH tabs' saved form, layouts included.</summary>
    internal IReadOnlyList<string> LayoutLinesForSnapshot() =>
        CurrentLayout().Select(t => $"{t.Connection[..8]} {t.Mode} [{string.Join(", ", t.Layout ?? [])}]").ToList();

    /// <summary>Snapshot only: split the active tab's focused pane with a given share (a divider dragged there).</summary>
    internal void SplitWithShareForSnapshot(SplitAxis axis, double share)
    {
        if (_active is not { Panes: { } panes } tab) return;
        var at = panes.Focused;
        var session = tab.StartLocal is { } start ? start() : at.Session.OpenSibling(at.Session.Screen().Cols, at.Session.Screen().Rows);
        panes.Split(at, MakePane(session, at), axis, share);
    }

    /// <summary>Snapshot only: rebuild a layout on the active tab, as reopening a workspace does.</summary>
    internal bool ApplyLayoutForSnapshot(IReadOnlyList<string> steps) => _active is { } tab && ApplyLayout(tab, steps);

    internal bool ToolbarLabelsShownForSnapshot => false; // the title bar has no text labels since WIN-HEADER-MAC

    internal void ResetSizeForSnapshot() => SizeWindow();

    internal void DisposeQuickLibraries()
    {
        foreach (var lib in _quickLibraries) lib.Dispose();
        _quickLibraries.Clear();
    }
}
