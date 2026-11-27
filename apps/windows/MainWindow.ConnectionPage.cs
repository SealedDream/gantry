using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

// UI-04 (Native Windows, as Native Mac #1378): clicking a connection that has no open session shows its page in the
// session area. Top to bottom in a left-aligned column of at most ConnectionPageMaxWidth: header (protocol icon in the
// host colour, name, Production mark, address, protocol), the login line (opens Logins…), Connect with Files, Tunnel,
// Tools and Properties beside it (folded into More when the column is narrow, so Connect is never clipped), the two
// stored facts and the session history, then notes. No boxes: space and a hairline. The details pane stays Properties.
public sealed partial class MainWindow
{
    /// <summary>The column's cap, as the Mac's DS.Size.connectionPageMax.</summary>
    private const double ConnectionPageMaxWidth = 720;
    /// <summary>Space reserved beside the quiet buttons before they fold into More.</summary>
    private const double ConnectionPageFoldSlack = 8;

    /// <summary>The connection whose page shows, or null (a tab, Home or the start page shows instead).</summary>
    private string? _pageConnectionId;
    private ScrollViewer? _connectionPage;

    /// <summary>A selection changed: a connection with no open tab gets its page; anything else clears it.</summary>
    /// <summary>
    /// The tab belongs to the connection: its SSH/shell <see cref="WorkspaceTab.ConnectionId"/>, or, for an RDP or web tab
    /// (which sets none), the connection it opened (<see cref="WorkspaceTab.HostColorId"/>). Without the second case the
    /// connection page came back over a live remote desktop once its connect was recorded (q-rdpfail w22: the page took
    /// the keyboard from the remote, so Alt+F4 closed the window's full screen; "Open sessions: None").
    /// </summary>
    private static bool IsTabOf(WorkspaceTab t, string connectionId) =>
        t.ConnectionId == connectionId || (t.ConnectionId is null && (t.Rdp is not null || t.Web is not null) && t.HostColorId == connectionId);

    private void SetConnectionPageFor(TreeItem? item)
    {
        var id = item is { IsGroup: false, IsFolder: false, Connection: { IsUnavailable: false } } && !_library.IsQuickConnect
            && !_tabs.Any(t => IsTabOf(t, item.Id) && IsDocked(t)) ? item.Id : null;
        if (id == _pageConnectionId) return;
        _pageConnectionId = id;
        // Not inside the tree's SelectionChanged: changing the session area's visibility and content there crashed
        // WinUI (stowed exception 0xC000027B in q-ui04w). The next turn of the dispatcher is still the same frame.
        DispatcherQueue.TryEnqueue(() => { if (_pageConnectionId == id && !_windowClosed) ApplyHome(); });
    }

    /// <summary>Show or hide the page; called from ApplyHome. Returns true when it shows.</summary>
    private bool ApplyConnectionPage()
    {
        var item = _pageConnectionId is { } id ? TreeItem.Find(_roots, id) : null;
        if (item?.Connection is null || _homeShown)
        {
            if (_connectionPage is not null) _connectionPage.Visibility = Visibility.Collapsed;
            return false;
        }
        try
        {
            EnsureConnectionPage();
            _connectionPage!.Visibility = Visibility.Visible;
            // The content is built on the next dispatcher turn, never inside a tree reload or selection event.
            var pageId = item.Id;
            DispatcherQueue.TryEnqueue(() => FillConnectionPage(pageId));
            return true;
        }
        catch (Exception ex)
        {
            // The page is extra: a failure leaves the start page, logged with the cause.
            AppLog.Error("UI-04 connection page failed: " + ex);
            _pageConnectionId = null;
            if (_connectionPage is not null) _connectionPage.Visibility = Visibility.Collapsed;
            return false;
        }
    }

    private void FillConnectionPage(string id)
    {
        if (_windowClosed || _pageConnectionId != id || _connectionPage is not { Visibility: Visibility.Visible } page) return;
        if (TreeItem.Find(_roots, id) is not { Connection: not null } item) return;
        try
        {
            AppLog.Info("UI-04 connection page: build " + id);
            page.Content = ConnectionPageColumn(BuildConnectionPage(item));
            AppLog.Info("UI-04 connection page: shown");
        }
        catch (Exception ex)
        {
            AppLog.Error("UI-04 connection page failed: " + ex);
            page.Content = Ui.Text("This page could not be shown: " + ex.Message, "BodySecondaryTextStyle");
        }
    }

    private void EnsureConnectionPage()
    {
        if (_connectionPage is not null) return;
        _connectionPage = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Visibility = Visibility.Collapsed };
        AutomationProperties.SetAutomationId(_connectionPage, "ConnectionPage");
        AutomationProperties.SetName(_connectionPage, "Connection page");
        Grid.SetRow(_connectionPage, Grid.GetRow(StartPage));
        Grid.SetColumn(_connectionPage, Grid.GetColumn(StartPage));
        ((Panel)StartPage.Parent).Children.Add(_connectionPage);
    }

    /// <summary>The page in a left column of the window's width up to ConnectionPageMaxWidth. The column's width comes
    /// from the window, never from the page's content: a content-sized column re-sized itself when the quiet buttons
    /// folded into More, which folded them back (WinUI layout cycle 0x802B0014, q-ui04w3).</summary>
    private static Grid ConnectionPageColumn(StackPanel page)
    {
        var column = new Grid();
        column.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star), MaxWidth = ConnectionPageMaxWidth });
        column.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(0, GridUnitType.Auto) });
        column.Children.Add(page);
        return column;
    }

    private StackPanel BuildConnectionPage(TreeItem item)
    {
        var c = item.Connection!;
        var page = new StackPanel
        {
            Spacing = Ui.Double("Space16"),
            Padding = Ui.Thickness("InspectorBodyPadding"),
        };
        page.Children.Add(ConnectionPageHeader(c));
        page.Children.Add(ConnectionPageLoginLine(c));
        page.Children.Add(ConnectionPageActions(item));
        page.Children.Add(new Border { Height = 1, Background = Ui.Brush(RootGrid, "DividerBrush") });
        page.Children.Add(ConnectionPageFacts(c));
        var rows = new StackPanel { Spacing = Ui.Double("Space4") };
        AutomationProperties.SetName(rows, "History");
        rows.Children.Add(Ui.Text("Loading…", "CaptionSecondaryTextStyle"));
        var heading = Ui.Text("History", "BodyStrongTextStyle");
        AutomationProperties.SetHeadingLevel(heading, Microsoft.UI.Xaml.Automation.Peers.AutomationHeadingLevel.Level2);
        AutomationProperties.SetAutomationId(heading, "ConnectionPageHistory");
        page.Children.Add(new StackPanel { Spacing = Ui.Double("Space4"), Children = { heading, rows } });
        _ = FillHistoryAsync(rows, "connection", c.Id);
        if (ConnectionNotes(c.Id) is { Length: > 0 } notes) page.Children.Add(ConnectionPageNotes(notes));
        return page;
    }

    /// <summary>The header icon, chosen as the tree row chooses it (TreeItem.ConnectionItem): the type art from the icon
    /// set, else the user's own icon or the type's glyph. Protocol glyphs are Nerd Font code points above U+FFFF that the
    /// Segoe symbol fonts lack, so a FontIcon for "ssh" drew an empty box; the art is what the tree and the Mac show.</summary>
    private FrameworkElement ConnectionPageIcon(ConnectionDto c, double size)
    {
        var id = c.Icon ?? c.Protocol;
        var accent = HostColorFor(c.Id) is { } paint ? HostColors.Brush(paint.Accent) : null;
        if (c.OwnIcon is null && (ConnectionIcon.Art(id) ?? ConnectionIcon.Art(c.Protocol)) is { } art)
            return new ConnectionIcon { IconId = art, Tint = accent, Width = size, Height = size, VerticalAlignment = VerticalAlignment.Center };
        var glyph = MenuIcon(FluentIcons.Object(c.OwnIcon ?? id));
        glyph.FontSize = size;
        if (accent is not null) glyph.Foreground = accent;
        return glyph;
    }

    private StackPanel ConnectionPageHeader(ConnectionDto c)
    {
        var icon = ConnectionPageIcon(c, Ui.Double("EmptyStateIconSize") / 1.6);
        AutomationProperties.SetAccessibilityView(icon, Microsoft.UI.Xaml.Automation.Peers.AccessibilityView.Raw);
        var name = Ui.Text(c.Name, "SubtitleTextStyle");
        name.TextWrapping = TextWrapping.Wrap;
        name.IsTextSelectionEnabled = true;
        AutomationProperties.SetHeadingLevel(name, Microsoft.UI.Xaml.Automation.Peers.AutomationHeadingLevel.Level1);
        AutomationProperties.SetAutomationId(name, "ConnectionPageName");
        var title = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { icon, name } };
        if (_production.Contains(c.Id))
        {
            var mark = Ui.Text("Production", "CaptionTextStyle");
            mark.Foreground = Ui.Brush(RootGrid, "CriticalBrush");
            mark.VerticalAlignment = VerticalAlignment.Center;
            AutomationProperties.SetName(mark, "Production connection");
            title.Children.Add(mark);
        }
        var address = Ui.Text(c.Port is { } port ? $"{c.Host}:{port}" : c.Host, "BodySecondaryTextStyle");
        address.FontFamily = new FontFamily("Cascadia Mono, Consolas");
        address.IsTextSelectionEnabled = true;
        address.TextWrapping = TextWrapping.Wrap;
        AutomationProperties.SetAutomationId(address, "ConnectionPageAddress");
        var header = new StackPanel { Spacing = Ui.Double("Space4"), Children = { title, address } };
        header.Children.Add(ConnectionPageProtocol(c));
        return header;
    }

    /// <summary>The protocol as a compact drop-down (the same choices as right-click › Protocol), or a label.</summary>
    private FrameworkElement ConnectionPageProtocol(ConnectionDto c)
    {
        var label = c.Protocol.ToUpperInvariant();
        var current = c.Protocol.ToLowerInvariant();
        if (!SwitchableProtocols.Any(p => p.Id == current)) return Ui.Text(label, "CaptionTextStyle");
        // Fresh items, not the right-click menu's: a menu item belongs to one menu.
        var flyout = new MenuFlyout();
        foreach (var (id, text) in SwitchableProtocols)
        {
            var entry = new MenuFlyoutItem { Text = text, IsEnabled = id != current };
            entry.Click += (_, _) => _ = Mutate(() => { _library.SetProperty(c.Id, "protocol", id); return c.Id; }, "Could not change the protocol");
            flyout.Items.Add(entry);
        }
        var button = new DropDownButton { Content = label, Flyout = flyout, MinHeight = Ui.Double("MinHitTarget") };
        AutomationProperties.SetName(button, "Protocol " + label);
        AutomationProperties.SetAutomationId(button, "ConnectionPageProtocol");
        ToolTipService.SetToolTip(button, "Change the connection type");
        return button;
    }

    /// <summary>"Signs in as admin · From folder Customer A": which login a connect will use, read without opening the
    /// vault (no prompt). No secret. Clicking it opens Logins….</summary>
    private HyperlinkButton ConnectionPageLoginLine(ConnectionDto c)
    {
        var text = ConnectionSummary.LoginLine(ConnectionLoginState(c));
        var link = new HyperlinkButton { Content = text, Padding = new Thickness(0), MinHeight = Ui.Double("MinHitTarget") };
        AutomationProperties.SetName(link, text);
        AutomationProperties.SetAutomationId(link, "ConnectionPageLogin");
        ToolTipService.SetToolTip(link, "Edit this connection's logins");
        link.Click += (_, _) => _ = ShowLoginsDialogAsync(c.Id, c.Name);
        return link;
    }

    private ConnectionSummary.LoginState ConnectionLoginState(ConnectionDto c)
    {
        var user = c.Username ?? "";
        var assigned = c.EffectiveCredentialId is not null || c.CredentialId is not null;
        if (_credentials is not { } vault) return assigned ? ConnectionSummary.LoginState.Locked(user) : ConnectionSummary.LoginState.None;
        try
        {
            var best = vault.Logins(_library, c.Id, passwordsOnly: c.Protocol == "rdp").FirstOrDefault();
            return best is null ? ConnectionSummary.LoginState.None
                : ConnectionSummary.LoginState.Offer(best.Username.Length > 0 ? best.Username : user, best.Source, best.SourceName, best.AutoUse);
        }
        catch (BastionException) { return assigned ? ConnectionSummary.LoginState.Locked(user) : ConnectionSummary.LoginState.None; }
    }

    /// <summary>Connect (accent, Enter), then the quiet next steps; these fold into More when the column is too narrow.</summary>
    private Grid ConnectionPageActions(TreeItem item)
    {
        var c = item.Connection!;
        var connect = new Button { Content = "Connect", Style = Ui.Style("AccentButtonStyle") };
        AutomationProperties.SetName(connect, "Connect, " + c.Name); // not "Connect" or "Connect to …": the toolbar and the sign-in sheet use those
        AutomationProperties.SetAutomationId(connect, "ConnectionPageConnect");
        connect.Click += (_, _) => _ = RunAsync("connect-new-tab", item);
        var entries = ConnectionPageQuietActions(item, c);
        var quiet = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        var more = new MenuFlyout();
        var folded = new List<MenuFlyoutItem>();
        var tools = new MenuFlyout();
        foreach (var (label, id, run) in entries)
        {
            var m = new MenuFlyoutItem { Text = label };
            m.Click += (_, _) => run();
            more.Items.Add(m);
            if (ConnectionPageIcon(id) is not { } icon) continue; // Properties lives only in the "…" menu
            m.Visibility = Visibility.Collapsed; // shown only while the icon buttons are folded
            folded.Add(m);
            if (id.StartsWith("Tool")) { tools.Items.Add(ToolsItem(label, run)); continue; }
            var b = new Button { Content = icon, Style = Ui.Style("SubtleButtonStyle") };
            AutomationProperties.SetName(b, $"{label}, {c.Name}");
            AutomationProperties.SetAutomationId(b, "ConnectionPage" + id);
            ToolTipService.SetToolTip(b, label);
            b.Click += (_, _) => run();
            quiet.Children.Add(b);
        }
        if (tools.Items.Count > 0)
        {
            var toolsButton = new Button { Content = Ui.Icon("GlyphSettings"), Flyout = tools, Style = Ui.Style("SubtleButtonStyle") };
            AutomationProperties.SetName(toolsButton, $"Tools, {c.Name}");
            AutomationProperties.SetAutomationId(toolsButton, "ConnectionPageTools");
            ToolTipService.SetToolTip(toolsButton, "Tools");
            quiet.Children.Add(toolsButton);
        }
        var moreButton = new Button { Content = Ui.Icon("GlyphMore"), Flyout = more, Style = Ui.Style("SubtleButtonStyle") };
        ToolTipService.SetToolTip(moreButton, "More");
        AutomationProperties.SetName(moreButton, "More actions");
        AutomationProperties.SetAutomationId(moreButton, "ConnectionPageMore");
        var row = new Grid { ColumnSpacing = Ui.Double("Space8") };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.Children.Add(connect);
        var rest = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { quiet, moreButton } };
        Grid.SetColumn(rest, 1);
        row.Children.Add(rest);
        // Fold by the room left after Connect, not by window size: the column narrows with the panes too (point 22).
        // The buttons' full width is measured once, from the buttons themselves (a collapsed panel measures 0, which
        // made the fold flip on every pass). The room is the star column's, which never depends on the buttons.
        var needed = -1.0;
        row.SizeChanged += (_, _) =>
        {
            if (needed < 0)
            {
                var infinite = new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity);
                needed = quiet.Spacing * Math.Max(0, quiet.Children.Count - 1);
                foreach (var child in quiet.Children) { child.Measure(infinite); needed += child.DesiredSize.Width; }
                moreButton.Measure(infinite);
                needed += moreButton.DesiredSize.Width + rest.Spacing;
            }
            var fits = needed + ConnectionPageFoldSlack <= row.ActualWidth - connect.ActualWidth - row.ColumnSpacing;
            var quietState = fits ? Visibility.Visible : Visibility.Collapsed;
            if (quiet.Visibility == quietState) return;
            quiet.Visibility = quietState;
            foreach (var m in folded) m.Visibility = fits ? Visibility.Collapsed : Visibility.Visible;
        };
        return row;
    }

    private static MenuFlyoutItem ToolsItem(string label, Action run)
    {
        var m = new MenuFlyoutItem { Text = label };
        m.Click += (_, _) => run();
        return m;
    }

    /// <summary>The icon for a quiet action; null for Properties, which stays in the "…" menu.</summary>
    private static UIElement? ConnectionPageIcon(string id) => id switch
    {
        "ShowSession" => Ui.Icon("GlyphTerminal"),
        "Files" => new AppIcon { Kind = "Folder" },
        "Tunnel" => Ui.Icon("GlyphConnect"),
        "Properties" => null,
        _ => Ui.Icon("GlyphSettings"), // Tools entries: one Tools button holds them
    };

    private List<(string Label, string Id, Action Run)> ConnectionPageQuietActions(TreeItem item, ConnectionDto c)
    {
        var list = new List<(string, string, Action)>();
        if (_tabs.FirstOrDefault(t => IsTabOf(t, c.Id)) is { } open) list.Add(("Show Session", "ShowSession", () => PickTab(open)));
        if (IsSsh(item))
        {
            list.Add(("Files", "Files", () => _ = RunAsync("open-sftp", item)));
            list.Add(("Tunnel", "Tunnel", OpenTunnelManager));
        }
        if (c.HasTools)
            foreach (var (id, label) in SystemViews) list.Add((label, "Tool" + label.Replace(" ", ""), () => _ = OpenSystemViewAsync(item, id)));
        list.Add(("Properties", "Properties", () => _ = PropertiesAsync(item)));
        return list;
    }

    private StackPanel ConnectionPageFacts(ConnectionDto c)
    {
        ConnectionHistoryDto h;
        try { h = ConnectionHistory.Get(HistoryDir, c.Id); }
        catch (BastionException) { h = new(null, null, null); } // an unreadable history only blanks the facts
        var last = h.LastConnectedAt is { } at
            ? FormatWhen(DateTimeOffset.FromUnixTimeSeconds(at).ToLocalTime(), DateTimeOffset.Now) + (h.LastUser is { Length: > 0 } u ? " as " + u : "")
            : "Never";
        var open = _tabs.Count(t => IsTabOf(t, c.Id));
        var facts = new StackPanel { Spacing = Ui.Double("Space8") };
        // Ids in the same camel case as the Mac and the tests: ConnectionPageLastConnected, …LastResult, …OpenSessions.
        foreach (var (label, id, value) in new[] { ("Last connected", "LastConnected", last), ("Last result", "LastResult", ConnectionSummary.LastResult(h.LastResult)), ("Open sessions", "OpenSessions", open == 0 ? "None" : open.ToString()) })
        {
            var v = Ui.Text(value, "BodyTextStyle");
            v.IsTextSelectionEnabled = true;
            v.TextWrapping = TextWrapping.Wrap;
            AutomationProperties.SetName(v, $"{label}: {value}");
            AutomationProperties.SetAutomationId(v, "ConnectionPage" + id);
            facts.Children.Add(new StackPanel { Spacing = 1, Children = { Ui.Text(label, "CaptionSecondaryTextStyle"), v } });
        }
        return facts;
    }

    private string ConnectionNotes(string id)
    {
        try { return _library.Notes(id); }
        catch (BastionException) { return ""; } // notes are optional on the page; the details pane reports errors
    }

    private StackPanel ConnectionPageNotes(string notes)
    {
        var text = Ui.Text(notes, "BodyTextStyle");
        text.TextWrapping = TextWrapping.Wrap;
        text.IsTextSelectionEnabled = true;
        AutomationProperties.SetAutomationId(text, "ConnectionPageNotes");
        return new StackPanel
        {
            Spacing = Ui.Double("Space8"),
            Children = { new Border { Height = 1, Background = Ui.Brush(RootGrid, "DividerBrush") }, Ui.Text("Notes", "BodyStrongTextStyle"), text },
        };
    }
}
