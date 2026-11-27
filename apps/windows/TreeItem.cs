using System.Collections.ObjectModel;
using System.ComponentModel;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// A node of the navigation tree: a folder, a connection, or the Favorites section heading. Favorites rows mirror library
/// rows: same <see cref="Id"/> and connection, so every command acts on the library item (as on macOS).
/// </summary>
public sealed partial class TreeItem : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed(params string[] names) { foreach (var n in names) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n)); }

    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public bool IsFolder { get; init; }
    /// <summary>A section heading (Favorites); not a library item, never selected for commands.</summary>
    public bool IsGroup { get; init; }
    /// <summary>A row of the Application section (Credentials, Tunnels, Workspaces, Default Settings): not a heading, not a library item.</summary>
    public bool IsAppRow { get; init; }
    /// <summary>What a click or Enter on an Application row opens (a manager page or a type's Default Settings).</summary>
    public Action? Open { get; init; }
    /// <summary>A Favorites row standing for a connection that lives in the library below.</summary>
    public bool IsMirror { get; init; }
    public string? ParentId { get; init; }
    /// <summary>Symbol-font glyph for the core icon id (FluentIcons); folders use AppIcon.</summary>
    public string Glyph { get; init; } = "";
    /// <summary>The core's tint for the icon, for the current theme.</summary>
    public Brush? IconBrush { get; init; }
    /// <summary>The icon's full name from the core ("SSH Terminal"), for the icon's tooltip.</summary>
    public string IconLabel { get; init; } = "";
    /// <summary>One line for tooltips and screen readers, e.g. "SSH Terminal, ops@web-1.acme.example". Never holds secrets.</summary>
    public string Description { get; init; } = "";
    public TreeChildren Children { get; private init; } = new();
    /// <summary>Whether the folder shows its children (LibraryTree walks the open ones).</summary>
    public bool Expanded
    {
        get => _expanded;
        set
        {
            if (_expanded == value) return;
            _expanded = value;
            Changed(nameof(CountVisibility), nameof(AccessibleName), nameof(FolderCountVisibility), nameof(ConnectedMarkVisibility));
            ExpandedChanged?.Invoke();
        }
    }

    /// <summary>
    /// The open state of a row that is not shown yet (just built, bound nowhere): no change events. Raising
    /// <see cref="ExpandedChanged"/> here made the library tree walk all its open rows again for rows it never shows
    /// (the Credentials section is rebuilt on every search change).
    /// </summary>
    public void InitExpanded(bool value) => _expanded = value;

    /// <summary>WIN-FLAT-TREE: any row opened or closed, so the library tree rebuilds its open-row list (coalesced).</summary>
    public static event Action? ExpandedChanged;
    private bool _expanded = true;
    public FolderDto? Folder { get; init; }
    public ConnectionDto? Connection { get; init; }
    /// <summary>A row of the Credentials section (a vault folder or a credential); such rows are not library items.</summary>
    public CredentialTreeRowDto? Credential { get; init; }

    private bool ShowsFolder => IsFolder || Credential is { IsFolder: true };
    public Visibility GlyphVisibility => ShowsFolder ? Visibility.Collapsed : Visibility.Visible;
    /// <summary>The old AppIcon folder: only where no D12 art is set.</summary>
    public Visibility FolderVisibility => ShowsFolder && ArtId is null ? Visibility.Visible : Visibility.Collapsed;
    /// <summary>The star after a favourite's name (not on its Favorites row, where the section says it).</summary>
    /// <summary>The connection's effective per-host colour (own or a folder's), or null.</summary>
    public HostColorDto? HostColor { get; init; }
    public Brush? HostColorBrush => HostColor is { } c ? HostColors.Brush(c.Accent) : null;
    public Visibility HostColorVisibility => HostColor is not null && Connection is not null ? Visibility.Visible : Visibility.Collapsed;
    public string HostColorLabel => HostColor is { } c ? "Host colour " + c.Accent : "";
    /// <summary>PLUG-03a: an entry of a type this build does not know shows a marker with the core's text.</summary>
    /// PLUG-08-WIN: not when an installed plugin opens the entry (<see cref="OpenablePluginTypes"/>).
    public Visibility UnavailableVisibility => Connection is { IsUnavailable: true } c && !OpenablePluginTypes.Contains(c.Protocol) ? Visibility.Visible : Visibility.Collapsed;
    /// <summary>The installed plugins' connection type ids (set by the window before it builds the tree).</summary>
    public static IReadOnlySet<string> OpenablePluginTypes { get; set; } = new HashSet<string>();
    /// <summary>Installed plugin types' names by type id: a plugin entry's type label (inspector Type, header, icon
    /// tooltip) is its plugin type's name, never the core's "needs a plugin" text, when an installed plugin opens it.</summary>
    public static IReadOnlyDictionary<string, string> PluginTypeNames { get; set; } = new Dictionary<string, string>();

    /// <summary>The type label of <paramref name="c"/>: the installed plugin type's name for a plugin entry, else the core's.</summary>
    public static string TypeLabel(ConnectionDto c, string fallback) =>
        c.IsUnavailable && PluginTypeNames.TryGetValue(c.Protocol, out var name) && name.Length > 0 ? name : fallback;
    public string UnavailableText => Connection?.Unavailable ?? "";
    public Visibility FavoriteVisibility => Connection is { Favorite: true } && !IsMirror ? Visibility.Visible : Visibility.Collapsed;
    /// <summary>A section heading (Favorites, Credentials), drawn in the heading style.</summary>
    public bool IsHeading => IsGroup && Credential is null && !IsAppRow;
    public Visibility NameVisibility => IsHeading ? Visibility.Collapsed : Visibility.Visible;
    public Visibility GroupVisibility => IsHeading ? Visibility.Visible : Visibility.Collapsed;
    /// <summary>Folders, section headings and connections with open sessions have children the tree expands.</summary>
    public bool HasChildren => IsFolder || IsGroup || SessionCount > 0 || HasSidebarTree || (IsPluginRow && Children.Count > 0);

    // ---- PLUG-API-13: a plugin's tree under its entry in the library (Mac PluginSidebar.swift). Never saved. ----

    /// <summary>Connection types whose plugin declares <c>sidebar = "tree"</c> (set with the installed types).</summary>
    public static IReadOnlySet<string> SidebarTreeTypes { get; set; } = new HashSet<string>();
    /// <summary>A plugin entry whose type lists its items under it in the library.</summary>
    public bool HasSidebarTree => Connection is { } c && !IsMirror && SidebarTreeTypes.Contains(c.Protocol);
    /// <summary>For a row of a plugin's tree: the entry it belongs to.</summary>
    public string? PluginEntryId { get; init; }
    public bool IsPluginRow => PluginEntryId is not null;
    /// <summary>The plugin's item key; null for a status row ("Loading…", a refusal).</summary>
    public string? PluginKey { get; init; }
    /// <summary>The item's menu as the plugin gave it (id, title); the item <c>open</c> is the double-click action.</summary>
    public IReadOnlyList<(string Id, string Title)> PluginMenu { get; init; } = [];

    // ---- UI-05: open sessions in the library tree (docs/design/SESSION-TREE.md). Never saved. ----

    /// <summary>The D12 art id for the icon cell (a connection type, folder or credential), or null for a font glyph.</summary>
    public string? ArtId { get; init; }
    public Visibility ArtVisibility => ArtId is not null && !IsSession ? Visibility.Visible : Visibility.Collapsed;
    public Visibility FontGlyphVisibility => ArtId is null && !IsSession && !ShowsFolder ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>A row standing for an open tab (UI-05): status dot and the tab's title, a child of its connection.</summary>
    public bool IsSession { get; init; }
    /// <summary>The tab's id in the strip (WorkspaceTab.StripId) for a session row.</summary>
    public Guid TabId { get; init; }
    /// <summary>The Other sessions heading (tabs with no saved connection).</summary>
    public bool IsOtherSessions => Id == OtherSessionsId;
    public const string OtherSessionsId = "group:other-sessions";

    private string _title = "";
    private SessionRowState _state;
    /// <summary>The parent connection's name, for the accessible name ("…, session of build-01").</summary>
    public string SessionOf { get; set; } = "";

    /// <summary>A session row's title: the tab's own text.</summary>
    public string Title
    {
        get => _title;
        set { if (_title == value) return; _title = value; Changed(nameof(Title), nameof(SessionLabel), nameof(AccessibleName), nameof(RowTip)); }
    }

    public SessionRowState State
    {
        get => _state;
        set { if (_state == value) return; _state = value; Changed(nameof(State), nameof(DotBrush), nameof(SessionLabel), nameof(AccessibleName), nameof(RowTip), nameof(StateText)); }
    }

    public string StateText => StateWord(_state);

    public static string StateWord(SessionRowState s) => s switch
    {
        SessionRowState.Connected => "connected",
        SessionRowState.Connecting => "connecting",
        SessionRowState.Failed => "failed",
        _ => "not started",
    };

    /// <summary>"Terminal 2, connected, session of build-01" (or "…, other session" under Other sessions).</summary>
    public string SessionLabel => IsSession ? $"{_title}, {StateWord(_state)}, {(SessionOf.Length > 0 ? "session of " + SessionOf : "other session")}" : "";

    public Brush? DotBrush => IsSession ? SessionDots.Brush(_state) : null;
    public Visibility SessionVisibility => IsSession ? Visibility.Visible : Visibility.Collapsed;
    public Visibility RowVisibility => IsSession ? Visibility.Collapsed : Visibility.Visible;

    /// <summary>Open sessions under this connection (rows in <see cref="Children"/>).</summary>
    public int SessionCount => Connection is null && !IsOtherSessions ? 0 : Children.Count(c => c.IsSession);

    /// <summary>"(3)" after a collapsed connection's name while it has sessions.</summary>
    public string CountText => $"({SessionCount})";
    public Visibility CountVisibility => Connection is not null && !_expanded && SessionCount > 0 ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>A connection's accessible name: its name, plus "3 sessions" while collapsed with sessions.</summary>
    public string AccessibleName => IsSession ? SessionLabel : CountVisibility == Visibility.Visible ? $"{Name}, {SessionCount} session{(SessionCount == 1 ? "" : "s")}" : Badge.Length > 0 ? $"{Name}, {Badge}" : Name;
    /// <summary>A short state shown after the name in secondary text ("Unsupported": a credential kind a newer version saved).</summary>
    public string Badge { get; init; } = "";
    public Visibility BadgeVisibility => Badge.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    public string RowTip => IsSession ? SessionLabel : Description;

    /// <summary>Repaint the count and accessible name after session rows were added or removed (no reload).</summary>
    public void SessionsChanged() => Changed(nameof(CountText), nameof(CountVisibility), nameof(AccessibleName), nameof(HasChildren),
        nameof(LinkState), nameof(ConnectedMarkVisibility), nameof(ConnectingMarkVisibility), nameof(FailedMarkVisibility), nameof(LinkText));

    // ---- UI-01: status marks after the name (shape and words, never colour alone; static, no animation) ----

    /// <summary>A connection row's state from its open sessions: connected wins, then connecting, then failed.</summary>
    public SessionRowState LinkState
    {
        get
        {
            if (Connection is null || IsMirror) return SessionRowState.NotStarted;
            var states = Children.Where(c => c.IsSession).Select(c => c.State).ToList();
            if (states.Contains(SessionRowState.Connected)) return SessionRowState.Connected;
            if (states.Contains(SessionRowState.Connecting)) return SessionRowState.Connecting;
            return states.Contains(SessionRowState.Failed) ? SessionRowState.Failed : SessionRowState.NotStarted;
        }
    }
    public Visibility ConnectedMarkVisibility => LinkState == SessionRowState.Connected || (IsFolder && !_expanded && _connectedInside > 0) ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ConnectingMarkVisibility => LinkState == SessionRowState.Connecting ? Visibility.Visible : Visibility.Collapsed;
    public Visibility FailedMarkVisibility => LinkState == SessionRowState.Failed ? Visibility.Visible : Visibility.Collapsed;
    public string LinkText => IsFolder ? (_connectedInside > 0 ? $"{_connectedInside} connected" : "")
        : LinkState switch { SessionRowState.Connected => "Connected", SessionRowState.Connecting => "Connecting", SessionRowState.Failed => "Last attempt failed", _ => "" };

    private int _connectedInside;
    /// <summary>Connected items inside a folder; shown as "2/5" while it is collapsed.</summary>
    public int ConnectedInside
    {
        get => _connectedInside;
        set { if (_connectedInside == value) return; _connectedInside = value; Changed(nameof(ConnectedInside), nameof(ConnectedMarkVisibility), nameof(LinkText), nameof(FolderCountText), nameof(FolderCountVisibility)); }
    }
    public string FolderCountText => $"{_connectedInside}/{ConnectionCount}";
    public Visibility FolderCountVisibility => IsFolder && !_expanded && _connectedInside > 0 ? Visibility.Visible : Visibility.Collapsed;

    // ---- UI-01: the name in a text-safe tone of the identity colour ----

    /// <summary>Set before a tree build from the window's theme (a theme switch rebuilds the tree).</summary>
    public static bool DarkNames { get; set; }
    /// <summary>The core's tone for the current theme; null in high contrast (the icon keeps the colour there).</summary>
    public Brush? NameBrush => HostColor is { } c && !Ui.HighContrast ? HostColors.Brush(DarkNames ? c.FgDark : c.FgLight) : null;
    public Visibility PlainNameVisibility => NameVisibility == Visibility.Visible && NameBrush is null ? Visibility.Visible : Visibility.Collapsed;
    public Visibility TintedNameVisibility => NameVisibility == Visibility.Visible && NameBrush is not null ? Visibility.Visible : Visibility.Collapsed;

    public int ConnectionCount => Folder is null ? 0 : CountConnections(Folder);

    private static int CountConnections(FolderDto f) => f.Connections.Count + f.Folders.Sum(CountConnections);

    /// <summary>
    /// Folders first, then connections, in the library's order. The library root itself is not shown. <paramref name="tint"/>
    /// maps a core tint token (<c>icon.terminal</c>) to a brush. With <paramref name="reuse"/>, rows that did not change
    /// are the earlier tree's row objects (WIN-TREE-REBUILD).
    /// </summary>
    internal static List<TreeItem> Build(FolderDto root, Func<string, Brush?> tint, Func<string, HostColorDto?>? hostColor = null, TreeReuse? reuse = null) =>
        BuildChildren(root, parentId: null, tint, hostColor ?? (_ => null), reuse);

    // ---- WIN-TREE-REBUILD: which rows a rebuild may keep ----

    /// <summary>
    /// Whether <paramref name="made"/> shows and acts exactly as <paramref name="old"/>, so the old row object can stay:
    /// every field a row draws or a command reads, and for a folder the same children (already kept or new) in the same
    /// order. A connection's children are its session and plugin rows, which the window keeps in step itself.
    /// </summary>
    internal static bool SameRow(TreeItem old, TreeItem made) =>
        SameFields(old, made) && (!old.IsFolder || SameObjects(old.Children, made.Children));

    /// <summary>A section rebuilt on every pass (Favorites, Application): the earlier one when all its rows are the same.</summary>
    internal static TreeItem KeepSection(TreeItem? old, TreeItem made) => old is not null && SameSection(old, made) ? old : made;

    private static bool SameSection(TreeItem a, TreeItem b)
    {
        if (!SameFields(a, b) || a.Children.Count != b.Children.Count) return false;
        for (var i = 0; i < a.Children.Count; i++)
            if (!SameSection(a.Children[i], b.Children[i])) return false;
        return true;
    }

    private static bool SameObjects(IList<TreeItem> a, IList<TreeItem> b)
    {
        if (a.Count != b.Count) return false;
        for (var i = 0; i < a.Count; i++)
            if (!ReferenceEquals(a[i], b[i])) return false;
        return true;
    }

    // Brushes come from the window's per-theme cache, so the same tint is the same object. Open (an Application row's
    // action) is not compared: it is the same window method either way.
    private static bool SameFields(TreeItem a, TreeItem b) =>
        a.Id == b.Id && a.Name == b.Name && a.IsFolder == b.IsFolder && a.IsGroup == b.IsGroup && a.IsAppRow == b.IsAppRow
        && a.IsMirror == b.IsMirror && a.IsSession == b.IsSession && a.ParentId == b.ParentId && a.Glyph == b.Glyph
        && a.ArtId == b.ArtId && a.IconLabel == b.IconLabel && a.Description == b.Description && a.Badge == b.Badge
        && ReferenceEquals(a.IconBrush, b.IconBrush) && a.HostColor == b.HostColor && a.Credential == b.Credential
        && a.PluginEntryId == b.PluginEntryId && a.PluginKey == b.PluginKey && SameConnection(a.Connection, b.Connection);

    /// <summary>Record equality, with the tag list compared by its items (a list compares by reference).</summary>
    private static bool SameConnection(ConnectionDto? a, ConnectionDto? b)
    {
        if (ReferenceEquals(a, b)) return true;
        if (a is null || b is null) return false;
        return a with { Tags = null } == b with { Tags = null } && (a.Tags ?? []).SequenceEqual(b.Tags ?? []);
    }

    /// <summary>The Favorites section over the favourite connections in <paramref name="items"/>, or null when there are none.</summary>
    public static TreeItem? Favorites(IEnumerable<TreeItem> items, Func<string, Brush?> tint)
    {
        var favorites = new List<TreeItem>();
        void Collect(IEnumerable<TreeItem> level)
        {
            foreach (var i in level)
            {
                if (i.Connection is { Favorite: true } c) favorites.Add(ConnectionItem(c, i.ParentId, tint, mirror: true, hostColor: i.HostColor));
                Collect(i.Children);
            }
        }
        Collect(items);
        if (favorites.Count == 0) return null;
        var group = new TreeItem
        {
            Id = "group:favorites", Name = "Favorites", IsFolder = false, IsGroup = true, Glyph = FluentIcons.Object("favorite"),
            IconBrush = tint("icon.neutral"), IconLabel = "Favorites", Description = $"Favorites, {favorites.Count} connection{(favorites.Count == 1 ? "" : "s")}",
        };
        group.Children.AddRange(favorites);
        return group;
    }

    /// <summary>The id of the Credentials section heading; its menu adds folders and credentials at the vault root.</summary>
    public const string CredentialsGroupId = "group:credentials";

    /// <summary>The id of the Application section heading (Royal TS layout): Credentials, Tunnels, Workspaces, Default Settings.</summary>
    public const string ApplicationGroupId = "group:application";

    /// <summary>
    /// The Credentials section over the vault's rows (core order: folders, then credentials, by name). While searching,
    /// only credentials whose name or user name match are kept, with the folders that lead to them.
    /// </summary>
    /// <param name="locked">The vault is closed: the heading itself says so, so the state shows even while it is collapsed.</param>
    public static TreeItem CredentialsSection(IReadOnlyList<CredentialTreeRowDto> rows, Func<string, Brush?> tint, string query, bool locked = false)
    {
        var items = rows.ToDictionary(r => r.Id, r => CredentialItem(r, tint));
        var group = new TreeItem
        {
            Id = CredentialsGroupId, Name = locked ? "Credentials (locked)" : "Credentials", IsFolder = false, IsGroup = true, Glyph = FluentIcons.Object("credential"),
            IconBrush = tint("icon.neutral"), IconLabel = "Credentials",
            Description = locked ? "Credentials, locked. Right-click to unlock." : $"Credentials, {rows.Count(r => !r.IsFolder)} saved",
        };
        foreach (var r in rows)
        {
            var parent = r.Parent is { } p && items.TryGetValue(p, out var f) ? f : group;
            parent.Children.Add(items[r.Id]);
        }
        if (query.Length > 0) Prune(group.Children, query);
        return group;
    }

    /// <summary>Drop credentials that do not match and folders left empty by that.</summary>
    private static void Prune(IList<TreeItem> level, string query)
    {
        foreach (var i in level.ToList())
        {
            if (i.Credential is { IsFolder: true })
            {
                Prune(i.Children, query);
                if (i.Children.Count == 0 && !i.Name.Contains(query, StringComparison.OrdinalIgnoreCase)) level.Remove(i);
            }
            else if (!(i.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || (i.Credential?.Username ?? "").Contains(query, StringComparison.OrdinalIgnoreCase)))
                level.Remove(i);
        }
    }

    private static TreeItem CredentialItem(CredentialTreeRowDto r, Func<string, Brush?> tint)
    {
        var kind = r.IsFolder ? "Credential folder" : r.Kind == "ssh-key" ? "SSH key" : r.Kind == "unsupported" ? "Unsupported" : "Password";
        return new TreeItem
        {
            Id = "cred:" + r.Id, Name = r.Name, IsFolder = false, IsGroup = true, Credential = r, ParentId = r.Parent is null ? CredentialsGroupId : "cred:" + r.Parent,
            Glyph = FluentIcons.Object("credential"), ArtId = r.IsFolder ? "folder" : "credential", IconBrush = tint("icon.neutral"), IconLabel = kind,
            Description = r.IsFolder ? kind : r.Kind == "unsupported" ? "Saved by a newer version; it can only be deleted here" : $"{kind}, {r.Username}",
            Badge = r.Kind == "unsupported" ? "Unsupported" : "",
        };
    }

    private static TreeItem ConnectionItem(ConnectionDto c, string? parentId, Func<string, Brush?> tint, bool mirror = false, HostColorDto? hostColor = null)
    {
        var icon = c.Icon ?? c.Protocol;
        var info = IconInfo(icon);
        return new TreeItem
        {
            // The user's own icon (PARITY-01 row 8) replaces the type art; the type stays in the tooltip.
            Id = c.Id, Name = c.Name, IsFolder = false, IsMirror = mirror, ParentId = parentId,
            Glyph = FluentIcons.Object(c.OwnIcon ?? icon), ArtId = c.OwnIcon is null ? ConnectionIcon.Art(icon) ?? ConnectionIcon.Art(c.Protocol) : null, // plugin types: by type id
            IconBrush = tint(info?.Tint ?? "icon.neutral"), IconLabel = TypeLabel(c, c.IconLabel ?? info?.Label ?? c.Protocol.ToUpperInvariant()),
            Connection = c, Description = Describe(c), Expanded = false, HostColor = hostColor,
        };
    }

    private static Dictionary<string, IconDto>? _icons;

    /// <summary>The core's label and tint for an icon id (read once from the core).</summary>
    private static IconDto? IconInfo(string id)
    {
        try { _icons ??= LibraryClient.Icons().ToDictionary(i => i.Id); }
        catch (BastionException) { _icons = new(); }
        return _icons.GetValueOrDefault(id);
    }

    private static List<TreeItem> BuildChildren(FolderDto folder, string? parentId, Func<string, Brush?> tint, Func<string, HostColorDto?> hostColor, TreeReuse? reuse)
    {
        var items = new List<TreeItem>(folder.Folders.Count + folder.Connections.Count);
        foreach (var f in folder.Folders)
        {
            var count = CountConnections(f);
            // Children given at construction: adding them one by one raised TreeChildren.AnyChanged per row (5,000 on a
            // large library), each queueing a tree refresh for rows that are not shown yet.
            var item = new TreeItem
            {
                Id = f.Id, Name = f.Name, IsFolder = true, ParentId = parentId, Glyph = "", Folder = f, ArtId = "folder",
                Description = $"Folder, {count} connection{(count == 1 ? "" : "s")}", HostColor = hostColor(f.Id),
                Children = new TreeChildren(BuildChildren(f, f.Id, tint, hostColor, reuse)),
            };
            items.Add(reuse?.Keep(item) ?? item);
        }
        foreach (var c in folder.Connections)
        {
            var item = ConnectionItem(c, parentId, tint, hostColor: hostColor(c.Id));
            items.Add(reuse?.Keep(item) ?? item);
        }
        return items;
    }

    /// <summary>"SSH Terminal, ops@web-1.acme.example:2222": the icon's full name, user, host and a non-default port.</summary>
    public static string Describe(ConnectionDto c)
    {
        var user = string.IsNullOrEmpty(c.Username) ? "" : c.Username + "@";
        var port = c.Port is { } p && p != DefaultPort(c.Protocol) ? ":" + p : "";
        var kind = TypeLabel(c, c.IconLabel ?? IconInfo(c.Icon ?? c.Protocol)?.Label ?? c.Protocol.ToUpperInvariant());
        return $"{kind}, {user}{c.Host}{port}{(c.Favorite ? ", favorite" : "")}";
    }

    public static int? DefaultPort(string protocol) => protocol switch
    {
        "ssh" or "sftp" or "scp" => 22,
        "rdp" => 3389,
        "vnc" => 5900,
        "ftp" or "ftps" => 21,
        "web" => 443,
        "telnet" => 23,
        _ => null,
    };

    public static TreeItem? Find(IEnumerable<TreeItem> items, string id)
    {
        foreach (var i in items)
        {
            if (i.Id == id) return i;
            var hit = Find(i.Children, id);
            if (hit is not null) return hit;
        }
        return null;
    }

    /// <summary>"Acme Corp / Staging" for an item's parent folder chain; null at the library root.</summary>
    public static string? FolderPath(IEnumerable<TreeItem> roots, string? folderId)
    {
        var names = new List<string>();
        for (var id = folderId; id is not null;)
        {
            var folder = Find(roots, id);
            if (folder is null) break;
            names.Insert(0, folder.Name);
            id = folder.ParentId;
        }
        return names.Count == 0 ? null : string.Join(" / ", names);
    }

    /// <summary>
    /// The items matching <paramref name="query"/> (case-insensitive, on name, host, user, protocol, group and tags; <c>tag:name</c> terms must all be tags), with
    /// the folders that lead to them. A folder whose own name matches keeps all of its contents. Returns copies, so
    /// the full tree is untouched.
    /// </summary>
    public static List<TreeItem> Filter(IEnumerable<TreeItem> items, string query) => Filter(items, TagQuery.Parse(query));

    /// <summary>With <c>tag:</c> terms only connections holding every tag match; folder names do not.</summary>
    private static List<TreeItem> Filter(IEnumerable<TreeItem> items, TagQuery query)
    {
        var result = new List<TreeItem>();
        foreach (var item in items)
        {
            if (Matches(item, query))
            {
                result.Add(item);
                continue;
            }
            if (!item.IsFolder) continue;
            var children = Filter(item.Children, query);
            if (children.Count == 0) continue;
            // Children given at construction: adding them one by one raised TreeChildren.AnyChanged per child, which
            // queued one more full tree refresh after every keystroke.
            var copy = new TreeItem
            {
                Id = item.Id, Name = item.Name, IsFolder = true, ParentId = item.ParentId, Glyph = item.Glyph, ArtId = item.ArtId,
                Folder = item.Folder, Description = item.Description, Children = new TreeChildren(children),
            };
            result.Add(copy);
        }
        return result;
    }

    private static bool Matches(TreeItem item, TagQuery q)
    {
        if (q.Tags.Count > 0)
        {
            if (item.Connection is not { } tagged || !q.Admits(tagged.Tags)) return false;
            if (q.Text.Length == 0) return true;
        }
        var query = q.Text;
        bool Has(string? s) => s is not null && s.Contains(query, StringComparison.OrdinalIgnoreCase);
        if (Has(item.Name)) return true;
        if (item.Children.Any(c => c.IsSession && Has(c.Title))) return true;
        return item.Connection is { } c && (Has(c.Host) || Has(c.Username) || Has(c.Protocol) || Has(c.Group) || (c.Tags?.Any(Has) ?? false));
    }

    /// <summary>Every tag on a connection in <paramref name="items"/>, sorted.</summary>
    public static IReadOnlyList<string> AllTags(IEnumerable<TreeItem> items)
    {
        var seen = new SortedSet<string>(StringComparer.Ordinal);
        void Walk(IEnumerable<TreeItem> level)
        {
            foreach (var i in level)
            {
                if (i.Connection?.Tags is { } tags) seen.UnionWith(tags);
                Walk(i.Children);
            }
        }
        Walk(items);
        return [.. seen];
    }

    public static int CountFolders(IEnumerable<TreeItem> items) => items.Where(i => i.IsFolder).Sum(i => 1 + CountFolders(i.Children));

    public static int CountConnections(IEnumerable<TreeItem> items) => items.Where(i => !i.IsSession).Sum(i => (i.IsFolder ? 0 : 1) + CountConnections(i.Children));
}

/// <summary>A tree row's children: observable, so session rows are inserted and removed one at a time (UI-05).</summary>
public sealed partial class TreeChildren : ObservableCollection<TreeItem>
{
    /// <summary>WIN-FLAT-TREE: any child list changed, so the library tree rebuilds its open-row list (coalesced).</summary>
    public static event Action? AnyChanged;

    public TreeChildren() { }

    public TreeChildren(IEnumerable<TreeItem> items) : base(items) { }

    protected override void OnCollectionChanged(System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
    {
        base.OnCollectionChanged(e);
        AnyChanged?.Invoke();
    }

    public void AddRange(IEnumerable<TreeItem> items) { foreach (var i in items) Add(i); }
}

/// <summary>A session row's status dot (docs/design/SESSION-TREE.md).</summary>
public enum SessionRowState { NotStarted, Connecting, Connected, Failed }

/// <summary>The dot colours: green, amber, red, grey. Fixed in both themes; the state is also in words.</summary>
public static class SessionDots
{
    private static readonly Dictionary<SessionRowState, Brush> Brushes = new();

    public static Windows.UI.Color Color(SessionRowState s) => s switch
    {
        SessionRowState.Connected => Microsoft.UI.ColorHelper.FromArgb(0xFF, 0x16, 0xA3, 0x4A),
        SessionRowState.Connecting => Microsoft.UI.ColorHelper.FromArgb(0xFF, 0xD9, 0x77, 0x06),
        SessionRowState.Failed => Microsoft.UI.ColorHelper.FromArgb(0xFF, 0xDC, 0x26, 0x26),
        _ => Microsoft.UI.ColorHelper.FromArgb(0xFF, 0x8E, 0x8E, 0x93),
    };

    public static Brush Brush(SessionRowState s)
    {
        if (!Brushes.TryGetValue(s, out var b)) Brushes[s] = b = new SolidColorBrush(Color(s));
        return b;
    }
}
