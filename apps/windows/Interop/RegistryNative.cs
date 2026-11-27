using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>One context-menu entry evaluated by the core registry (core-cabi `bastion_library_menu_json`).</summary>
public sealed record MenuItemDto(string Id, string Label, string Glyph, int Section, bool Enabled, string? DisabledReason,
    bool Destructive, string? Confirm, bool Primary);

/// <summary>A core icon id with its full name (tooltips, screen readers) and colour token.</summary>
public sealed record IconDto(string Id, string Label, string Tint);

/// <summary>Row and icon metrics of an <c>appearance.density</c> (core/src/theme.rs), in device-independent pixels.</summary>
public sealed record ThemeMetricsDto(double TreeRow, double TreeIcon, double TreeIndent, double InspectorRow);

/// <summary>C ABI 15: registry menus, ordered moves, rename, duplicate, sort, favourites, tokens, view state.</summary>
internal static partial class Native
{
    private const string L = "bastion_cabi";

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_menu_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string? id,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? sessions, [MarshalAs(UnmanagedType.LPUTF8Str)] string handled, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_move_before(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? parent, [MarshalAs(UnmanagedType.LPUTF8Str)] string? before, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_rename(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_duplicate(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_sort(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string? id, int recursive, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_copy_text(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, int ssh, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_favorite(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, int favorite, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_icons_json();

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_theme_colors_json(int dark);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_theme_accents_json();

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_theme_metrics_json([MarshalAs(UnmanagedType.LPUTF8Str)] string? density);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_tree_state_open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_tree_state_free(IntPtr state);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_tree_state_expanded_json(IntPtr state, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_tree_state_set_expanded(IntPtr state, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, int expanded, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_tree_state_set_subtree(IntPtr state, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string? id, int expanded, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_tree_state_prune(IntPtr state, IntPtr lib, out IntPtr err);
}

public sealed partial class LibraryClient
{
    private static readonly JsonSerializerOptions Camel = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    /// <summary>
    /// The context menu for a folder or connection (null = the library root), limited to <paramref name="handled"/>.
    /// <paramref name="connected"/> are connections with an open tab.
    /// </summary>
    public List<MenuItemDto> Menu(string? id, IEnumerable<string> handled, IEnumerable<string>? connected = null)
    {
        var sessions = new System.Text.Json.Nodes.JsonObject { ["connected"] = new System.Text.Json.Nodes.JsonArray((connected ?? []).Select(c => (System.Text.Json.Nodes.JsonNode?)c).ToArray()) }.ToJsonString();
        var json = TakeString(Native.bastion_library_menu_json(Handle, id, sessions, AotJson.Write<string[]>(handled.ToArray(), AotJson.Options), out var err), err);
        return JsonSerializer.Deserialize(json, Camel.Info<List<MenuItemDto>>()) ?? [];
    }

    /// <summary>Move into <paramref name="parentId"/> (null = root) before <paramref name="beforeId"/> (null = last).</summary>
    public void MoveBefore(string id, string? parentId, string? beforeId) =>
        Check(Native.bastion_library_move_before(Handle, id, parentId, beforeId, out var err), err, "could not move the item");

    public void Rename(string id, string name) => Check(Native.bastion_library_rename(Handle, id, name, out var err), err, "could not rename");

    /// <summary>Returns the copy's id.</summary>
    public string Duplicate(string id) => TakeString(Native.bastion_library_duplicate(Handle, id, out var err), err);

    public void Sort(string? folderId) => Check(Native.bastion_library_sort(Handle, folderId, 0, out var err), err, "could not sort");

    /// <summary>Copy SSH Command (<paramref name="sshCommand"/>) or Copy Address text.</summary>
    public string CopyText(string id, bool sshCommand) => TakeString(Native.bastion_library_copy_text(Handle, id, sshCommand ? 1 : 0, out var err), err);

    public void SetFavorite(string id, bool favorite) =>
        Check(Native.bastion_library_set_favorite(Handle, id, favorite ? 1 : 0, out var err), err, "could not change Favorites");

    public static List<IconDto> Icons() => JsonSerializer.Deserialize(TakeString(Native.bastion_icons_json(), IntPtr.Zero), Camel.Info<List<IconDto>>()) ?? [];

    /// <summary>Colour tokens (<c>icon.terminal</c> → <c>#RRGGBB</c>) for the dark or light theme.</summary>
    public static Dictionary<string, string> ThemeColors(bool dark) =>
        JsonSerializer.Deserialize(TakeString(Native.bastion_theme_colors_json(dark ? 1 : 0), IntPtr.Zero), AotJson.Options.Info<Dictionary<string, string>>()) ?? [];

    /// <summary>The accent palette (C ABI 18): <c>appearance.accent</c> id → <c>#RRGGBB</c>.</summary>
    public static Dictionary<string, string> ThemeAccents() =>
        JsonSerializer.Deserialize(TakeString(Native.bastion_theme_accents_json(), IntPtr.Zero), AotJson.Options.Info<Dictionary<string, string>>()) ?? [];

    /// <summary>Metrics for a density id (an unknown id gives comfortable).</summary>
    public static ThemeMetricsDto ThemeMetrics(string density) =>
        JsonSerializer.Deserialize(TakeString(Native.bastion_theme_metrics_json(density), IntPtr.Zero), Camel.Info<ThemeMetricsDto>()) ?? new ThemeMetricsDto(26, 16, 16, 24);

    internal static void Check(int rc, IntPtr err, string fallback)
    {
        if (rc != 0) throw new BastionException(TakeError(err, fallback));
    }
}

/// <summary>Persisted view state (<c>ui-state.json</c> next to the library): which folders are open. Saved on every change.</summary>
public sealed partial class TreeStateClient : IDisposable
{
    private IntPtr _handle;

    private TreeStateClient(IntPtr handle) => _handle = handle;

    public static TreeStateClient Open(string path)
    {
        var h = Native.bastion_tree_state_open(path, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "could not open the view state"));
        return new TreeStateClient(h);
    }

    private IntPtr Handle => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(TreeStateClient));

    public HashSet<string> Expanded() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(Native.bastion_tree_state_expanded_json(Handle, out var err), err), AotJson.Options.Info<HashSet<string>>()) ?? [];

    public void SetExpanded(string folderId, bool expanded) =>
        LibraryClient.Check(Native.bastion_tree_state_set_expanded(Handle, folderId, expanded ? 1 : 0, out var err), err, "could not save the view state");

    /// <summary>Expand All / Collapse All below <paramref name="folderId"/> (null = the whole library).</summary>
    public void SetSubtree(LibraryClient library, string? folderId, bool expanded) =>
        LibraryClient.Check(Native.bastion_tree_state_set_subtree(Handle, library.Handle, folderId, expanded ? 1 : 0, out var err), err, "could not save the view state");

    /// <summary>Forget folders that were deleted.</summary>
    public void Prune(LibraryClient library) =>
        LibraryClient.Check(Native.bastion_tree_state_prune(Handle, library.Handle, out var err), err, "could not save the view state");

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        Native.bastion_tree_state_free(_handle);
        _handle = IntPtr.Zero;
    }
}
