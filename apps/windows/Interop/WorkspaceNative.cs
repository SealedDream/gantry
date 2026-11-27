using System.Text.Json.Nodes;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

internal static class WorkspaceNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_workspaces_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_workspace_save([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionIdsJson, uint selected, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_workspace_save_layout([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string tabsJson, uint selected, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_workspace_save_grouped_layout([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string tabsJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string groupsJson, uint selected, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_workspace_add_tab([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string tabJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_workspace_rename([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_workspace_duplicate([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_workspace_mark_used([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_workspace_create([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string tabsJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_workspace_restore_plan_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string existingJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string openJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_workspace_remove([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);
}

/// <summary>
/// One saved tab. <see cref="Layout"/> (C ABI 16) is its split panes in pre-order: <c>leaf</c>, or <c>right:0.620</c> /
/// <c>down:0.500</c> followed by the two children, the ratio being the first child's share; empty = one pane.
/// <see cref="Group"/> (C ABI 32) is the id of the tab group it belongs to, from <see cref="WorkspaceDto.Groups"/>; null = none.
/// </summary>
public sealed record WorkspaceTabDto(string Connection, string Mode, List<string>? Layout = null, string? Group = null);

/// <summary>A saved set of connection tabs. Ids only: no hosts, users or secrets. <see cref="LastUsed"/> is Unix seconds.
/// <see cref="Groups"/>: the tab groups its tabs refer to, <c>[{"id","name","color","collapsed","folder"}]</c> (Codex Y03).</summary>
public sealed record WorkspaceDto(string Id, string Name, int Selected, List<WorkspaceTabDto> Tabs, long? LastUsed = null,
    System.Text.Json.Nodes.JsonArray? Groups = null);

/// <summary>
/// What opening a workspace should do (C ABI 61): tabs to connect in order (deleted and already-open ones left
/// out), how many were dropped as deleted, and the saved tab to select.
/// </summary>
public sealed record WorkspaceRestorePlanDto(List<WorkspaceTabDto> Open, int Missing, WorkspaceTabDto? Select);

/// <summary>The per-user <c>workspaces.json</c> next to the library (core <c>WorkspaceStore</c>).</summary>
public sealed class WorkspaceStore
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private readonly string _dataDir;

    public WorkspaceStore(string dataDir) => _dataDir = dataDir;

    public IReadOnlyList<WorkspaceDto> List()
    {
        var p = WorkspaceNative.bastion_workspaces_json(_dataDir, out var err);
        if (p == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not read the workspaces");
        return JsonSerializer.Deserialize(Take(p) ?? "[]", Json.Info<List<WorkspaceDto>>()) ?? [];
    }

    /// <summary>Save (or replace, by name) a workspace of these connection tabs; returns its id.</summary>
    /// <summary>Save tabs by connection id and mode ("terminal", or "files" for a tab with its Files panel open).</summary>
    /// <summary>Tabs as the core stores them: [{"connection","mode"}] (no reflection: Native AOT).</summary>
    private static string TabsJson(IEnumerable<WorkspaceTabDto> tabs) =>
        new JsonArray(tabs.Select(t => (JsonNode)new JsonObject { ["connection"] = t.Connection, ["mode"] = t.Mode }).ToArray()).ToJsonString();

    public string Save(string name, IReadOnlyList<WorkspaceTabDto> tabs, int selected)
    {
        var json = TabsJson(tabs);
        var p = WorkspaceNative.bastion_workspace_save(_dataDir, name, json, (uint)Math.Max(0, selected), out var err);
        return Take(p) ?? throw new BastionException(Take(err) ?? "could not save the workspace");
    }

    /// <summary>
    /// Save Current Layout: same name (any case) keeps the workspace and its place; marks it used. Each tab keeps its
    /// tab group; <paramref name="groupsJson"/> holds those groups' definitions (Codex Y03).
    /// </summary>
    public WorkspaceDto SaveLayout(string name, IReadOnlyList<WorkspaceTabDto> tabs, int selected, string groupsJson = "[]")
    {
        var json = new JsonArray(tabs.Select(t => (JsonNode)new JsonObject { ["connection"] = t.Connection, ["mode"] = t.Mode, ["layout"] = new JsonArray((t.Layout ?? []).Select(l => (JsonNode?)l).ToArray()), ["group"] = t.Group }).ToArray()).ToJsonString();
        return Parse(WorkspaceNative.bastion_workspace_save_grouped_layout(_dataDir, name, json, groupsJson, (uint)Math.Max(0, selected), out var err), err, "could not save the workspace");
    }

    /// <summary>Add to Workspace: append one tab; the same connection and mode twice is refused.</summary>
    public WorkspaceDto AddTab(string id, WorkspaceTabDto tab) =>
        Parse(WorkspaceNative.bastion_workspace_add_tab(_dataDir, id, new JsonObject { ["connection"] = tab.Connection, ["mode"] = tab.Mode }.ToJsonString(), out var err), err, "could not add the tab");

    public void Rename(string id, string name)
    {
        if (WorkspaceNative.bastion_workspace_rename(_dataDir, id, name, out var err) != 0) throw new BastionException(Take(err) ?? "could not rename the workspace");
    }

    /// <summary>
    /// New Workspace: a name already used (any case) is refused; returns the id. Tabs are stored by connection
    /// and mode only (split layouts are not kept; use <see cref="SaveLayout"/> for the current layout).
    /// </summary>
    public string Create(string name, IReadOnlyList<WorkspaceTabDto> tabs)
    {
        var json = TabsJson(tabs);
        return Take(WorkspaceNative.bastion_workspace_create(_dataDir, name, json, out var err)) ?? throw new BastionException(Take(err) ?? "could not create the workspace");
    }

    /// <summary>
    /// Read-only plan for opening workspace <paramref name="id"/>: <paramref name="existing"/> = connection ids in
    /// the library, <paramref name="open"/> = live tabs. Call <see cref="MarkUsed"/> once it is opened.
    /// </summary>
    public WorkspaceRestorePlanDto RestorePlan(string id, IEnumerable<string> existing, IEnumerable<WorkspaceTabDto> open)
    {
        var live = TabsJson(open);
        var p = WorkspaceNative.bastion_workspace_restore_plan_json(_dataDir, id, AotJson.Write<IEnumerable<string>>(existing, AotJson.Options), live, out var err);
        var json = Take(p) ?? throw new BastionException(Take(err) ?? "could not plan the workspace");
        return JsonSerializer.Deserialize(json, Json.Info<WorkspaceRestorePlanDto>()) ?? throw new BastionException("could not plan the workspace");
    }

    public WorkspaceDto Duplicate(string id) => Parse(WorkspaceNative.bastion_workspace_duplicate(_dataDir, id, out var err), err, "could not duplicate the workspace");

    public void MarkUsed(string id)
    {
        if (WorkspaceNative.bastion_workspace_mark_used(_dataDir, id, out var err) != 0) throw new BastionException(Take(err) ?? "could not update the workspace");
    }

    private static WorkspaceDto Parse(IntPtr p, IntPtr err, string fallback)
    {
        var json = Take(p) ?? throw new BastionException(Take(err) ?? fallback);
        return JsonSerializer.Deserialize(json, Json.Info<WorkspaceDto>()) ?? throw new BastionException(fallback);
    }

    public void Remove(string id)
    {
        if (WorkspaceNative.bastion_workspace_remove(_dataDir, id, out var err) != 0) throw new BastionException(Take(err) ?? "could not remove the workspace");
    }

    private static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { Native.bastion_string_free(s); }
    }
}
