using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for core-cabi/src/tabs.rs (C ABI 32): tab strip operations and folder auto-grouping.</summary>
internal static class TabGroupNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_tab_strip_apply_json([MarshalAs(UnmanagedType.LPUTF8Str)] string strip, [MarshalAs(UnmanagedType.LPUTF8Str)] string op, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_tab_strip_auto_group_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string strip, int enabled, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_tab_group_colors_json();
}

/// <summary>The core's tab strip rules (the same as Native Mac and Tauri). The strip crosses as JSON with tab and connection ids only.</summary>
public static class TabGroups
{
    /// <summary>Applies one op (<c>newGroup</c>, <c>rename</c>, <c>recolor</c>, <c>setCollapsed</c>, <c>addToGroup</c>,
    /// <c>removeFromGroup</c>, <c>move</c>, <c>ungroup</c>, <c>closeGroup</c>). Returns <c>{"strip","closed"}</c>.</summary>
    public static JsonObject Apply(JsonObject strip, JsonObject op) =>
        Parse(LibraryClient.TakeString(TabGroupNative.bastion_tab_strip_apply_json(strip.ToJsonString(), op.ToJsonString(), out var err), err));

    /// <summary>Groups tabs of one folder (two or more) under the folder's name and inherited tab group colour.</summary>
    public static JsonObject AutoGroup(LibraryClient library, JsonObject strip) =>
        Parse(LibraryClient.TakeString(TabGroupNative.bastion_tab_strip_auto_group_json(library.NativeHandle, strip.ToJsonString(), 1, out var err), err));

    /// <summary>The eight group colours as (id, label).</summary>
    public static IReadOnlyList<(string Id, string Label)> Colors()
    {
        var json = LibraryClient.TakeString(TabGroupNative.bastion_tab_group_colors_json(), IntPtr.Zero);
        return (JsonNode.Parse(json) as JsonArray ?? [])
            .Select(c => ((string?)c?["id"] ?? "", (string?)c?["label"] ?? ""))
            .Where(c => c.Item1.Length > 0)
            .ToList();
    }

    private static JsonObject Parse(string json) =>
        JsonNode.Parse(json) as JsonObject ?? throw new BastionException("the core returned an invalid tab strip");
}
