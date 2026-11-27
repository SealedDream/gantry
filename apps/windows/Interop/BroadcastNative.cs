using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for core-cabi/src/panes.rs (C ABI 53): the broadcast input review.</summary>
internal static class BroadcastNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_broadcast_review_json([MarshalAs(UnmanagedType.LPUTF8Str)] string kind, [MarshalAs(UnmanagedType.LPUTF8Str)] string input,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string targets, int acknowledged, out IntPtr err);
}

/// <summary>One pane that may receive broadcast input.</summary>
public sealed record BroadcastTarget(string Pane, string Name, bool Connected, bool Sensitive);

/// <summary>The core's answer: who gets the input, who is skipped (disconnected), and whether to ask first.</summary>
public sealed record BroadcastReview(IReadOnlyList<string> SendTo, IReadOnlyList<string> Skipped, IReadOnlyList<string> Sensitive, bool NeedsConfirm);

/// <summary>Broadcast rules shared with Native Mac and Tauri: disconnected panes are skipped, a multi-line paste to several
/// panes or a not-yet-acknowledged sensitive host asks first, and NUL, over 64 KiB or a bracketed-paste end sequence is refused.</summary>
public static class Broadcast
{
    /// <summary><paramref name="paste"/> selects the paste rules; otherwise keystrokes. Throws <see cref="BastionException"/> on refused input.</summary>
    public static BroadcastReview Review(bool paste, string input, IEnumerable<BroadcastTarget> targets, bool acknowledged)
    {
        var list = new JsonArray(targets.Select(t => (JsonNode)new JsonObject { ["pane"] = t.Pane, ["name"] = t.Name, ["connected"] = t.Connected, ["sensitive"] = t.Sensitive }).ToArray());
        var json = LibraryClient.TakeString(BroadcastNative.bastion_broadcast_review_json(paste ? "paste" : "keys", input, list.ToJsonString(), acknowledged ? 1 : 0, out var err), err);
        var o = JsonNode.Parse(json) as JsonObject ?? throw new BastionException("the core returned an invalid broadcast review");
        static List<string> Ids(JsonNode? n) => (n as JsonArray ?? []).Select(x => (string?)x ?? "").Where(x => x.Length > 0).ToList();
        return new(Ids(o["sendTo"]), Ids(o["skipped"]), Ids(o["sensitive"]), (bool?)o["needsConfirm"] ?? false);
    }
}
