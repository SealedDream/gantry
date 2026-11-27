using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

/// <summary>One saved tab: connection id, "terminal" or "files", optional pane layout, group and remote cwd. No secrets.</summary>
public sealed record OpenTabDto(string Connection, string Mode, JsonNode? Layout = null, string? Group = null, string? Cwd = null, string? Window = null);

/// <summary>B12-W2c (core B12-C <c>SavedWindow</c>): a torn-off window's id, frame (screen pixels, top-left origin) and
/// the index in the set's tabs of its front tab.</summary>
public sealed record SavedWindowDto(string Id, double X, double Y, double Width, double Height, int? Selected = null);

/// <summary>What the core says to do at launch (C ABI 80). <c>LastExit</c> is "none", "clean" or "crash".</summary>
public sealed record LaunchPlanDto(string LastExit, bool Restore, List<OpenTabDto> Tabs, int? Selected, JsonArray Groups, int Missing, bool AutoReconnect, List<SavedWindowDto>? Windows = null);

/// <summary>One start page "Recent sessions" row; <c>LastConnectedAt</c> is Unix seconds.</summary>
public sealed record RecentSessionDto(string Connection, string Name, string Host, int? Port, string? User, string Protocol, long LastConnectedAt, string? LastError);

/// <summary>P/Invoke for core-cabi/src/open_sessions.rs (ABI 80).</summary>
internal static class SessionRestoreNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_open_sessions_save([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string setJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_open_sessions_mark_clean_quit([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_open_sessions_begin_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, int restoreOnLaunch, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_recent_sessions_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, uint limit, out IntPtr err);
}

/// <summary>Session restore after a crash: call <see cref="Begin"/> once at launch, <see cref="Save"/> after every tab
/// change, <see cref="MarkCleanQuit"/> on a normal quit. Restored tabs reconnect with auto-reconnect on.</summary>
public static class SessionRestore
{
    /// <summary>The "Restore sessions on launch" setting id (toggle, default on).</summary>
    public const string RestoreSettingId = "session.restore-on-launch";

    private static readonly JsonSerializerOptions Json = new()
    {
        TypeInfoResolver = AotJson.Resolver,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static LaunchPlanDto Begin(LibraryClient library, string dataDir, bool restoreOnLaunch)
    {
        var json = LibraryClient.TakeString(SessionRestoreNative.bastion_open_sessions_begin_json(library.NativeHandle, dataDir, restoreOnLaunch ? 1 : 0, out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<LaunchPlanDto>()) ?? throw new BastionException("invalid launch plan");
    }

    public static void Save(string dataDir, IReadOnlyList<OpenTabDto> tabs, int selected, JsonArray? groups = null, IReadOnlyList<SavedWindowDto>? windows = null)
    {
        var set = new JsonObject
        {
            ["tabs"] = AotJson.WriteToNode<IReadOnlyList<OpenTabDto>>(tabs, Json),
            ["selected"] = selected,
            ["groups"] = groups?.DeepClone() ?? new JsonArray(),
            ["windows"] = AotJson.WriteToNode<IReadOnlyList<SavedWindowDto>>(windows ?? [], Json),
        };
        if (SessionRestoreNative.bastion_open_sessions_save(dataDir, set.ToJsonString(), out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not save the open sessions"));
    }

    public static void MarkCleanQuit(string dataDir)
    {
        if (SessionRestoreNative.bastion_open_sessions_mark_clean_quit(dataDir, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not record the quit"));
    }

    /// <summary>Most recent first. "Remove from recents" is <see cref="ConnectionHistory.Forget"/>.</summary>
    public static IReadOnlyList<RecentSessionDto> Recents(LibraryClient library, string dataDir, uint limit = 50)
    {
        var json = LibraryClient.TakeString(SessionRestoreNative.bastion_recent_sessions_json(library.NativeHandle, dataDir, limit, out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<List<RecentSessionDto>>()) ?? [];
    }
}
