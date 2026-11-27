using System;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for session log v2 (C ABI 138, LOG-CORE-02): the core plans the path, header, timestamps and
/// retention; the app passes its data folder, name, version and UTC offset.</summary>
internal static class SessionLogV2Native
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_session_log_plan_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string app,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string version, int utcOffsetMinutes, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_start_planned_log(IntPtr t, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string app,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string version, int utcOffsetMinutes, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_log_state_json(IntPtr t, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_finish_log(IntPtr t, [MarshalAs(UnmanagedType.LPUTF8Str)] string? reason, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_purge_session_logs_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string? root,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);
}

/// <summary>The core shows the session log v2 settings only to an app that reports this capability.</summary>
public static class SessionLogV2
{
    public const string Capability = "session-log-v2";
}

/// <summary>Where and how a saved connection's session would be logged.</summary>
public sealed record SessionLogPlan(string Root, string Path, bool Timestamps);

/// <summary>A terminal's log: <c>off</c>, <c>active</c> (with <see cref="Path"/>) or <c>stopped</c> (with <see cref="Reason"/>).</summary>
public sealed record SessionLogState(string State, string? Path, string? Reason)
{
    public bool IsActive => State == "active";
    public bool IsStopped => State == "stopped";

    internal static SessionLogState Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        return new(Str(r, "state") ?? "off", Str(r, "path"), Str(r, "reason"));
    }

    internal static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>What one retention pass removed.</summary>
public sealed record SessionLogPurge(long DeletedFiles, long FreedBytes, long RemovedFolders);

/// <summary>The app identity the core writes into every log header.</summary>
public readonly record struct SessionLogContext(string DataDir, string App, string Version)
{
    /// <summary>The local time's offset now, in whole minutes (the core has no time-zone data).</summary>
    public static int UtcOffsetMinutes() => (int)TimeZoneInfo.Local.GetUtcOffset(DateTime.Now).TotalMinutes;
}

public sealed partial class LibraryClient
{
    public SessionLogPlan SessionLogPlan(string connectionId, SessionLogContext ctx)
    {
        var json = TakeString(SessionLogV2Native.bastion_session_log_plan_json(Handle, connectionId, ctx.DataDir, ctx.App, ctx.Version,
            SessionLogContext.UtcOffsetMinutes(), out var err), err);
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        return new(SessionLogState.Str(r, "root") ?? "", SessionLogState.Str(r, "path") ?? "",
            r.TryGetProperty("timestamps", out var t) && t.ValueKind == JsonValueKind.True);
    }

    /// <summary>Apply retention (settings and each folder's keep-days) under <paramref name="root"/> (null: the default
    /// root). Holds a lease, so it is safe off the UI thread.</summary>
    public SessionLogPurge PurgeSessionLogs(string? root, string dataDir)
    {
        using var lease = AcquireLease();
        var json = TakeString(SessionLogV2Native.bastion_purge_session_logs_json(lease.Handle, root, dataDir, out var err), err);
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        static long N(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.TryGetInt64(out var x) ? x : 0;
        return new(N(r, "deleted_files"), N(r, "freed_bytes"), N(r, "removed_folders"));
    }
}

public sealed partial class TerminalSession
{
    /// <summary>Start the planned log for saved connection <paramref name="connectionId"/>; returns the file used.</summary>
    public string StartPlannedLog(LibraryClient library, string connectionId, SessionLogContext ctx) =>
        LibraryClient.TakeString(SessionLogV2Native.bastion_terminal_start_planned_log(H, library.NativeHandle, connectionId, ctx.DataDir, ctx.App,
            ctx.Version, SessionLogContext.UtcOffsetMinutes(), out var err), err);

    public SessionLogState LogState() =>
        SessionLogState.Parse(LibraryClient.TakeString(SessionLogV2Native.bastion_terminal_log_state_json(H, out var err), err));

    /// <summary>Stop the log with <paramref name="reason"/> in its footer. Returns the file's SHA-256, or null when no
    /// log was running.</summary>
    public string? FinishLog(string reason)
    {
        var s = SessionLogV2Native.bastion_terminal_finish_log(H, reason, out var err);
        if (s == IntPtr.Zero)
        {
            if (err != IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "could not finish the session log"));
            return null;
        }
        return LibraryClient.TakeString(s, err);
    }
}
