using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

/// <summary>One session of the activity store (core-cabi/src/activity.rs, C ABI 98). Times are Unix milliseconds.
/// Metadata only: no secrets, no session content.</summary>
public sealed record ActivitySessionDto(
    string SessionId, string ConnectionId, string ConnectionName, string Protocol, string Host, int? Port,
    string? Username, long StartedAt, bool Open, long? ConnectedAt, long? EndedAt, long? DurationMs, string? EndReason,
    int? Reconnects, string? TranscriptPath);

/// <summary>The query the core filters on: every field that is set must match. Null fields are left out of the JSON.</summary>
public sealed record ActivityFilter(string? Protocol = null, string? Result = null, long? From = null, long? To = null,
    string? User = null, string? Connection = null, string? Folder = null);

/// <summary>P/Invoke for core-cabi/src/activity.rs. Every call can touch the disk: call it off the UI thread.</summary>
internal static class ActivityNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_activity_query_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string filterJson, uint offset, uint limit, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_activity_purge([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_activity_close_orphans([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport("bastion_cabi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_activity_begin([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string startJson, out IntPtr err);

    [DllImport("bastion_cabi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_activity_end([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string sessionId, [MarshalAs(UnmanagedType.LPUTF8Str)] string endJson, out IntPtr err);
}

/// <summary>Reads the session history. The core records SSH, SFTP, SCP and FTPS sessions itself.</summary>
public static class ActivityClient
{
    /// <summary>The core's page cap.</summary>
    public const int PageSize = 500;

    // JSON options: ActivityJsonContext (InteropJsonContexts.cs), source-generated for trimming.

    public static string FilterJson(ActivityFilter filter) => JsonSerializer.Serialize(filter, ActivityJsonContext.Default.ActivityFilter);

    /// <summary>One page, newest first.</summary>
    public static IReadOnlyList<ActivitySessionDto> Query(string dataDir, ActivityFilter filter, int offset, int limit = PageSize)
    {
        var json = LibraryClient.TakeString(ActivityNative.bastion_activity_query_json(dataDir, FilterJson(filter), (uint)Math.Max(0, offset),
            (uint)Math.Clamp(limit, 1, PageSize), out var err), err);
        return Parse(json);
    }

    public static IReadOnlyList<ActivitySessionDto> Parse(string json) =>
        JsonSerializer.Deserialize(json, ActivityJsonContext.Default.ListActivitySessionDto) ?? [];

    /// <summary>One folder on the way to a connection, root first.</summary>
    public sealed record FolderRef(string Id, string Name);

    /// <summary>What the app knows when an app-driven session (RDP, VNC, web) starts. No secrets: there is no field for one.</summary>
    public sealed record SessionStart(string ConnectionId, string ConnectionName, IReadOnlyList<FolderRef> FolderPath, string Protocol,
        string Host, int? Port, string? Username, IReadOnlyList<string> Route, string LoginSource, long StartedAt, string App,
        string AppVersion, string DeviceName);

    public sealed record SessionEnd(long? ConnectedAt, long EndedAt, string EndReason);

    /// <summary>The core refuses a start whose login source is "unknown" (that value is only ever read), so the app
    /// says where the login came from: VNC asks for a password, the others use the connection's own saved user or ask.</summary>
    public static string LoginSourceFor(string protocol, bool hasSavedUsername) =>
        protocol == "vnc" || !hasSavedUsername ? "typed" : "own";

    public static string StartJson(SessionStart start) => JsonSerializer.Serialize(start, ActivityJsonContext.Default.SessionStart);
    public static string EndJson(SessionEnd end) => JsonSerializer.Serialize(end, ActivityJsonContext.Default.SessionEnd);

    /// <summary>Record the start; returns the core's session id. Touches the disk: call off the UI thread.</summary>
    public static string Begin(string dataDir, SessionStart start) =>
        LibraryClient.TakeString(ActivityNative.bastion_activity_begin(dataDir, StartJson(start), out var err), err);

    /// <summary>Record the end, once. Touches the disk: call off the UI thread.</summary>
    public static void End(string dataDir, string sessionId, SessionEnd end)
    {
        if (ActivityNative.bastion_activity_end(dataDir, sessionId, EndJson(end), out var err) < 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not record the end of a session"));
    }

    /// <summary>The core's end reason for the short error the app's connect sites record.</summary>
    public static string FailureReason(string error) =>
        error.StartsWith("Authentication failed", StringComparison.Ordinal) ? "auth_failed"
        : error.StartsWith("Timed out", StringComparison.Ordinal) ? "timeout" : "failed";

    /// <summary>At launch: drop history past the retention setting, then close sessions a crashed run left open.</summary>
    public static void Housekeep(string dataDir)
    {
        if (ActivityNative.bastion_activity_purge(dataDir, out var err) < 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not purge the session history"));
        if (ActivityNative.bastion_activity_close_orphans(dataDir, out err) < 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not close old sessions"));
    }
}

/// <summary>The words and files the Activity page shows; no WinUI here, so the console test checks them.</summary>
public static class ActivityFormat
{
    /// <summary>"Open", or how the session ended, short.</summary>
    public static string Result(ActivitySessionDto s) => s.Open ? "Open" : s.EndReason switch
    {
        "closed_by_user" => "Closed",
        "remote_closed" => "Closed by host",
        "app_quit" => "App quit",
        "network_lost" => "Network lost",
        "auth_failed" => "Sign-in failed",
        "host_key" => "Host key rejected",
        "timeout" => "Timed out",
        "app_crashed" => "App stopped",
        "failed" => "Failed",
        _ => "Unknown",
    };

    /// <summary>True for a normal end (as the core's result filter "ok").</summary>
    public static bool IsOk(ActivitySessionDto s) => s.EndReason is "closed_by_user" or "remote_closed" or "app_quit";

    /// <summary>"45 s", "12 min", "3 h 05 min"; "—" with no duration.</summary>
    public static string Duration(long? ms)
    {
        if (ms is not { } v || v < 0) return "—";
        var t = TimeSpan.FromMilliseconds(v);
        if (t.TotalSeconds < 60) return $"{(int)t.TotalSeconds} s";
        if (t.TotalMinutes < 60) return $"{(int)t.TotalMinutes} min";
        return $"{(int)t.TotalHours} h {t.Minutes:00} min";
    }

    public static string Protocol(string p) => p.ToUpperInvariant();

    /// <summary>A History row in the details pane: "Today 14:05 · ops · 12 min · Closed"; a folder's rows start with the
    /// connection's name. <paramref name="when"/> is the start, already formatted by the app.</summary>
    public static string HistoryLine(ActivitySessionDto s, bool withConnection, string when)
    {
        var parts = new List<string>();
        if (withConnection) parts.Add(s.ConnectionName);
        parts.Add(when);
        if (s.Username is { Length: > 0 } u) parts.Add(u);
        if (!s.Open) parts.Add(Duration(s.DurationMs));
        parts.Add(Result(s));
        return string.Join(" · ", parts);
    }

    /// <summary>"host" or "host:port".</summary>
    public static string Target(ActivitySessionDto s) => s.Port is { } port ? $"{s.Host}:{port}" : s.Host;

    /// <summary>The free-text filter: connection name, host or user, ignoring case.</summary>
    public static bool Matches(ActivitySessionDto s, string text) =>
        text.Length == 0
        || s.ConnectionName.Contains(text, StringComparison.CurrentCultureIgnoreCase)
        || s.Host.Contains(text, StringComparison.CurrentCultureIgnoreCase)
        || (s.Username?.Contains(text, StringComparison.CurrentCultureIgnoreCase) ?? false);

    /// <summary>Start of the range for "Last 24 hours", "Last 7 days", "Last 30 days"; null for all.</summary>
    public static long? RangeStart(string range, DateTimeOffset now) => range switch
    {
        "day" => now.AddDays(-1).ToUnixTimeMilliseconds(),
        "week" => now.AddDays(-7).ToUnixTimeMilliseconds(),
        "month" => now.AddDays(-30).ToUnixTimeMilliseconds(),
        _ => null,
    };

    private static readonly string[] Columns = ["Started", "Connection", "Protocol", "Host", "User", "Duration", "Result"];

    private static string[] Cells(ActivitySessionDto s) =>
    [
        DateTimeOffset.FromUnixTimeMilliseconds(s.StartedAt).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        s.ConnectionName, Protocol(s.Protocol), Target(s), s.Username ?? "", Duration(s.DurationMs), Result(s),
    ];

    /// <summary>CSV of exactly the rows and columns shown. A cell a spreadsheet would run as a formula gets a leading
    /// apostrophe.</summary>
    public static string Csv(IEnumerable<ActivitySessionDto> rows)
    {
        var sb = new StringBuilder();
        sb.Append(string.Join(',', Columns)).Append("\r\n");
        foreach (var s in rows) sb.Append(string.Join(',', Cells(s).Select(CsvCell))).Append("\r\n");
        return sb.ToString();
    }

    public static string CsvCell(string v)
    {
        if (v.Length > 0 && v[0] is '=' or '+' or '-' or '@' or '\t' or '\r') v = "'" + v;
        return v.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;
    }

    /// <summary>JSON of exactly the rows and columns shown.</summary>
    public static string JsonExport(IEnumerable<ActivitySessionDto> rows) =>
        JsonSerializer.Serialize(rows.Select(s => Columns.Zip(Cells(s)).ToDictionary(p => p.First.ToLowerInvariant(), p => p.Second)).ToList(),
            ActivityExportJsonContext.Default.ListDictionaryStringString);
}
