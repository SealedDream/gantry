using System;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>The inspector footer's two values for one connection (C ABI 36). Times are Unix seconds.</summary>
public sealed record ConnectionHistoryDto(long? LastConnectedAt, string? LastUser, string? LastResult);

/// <summary>P/Invoke for core-cabi/src/history.rs: the local, owner-only connection history. Never holds secrets.</summary>
internal static class HistoryNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_connection_history_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_connection_history_success([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? user, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_connection_history_failure([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string error, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_connection_history_forget([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);
}

/// <summary>Reads and records connection history; the core shortens errors and strips anything that looks secret.</summary>
public static class ConnectionHistory
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static ConnectionHistoryDto Get(string dataDir, string connectionId)
    {
        var json = LibraryClient.TakeString(HistoryNative.bastion_connection_history_json(dataDir, connectionId, out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<ConnectionHistoryDto>()) ?? new(null, null, null);
    }

    public static void Success(string dataDir, string connectionId, string? user)
    {
        if (HistoryNative.bastion_connection_history_success(dataDir, connectionId, string.IsNullOrEmpty(user) ? null : user, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not record the connection"));
    }

    public static void Failure(string dataDir, string connectionId, string error)
    {
        if (HistoryNative.bastion_connection_history_failure(dataDir, connectionId, error, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not record the connection"));
    }

    /// <summary>Forgets a connection's history; also "Remove from recents" on the start page.</summary>
    public static void Forget(string dataDir, string connectionId)
    {
        if (HistoryNative.bastion_connection_history_forget(dataDir, connectionId, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not remove the connection from recents"));
    }
}
