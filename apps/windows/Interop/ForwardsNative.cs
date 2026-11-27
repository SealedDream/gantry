using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>A saved tunnel running on a terminal's own SSH connection (core-cabi/src/forwards.rs, ABI 65): a
/// "start with connection" tunnel the core started when the terminal connected.</summary>
public sealed record ForwardStatusDto(string Id, string Name, string Summary, string Kind, int Port, int? MovedFrom, bool Running,
    long Connections, long BytesUp, long BytesDown, string? LastError);

internal static class ForwardsNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_forwards_json(IntPtr t, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_stop_forward(IntPtr t, [MarshalAs(UnmanagedType.LPUTF8Str)] string tunnelId, out IntPtr err);
}

public static class TerminalForwards
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    /// <summary>Tunnels on the terminal's connection (running, failed and stopped); empty for a local shell or a closed terminal.</summary>
    public static IReadOnlyList<ForwardStatusDto> Forwards(this TerminalSession t)
    {
        if (t.IsDisposed) return [];
        var json = LibraryClient.TakeString(ForwardsNative.bastion_terminal_forwards_json(t.NativeHandle, out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<List<ForwardStatusDto>>()) ?? [];
    }

    /// <summary>Stop one tunnel on the terminal's connection; it stays listed as stopped and does not restart on reconnect.</summary>
    public static void StopForward(this TerminalSession t, string tunnelId)
    {
        if (t.IsDisposed) return;
        if (ForwardsNative.bastion_terminal_stop_forward(t.NativeHandle, tunnelId, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not stop the tunnel"));
    }
}
