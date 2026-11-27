using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>A saved tunnel (core tunneldefs). <see cref="Kind"/> is <c>local</c>, <c>remote</c> or <c>dynamic</c>.</summary>
public sealed record TunnelDefDto(string Id, string Name, string ViaId, string ViaName, string Kind, int LocalPort, string Host, int Port,
    string Summary, bool StartWithConnection);

/// <summary>What a running tunnel reports (<c>bastion_tunnel_status_json</c>).</summary>
public sealed record TunnelStatusDto(string Summary, bool Running, long Connections, string? LastError);

/// <summary>P/Invoke for the saved-tunnel list (core-cabi/src/webtunnel.rs) and running tunnels (core-cabi/src/tunnels.rs, ABI 72).</summary>
internal static class TunnelNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_tunnels_json(IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_put_tunnel_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_remove_tunnel(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    // Secrets as raw pointers the caller zeroes (see Utf8Secret), as for bastion_session_connect_ssh_mfa.
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_tunnel_start(
        IntPtr m,
        IntPtr lib,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string tunnelId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        int loginKind,
        IntPtr password,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath,
        IntPtr code,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? trustFingerprint,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? jumpTrustJson,
        IntPtr jumpLoginsJson,
        out int outcome,
        out IntPtr fingerprint,
        out IntPtr hop,
        out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_tunnel_status_json(IntPtr t, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_tunnel_stop(IntPtr t, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_tunnel_free(IntPtr t);
}

public sealed partial class LibraryClient
{
    public IReadOnlyList<TunnelDefDto> Tunnels() =>
        JsonSerializer.Deserialize(TakeString(TunnelNative.bastion_library_tunnels_json(Handle, out var err), err), Json.Info<List<TunnelDefDto>>()) ?? [];

    /// <summary>Add (empty <see cref="TunnelDefDto.Id"/>) or replace a tunnel; returns its id. Save the library after.</summary>
    public string PutTunnel(TunnelDefDto t)
    {
        var body = new System.Text.Json.Nodes.JsonObject
        {
            ["id"] = t.Id, ["name"] = t.Name, ["viaId"] = t.ViaId, ["kind"] = t.Kind, ["localPort"] = t.LocalPort,
            ["host"] = t.Host, ["port"] = t.Port, ["startWithConnection"] = t.StartWithConnection,
        }.ToJsonString();
        return TakeString(TunnelNative.bastion_library_put_tunnel_json(Handle, body, out var err), err);
    }

    public void RemoveTunnel(string id)
    {
        if (TunnelNative.bastion_library_remove_tunnel(Handle, id, out var err) != 0) throw new BastionException(TakeError(err, "could not remove the tunnel"));
    }
}

/// <summary>The result of one tunnel start. <see cref="Tunnel"/> is set only for <see cref="ConnectOutcome.Ok"/>. Never carries a secret.</summary>
public sealed record TunnelStartResult(ConnectOutcome Outcome, RunningTunnelHandle? Tunnel, string? Fingerprint, string? Hop, string? Error);

/// <summary>A started tunnel. Disposing it stops the tunnel.</summary>
public sealed partial class RunningTunnelHandle : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private IntPtr _handle;

    internal RunningTunnelHandle(IntPtr handle) => _handle = handle;

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(RunningTunnelHandle));

    public TunnelStatusDto Status() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(TunnelNative.bastion_tunnel_status_json(H, out var err), err), Json.Info<TunnelStatusDto>())
        ?? throw new BastionException("the tunnel returned no status");

    public void Stop()
    {
        if (TunnelNative.bastion_tunnel_stop(H, out var err) != 0) throw new BastionException(LibraryClient.TakeError(err, "could not stop the tunnel"));
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        var h = _handle;
        _handle = IntPtr.Zero;
        TunnelNative.bastion_tunnel_free(h);
    }
}

public sealed partial class SessionManagerClient
{
    /// <summary>
    /// Sign in to saved tunnel <paramref name="tunnelId"/>'s SSH connection and start it. Blocking: call it off the UI
    /// thread. Same login and host-key rules as <see cref="ConnectSsh"/>; never throws for a connection failure.
    /// </summary>
    public TunnelStartResult StartTunnel(LibraryClient library, string tunnelId, string? username, SshLoginKind kind, string? secret,
        string? keyPath, string? trustFingerprint, IReadOnlyDictionary<string, string>? jumpTrust, string? code = null)
    {
        var jumpJson = jumpTrust is { Count: > 0 } ? AotJson.Write<IReadOnlyDictionary<string, string>>(jumpTrust, AotJson.Options) : null;
        using var password = new Utf8Secret(secret);
        using var oneTimeCode = new Utf8Secret(code);
        using var manager = AcquireLease();
        using var lib = library.AcquireLease();
        var handle = TunnelNative.bastion_tunnel_start(
            manager.Handle, lib.Handle, tunnelId, string.IsNullOrWhiteSpace(username) ? null : username, (int)kind, password.Pointer,
            string.IsNullOrWhiteSpace(keyPath) ? null : keyPath, oneTimeCode.Pointer,
            string.IsNullOrWhiteSpace(trustFingerprint) ? null : trustFingerprint, jumpJson, IntPtr.Zero,
            out var outcome, out var fingerprint, out var hop, out var err);
        var fp = Take(fingerprint);
        var h = Take(hop);
        var message = Take(err);
        var status = Enum.IsDefined(typeof(ConnectOutcome), outcome) ? (ConnectOutcome)outcome : ConnectOutcome.Failed;
        if (handle == IntPtr.Zero)
            return new TunnelStartResult(status == ConnectOutcome.Ok ? ConnectOutcome.Failed : status, null, fp, h, message ?? "the tunnel did not start");
        return new TunnelStartResult(ConnectOutcome.Ok, new RunningTunnelHandle(handle), null, null, null);
    }
}
