using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>A shared SSH gateway from the Gateway Manager (no secrets). <see cref="UsedBy"/> names what references it.</summary>
public sealed record GatewayDto(string Id, string Name, string Host, int? Port, string? Username, string Notes, List<string> UsedBy);

/// <summary>The gateway an RDP, VNC or web connection goes through: its name, <c>host:port</c> and own user name.</summary>
public sealed record GatewayHopDto(string Name, string Key, string? Username);

/// <summary>How opening a gateway route ended. <see cref="Route"/> is set only when it opened.</summary>
public sealed record GatewayRouteResult(ConnectOutcome Outcome, GatewayRoute? Route, string? Fingerprint, string? Error);

internal static class GatewayNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_gateways_json(IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_gateway_add(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_gateway_update(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_gateway_remove(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_gateway_route_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);

    // The password goes over as a raw pointer to a caller-owned buffer that is zeroed after the call (Utf8Secret).
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_gateway_route_open(
        IntPtr m,
        IntPtr lib,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        int loginKind,
        IntPtr password,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? trustFingerprint,
        out int outcome,
        out IntPtr fingerprint,
        out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern ushort bastion_gateway_route_port(IntPtr r);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_gateway_route_is_socks(IntPtr r);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_gateway_route_is_running(IntPtr r);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_gateway_route_summary(IntPtr r, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_gateway_route_free(IntPtr r);

    internal static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { Native.bastion_string_free(s); }
    }
}

/// <summary>Gateway Manager calls on the library (C ABI 22). Call <see cref="LibraryClient.Save"/> after a change.</summary>
public sealed partial class LibraryClient
{
    private static readonly JsonSerializerOptions GatewayJson = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    private static string GatewayInput(string name, string host, int? port, string? username, string notes) =>
        new System.Text.Json.Nodes.JsonObject
        {
            ["name"] = name, ["host"] = host, ["port"] = port, ["username"] = string.IsNullOrWhiteSpace(username) ? null : username, ["notes"] = notes,
        }.ToJsonString();

    public IReadOnlyList<GatewayDto> Gateways()
    {
        var p = GatewayNative.bastion_gateways_json(NativeHandle, out var err);
        if (p == IntPtr.Zero) throw new BastionException(GatewayNative.Take(err) ?? "could not list the gateways");
        return JsonSerializer.Deserialize(GatewayNative.Take(p) ?? "[]", GatewayJson.Info<List<GatewayDto>>()) ?? [];
    }

    public string AddGateway(string name, string host, int? port, string? username, string notes)
    {
        var p = GatewayNative.bastion_gateway_add(NativeHandle, GatewayInput(name, host, port, username, notes), out var err);
        if (p == IntPtr.Zero) throw new BastionException(GatewayNative.Take(err) ?? "could not add the gateway");
        return GatewayNative.Take(p)!;
    }

    public void UpdateGateway(string id, string name, string host, int? port, string? username, string notes)
    {
        if (GatewayNative.bastion_gateway_update(NativeHandle, id, GatewayInput(name, host, port, username, notes), out var err) != 0)
            throw new BastionException(GatewayNative.Take(err) ?? "could not save the gateway");
    }

    /// <summary>Refused while anything uses the gateway; the message names those places.</summary>
    public void RemoveGateway(string id)
    {
        if (GatewayNative.bastion_gateway_remove(NativeHandle, id, out var err) != 0)
            throw new BastionException(GatewayNative.Take(err) ?? "could not delete the gateway");
    }

    /// <summary>The gateway this RDP, VNC or web connection goes through, or null for a direct one. A dangling reference throws.</summary>
    public GatewayHopDto? GatewayHop(string connectionId)
    {
        var p = GatewayNative.bastion_gateway_route_json(NativeHandle, connectionId, out var err);
        if (p == IntPtr.Zero) throw new BastionException(GatewayNative.Take(err) ?? "could not resolve the gateway");
        return JsonSerializer.Deserialize(GatewayNative.Take(p) ?? "null", GatewayJson.Info<GatewayHopDto?>());
    }
}

/// <summary>
/// An open route through a gateway: a loopback port forward (RDP, VNC) or SOCKS proxy (web) over one SSH session to the
/// gateway. Disposing closes the listener and the session; the tab that uses the route owns it.
/// </summary>
public sealed partial class GatewayRoute : IDisposable
{
    private IntPtr _handle;

    private GatewayRoute(IntPtr handle)
    {
        _handle = handle;
        Port = GatewayNative.bastion_gateway_route_port(handle);
        IsSocks = GatewayNative.bastion_gateway_route_is_socks(handle) != 0;
        var s = GatewayNative.bastion_gateway_route_summary(handle, out var err);
        GatewayNative.Take(err);
        Summary = GatewayNative.Take(s) ?? "";
    }

    public ushort Port { get; }
    public bool IsSocks { get; }
    /// <summary>e.g. <c>via Jump (10.0.0.1:22) → 10.0.0.5:3389</c>.</summary>
    public string Summary { get; }
    public bool IsRunning => _handle != IntPtr.Zero && GatewayNative.bastion_gateway_route_is_running(_handle) != 0;

    /// <summary>
    /// Sign in to the connection's gateway and open its route. Blocking: call it off the UI thread. Never throws for a
    /// connection failure; read <see cref="GatewayRouteResult.Outcome"/>. <paramref name="trustFingerprint"/> is only a
    /// fingerprint the user verified after a <see cref="ConnectOutcome.HostKeyUnknown"/> result.
    /// </summary>
    public static GatewayRouteResult Open(SessionManagerClient sessions, LibraryClient library, string connectionId, string? username,
        SshLoginKind kind, string? secret, string? keyPath, string? trustFingerprint)
    {
        using var password = new Utf8Secret(secret);
        var handle = GatewayNative.bastion_gateway_route_open(sessions.NativeHandle, library.NativeHandle, connectionId,
            string.IsNullOrWhiteSpace(username) ? null : username, (int)kind, password.Pointer,
            string.IsNullOrWhiteSpace(keyPath) ? null : keyPath, string.IsNullOrWhiteSpace(trustFingerprint) ? null : trustFingerprint,
            out var outcome, out var fingerprint, out var err);
        var fp = GatewayNative.Take(fingerprint);
        var message = GatewayNative.Take(err);
        if (handle != IntPtr.Zero) return new GatewayRouteResult(ConnectOutcome.Ok, new GatewayRoute(handle), null, null);
        var status = Enum.IsDefined(typeof(ConnectOutcome), outcome) && outcome != 0 ? (ConnectOutcome)outcome : ConnectOutcome.Failed;
        return new GatewayRouteResult(status, null, fp, message ?? "could not open the gateway route");
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        var h = _handle;
        _handle = IntPtr.Zero;
        GatewayNative.bastion_gateway_route_free(h);
    }
}
