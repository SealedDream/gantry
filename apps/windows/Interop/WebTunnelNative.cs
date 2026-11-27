using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>How a web connection opens through a saved tunnel (core webtunnel). Exactly one of
/// <see cref="ProxyUrl"/> (a SOCKS tunnel) or <see cref="ForwardAddress"/> (a -L tunnel) is set.</summary>
public sealed record WebTunnelPlanDto(string TunnelId, string TunnelName, string ViaId, string? ProxyUrl, string? ForwardAddress, string DataDir);

/// <summary>P/Invoke for web tabs through a tunnel (core-cabi/src/webtunnel.rs, C ABI 37).</summary>
internal static class WebTunnelNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_web_tunnel(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? tunnelId, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_web_tunnel_plan_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);
}

public sealed partial class LibraryClient
{
    /// <summary>Set (null clears) the tunnel a web connection opens through. Save the library after.</summary>
    public void SetWebTunnel(string connectionId, string? tunnelId)
    {
        if (WebTunnelNative.bastion_library_set_web_tunnel(Handle, connectionId, tunnelId, out var err) != 0)
            throw new BastionException(TakeError(err, "could not set the web tunnel"));
    }

    /// <summary>Null for a direct page. A deleted tunnel throws: never a silent direct load.</summary>
    public WebTunnelPlanDto? WebTunnelPlan(string connectionId, string dataDir) =>
        JsonSerializer.Deserialize(TakeString(WebTunnelNative.bastion_library_web_tunnel_plan_json(Handle, connectionId, dataDir, out var err), err), Json.Info<WebTunnelPlanDto?>());
}
