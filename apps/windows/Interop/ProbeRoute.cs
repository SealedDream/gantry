using System.Net;
using System.Net.Sockets;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

// A1-NW-JUMPS: the jump hosts of a Test Connection, so a saved login is tested over the route a real connect
// dials. Pure: tests\probe-console compiles this file alone.

/// <summary>One jump host of a test, as <c>bastion_probe_start</c> reads it.</summary>
public sealed record ProbeHop(
    [property: JsonPropertyName("host")] string Host,
    [property: JsonPropertyName("port")] int Port,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("login")] ProbeLogin Login);

/// <summary>A saved jump host as the core resolves it (<c>bastion_session_jump_hosts_json</c>): its
/// <c>host:port</c> key, the user it signs in as, and the login the user gave it in the sheet (null: the target's).</summary>
public sealed record SavedHop(string Key, string Username, ProbeLogin? OwnLogin = null);

public static class ProbeRoute
{
    private const int MaxPort = 65535;

    /// <summary>Split a core <c>host:port</c> key. <c>[v6]:port</c> is unbracketed. Without brackets the port
    /// is after the last colon, and the host must then be a name or IPv4 (no colon) or a valid IPv6 address:
    /// a bare address such as <c>fe80::1</c> is not split into <c>fe80:</c> and port 1. Null when not a key.</summary>
    public static (string Host, int Port)? SplitKey(string key)
    {
        var colon = key.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(key.AsSpan(colon + 1), System.Globalization.NumberStyles.None, null, out var port) || port is < 1 or > MaxPort)
            return null;
        var host = key[..colon];
        if (host.StartsWith('[') && host.EndsWith(']'))
            return IsIPv6(host[1..^1]) ? (host[1..^1], port) : null;
        if (host.Contains('[') || host.Contains(']')) return null;
        if (host.Contains(':') && !IsIPv6(host)) return null;
        return (host, port);
    }

    private static bool IsIPv6(string text) =>
        text.Length > 0 && IPAddress.TryParse(text, out var a) && a.AddressFamily == AddressFamily.InterNetworkV6;

    /// <summary>The hops of a test, in connect order. Each signs in with its own login from the sheet or else a
    /// copy of the target's, as a real connect does; the user is the saved one, or the target's when empty.
    /// Null when any key cannot be read: a test must not quietly drop a hop and dial the target directly.</summary>
    public static IReadOnlyList<ProbeHop>? Hops(IReadOnlyList<SavedHop> saved, string targetUser, ProbeLogin targetLogin)
    {
        var hops = new List<ProbeHop>(saved.Count);
        foreach (var hop in saved)
        {
            if (SplitKey(hop.Key) is not { } at) return null;
            var user = string.IsNullOrWhiteSpace(hop.Username) ? targetUser : hop.Username;
            hops.Add(new ProbeHop(at.Host, at.Port, user, hop.OwnLogin ?? targetLogin));
        }
        return hops;
    }
}
