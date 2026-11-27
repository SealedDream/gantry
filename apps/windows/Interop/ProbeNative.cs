using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

internal static class ProbeNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_probe_start(IntPtr manager, IntPtr lib, IntPtr inputJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_probe_wait_json(IntPtr probe, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_probe_cancel(IntPtr probe);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_probe_free(IntPtr probe);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_recent_usernames_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string host, int port, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_recent_username_record([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string host, int port, [MarshalAs(UnmanagedType.LPUTF8Str)] string username, out IntPtr err);
}

/// <summary>
/// One running Test Connection (the core's <c>probe</c>, shared with the Mac app). <see cref="WaitAsync"/> blocks a
/// pool thread, never the UI thread; <see cref="Cancel"/> works from any thread. The request JSON may hold a
/// password, so it crosses the boundary in a <see cref="Utf8Secret"/> that is zeroed after the start call.
/// </summary>
public sealed partial class ConnectionProbe : IDisposable
{
    private IntPtr _handle;

    private ConnectionProbe(IntPtr handle) => _handle = handle;

    /// <summary>Start a test. Throws with the core's reason (a refused protocol, a bad request, a saved login the
    /// connection may not use). <paramref name="library"/> and <paramref name="connectionId"/> name the saved
    /// connection being tested; the core reads a saved (vault) login only for one (ABI 104).</summary>
    /// <param name="trustedFingerprint">Only what <see cref="PendingHostKey.TrustFor"/> returned after the user
    /// confirmed the fingerprint shown to them (SEC-07). Used for this one test; nothing is stored.</param>
    public static ConnectionProbe Start(SessionManagerClient sessions, string protocol, string host, int port, string? username, ProbeLogin? login,
        LibraryClient? library = null, string? connectionId = null, string? trustedFingerprint = null, IReadOnlyList<ProbeHop>? jumps = null)
    {
        using var input = new Utf8Secret(ProbeWire.Request(protocol, host, port, username, login, trustedFingerprint, connectionId, jumps));
        var handle = ProbeNative.bastion_probe_start(sessions.NativeHandle, library?.NativeHandle ?? IntPtr.Zero, input.Pointer, out var err);
        if (handle == IntPtr.Zero) throw new BastionException(GatewayNative.Take(err) ?? "could not start the test");
        return new ConnectionProbe(handle);
    }

    public Task<ProbeReportDto> WaitAsync() => Task.Run(() =>
    {
        var json = ProbeNative.bastion_probe_wait_json(_handle, out var err);
        var text = GatewayNative.Take(json) ?? throw new BastionException(GatewayNative.Take(err) ?? "the test returned no report");
        return ProbeWire.Report(text) ?? throw new BastionException("the test returned no report");
    });

    public void Cancel()
    {
        if (_handle != IntPtr.Zero) ProbeNative.bastion_probe_cancel(_handle);
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        ProbeNative.bastion_probe_free(_handle);
        _handle = IntPtr.Zero;
    }
}

/// <summary>Recent user names per host for Connect as… (C ABI 30). Names only, never a secret.</summary>
public static class RecentUsernames
{
    public static IReadOnlyList<string> For(string dataDir, string host, int? port)
    {
        var json = ProbeNative.bastion_recent_usernames_json(dataDir, host, port ?? 0, out var err);
        var text = GatewayNative.Take(json) ?? throw new BastionException(GatewayNative.Take(err) ?? "could not read recent user names");
        return JsonSerializer.Deserialize(text, AotJson.Options.Info<List<string>>()) ?? [];
    }

    public static void Record(string dataDir, string host, int? port, string username)
    {
        if (ProbeNative.bastion_recent_username_record(dataDir, host, port ?? 0, username, out var err) != 0)
            throw new BastionException(GatewayNative.Take(err) ?? "could not remember the user name");
    }
}
