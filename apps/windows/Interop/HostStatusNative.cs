using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>One dashboard row. <see cref="State"/> is <c>unknown</c>, <c>up</c>, <c>down</c> or <c>skipped</c>
/// (behind a jump host or gateway); times are Unix seconds.</summary>
public sealed record HostStatusDto(string Id, string Name, string State, long? LatencyMs, string? Error, long? CheckedAt, long? ChangedAt);

internal static class HostStatusNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_host_status_new(uint intervalSecs);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_host_status_free(IntPtr h);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_host_status_load(IntPtr h, IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_host_status_set_visible(IntPtr h, int visible);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_host_status_set_interval(IntPtr h, uint intervalSecs);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_host_status_check_now(IntPtr h);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_host_status_snapshot_json(IntPtr h, out IntPtr err);
}

/// <summary>
/// Host status dashboard (C ABI 68). Connections opt in with the inheritable <c>host_status</c> property. The checker
/// starts hidden and opens no socket or timer until <see cref="SetVisible"/>(true); set it false when the view hides.
/// </summary>
public sealed partial class HostStatusDashboard : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private IntPtr _h;

    /// <param name="intervalSecs">Check interval; the core clamps it to 30–3600.</param>
    public HostStatusDashboard(uint intervalSecs = 60) => _h = HostStatusNative.bastion_host_status_new(intervalSecs);

    private IntPtr H => _h != IntPtr.Zero ? _h : throw new ObjectDisposedException(nameof(HostStatusDashboard));

    /// <summary>Takes the opted-in connections from the library (call again after edits). Returns how many.</summary>
    public int Load(LibraryClient library)
    {
        var n = HostStatusNative.bastion_host_status_load(H, library.NativeHandle, out var err);
        if (n < 0) throw new BastionException(LibraryClient.TakeError(err, "could not load host status connections"));
        return n;
    }

    public void SetVisible(bool visible) => HostStatusNative.bastion_host_status_set_visible(H, visible ? 1 : 0);

    public void SetInterval(uint intervalSecs) => HostStatusNative.bastion_host_status_set_interval(H, intervalSecs);

    /// <summary>Refresh now; has no effect while hidden.</summary>
    public void CheckNow() => HostStatusNative.bastion_host_status_check_now(H);

    public IReadOnlyList<HostStatusDto> Snapshot() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(HostStatusNative.bastion_host_status_snapshot_json(H, out var err), err), Json.Info<List<HostStatusDto>>()) ?? [];

    public void Dispose()
    {
        if (_h == IntPtr.Zero) return;
        HostStatusNative.bastion_host_status_free(_h);
        _h = IntPtr.Zero;
    }
}
