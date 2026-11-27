using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>What waking a connection would do (C ABI 71). The SecureOn password itself never leaves the core.</summary>
public sealed record WolPlanDto(string Mac, string Broadcast, int Port, bool HasSecureon, bool BeforeConnect, int WaitSecs, string Host, int CheckPort);

/// <summary>Result of <see cref="LibraryClient.WakeBeforeConnect"/>.</summary>
public enum WakeResult { NotNeeded = 0, Up = 1, TimedOut = 2, Cancelled = 3 }

internal static class WolNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_wol_plan_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_wake(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_wake_before_connect(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, IntPtr cancel, out ulong afterMs, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_connection_sensitive(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_wake_cancel_new();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_wake_cancel(IntPtr cancel);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_wake_cancel_free(IntPtr cancel);
}

/// <summary>Cancels a running <see cref="LibraryClient.WakeBeforeConnect"/>. Dispose only after that call returned.</summary>
public sealed partial class WakeCancel : IDisposable
{
    internal IntPtr Handle { get; private set; } = WolNative.bastion_wake_cancel_new();

    public void Cancel()
    {
        if (Handle != IntPtr.Zero) WolNative.bastion_wake_cancel(Handle);
    }

    public void Dispose()
    {
        if (Handle == IntPtr.Zero) return;
        WolNative.bastion_wake_cancel_free(Handle);
        Handle = IntPtr.Zero;
    }
}

/// <summary>
/// Wake-on-LAN. Settings are ordinary properties (<c>wol_mac</c>, <c>wol_broadcast</c>, <c>wol_port</c>,
/// <c>wol_secureon</c>, <c>wol_before_connect</c>, <c>wol_wait_secs</c>) set with <c>SetProperty</c>; nothing is sent
/// unless one of these calls is made.
/// </summary>
public sealed partial class LibraryClient
{
    private static readonly JsonSerializerOptions WolJson = new() { TypeInfoResolver = AotJson.Resolver, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    /// <summary>The wake plan, or null when no MAC is set (hide Wake in the context menu).</summary>
    public WolPlanDto? WolPlan(string id)
    {
        var json = TakeString(WolNative.bastion_library_wol_plan_json(NativeHandle, id, out var err), err);
        return json == "null" ? null : JsonSerializer.Deserialize(json, WolJson.Info<WolPlanDto>());
    }

    /// <summary>Production, customer-sensitive or privileged host (C ABI 77): broadcast and multi-exec ask before sending.</summary>
    public bool IsSensitive(string id)
    {
        var r = WolNative.bastion_library_connection_sensitive(NativeHandle, id, out var err);
        if (r < 0) throw new BastionException(TakeError(err, "unknown connection"));
        return r == 1;
    }

    /// <summary>Wake action: send the magic packet now.</summary>
    public void Wake(string id)
    {
        if (WolNative.bastion_library_wake(NativeHandle, id, out var err) != 0) throw new BastionException(TakeError(err, "could not wake the host"));
    }

    /// <summary>Before connecting: wakes and waits (up to 300 s) when "Wake before connect" is on. Blocking: run it off the UI thread.</summary>
    public (WakeResult Result, TimeSpan After) WakeBeforeConnect(string id, WakeCancel? cancel)
    {
        var r = WolNative.bastion_library_wake_before_connect(NativeHandle, id, cancel?.Handle ?? IntPtr.Zero, out var ms, out var err);
        GC.KeepAlive(cancel);
        if (r < 0) throw new BastionException(TakeError(err, "could not wake the host"));
        return ((WakeResult)r, r == (int)WakeResult.Up ? TimeSpan.FromMilliseconds(ms) : TimeSpan.Zero);
    }
}
