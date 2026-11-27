using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

internal static class IpcNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_ipc_listen(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_ipc_next_open(IntPtr l);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_ipc_error(IntPtr l);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_ipc_endpoint([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_ipc_free(IntPtr l);
}

/// <summary>
/// Serves the <c>bastion</c> CLI (<c>ping</c>, <c>list</c>, <c>open &lt;name&gt;</c>) on the owner-only named pipe for the
/// library's folder. The core answers ping and list and resolves <c>open</c> to a saved connection id; the window polls
/// <see cref="NextOpen"/> and runs its normal Connect flow, so nothing connects without the app's own dialogs.
/// </summary>
public sealed partial class IpcListener : IDisposable
{
    private IntPtr _handle;

    private IpcListener(IntPtr handle) => _handle = handle;

    /// <summary>Listen for <paramref name="dataDir"/>. Throws when another instance already listens there.</summary>
    public static IpcListener Start(LibraryClient library, string dataDir)
    {
        var h = IpcNative.bastion_ipc_listen(library.NativeHandle, dataDir, out var err);
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not start the IPC listener");
        return new IpcListener(h);
    }

    /// <summary>The pipe name for <paramref name="dataDir"/>.</summary>
    public static string Endpoint(string dataDir)
    {
        var p = IpcNative.bastion_ipc_endpoint(dataDir, out var err);
        return Take(p) ?? throw new BastionException(Take(err) ?? "no IPC endpoint");
    }

    /// <summary>The next connection id the CLI asked to open, or null.</summary>
    public string? NextOpen() => _handle == IntPtr.Zero ? null : Take(IpcNative.bastion_ipc_next_open(_handle));

    /// <summary>Why the listener stopped, or null while it runs.</summary>
    public string? Error => _handle == IntPtr.Zero ? null : Take(IpcNative.bastion_ipc_error(_handle));

    private static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { Native.bastion_string_free(s); }
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        var h = _handle;
        _handle = IntPtr.Zero;
        IpcNative.bastion_ipc_free(h);
    }
}
