using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

internal static class VncNative
{
    private const string Lib = "bastion_cabi";
    internal const int AuthFailed = 2; // CONNECT_AUTH_FAILED

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_vnc_connect([MarshalAs(UnmanagedType.LPUTF8Str)] string host, ushort port, IntPtr password, out IntPtr viewer, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_vnc_is_closed(IntPtr v);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_vnc_close_reason(IntPtr v);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe int bastion_vnc_frame(IntPtr v, ulong afterSerial, byte* buf, nuint bufLen, out ushort width, out ushort height, out ulong serial);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_vnc_mouse_move(IntPtr v, ushort x, ushort y);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_vnc_mouse_button(IntPtr v, byte button, byte down);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_vnc_key(IntPtr v, uint keysym, byte down);

    /// <summary>ABI 129 (RDP-VNC-FIT): ask the server to resize its desktop (ExtendedDesktopSize); refusals are ignored.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_vnc_resize(IntPtr v, ushort width, ushort height);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_vnc_close(IntPtr v);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_vnc_free(IntPtr v);

    internal static string? Take(IntPtr p)
    {
        if (p == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(p); }
        finally { Native.bastion_string_free(p); }
    }
}

public sealed record VncConnectResult(VncSession? Session, bool AuthFailed, string? Error);

/// <summary>
/// One VNC viewer (core <c>vnc.rs</c> through the C ABI). <see cref="Connect"/> blocks on the network: call it off the UI
/// thread. The password is used once, only if the server asks, in a buffer zeroed after the call. RFB is not encrypted.
/// </summary>
public sealed partial class VncSession : IDisposable
{
    private IntPtr _handle;

    private VncSession(IntPtr handle) => _handle = handle;

    public static VncConnectResult Connect(string host, ushort port, string? password)
    {
        using var secret = new Utf8Secret(password);
        var rc = VncNative.bastion_vnc_connect(host, port, secret.Pointer, out var viewer, out var err);
        var text = VncNative.Take(err);
        return rc == 0 && viewer != IntPtr.Zero
            ? new(new VncSession(viewer), false, null)
            : new(null, rc == VncNative.AuthFailed, text ?? "The connection failed.");
    }

    public bool IsClosed => _handle == IntPtr.Zero || VncNative.bastion_vnc_is_closed(_handle) != 0;

    public string? CloseReason => _handle == IntPtr.Zero ? null : VncNative.Take(VncNative.bastion_vnc_close_reason(_handle));

    public unsafe bool Frame(ref byte[] buffer, ref ulong serial, out int width, out int height)
    {
        width = height = 0;
        if (_handle == IntPtr.Zero) return false;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            int rc;
            ushort w, h;
            ulong s;
            fixed (byte* p = buffer) rc = VncNative.bastion_vnc_frame(_handle, serial, p, (nuint)buffer.Length, out w, out h, out s);
            width = w;
            height = h;
            if (rc == 1) { serial = s; return true; }
            if (rc != -1) return false;
            buffer = new byte[w * h * 4];
        }
        return false;
    }

    public void MouseMove(int x, int y)
    {
        if (_handle != IntPtr.Zero) VncNative.bastion_vnc_mouse_move(_handle, (ushort)Math.Clamp(x, 0, ushort.MaxValue), (ushort)Math.Clamp(y, 0, ushort.MaxValue));
    }

    /// <summary><paramref name="button"/>: 0 left, 1 middle, 2 right, 3 wheel up, 4 wheel down.</summary>
    public void MouseButton(byte button, bool down)
    {
        if (_handle != IntPtr.Zero) VncNative.bastion_vnc_mouse_button(_handle, button, (byte)(down ? 1 : 0));
    }

    public void Key(uint keysym, bool down)
    {
        if (_handle != IntPtr.Zero) VncNative.bastion_vnc_key(_handle, keysym, (byte)(down ? 1 : 0));
    }

    /// <summary>Ask the server to follow the view's size; a server that refuses keeps its size.</summary>
    public void Resize(int width, int height)
    {
        if (_handle != IntPtr.Zero && width > 0 && height > 0)
            VncNative.bastion_vnc_resize(_handle, (ushort)Math.Min(width, ushort.MaxValue), (ushort)Math.Min(height, ushort.MaxValue));
    }

    public void Dispose()
    {
        var h = _handle;
        _handle = IntPtr.Zero;
        if (h != IntPtr.Zero) VncNative.bastion_vnc_free(h);
    }
}
