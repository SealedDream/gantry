using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke surface of <c>bastion_rdp.dll</c> (rdp-ffi/src/cabi.rs), a separate library from the core.</summary>
/// <summary>rdp-ffi <c>BastionRdpOptions</c> (24 bytes on x64; layout checked by the Rust tests and at startup here).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct BastionRdpOptions
{
    public uint StructSize;
    public byte NlaOnly;
    public byte Clipboard;
    public byte Audio;
    public byte Reserved0;
    public ushort GatewayPort;
    public ushort Reserved1;
    public uint ColorDepth;
    public IntPtr SharedFolder;
}

internal static class RdpNative
{
    private const string Lib = "bastion_rdp";
    internal const uint AbiVersion = 4;

    internal const int Ok = 0, Failed = -1, CertificateUnknown = -2, AuthFailed = -3;

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bastion_rdp_abi_version();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_rdp_new(out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_rdp_connect(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string host, ushort port,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string user, [MarshalAs(UnmanagedType.LPUTF8Str)] string? domain, ushort width, ushort height,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? trustedFingerprint, IntPtr password, out IntPtr err);

    /// <summary>RDP ABI 2 (Codex R04): as <see cref="bastion_rdp_connect"/> with session options; NULL = the old defaults.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_rdp_connect_with_options(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string host, ushort port,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string user, [MarshalAs(UnmanagedType.LPUTF8Str)] string? domain, ushort width, ushort height,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? trustedFingerprint, IntPtr password, ref BastionRdpOptions options, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_rdp_state(IntPtr s);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_rdp_close_reason(IntPtr s);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe int bastion_rdp_frame(IntPtr s, ulong afterSerial, byte* buf, nuint bufLen, out ushort width, out ushort height, out ulong serial);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_mouse_move(IntPtr s, ushort x, ushort y);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_mouse_button(IntPtr s, byte button, byte down);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_key(IntPtr s, byte scancode, byte extended, byte down);

    /// <summary>RDP ABI 3 (owner point 29): typed text as Unicode keyboard events.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_type_text(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string text);

    /// <summary>RDP ABI 3: release every key still down on the server.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_release_all(IntPtr s);

    /// <summary>RDP ABI 4 (RDP-VNC-FIT): ask the server to resize its desktop (Display Control); held until the channel opens.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_resize(IntPtr s, uint width, uint height);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_set_local_clipboard(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string text);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_rdp_take_remote_clipboard(IntPtr s);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_close(IntPtr s);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_free(IntPtr s);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_string_free(IntPtr s);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_rdp_set_openh264_library_path([MarshalAs(UnmanagedType.LPUTF8Str)] string? path);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_rdp_install_openh264([MarshalAs(UnmanagedType.LPUTF8Str)] string codecsDir, out IntPtr err);

    internal static string? TakeString(IntPtr p)
    {
        if (p == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(p); }
        finally { bastion_rdp_string_free(p); }
    }
}

public enum RdpConnectOutcome { Connected, CertificateUnknown, AuthFailed, Failed }

/// <summary>
/// Session options for <see cref="RdpSession.Connect"/> (Codex R04), resolved from the connection's shared properties.
/// <paramref name="GatewayPort"/>: loopback port of a gateway forward to dial instead of host:port (0 = direct); the
/// certificate is still checked for the real host. Clipboard, audio and a shared folder stay off until the shared model
/// offers them.
/// </summary>
public sealed record RdpOptions(uint ColorDepth = 32, bool NlaOnly = true, ushort GatewayPort = 0, bool Clipboard = false, bool Audio = false, string? SharedFolder = null)
{
    public static readonly RdpOptions Default = new();
}

public sealed record RdpConnectResult(RdpConnectOutcome Outcome, RdpSession? Session, string? Fingerprint, string? Error);

/// <summary>
/// One RDP session (IronRDP in <c>bastion_rdp.dll</c>). <see cref="Connect"/> blocks on the network: call it off the UI
/// thread. Frames and input are cheap and may be called from the UI thread.
/// </summary>
public sealed partial class RdpSession : IDisposable
{
    private IntPtr _handle;

    private RdpSession(IntPtr handle, bool sharesClipboard) => (_handle, SharesClipboard) = (handle, sharesClipboard);

    /// <summary>Test builds: record the options exactly as they cross into rdp-ffi (BASTION_RDP_OPTIONS_LOG). No login, no password.</summary>
    private static void LogOptions(string host, ushort port, BastionRdpOptions native, string? sharedFolder)
    {
        if (Bastion.Shell.TestHooks.RdpOptionsLog is not { } path) return;
        var line = new System.Text.Json.Nodes.JsonObject
        {
            ["host"] = host, ["port"] = port, ["structSize"] = native.StructSize, ["nlaOnly"] = native.NlaOnly, ["clipboard"] = native.Clipboard, ["audio"] = native.Audio,
            ["gatewayPort"] = native.GatewayPort, ["colorDepth"] = native.ColorDepth, ["sharedFolder"] = native.SharedFolder == IntPtr.Zero ? null : sharedFolder,
        }.ToJsonString();
        try { File.AppendAllText(path, line + Environment.NewLine); }
        catch (IOException e) { System.Diagnostics.Debug.WriteLine($"rdp options log: {e.Message}"); }
    }

    /// <summary>The connection shares text copied on either side (the clipboard channel was offered).</summary>
    public bool SharesClipboard { get; }

    /// <summary>rdp-ffi's <c>BastionRdpOptions</c> size on x64 (rdp-ffi/src/cabi.rs layout test).</summary>
    internal const int RdpOptionsSize = 24;

    /// <summary>
    /// Connect and log in. The password crosses the boundary in a zeroed-after-use UTF-8 buffer and is not kept.
    /// <paramref name="trustedFingerprint"/> is the certificate SHA-256 the user accepted (a stored pin or one just verified).
    /// </summary>
    public static RdpConnectResult Connect(string host, ushort port, string user, string? domain, ushort width, ushort height,
        string? trustedFingerprint, string password, RdpOptions? options = null)
    {
        options ??= RdpOptions.Default;
        if (Marshal.SizeOf<BastionRdpOptions>() != RdpOptionsSize)
            return new(RdpConnectOutcome.Failed, null, null, "bastion_rdp.dll options layout does not match this app.");
        if (RdpNative.bastion_rdp_abi_version() != RdpNative.AbiVersion)
            return new(RdpConnectOutcome.Failed, null, null, "bastion_rdp.dll does not match this app version.");
        var handle = RdpNative.bastion_rdp_new(out var err);
        if (handle == IntPtr.Zero) return new(RdpConnectOutcome.Failed, null, null, RdpNative.TakeString(err) ?? "could not start RDP");
        var bytes = System.Text.Encoding.UTF8.GetBytes(password + "\0");
        var pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        int rc;
        var folder = options.SharedFolder is { Length: > 0 } f ? Marshal.StringToCoTaskMemUTF8(f) : IntPtr.Zero;
        var native = new BastionRdpOptions
        {
            StructSize = (uint)Marshal.SizeOf<BastionRdpOptions>(),
            NlaOnly = options.NlaOnly ? (byte)1 : (byte)0,
            Clipboard = options.Clipboard ? (byte)1 : (byte)0,
            Audio = options.Audio ? (byte)1 : (byte)0,
            GatewayPort = options.GatewayPort,
            ColorDepth = options.ColorDepth,
            SharedFolder = folder,
        };
        LogOptions(host, port, native, options.SharedFolder);
        try { rc = RdpNative.bastion_rdp_connect_with_options(handle, host, port, user, domain, width, height, trustedFingerprint, pin.AddrOfPinnedObject(), ref native, out err); }
        finally
        {
            Array.Clear(bytes);
            pin.Free();
            if (folder != IntPtr.Zero) Marshal.FreeCoTaskMem(folder);
        }
        var text = RdpNative.TakeString(err);
        if (rc == RdpNative.Ok) return new(RdpConnectOutcome.Connected, new RdpSession(handle, options.Clipboard), null, null);
        RdpNative.bastion_rdp_free(handle);
        return rc switch
        {
            RdpNative.CertificateUnknown => new(RdpConnectOutcome.CertificateUnknown, null, text, null),
            RdpNative.AuthFailed => new(RdpConnectOutcome.AuthFailed, null, null, text),
            _ => new(RdpConnectOutcome.Failed, null, null, text ?? "The connection failed."),
        };
    }

    /// <summary>True until the server or the network ends the session.</summary>
    public bool IsConnected => _handle != IntPtr.Zero && RdpNative.bastion_rdp_state(_handle) == 2;

    public string? CloseReason => _handle == IntPtr.Zero ? null : RdpNative.TakeString(RdpNative.bastion_rdp_close_reason(_handle));

    /// <summary>
    /// Copy the picture into <paramref name="buffer"/> when it changed since <paramref name="serial"/> (BGRA, top-down).
    /// Grows the buffer when the desktop size needs it. Returns false when nothing changed.
    /// </summary>
    public unsafe bool Frame(ref byte[] buffer, ref ulong serial, out int width, out int height)
    {
        width = height = 0;
        if (_handle == IntPtr.Zero) return false;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            int rc;
            ushort w, h;
            ulong s;
            fixed (byte* p = buffer) rc = RdpNative.bastion_rdp_frame(_handle, serial, p, (nuint)buffer.Length, out w, out h, out s);
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
        if (_handle != IntPtr.Zero) RdpNative.bastion_rdp_mouse_move(_handle, (ushort)Math.Clamp(x, 0, ushort.MaxValue), (ushort)Math.Clamp(y, 0, ushort.MaxValue));
    }

    /// <summary><paramref name="button"/>: 0 left, 1 right, 2 middle.</summary>
    public void MouseButton(byte button, bool down)
    {
        if (_handle != IntPtr.Zero) RdpNative.bastion_rdp_mouse_button(_handle, button, (byte)(down ? 1 : 0));
    }

    public void Key(byte scancode, bool extended, bool down)
    {
        if (_handle != IntPtr.Zero) RdpNative.bastion_rdp_key(_handle, scancode, (byte)(extended ? 1 : 0), (byte)(down ? 1 : 0));
    }

    /// <summary>Ask the server for a new desktop size (Display Control); a server without it keeps its size.</summary>
    public void Resize(int width, int height)
    {
        if (_handle != IntPtr.Zero && width > 0 && height > 0) RdpNative.bastion_rdp_resize(_handle, (uint)width, (uint)height);
    }

    public void TypeText(string text)
    {
        if (_handle != IntPtr.Zero && text.Length > 0) RdpNative.bastion_rdp_type_text(_handle, text);
    }

    /// <summary>Offer text copied on this computer to the server.</summary>
    public void SetLocalClipboard(string text)
    {
        if (_handle != IntPtr.Zero && SharesClipboard) RdpNative.bastion_rdp_set_local_clipboard(_handle, text);
    }

    /// <summary>Text copied on the server since the last call, or null.</summary>
    public string? TakeRemoteClipboard() =>
        _handle == IntPtr.Zero || !SharesClipboard ? null : RdpNative.TakeString(RdpNative.bastion_rdp_take_remote_clipboard(_handle));

    public void ReleaseAll()
    {
        if (_handle != IntPtr.Zero) RdpNative.bastion_rdp_release_all(_handle);
    }

    public void Dispose()
    {
        var h = _handle;
        _handle = IntPtr.Zero;
        if (h == IntPtr.Zero) return;
        RdpNative.bastion_rdp_close(h);
        // Give the graceful shutdown a moment on the session's own runtime before dropping it.
        _ = Task.Run(async () => { await Task.Delay(500); RdpNative.bastion_rdp_free(h); });
    }
}
