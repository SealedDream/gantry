using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

/// <summary>
/// Telnet terminals (B7, docs/plans/B7-TELNET-SERIAL.md, core-cabi telnet_serial.rs). The core makes every decision:
/// whether Telnet is allowed (the user's Allow Telnet under the managed policy) and whether the saved password may be
/// typed (the connection's own opt-in). Serial is not offered on Windows (owner, 2026-11-15).
/// </summary>
internal static class TelnetSerialNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_telnet_allowed(IntPtr settings);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_telnet_policy_lock();
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_telnet_warning();
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_session_connect_telnet(
        IntPtr m, IntPtr lib, IntPtr settings,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        int loginKind, IntPtr secret, ushort cols, ushort rows, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_reconnect(IntPtr t, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_remote_status(IntPtr t);
}

/// <summary>Allow Telnet and the warning text. (Serial is not offered on Windows, owner 2026-11-15.)</summary>
public static class TelnetSerial
{
    public const string AllowSetting = "security.allow-telnet";

    /// <summary>Telnet may be opened now: the user's switch under the managed policy (false when the policy is broken).</summary>
    public static bool Allowed(SettingsClient settings) => TelnetSerialNative.bastion_telnet_allowed(settings.NativeHandle) == 1;

    /// <summary>The administrator's reason when the managed policy forbids Telnet, else null.</summary>
    public static string? PolicyLock => SessionManagerClient.Take(TelnetSerialNative.bastion_telnet_policy_lock());

    /// <summary>The full risk text, for the confirm and tool tips.</summary>
    public static string Warning => SessionManagerClient.Take(TelnetSerialNative.bastion_telnet_warning()) ?? "Telnet is not encrypted.";
}

public sealed partial class TerminalSession
{
    /// <summary>Reconnect a Telnet terminal (nothing typed for you); the screen stays. Blocking.</summary>
    public void Reconnect()
    {
        if (TelnetSerialNative.bastion_terminal_reconnect(H, out var err) != 0) throw new BastionException(Take(err) ?? "could not reconnect");
    }

    /// <summary>"Connection lost" or "Port disconnected" after a drop; null while connected or for other terminals.</summary>
    public string? RemoteStatus => _handle == IntPtr.Zero ? null : Take(TelnetSerialNative.bastion_terminal_remote_status(_handle));
}

public sealed partial class SessionManagerClient
{
    /// <summary>
    /// Open a saved Telnet connection (blocking; run off the UI thread). Refused with the reason unless Telnet is allowed.
    /// <paramref name="kind"/> and <paramref name="secret"/> are used only when the connection's own "Type the saved
    /// password after the login prompt" is on (checked in the core); pass null for no login.
    /// </summary>
    public TerminalSession ConnectTelnet(LibraryClient library, SettingsClient settings, string connectionId, string? username, SshLoginKind? kind, string? secret, int cols, int rows)
    {
        using var s = new Utf8Secret(secret);
        using var manager = AcquireLease();
        using var lib = library.AcquireLease();
        var h = TelnetSerialNative.bastion_session_connect_telnet(manager.Handle, lib.Handle, settings.NativeHandle, connectionId,
            string.IsNullOrWhiteSpace(username) ? null : username, kind is { } k ? (int)k : -1, s.Pointer, (ushort)cols, (ushort)rows, out var err);
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not open the Telnet connection");
        return TerminalSession.Adopt(h);
    }
}
