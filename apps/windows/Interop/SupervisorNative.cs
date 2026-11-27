using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

/// <summary>Lifecycle of a supervised SSH session (<c>STATE_*</c> in core-cabi/src/supervisor.rs).</summary>
public enum SessionLinkState
{
    Connecting = 0,
    Connected = 1,
    Reconnecting = 2,
    /// <summary>The PC went to sleep; the link was dropped on purpose and comes back on resume.</summary>
    Suspended = 3,
    /// <summary>Disconnected and not retrying: reconnect by hand.</summary>
    Failed = 4,
    Closed = 5,
}

/// <summary>What a tab shows about its link. <see cref="Reason"/> never carries a secret.</summary>
public readonly record struct SessionLinkStatus(SessionLinkState State, uint Attempt, string? Reason);

internal static class SupervisorNative
{
    private const string Lib = "bastion_cabi";

    internal const int EventSleep = 0;
    internal const int EventWake = 1;
    internal const int EventCancel = 2;
    internal const int EventNetworkChanged = 3;

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_supervisor_new(
        IntPtr m,
        IntPtr lib,
        IntPtr terminal,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        int loginKind,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? credentialOrKey,
        uint maxAttempts,
        out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_supervisor_state(IntPtr s, out uint attempt, out IntPtr reason);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern ulong bastion_supervisor_link(IntPtr s);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_supervisor_terminal(IntPtr s, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_supervisor_event(IntPtr s, int ev, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_supervisor_free(IntPtr s);
}

/// <summary>
/// The core's supervisor for one SSH tab: reconnects a dropped link (only for vault and passphrase-less key
/// logins; a password session is never re-entered silently), drops the link on sleep and brings it back on
/// resume. Poll <see cref="Status"/> and <see cref="Link"/> from the UI thread; when <see cref="Link"/>
/// moves, take the new shell with <see cref="TakeTerminal"/>.
/// </summary>
public sealed partial class SupervisedSession : IDisposable
{
    /// <summary>Reconnect attempts per drop: the core's ReconnectPolicy default (back-off 1 s doubling to 60 s, about five
    /// minutes in all; owner point W25).</summary>
    public const uint MaxAttempts = 10;

    private IntPtr _handle;

    private SupervisedSession(IntPtr handle) => _handle = handle;

    /// <summary>
    /// Supervise <paramref name="terminal"/>, just opened for <paramref name="connectionId"/>. Pass the login
    /// kind used and, for a vault login, the credential id; for a key file, the key path. A key with a
    /// passphrase, or a password, must be passed as <see cref="SshLoginKind.Password"/> with no value: the
    /// session is then not reconnected without the user.
    /// </summary>
    public static SupervisedSession Start(SessionManagerClient manager, LibraryClient library, TerminalSession terminal,
        string connectionId, string? username, SshLoginKind kind, string? credentialOrKey)
    {
        var h = SupervisorNative.bastion_supervisor_new(manager.NativeHandle, library.NativeHandle, terminal.NativeHandle, connectionId,
            string.IsNullOrWhiteSpace(username) ? null : username, (int)kind, kind == SshLoginKind.Password ? null : credentialOrKey,
            MaxAttempts, out var err);
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not supervise the session");
        return new SupervisedSession(h);
    }

    /// <summary>Whether a login of this kind may be repeated by the core without the user.</summary>
    public static bool CanReconnect(SshLoginKind kind, string? secret) =>
        kind is SshLoginKind.Vault or SshLoginKind.Vaultwarden or SshLoginKind.Agent || (kind == SshLoginKind.KeyFile && string.IsNullOrEmpty(secret));

    public SessionLinkStatus Status
    {
        get
        {
            if (_handle == IntPtr.Zero) return new(SessionLinkState.Closed, 0, null);
            var s = SupervisorNative.bastion_supervisor_state(_handle, out var attempt, out var reason);
            var state = Enum.IsDefined(typeof(SessionLinkState), s) ? (SessionLinkState)s : SessionLinkState.Closed;
            return new(state, attempt, Take(reason));
        }
    }

    /// <summary>How many links have connected; starts at 1.</summary>
    public ulong Link => _handle == IntPtr.Zero ? 0 : SupervisorNative.bastion_supervisor_link(_handle);

    /// <summary>The current shell as a new terminal the caller owns.</summary>
    public TerminalSession TakeTerminal()
    {
        var t = SupervisorNative.bastion_supervisor_terminal(H, out var err);
        if (t == IntPtr.Zero) throw new BastionException(Take(err) ?? "no terminal");
        return TerminalSession.Adopt(t);
    }

    public void Sleep() => Send(SupervisorNative.EventSleep);
    public void Wake() => Send(SupervisorNative.EventWake);

    /// <summary>The network path changed (C ABI 62): with auto-reconnect the link is replaced at once.</summary>
    public void NetworkChanged() => Send(SupervisorNative.EventNetworkChanged);

    private void Send(int ev)
    {
        // A supervisor that already stopped (closed, failed) simply ignores the event.
        if (_handle != IntPtr.Zero && SupervisorNative.bastion_supervisor_event(_handle, ev, out var err) != 0) Take(err);
    }

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(SupervisedSession));

    private static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { Native.bastion_string_free(s); }
    }

    /// <summary>Cancel: the shell is closed and no reconnect follows.</summary>
    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        var h = _handle;
        _handle = IntPtr.Zero;
        SupervisorNative.bastion_supervisor_free(h);
    }
}
