using System;
using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for session logging (C ABI 58): rotation and prompt redaction happen in the core.</summary>
internal static class TerminalLogNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_start_log(IntPtr t, [MarshalAs(UnmanagedType.LPUTF8Str)] string dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string label,
        ulong maxBytes, uint keep, int stripAnsi, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_terminal_stop_log(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_is_logging(IntPtr t);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_session_log(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);
}

public sealed partial class LibraryClient
{
    /// <summary>"Log session output" for a connection, after folder inheritance (C ABI 106, LOG-01).</summary>
    public bool SessionLog(string connectionId)
    {
        var r = TerminalLogNative.bastion_library_session_log(Handle, connectionId, out var err);
        if (r < 0) throw new BastionException(TakeError(err, "could not read the session log setting"));
        return r == 1;
    }
}

public sealed partial class TerminalSession
{
    /// <summary>Starts logging this session to a file in <paramref name="dir"/>; returns the log path.
    /// <paramref name="maxBytes"/> 0 = 10 MB; <paramref name="keep"/> = older files kept after rotation.</summary>
    public string StartLog(string dir, string label, ulong maxBytes = 0, uint keep = 0, bool stripAnsi = true) =>
        LibraryClient.TakeString(TerminalLogNative.bastion_terminal_start_log(H, dir, label, maxBytes, keep, stripAnsi ? 1 : 0, out var err), err);

    public void StopLog() => TerminalLogNative.bastion_terminal_stop_log(H);

    public bool IsLogging => TerminalLogNative.bastion_terminal_is_logging(H) == 1;
}
