using System;
using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for core-cabi/src/errcodes.rs (LOG-ERRCODES; C ABI 146).</summary>
internal static class ErrorCodeNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_error_code([MarshalAs(UnmanagedType.LPUTF8Str)] string? area, [MarshalAs(UnmanagedType.LPUTF8Str)] string? message);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_log_redact([MarshalAs(UnmanagedType.LPUTF8Str)] string? text);
}

/// <summary>Support codes and log redaction from the core (docs/ERROR-CODES.md). Never throws.</summary>
public static class ErrorCodes
{
    /// <summary>The <c>GT-</c> code for <paramref name="message"/> in <paramref name="area"/> (SSH, RDP, VNC, VAULT, NET, PLUG, UPD, FILE, APP).</summary>
    public static string Code(string area, string message)
    {
        try { return LibraryClient.TakeString(ErrorCodeNative.bastion_error_code(area, message), IntPtr.Zero); }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BastionException) { return "GT-APP-000"; }
    }

    /// <summary><paramref name="text"/> without secrets, user names, host names or addresses. If the core cannot be
    /// reached the text is dropped rather than written unredacted.</summary>
    public static string Redact(string text)
    {
        try { return LibraryClient.TakeString(ErrorCodeNative.bastion_log_redact(text), IntPtr.Zero); }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BastionException) { return "(not redacted, dropped)"; }
    }
}
