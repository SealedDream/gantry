using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

// The two LibraryClient helpers HighlightNative.cs uses, as BastionNative.cs has them (string ownership: the
// returned string and the error are freed with bastion_string_free).
public sealed class BastionException(string message) : Exception(message);

internal static class LibraryClient
{
    [DllImport("bastion_cabi", CallingConvention = CallingConvention.Cdecl)]
    private static extern void bastion_string_free(IntPtr s);

    internal static string TakeError(IntPtr err, string fallback)
    {
        if (err == IntPtr.Zero) return fallback;
        try { return Marshal.PtrToStringUTF8(err) ?? fallback; }
        finally { bastion_string_free(err); }
    }

    internal static string TakeString(IntPtr s, IntPtr err)
    {
        if (s == IntPtr.Zero) throw new BastionException(TakeError(err, "the core returned no value"));
        try { return Marshal.PtrToStringUTF8(s) ?? ""; }
        finally { bastion_string_free(s); }
    }
}
