using System;
using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for tab previews (C ABI 118, B11): the inherited "Hide tab preview" property.</summary>
internal static class PreviewNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_no_preview(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);
}

public sealed partial class LibraryClient
{
    /// <summary>"Hide tab preview" for a connection, after folder inheritance (C ABI 118, B11).</summary>
    public bool NoPreview(string connectionId)
    {
        var r = PreviewNative.bastion_library_no_preview(Handle, connectionId, out var err);
        if (r < 0) throw new BastionException(TakeError(err, "could not read the tab preview setting"));
        return r == 1;
    }
}
