using System;
using System.Runtime.InteropServices;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for core-cabi/src/logexport.rs (C ABI 54) and snippets.rs (C ABI 64).</summary>
internal static class LogExportNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_log_snippet_export([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? header, [MarshalAs(UnmanagedType.LPUTF8Str)] string text, int stripAnsi, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_snippet_put([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string text, [MarshalAs(UnmanagedType.LPUTF8Str)] string? id, out IntPtr err);
}

/// <summary>Saves terminal text as an owner-only log file or a named snippet; the core cleans the text and refuses secrets.</summary>
public static class LogExport
{
    /// <summary>Writes <paramref name="text"/> to a new <c>name.log</c> in <paramref name="dir"/> (never overwrites). Returns the path.</summary>
    public static string SaveLog(string dir, string name, string? header, string text) =>
        LibraryClient.TakeString(LogExportNative.bastion_log_snippet_export(dir, name, header, text, 1, out var err), err);

    /// <summary>Adds a snippet. Throws <see cref="BastionException"/> when the name is taken or the text looks secret.</summary>
    public static string SaveSnippet(string dataDir, string name, string text) =>
        LibraryClient.TakeString(LogExportNative.bastion_snippet_put(dataDir, name, text, null, out var err), err);
}
