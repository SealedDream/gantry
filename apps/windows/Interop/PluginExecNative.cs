using System.Runtime.InteropServices;
using System.Text.Json.Nodes;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for core-cabi/src/pluginexec.rs: plugin <c>exec</c> (plugin API 1.5; docs/specs/plugins.md, section 19).</summary>
internal static class PluginExecNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_exec_cancel_new();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_plugin_exec_cancel(IntPtr c, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_plugin_exec_cancel_free(IntPtr c);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_exec_json(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string entryId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? username, int loginKind, [MarshalAs(UnmanagedType.LPUTF8Str)] string? password,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath, [MarshalAs(UnmanagedType.LPUTF8Str)] string command, ulong timeoutMs,
        IntPtr cancel, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_exec_terminal_library(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string entryId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string command, [MarshalAs(UnmanagedType.LPUTF8Str)] string? label, out IntPtr err);
}

/// <summary>A cancel switch for one running plugin command.</summary>
public sealed class PluginExecCancel : IDisposable
{
    internal IntPtr Handle { get; private set; } = PluginExecNative.bastion_plugin_exec_cancel_new();

    public void Cancel()
    {
        if (Handle != IntPtr.Zero) PluginExecNative.bastion_plugin_exec_cancel(Handle, out _);
    }

    public void Dispose()
    {
        if (Handle == IntPtr.Zero) return;
        PluginExecNative.bastion_plugin_exec_cancel_free(Handle);
        Handle = IntPtr.Zero;
    }
}

public static class PluginExecClient
{
    /// <summary>Runs an <c>exec-go</c> command on plugin entry <paramref name="entryId"/>. Blocks: call it off the UI
    /// thread. Returns the core's <c>{exit, stdout, stderr, error}</c> object, ready for the view's answer.</summary>
    public static JsonObject Run(SessionManagerClient sessions, LibraryClient lib, string entryId, string? user, SshLoginKind kind,
        string? secret, string command, ulong timeoutMs, PluginExecCancel cancel)
    {
        var p = PluginExecNative.bastion_plugin_exec_json(sessions.NativeHandle, lib.NativeHandle, entryId, user, (int)kind, secret, null,
            command, timeoutMs, cancel.Handle, out var err);
        var json = LibraryClient.TakeString(p, err);
        return JsonNode.Parse(json) as JsonObject ?? new JsonObject { ["error"] = "The core gave no result." };
    }

    /// <summary>A one-connection library for an <c>exec-terminal</c> update: SSH to the entry, running the command.</summary>
    public static LibraryClient TerminalLibrary(LibraryClient lib, string entryId, string command, string label)
    {
        var h = PluginExecNative.bastion_plugin_exec_terminal_library(lib.NativeHandle, entryId, command, label, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "terminal not opened"));
        return LibraryClient.FromUnsavedHandle(h);
    }
}
