using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>Edit Locally and the terminal's OSC 7 folder (C ABI 45, <c>core-cabi/src/transfers.rs</c>).</summary>
internal static class EditLocalNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_edit_local_path([MarshalAs(UnmanagedType.LPUTF8Str)] string @base,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string session, [MarshalAs(UnmanagedType.LPUTF8Str)] string remote, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_edit_watcher_new();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_edit_watcher_free(IntPtr w);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_edit_watcher_watch(IntPtr w, [MarshalAs(UnmanagedType.LPUTF8Str)] string local,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? remote, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_edit_watcher_poll(IntPtr w, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_cwd(IntPtr t);
}

/// <summary>One edited copy: the local file and the remote file it replaces on save.</summary>
public sealed record EditCopy(string Local, string Remote);

/// <summary>
/// The copies one Files panel edits locally. Each lives in an owner-only folder under the data dir; the core reports
/// every save (size + SHA-256 change) so the panel can upload it. UI thread only.
/// </summary>
public sealed class EditLocalCopies : IDisposable
{
    private readonly string _base;
    private readonly string _session = Guid.NewGuid().ToString("N");
    private IntPtr _handle = EditLocalNative.bastion_edit_watcher_new();

    public EditLocalCopies(string dataDir) => _base = dataDir;

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(EditLocalCopies));

    /// <summary>Where the copy of <paramref name="remote"/> goes; the folder is created.</summary>
    public string LocalPath(string remote) =>
        LibraryClient.TakeString(EditLocalNative.bastion_edit_local_path(_base, _session, remote, out var err), err);

    /// <summary>Watch a just-downloaded copy (the core refuses files over 64 MiB).</summary>
    public void Watch(string local, string remote)
    {
        if (EditLocalNative.bastion_edit_watcher_watch(H, local, remote, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not watch the copy"));
    }

    /// <summary>Copies saved since the last poll; copies that disappeared are dropped by the core.</summary>
    public IReadOnlyList<EditCopy> Poll()
    {
        var json = LibraryClient.TakeString(EditLocalNative.bastion_edit_watcher_poll(H, out var err), err);
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("changed", out var changed)) return [];
        return changed.EnumerateArray()
            .Select(c => new EditCopy(c.GetProperty("local").GetString() ?? "", c.GetProperty("remote").GetString() ?? ""))
            .Where(c => c.Local.Length > 0 && c.Remote.Length > 0)
            .ToList();
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        EditLocalNative.bastion_edit_watcher_free(_handle);
        _handle = IntPtr.Zero;
    }
}
