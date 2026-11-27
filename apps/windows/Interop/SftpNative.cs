using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

internal static class SftpNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_open_sftp(IntPtr t, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_sftp_home(IntPtr s, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_sftp_list_json(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern long bastion_sftp_download(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string remote, [MarshalAs(UnmanagedType.LPUTF8Str)] string local, byte overwrite, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern long bastion_sftp_upload(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string local, [MarshalAs(UnmanagedType.LPUTF8Str)] string remote, byte overwrite, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern long bastion_sftp_download_progress(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string remote, [MarshalAs(UnmanagedType.LPUTF8Str)] string local, byte overwrite, IntPtr progress, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern long bastion_sftp_upload_progress(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string local, [MarshalAs(UnmanagedType.LPUTF8Str)] string remote, byte overwrite, IntPtr progress, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_sftp_mkdir(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_sftp_rename(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string from, [MarshalAs(UnmanagedType.LPUTF8Str)] string to, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern long bastion_sftp_remove(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte isDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_sftp_free(IntPtr s);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_sftp_edit_open(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_sftp_edit_save(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string text, [MarshalAs(UnmanagedType.LPUTF8Str)] string? fingerprintJson, byte force, out IntPtr err);
}

/// <summary>One entry of a remote directory, as <c>bastion_sftp_list_json</c> returns it.</summary>
public sealed record RemoteEntry(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("size")] ulong Size,
    [property: JsonPropertyName("modified")] uint? Modified,
    [property: JsonPropertyName("permissions")] uint? Permissions)
{
    public bool IsDir => Kind == "dir";
}

/// <summary>
/// An SFTP browser on an open SSH terminal's connection (no new login). Every call blocks on the network: call it
/// off the UI thread, one call at a time. <see cref="Dispose"/> frees the browser; the terminal keeps its connection.
/// </summary>
public sealed partial class SftpSession : IDisposable
{
    private IntPtr _handle;
    private readonly object _gate = new();

    private SftpSession(IntPtr handle) => _handle = handle;

    /// <summary>Open SFTP on <paramref name="terminal"/>'s SSH connection. Throws for a local terminal.</summary>
    public static SftpSession Open(TerminalSession terminal)
    {
        var h = SftpNative.bastion_terminal_open_sftp(terminal.NativeHandle, out var err);
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not open SFTP");
        return new SftpSession(h);
    }

    /// <summary>Own a handle a files-only connect returned (C ABI 87).</summary>
    internal static SftpSession Adopt(IntPtr handle) => new(handle);

    /// <summary>Set by <see cref="Dispose"/> before the handle is freed: no new call starts once the pane closes.</summary>
    private volatile bool _closing;

    private IntPtr H => !_closing && _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(SftpSession));

    public string Home()
    {
        lock (_gate) return Text(SftpNative.bastion_sftp_home(H, out var err), err);
    }

    public IReadOnlyList<RemoteEntry> List(string path)
    {
        string json;
        lock (_gate) json = Text(SftpNative.bastion_sftp_list_json(H, path, out var err), err);
        return JsonSerializer.Deserialize(json, AotJson.Options.Info<List<RemoteEntry>>()) ?? [];
    }

    public long Download(string remote, string local, bool overwrite = false)
    {
        lock (_gate) return Count(SftpNative.bastion_sftp_download(H, remote, local, overwrite ? (byte)1 : (byte)0, out var err), err);
    }

    public long Upload(string local, string remote, bool overwrite = false)
    {
        lock (_gate) return Count(SftpNative.bastion_sftp_upload(H, local, remote, overwrite ? (byte)1 : (byte)0, out var err), err);
    }

    /// <summary>Download while the core writes the bytes received so far into <paramref name="progress"/> (an aligned 8-byte cell).</summary>
    public long Download(string remote, string local, bool overwrite, IntPtr progress)
    {
        lock (_gate) return Count(SftpNative.bastion_sftp_download_progress(H, remote, local, overwrite ? (byte)1 : (byte)0, progress, out var err), err);
    }

    /// <summary>Upload while the core writes the bytes sent so far into <paramref name="progress"/>.</summary>
    public long Upload(string local, string remote, bool overwrite, IntPtr progress)
    {
        lock (_gate) return Count(SftpNative.bastion_sftp_upload_progress(H, local, remote, overwrite ? (byte)1 : (byte)0, progress, out var err), err);
    }

    public void Mkdir(string path)
    {
        lock (_gate) Check(SftpNative.bastion_sftp_mkdir(H, path, out var err), err);
    }

    public void Rename(string from, string to)
    {
        lock (_gate) Check(SftpNative.bastion_sftp_rename(H, from, to, out var err), err);
    }

    /// <summary>Delete a file or link, or (<paramref name="isDir"/>) a folder with everything in it. Returns the entries removed.</summary>
    public long Remove(string path, bool isDir)
    {
        lock (_gate) return Count(SftpNative.bastion_sftp_remove(H, path, isDir ? (byte)1 : (byte)0, out var err), err);
    }

    /// <summary>Open a remote text file for editing (C ABI 59): its text and the fingerprint to save against.</summary>
    public (string Text, string? Fingerprint) EditOpen(string path)
    {
        string json;
        lock (_gate) json = Text(SftpNative.bastion_sftp_edit_open(H, path, out var err), err);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var text = root.TryGetProperty("text", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString()! : throw new BastionException("The server sent an unreadable reply.");
        return (text, Fingerprint(root));
    }

    /// <summary>Save <paramref name="text"/> unless the server copy changed since <paramref name="fingerprint"/>
    /// (<paramref name="force"/> overwrites anyway). Returns the new fingerprint, or Saved=false when nothing was written.</summary>
    public (bool Saved, string? Fingerprint) EditSave(string path, string text, string? fingerprint, bool force)
    {
        string json;
        lock (_gate) json = Text(SftpNative.bastion_sftp_edit_save(H, path, text, fingerprint, force ? (byte)1 : (byte)0, out var err), err);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var saved = root.TryGetProperty("saved", out var s) && s.ValueKind == JsonValueKind.True;
        return (saved, saved ? Fingerprint(root) : fingerprint);
    }

    private static string? Fingerprint(JsonElement root) =>
        root.TryGetProperty("fingerprint", out var f) && f.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined) ? f.GetRawText() : null;

    /// <summary>Join a remote directory and a name with '/', as SFTP paths are.</summary>
    public static string Join(string dir, string name) => dir.EndsWith('/') ? dir + name : dir + "/" + name;

    /// <summary>The parent of a remote path, or the path itself at the root.</summary>
    public static string Parent(string path)
    {
        var trimmed = path.TrimEnd('/');
        var i = trimmed.LastIndexOf('/');
        return i <= 0 ? "/" : trimmed[..i];
    }

    private static string Text(IntPtr p, IntPtr err) => p == IntPtr.Zero ? throw new BastionException(Take(err) ?? "SFTP call failed") : Take(p) ?? "";

    private static long Count(long n, IntPtr err) => n < 0 ? throw new BastionException(Take(err) ?? "SFTP transfer failed") : n;

    private static void Check(int rc, IntPtr err)
    {
        if (rc != 0) throw new BastionException(Take(err) ?? "SFTP call failed");
    }

    private static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { Native.bastion_string_free(s); }
    }

    /// <summary>
    /// Never waits on the network (Codex W04): when no call holds the gate the handle is freed now; otherwise a pool
    /// thread frees it as soon as the in-flight transfer or listing returns. The gate still guarantees free-after-use.
    /// </summary>
    public void Dispose()
    {
        _closing = true;
        if (Monitor.TryEnter(_gate))
        {
            try { FreeLocked(); }
            finally { Monitor.Exit(_gate); }
            return;
        }
        _ = Task.Run(() => { lock (_gate) FreeLocked(); });
    }

    private void FreeLocked()
    {
        if (_handle == IntPtr.Zero) return;
        SftpNative.bastion_sftp_free(_handle);
        _handle = IntPtr.Zero;
    }
}
