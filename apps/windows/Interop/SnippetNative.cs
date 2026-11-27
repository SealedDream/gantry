using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>A command snippet. <see cref="Multiline"/> snippets need a confirmation before sending.</summary>
public sealed record SnippetDto(string Id, string Name, string Text, bool Multiline, int Lines);

/// <summary>What <see cref="SnippetStore.Send"/> did: <see cref="NeedsConfirm"/> means nothing was sent; ask, then send confirmed.</summary>
public readonly record struct SnippetSendResult(bool NeedsConfirm, int Tabs);

internal static class SnippetNative
{
    private const string Lib = "bastion_cabi";

    /// <summary><c>SNIPPET_NEEDS_CONFIRM</c>.</summary>
    internal const int NeedsConfirm = -2;

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_snippets_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string? query, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_snippet_put([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string text, [MarshalAs(UnmanagedType.LPUTF8Str)] string? id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_snippet_remove([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_snippet_send([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id,
        IntPtr[] terminals, UIntPtr count, int confirmed, IntPtr manager, out IntPtr err);
}

/// <summary>
/// Command snippets (C ABI 64): the same <c>snippets.json</c> the Mac and Tauri apps use. Text that looks like a
/// secret is refused by the core. Sends are audited by name and tab count only.
/// </summary>
public sealed class SnippetStore
{
    /// <summary>Tabs one send may reach (<c>SNIPPET_MAX_TARGETS</c>).</summary>
    public const int MaxTargets = 64;

    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private readonly string _dataDir;

    public SnippetStore(string dataDir) => _dataDir = dataDir;

    /// <summary>Snippets holding every word of <paramref name="query"/> in name or text (null lists all), by name.</summary>
    public IReadOnlyList<SnippetDto> Search(string? query = null) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(SnippetNative.bastion_snippets_json(_dataDir, string.IsNullOrEmpty(query) ? null : query, out var err), err), Json.Info<List<SnippetDto>>()) ?? [];

    /// <summary>Add (null <paramref name="id"/>) or replace; returns the id.</summary>
    public string Put(string name, string text, string? id = null) =>
        LibraryClient.TakeString(SnippetNative.bastion_snippet_put(_dataDir, name, text, id, out var err), err);

    public void Remove(string id)
    {
        if (SnippetNative.bastion_snippet_remove(_dataDir, id, out var err) != 0) throw new BastionException(LibraryClient.TakeError(err, "could not remove the snippet"));
    }

    /// <summary>
    /// Type snippet <paramref name="id"/> into each terminal like a paste. A multi-line snippet, or more than one
    /// tab, needs <paramref name="confirmed"/>; without it nothing is sent and <see cref="SnippetSendResult.NeedsConfirm"/> is set.
    /// <paramref name="audit"/> (may be null) records the send.
    /// </summary>
    public SnippetSendResult Send(string id, IReadOnlyList<TerminalSession> terminals, bool confirmed, SessionManagerClient? audit)
    {
        var handles = terminals.Select(t => t.NativeHandle).ToArray();
        var r = SnippetNative.bastion_snippet_send(_dataDir, id, handles, (UIntPtr)handles.Length, confirmed ? 1 : 0, audit?.NativeHandle ?? IntPtr.Zero, out var err);
        GC.KeepAlive(terminals);
        if (r == SnippetNative.NeedsConfirm) return new(true, 0);
        return r >= 0 ? new(false, r) : throw new BastionException(LibraryClient.TakeError(err, "could not send the snippet"));
    }
}
