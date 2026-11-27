using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>One Recently Deleted item (B10). <see cref="Kind"/> is <c>folder</c> or <c>connection</c>; <see cref="ParentId"/> null = the top.</summary>
public sealed record DeletedItemDto(string Id, string Name, string Kind, string? ParentId, string? ParentName, long DeletedAt, int ConnectionCount);

/// <summary>Where a restored item went. <see cref="LandedIn"/> null = the top of the library.</summary>
public sealed record RestoreDto(string? LandedIn, bool AtRootBecauseParentMissing);

/// <summary>P/Invoke for Recently Deleted (core-cabi/src/restore.rs, ABI 114).</summary>
internal static class RestoreNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_trash(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, long now, uint retentionDays, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_deleted_json(IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_restore(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_delete_permanently(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_empty_deleted(IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_purge_deleted(IntPtr lib, long now, uint retentionDays, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_live_connection_ids_json(IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern long bastion_credentials_prune_inline(IntPtr v, IntPtr lib, out IntPtr err);
}

public sealed partial class LibraryClient
{
    private static IReadOnlyList<string> Ids(string json) => JsonSerializer.Deserialize(json, AotJson.Options.Info<List<string>>()) ?? [];

    /// <summary>Delete to Recently Deleted (or for good when <paramref name="retentionDays"/> is 0). Returns the connection ids dropped for good.</summary>
    public IReadOnlyList<string> Trash(string id, long now, uint retentionDays) =>
        Ids(TakeString(RestoreNative.bastion_library_trash(Handle, id, now, retentionDays, out var err), err));

    public IReadOnlyList<DeletedItemDto> DeletedItems() =>
        JsonSerializer.Deserialize(TakeString(RestoreNative.bastion_library_deleted_json(Handle, out var err), err), Json.Info<List<DeletedItemDto>>()) ?? [];

    public RestoreDto Restore(string id) =>
        JsonSerializer.Deserialize(TakeString(RestoreNative.bastion_library_restore(Handle, id, out var err), err), Json.Info<RestoreDto>())
            ?? throw new BastionException("the core returned no restore result");

    public IReadOnlyList<string> DeletePermanently(string id) =>
        Ids(TakeString(RestoreNative.bastion_library_delete_permanently(Handle, id, out var err), err));

    public IReadOnlyList<string> EmptyDeleted() =>
        Ids(TakeString(RestoreNative.bastion_library_empty_deleted(Handle, out var err), err));

    public IReadOnlyList<string> PurgeDeleted(long now, uint retentionDays) =>
        Ids(TakeString(RestoreNative.bastion_library_purge_deleted(Handle, now, retentionDays, out var err), err));

    /// <summary>The tree plus Recently Deleted: the only correct live set for pruning inline secrets.</summary>
    public IReadOnlyList<string> LiveConnectionIds() =>
        Ids(TakeString(RestoreNative.bastion_library_live_connection_ids_json(Handle, out var err), err));
}

public sealed partial class CredentialStore
{
    /// <summary>Delete inline secrets of connections in neither the tree nor Recently Deleted, and save. Returns how many.</summary>
    public long PruneInline(LibraryClient library)
    {
        var n = RestoreNative.bastion_credentials_prune_inline(H, library.Handle, out var err);
        if (n < 0) throw new BastionException(Take(err) ?? "could not prune inline secrets");
        return n;
    }
}
