using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>A row of the Credentials section (<c>kind</c> folder | password | ssh-key; <c>parent</c> null at the root). No secret.</summary>
public sealed record CredentialTreeRowDto(string Id, string Name, string? Parent, bool IsFolder, string? Username, string Kind);

/// <summary>A host or library folder that points straight at a credential; <see cref="Path"/> = library folders above it.</summary>
public sealed record CredentialUserDto(string NodeId, string Name, bool IsFolder, List<string> Path);

/// <summary>Result of a checked delete: not <see cref="Removed"/> while in use without force, with who uses it.</summary>
public sealed record CredentialRemoveDto(bool Removed, List<CredentialUserDto> Users);

/// <summary>The credential a host connects with, and the node that sets it (itself, a folder or a type default).</summary>
public sealed record EffectiveCredentialDto(string CredentialId, string SourceId, bool Inherited);

/// <summary>P/Invoke declarations for core-cabi/src/credtree.rs (C ABI 38).</summary>
internal static class CredentialTreeNative
{
    private const string Lib = "bastion_cabi";
    private const UnmanagedType U8 = UnmanagedType.LPUTF8Str;

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_tree_json(IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_add_folder(IntPtr v, [MarshalAs(U8)] string name, [MarshalAs(U8)] string? parent, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_credentials_rename_folder(IntPtr v, [MarshalAs(U8)] string id, [MarshalAs(U8)] string name, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_credentials_move_folder(IntPtr v, [MarshalAs(U8)] string id, [MarshalAs(U8)] string? parent, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_credentials_remove_folder(IntPtr v, [MarshalAs(U8)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_credentials_rename(IntPtr v, [MarshalAs(U8)] string id, [MarshalAs(U8)] string name, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_credentials_move(IntPtr v, [MarshalAs(U8)] string id, [MarshalAs(U8)] string? folder, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_users_json(IntPtr v, IntPtr lib, [MarshalAs(U8)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_remove_checked_json(IntPtr v, IntPtr lib, [MarshalAs(U8)] string id, int force, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_credentials_assign(IntPtr v, IntPtr lib, [MarshalAs(U8)] string nodeId, [MarshalAs(U8)] string? credentialId, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_effective_json(IntPtr v, IntPtr lib, [MarshalAs(U8)] string connectionId, out IntPtr err);
}

/// <summary>
/// The Credentials section of the tree (one vault, user folders, stable ids). Every change is in memory until
/// <see cref="Save"/>; <see cref="Assign"/> and a forced <see cref="RemoveChecked"/> also change the library, which
/// the caller saves.
/// </summary>
public sealed partial class CredentialStore
{
    private static readonly JsonSerializerOptions TreeJson = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    /// <summary>Under each parent: its folders (each followed by its contents), then its credentials, by name.</summary>
    public IReadOnlyList<CredentialTreeRowDto> Tree() =>
        JsonSerializer.Deserialize(TakeString(CredentialTreeNative.bastion_credentials_tree_json(H, out var err), err), TreeJson.Info<List<CredentialTreeRowDto>>()) ?? [];

    /// <summary>A new folder under <paramref name="parent"/> (null: the root); returns its id.</summary>
    public string AddFolder(string name, string? parent) => TakeString(CredentialTreeNative.bastion_credentials_add_folder(H, name, parent, out var err), err);

    public void RenameFolder(string id, string name) => Check(CredentialTreeNative.bastion_credentials_rename_folder(H, id, name, out var err), err, "could not rename the folder");

    public void MoveFolder(string id, string? parent) => Check(CredentialTreeNative.bastion_credentials_move_folder(H, id, parent, out var err), err, "could not move the folder");

    /// <summary>Only an empty folder can go; the core refuses one that holds anything.</summary>
    public void RemoveFolder(string id) => Check(CredentialTreeNative.bastion_credentials_remove_folder(H, id, out var err), err, "could not delete the folder");

    public void Rename(string id, string name) => Check(CredentialTreeNative.bastion_credentials_rename(H, id, name, out var err), err, "could not rename the credential");

    public void Move(string id, string? folder) => Check(CredentialTreeNative.bastion_credentials_move(H, id, folder, out var err), err, "could not move the credential");

    /// <summary>Hosts and folders of <paramref name="library"/> that point straight at the credential.</summary>
    public IReadOnlyList<CredentialUserDto> Users(LibraryClient library, string id) =>
        JsonSerializer.Deserialize(TakeString(CredentialTreeNative.bastion_credentials_users_json(H, library.NativeHandle, id, out var err), err), TreeJson.Info<List<CredentialUserDto>>()) ?? [];

    /// <summary>
    /// Delete with the in-use check. In use and not <paramref name="force"/>: nothing changes and the users come back.
    /// Forced: those hosts and folders inherit again; save the vault and the library.
    /// </summary>
    public CredentialRemoveDto RemoveChecked(LibraryClient library, string id, bool force) =>
        JsonSerializer.Deserialize(TakeString(CredentialTreeNative.bastion_credentials_remove_checked_json(H, library.NativeHandle, id, force ? 1 : 0, out var err), err), TreeJson.Info<CredentialRemoveDto>())
        ?? throw new BastionException("could not read the delete result");

    /// <summary>Point a host or library folder at one credential, or with null let it inherit. Save the library afterwards.</summary>
    public void Assign(LibraryClient library, string nodeId, string? credentialId) =>
        Check(CredentialTreeNative.bastion_credentials_assign(H, library.NativeHandle, nodeId, string.IsNullOrEmpty(credentialId) ? null : credentialId, out var err), err, "could not assign the credential");

    /// <summary>The credential a host connects with, or null when nothing up the chain sets one.</summary>
    public EffectiveCredentialDto? Effective(LibraryClient library, string connectionId)
    {
        var json = TakeString(CredentialTreeNative.bastion_credentials_effective_json(H, library.NativeHandle, connectionId, out var err), err);
        return json == "null" ? null : JsonSerializer.Deserialize(json, TreeJson.Info<EffectiveCredentialDto>());
    }

    private static void Check(int result, IntPtr err, string fallback)
    {
        if (result != 0) throw new BastionException(Take(err) ?? fallback);
    }
}
