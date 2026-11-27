using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>Effective values of a host imported from an OpenSSH config, after the user's overrides (core-ffi EffectiveView).</summary>
public sealed record SshEffectiveDto(string Identity, string Hostname, string? User, int? Port, string? IdentityFile, string? ProxyJump,
    string? CredentialRef, List<string> Unresolved, List<string> SourcePlaceholders);

/// <summary>The user's personal values for one imported host; null or blank means the config's value.</summary>
public sealed record SshOverrideDto(string? User, string? Hostname, int? Port, string? IdentityFile, string? ProxyJump, string? CredentialRef,
    Dictionary<string, string> Placeholders);

/// <summary>C ABI 17: connection notes and the SSH-config overrides the inspector shows and edits.</summary>
internal static partial class Native
{
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_notes(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_notes(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string notes, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_ssh_effective_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_ssh_override_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string identity, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_ssh_set_override([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string identity,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);
}

public sealed partial class LibraryClient
{
    /// <summary>The connection's notes ("" when none).</summary>
    public string Notes(string id) => TakeString(Native.bastion_library_notes(Handle, id, out var err), err);

    /// <summary>Replace the notes in memory; <see cref="Save"/> writes them.</summary>
    public void SetNotes(string id, string notes) => Check(Native.bastion_library_set_notes(Handle, id, notes, out var err), err, "could not save the notes");
}

/// <summary>Imported SSH hosts: effective values and personal overrides in <c>ssh-workflow.json</c> (the data directory).</summary>
public static class SshOverrides
{
    /// <summary>Effective values, or null for a connection created in Bastion.</summary>
    public static SshEffectiveDto? Effective(string dataDir, LibraryClient library, string connectionId) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(Native.bastion_ssh_effective_json(dataDir, library.Handle, connectionId, out var err), err), PrefsNative.Json.Info<SshEffectiveDto?>());

    public static SshOverrideDto Get(string dataDir, string identity) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(Native.bastion_ssh_override_json(dataDir, identity, out var err), err), PrefsNative.Json.Info<SshOverrideDto>())
        ?? new SshOverrideDto(null, null, null, null, null, null, new());

    /// <summary>Replace the overrides (saved at once). The core refuses a port outside 1–65535 and changes nothing.</summary>
    public static void Set(string dataDir, string identity, SshOverrideDto value) =>
        LibraryClient.Check(Native.bastion_ssh_set_override(dataDir, identity, AotJson.Write<SshOverrideDto>(value, PrefsNative.Json), out var err), err, "could not save the overrides");
}
