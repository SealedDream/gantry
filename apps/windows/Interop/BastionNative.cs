using System.Runtime.InteropServices;
using System.Text.Json;

// Native libraries named in this assembly's DllImports (bastion_cabi, and the Windows App SDK's generated start-up
// import of Microsoft.WindowsAppRuntime.dll) load from the application directory, with their own dependencies from
// System32: never from the current directory or PATH (DLL planting). SafeDirectories = app folder + System32 (+ folders
// added with AddDllDirectory); ApplicationDirectory alone left Native AOT unable to resolve the runtime's dependencies.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]

namespace Bastion.Shell.Interop;

/// <summary>Raised when the native core reports an error.</summary>
public sealed partial class BastionException(string message) : Exception(message);

public sealed record ConnectionDto(string Id, string Name, string Protocol, string Host, int? Port, string? Username, string? Group, string? SourceStatus, bool Imported, string? CredentialId = null, string? VaultwardenItem = null,
    bool Favorite = false, string? Icon = null, string? IconLabel = null, bool HasTools = false, string? Unavailable = null, string? OwnIcon = null, string? EffectiveCredentialId = null, IReadOnlyList<string>? Tags = null)
{
    /// <summary>PLUG-03a: the core's fixed text ("Needs a newer Gantry or a plugin") for an entry of a type this build
    /// does not know, or null. Such an entry is kept and saved unchanged, shown with a marker, and never connected.</summary>
    public bool IsUnavailable => !string.IsNullOrEmpty(Unavailable);
}

public sealed record FolderDto(string Id, string Name, List<FolderDto> Folders, List<ConnectionDto> Connections);

/// <summary>
/// P/Invoke declarations for core-cabi (see core-cabi/src/lib.rs for the contract). All strings are
/// UTF-8. Strings returned by the library are freed with <c>bastion_string_free</c>.
/// </summary>
internal static partial class Native
{
    private const string Lib = "bastion_cabi";
    internal const uint ExpectedAbiVersion = 149;

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bastion_abi_version();

    /// <summary>SEC-03 (C ABI 105): minutes a remembered login may be reused; 0 = until Lock or quit.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bastion_session_login_reuse_minutes(uint userMinutes);

    /// <summary>SEC-03 (C ABI 105): 1 when a login remembered at <paramref name="rememberedAt"/> may be reused now.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_remembered_login_usable(ulong rememberedAt, ulong now, uint minutes);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_library_free(IntPtr lib);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_tree_json(IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_add_folder(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string? parent, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_add_connection(
        IntPtr lib,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? parent,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string protocol,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string host,
        int port,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_remove(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_save(IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_string_free(IntPtr s);
}

/// <summary>One open library document. Not thread-safe; use from the UI thread.</summary>
public sealed partial class LibraryClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private readonly NativeLifetime _life;

    public string Path { get; }

    private LibraryClient(IntPtr handle, string path)
    {
        _life = new NativeLifetime(handle, Native.bastion_library_free, nameof(LibraryClient));
        Path = path;
    }

    /// <summary>Open <paramref name="path"/>, creating an empty library if the file does not exist.</summary>
    public static LibraryClient Open(string path)
    {
        CheckAbi();

        var handle = Native.bastion_library_open(path, out var err);
        if (handle == IntPtr.Zero) throw new BastionException(TakeError(err, "could not open the library"));
        return new LibraryClient(handle, path);
    }

    /// <summary>Check the native core's ABI once before the first native call (shared by <see cref="Open"/> and Personal).</summary>
    internal static void CheckAbi()
    {
        uint abi;
        try { abi = Native.bastion_abi_version(); }
        catch (DllNotFoundException e)
        {
            throw new BastionException("bastion_cabi.dll was not found next to the app. Run apps\\windows\\build-core.ps1.\n" + e.Message);
        }
        if (abi != Native.ExpectedAbiVersion)
            throw new BastionException($"bastion_cabi.dll speaks ABI {abi}, this app needs {Native.ExpectedAbiVersion}. Rebuild the native core.");
    }

    /// <summary>A library handle taken from the Personal document (ABI 94). <paramref name="path"/> stays the old
    /// <c>library.json</c> path so the data directory (sessions, history, settings) is unchanged.</summary>
    internal static LibraryClient FromHandle(IntPtr handle, string path) => new(handle, path);

    /// <summary>
    /// An unsaved in-memory library with one connection for a Quick Connect target (<c>user@host:port</c>, <c>rdp://host</c>,
    /// <c>https://…</c>). <see cref="Save"/> refuses it; connecting through it still checks host keys and asks for the login.
    /// </summary>
    public static LibraryClient QuickConnect(string target)
    {
        var handle = PrefsNative.bastion_library_quick_connect(target, out var err);
        if (handle == IntPtr.Zero) throw new BastionException(TakeError(err, "not a host to connect to"));
        return new LibraryClient(handle, "");
    }

    /// <summary>Wraps a library handle the core just returned (an unsaved one, like Quick Connect).</summary>
    internal static LibraryClient FromUnsavedHandle(IntPtr handle) => new(handle, "");

    /// <summary>True for a Quick Connect library, which is never written.</summary>
    public bool IsQuickConnect => Path.Length == 0;

    public FolderDto Tree()
    {
        var json = TakeString(Native.bastion_library_tree_json(Handle, out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<FolderDto>()) ?? throw new BastionException("the core returned an empty tree");
    }

    public string AddFolder(string? parentId, string name) =>
        TakeString(Native.bastion_library_add_folder(Handle, parentId, name, out var err), err);

    /// <param name="port">null means the protocol's default port.</param>
    public string AddConnection(string? parentId, string name, string protocol, string host, int? port, string? username) =>
        TakeString(Native.bastion_library_add_connection(Handle, parentId, name, protocol, host, port ?? -1, string.IsNullOrWhiteSpace(username) ? null : username, out var err), err);

    public void Remove(string id)
    {
        if (Native.bastion_library_remove(Handle, id, out var err) != 0) throw new BastionException(TakeError(err, "could not remove the item"));
    }

    /// <summary>Assign a vault credential to a connection; null clears it.</summary>
    public void SetCredential(string connectionId, string? credentialId)
    {
        if (CredentialsNative.bastion_library_set_credential(Handle, connectionId, credentialId, out var err) != 0) throw new BastionException(TakeError(err, "could not assign the credential"));
    }

    /// <summary>Assign a Vaultwarden item to a connection, or clear it with null. The id is not a secret.</summary>
    public void SetVaultwardenItem(string connectionId, string? itemId)
    {
        if (VaultwardenNative.bastion_library_set_vaultwarden_item(Handle, connectionId, itemId, out var err) != 0) throw new BastionException(TakeError(err, "could not assign the Vaultwarden item"));
    }

    /// <summary>Read-only scan of an OpenSSH config dir plus an optional extra file (null to skip; missing is ignored).</summary>
    public static SshScanDto ScanSsh(string root, string? extraFile)
    {
        var json = TakeString(SshImportNative.bastion_ssh_scan_json(root, extraFile, out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<SshScanDto>()) ?? new SshScanDto([], [], []);
    }

    /// <summary>Import the chosen hosts (by identity), one folder per group; hosts already imported are skipped. Returns the count.</summary>
    public int ImportSsh(string root, string? extraFile, IEnumerable<string> identities)
    {
        var n = SshImportNative.bastion_library_import_ssh_hosts(Handle, root, extraFile, AotJson.Write<IEnumerable<string>>(identities, AotJson.Options), out var err);
        if (n < 0) throw new BastionException(TakeError(err, "could not import the hosts"));
        return n;
    }

    /// <summary>Import-preview rows for the forward lines of the scanned hosts; <paramref name="chosen"/> are ticked keys in tick order. Creates nothing.</summary>
    public List<SshForwardDto> SshForwards(string root, string? extraFile, IEnumerable<string> chosen)
    {
        var json = TakeString(SshImportNative.bastion_library_ssh_forwards_json(Handle, root, extraFile, AotJson.Write<IEnumerable<string>>(chosen, AotJson.Options), out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<List<SshForwardDto>>()) ?? new();
    }

    /// <summary>Create auto-starting tunnels for the ticked forward rows (import the hosts first). Returns the count.</summary>
    public int ImportSshForwards(string root, string? extraFile, IEnumerable<string> keys)
    {
        var n = SshImportNative.bastion_library_import_ssh_forwards(Handle, root, extraFile, AotJson.Write<IEnumerable<string>>(keys, AotJson.Options), out var err);
        if (n < 0) throw new BastionException(TakeError(err, "could not create the tunnels"));
        return n;
    }

    /// <summary>Write the SSH connections (all when <paramref name="ids"/> is null) to <paramref name="path"/> as an OpenSSH config (C ABI 34).</summary>
    public SshExportDto ExportSshConfig(string path, IEnumerable<string>? ids)
    {
        var json = TakeString(SshImportNative.bastion_library_export_ssh_config_json(Handle, path, ids is null ? null : AotJson.Write<IEnumerable<string>>(ids, AotJson.Options), out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<SshExportDto>()) ?? throw new BastionException("the core returned an empty export result");
    }

    /// <summary>What a portable <c>bastion-export</c> v1 would hold; nothing is written (C ABI 86).</summary>
    public ExportPreviewDto ExportPreview(IEnumerable<string>? ids)
    {
        var json = TakeString(SshImportNative.bastion_library_export_preview_json(Handle, ids is null ? null : AotJson.Write<IEnumerable<string>>(ids, AotJson.Options), out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<ExportPreviewDto>()) ?? throw new BastionException("the core returned an empty export preview");
    }

    /// <summary>Write the secret-free <c>bastion-export</c> v1 to <paramref name="path"/> (atomic, owner-only; C ABI 86).</summary>
    public void ExportPortable(string path, IEnumerable<string>? ids)
    {
        if (SshImportNative.bastion_library_export_portable(Handle, path, ids is null ? null : AotJson.Write<IEnumerable<string>>(ids, AotJson.Options), out var err) != 0)
            throw new BastionException(TakeError(err, "could not write the export"));
    }

    /// <summary>Editor fields for a type (<c>ssh</c>, …); <paramref name="defaultsOnly"/> gives the inheritable Default Settings (protocol null = folders).</summary>
    public static IReadOnlyList<PropertyDefDto> PropertySchema(string? protocol, bool defaultsOnly) =>
        JsonSerializer.Deserialize(TakeString(PropertiesNative.bastion_property_schema_json(protocol, defaultsOnly ? 1 : 0, out var err), err), Json.Info<List<PropertyDefDto>>()) ?? [];

    /// <summary>A connection's values, or a folder's Default Settings, with where each comes from.</summary>
    public IReadOnlyList<PropertyValueDto> PropertyValues(string id) =>
        JsonSerializer.Deserialize(TakeString(PropertiesNative.bastion_library_property_values_json(Handle, id, out var err), err), Json.Info<List<PropertyValueDto>>()) ?? [];

    /// <summary>A connection's effective per-host colour (own <c>host_color</c>, else the nearest folder's), or null (C ABI 66).</summary>
    public HostColorDto? HostColor(string id) =>
        JsonSerializer.Deserialize(TakeString(PropertiesNative.bastion_library_host_color_json(Handle, id, out var err), err), Json.Info<HostColorDto?>());

    /// <summary>Every coloured connection's effective colour by id, in one pass over the tree. Asking
    /// <see cref="HostColor"/> per row walks the whole tree each time (quadratic on 5,000 connections).</summary>
    public Dictionary<string, HostColorDto> HostColors() =>
        JsonSerializer.Deserialize(TakeString(PropertiesNative.bastion_library_host_colors_json(Handle, out var err), err), Json.Info<Dictionary<string, HostColorDto>>()) ?? new();

    public IReadOnlyList<PropertyValueDto> TypeDefaultValues(string protocol) =>
        JsonSerializer.Deserialize(TakeString(PropertiesNative.bastion_library_type_default_values_json(Handle, protocol, out var err), err), Json.Info<List<PropertyValueDto>>()) ?? [];

    /// <summary>Set a property on a connection or folder; null or blank resets it to inherited.</summary>
    public void SetProperty(string id, string key, string? value)
    {
        if (PropertiesNative.bastion_library_set_property(Handle, id, key, value, out var err) != 0) throw new BastionException(TakeError(err, "could not set " + key));
    }

    public void SetTypeDefault(string protocol, string key, string? value)
    {
        if (PropertiesNative.bastion_library_set_type_default(Handle, protocol, key, value, out var err) != 0) throw new BastionException(TakeError(err, "could not set " + key));
    }

    /// <summary>Names of connections a folder default (or, with <paramref name="folderId"/> null, a type default) applies to.</summary>
    public IReadOnlyList<string> AffectedByDefault(string? folderId, string? protocol, string key) =>
        JsonSerializer.Deserialize(TakeString(PropertiesNative.bastion_library_affected_by_default_json(Handle, folderId, protocol, key, out var err), err), Json.Info<List<string>>()) ?? [];

    /// <summary>B3-BULK-EDIT (C ABI 126): the properties every connection in <paramref name="ids"/> has, with the shared own
    /// value or Mixed. <c>name</c> and <c>host</c> are never listed.</summary>
    public IReadOnlyList<SelectionPropertyDto> PropertiesForSelection(IReadOnlyList<string> ids) =>
        JsonSerializer.Deserialize(TakeString(PropertiesNative.bastion_library_properties_for_selection_json(Handle, AotJson.Write<IReadOnlyList<string>>(ids, Json), out var err), err), Json.Info<List<SelectionPropertyDto>>()) ?? [];

    /// <summary>Set <paramref name="key"/> on every connection in <paramref name="ids"/>, or on none when one refuses it
    /// (null or blank: inherit). Returns how many changed. Call <see cref="Save"/> afterwards.</summary>
    public int ApplyToSelection(IReadOnlyList<string> ids, string key, string? value)
    {
        var n = PropertiesNative.bastion_library_apply_to_selection(Handle, AotJson.Write<IReadOnlyList<string>>(ids, Json), key, value, out var err);
        if (n < 0) throw new BastionException(TakeError(err, "could not set " + key));
        return n;
    }

    /// <summary>TAGS (C ABI 131): add and remove tags on every connection in <paramref name="ids"/>, or on none; other
    /// tags stay. Returns how many changed. Call <see cref="Save"/> afterwards.</summary>
    public int EditTagsOnSelection(IReadOnlyList<string> ids, IReadOnlyList<string> add, IReadOnlyList<string> remove)
    {
        var n = PropertiesNative.bastion_library_edit_tags_on_selection(Handle, AotJson.Write<IReadOnlyList<string>>(ids, Json), AotJson.Write<IReadOnlyList<string>>(add, Json), AotJson.Write<IReadOnlyList<string>>(remove, Json), out var err);
        if (n < 0) throw new BastionException(TakeError(err, "could not change tags"));
        return n;
    }

    public void Save()
    {
        if (Native.bastion_library_save(Handle, out var err) != 0) throw new BastionException(TakeError(err, "could not save the library"));
    }

    internal IntPtr Handle => _life.Handle;

    /// <summary>Hold the library for a blocking call made off the UI thread (SSH connect, tunnel start).</summary>
    internal NativeLifetime.Lease AcquireLease() => _life.Acquire();

    /// <summary>The raw handle, for the <c>bastion_session_*</c> calls that take a library (SessionNative.cs).</summary>
    internal IntPtr NativeHandle => Handle;

    /// <summary>Read and free a returned string; when it is NULL, throw the error that came with it.</summary>
    internal static string TakeString(IntPtr s, IntPtr err)
    {
        if (s == IntPtr.Zero) throw new BastionException(TakeError(err, "the core returned no value"));
        try { return Marshal.PtrToStringUTF8(s) ?? ""; }
        finally { Native.bastion_string_free(s); }
    }

    internal static string TakeError(IntPtr err, string fallback)
    {
        if (err == IntPtr.Zero) return fallback;
        try { return Marshal.PtrToStringUTF8(err) ?? fallback; }
        finally { Native.bastion_string_free(err); }
    }

    /// <summary>Never blocks; an in-flight connect that borrowed the library frees it when it returns (Codex W02).</summary>
    public void Dispose() => _life.Release();
}

public sealed record SshHostDto(string Alias, string Hostname, string? User, int? Port, string Group, string SourceFile, string Identity,
    string? ProxyJump, List<string> Flags, List<string> Placeholders);

public sealed record SshExportDto(int Exported, List<string> Skipped);
public sealed record ExportPreviewDto(int Folders, int Connections, int CredentialRefs, List<string> StrippedFields);

/// <summary>One forward line in the OpenSSH import preview; <see cref="Blocked"/> non-empty = cannot be imported.</summary>
public sealed record SshForwardDto(string Key, string HostIdentity, string HostAlias, string Kind, string Line, string Description, string Explain, string Warning, string Blocked);

public sealed record SshScanDto(List<SshHostDto> Hosts, List<string> Files, List<string> Warnings);

/// <summary>P/Invoke for core-cabi/src/sshimport.rs: a read-only OpenSSH config scan and the deduplicating import.</summary>
public sealed partial class LibraryClient
{
    /// <summary>Import a CSV, .rdp, PuTTY .reg, Royal TS .json or RDCMan .rdg file into a new top-level folder (C ABI 76).
    /// Passwords in the file are never read. Save the library after.</summary>
    public ImportFileDto ImportFile(string path) =>
        JsonSerializer.Deserialize(TakeString(ImportFileNative.bastion_library_import_file_json(Handle, path, out var err), err), Json.Info<ImportFileDto>())
        ?? throw new BastionException("the core returned no import result");
}

internal static class SshImportNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_ssh_scan_json([MarshalAs(UnmanagedType.LPUTF8Str)] string root, [MarshalAs(UnmanagedType.LPUTF8Str)] string? extraFile, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_import_ssh_hosts(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string root,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? extraFile, [MarshalAs(UnmanagedType.LPUTF8Str)] string identitiesJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_ssh_forwards_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string root,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? extraFile, [MarshalAs(UnmanagedType.LPUTF8Str)] string? chosenJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_import_ssh_forwards(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string root,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? extraFile, [MarshalAs(UnmanagedType.LPUTF8Str)] string keysJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_export_ssh_config_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? idsJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_export_preview_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string? idsJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_export_portable(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? idsJson, out IntPtr err);
}

/// <summary>Where Windows OpenSSH keeps its configs.</summary>
public static class SshConfigLocation
{
    /// <summary>%USERPROFILE%\.ssh (config, its Includes and config.d).</summary>
    public static string UserDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");

    /// <summary>%ProgramData%\ssh\ssh_config, the system-wide file.</summary>
    public static string SystemFile => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh", "ssh_config");
}
/// <summary>An editor field from the core; <see cref="Options"/> lists the values of a <c>choice</c> (C ABI 16).</summary>
public sealed record PropertyDefDto(string Key, string Label, string Category, string Kind, string Help, bool Inheritable, List<PropertyOptionDto>? Options = null);

public sealed record PropertyOptionDto(string Id, string Label);

/// <summary>Per-host colour: <c>#rrggbb</c> accent, readable text colour and <c>#rrggbbaa</c> tint (core <c>hostcolors</c>).</summary>
/// <summary>UI-01 added the nearest preset name, the privileged flag and text-safe tones (4.5:1, core-tested).</summary>
public sealed record HostColorDto(string Accent, string Text, string Tint, string Named = "", bool Privileged = false,
    string FgLight = "", string BgLight = "", string FgDark = "", string BgDark = "");

/// <summary>One row of the bulk editor: a shared property, its shared own value (null: all inherit) or Mixed.</summary>
public sealed record SelectionPropertyDto(PropertyDefDto Def, string? Value, bool Mixed);

public sealed record PropertyValueDto(string Key, string? Own, string? Effective, string Source, string? From);

/// <summary>P/Invoke for core-cabi/src/properties.rs: the property editor schema, values and defaults.</summary>
internal static class PropertiesNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_property_schema_json([MarshalAs(UnmanagedType.LPUTF8Str)] string? protocol, int defaultsOnly, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_property_values_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_host_color_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_host_colors_json(IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_type_default_values_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string protocol, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_property(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string key, [MarshalAs(UnmanagedType.LPUTF8Str)] string? value, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_type_default(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string protocol, [MarshalAs(UnmanagedType.LPUTF8Str)] string key, [MarshalAs(UnmanagedType.LPUTF8Str)] string? value, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_affected_by_default_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string? folderId, [MarshalAs(UnmanagedType.LPUTF8Str)] string? protocol, [MarshalAs(UnmanagedType.LPUTF8Str)] string key, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_properties_for_selection_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string idsJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_apply_to_selection(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string idsJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string key, [MarshalAs(UnmanagedType.LPUTF8Str)] string? value, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_edit_tags_on_selection(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string idsJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string addJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string removeJson, out IntPtr err);
}
