using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

// Personal as one encrypted .bastion document (ABI 94, NW-OF-A; owner points 7, 20; Native Mac #703). The tree and the
// credential vault live in Documents\Bastion\Personal.bastion. The document key is wrapped by a device key that the core
// keeps as one DPAPI (current user) blob in the data folder: read once, never a prompt. On first launch the old
// library.json + credentials.vault move in once, verified, and the old files are copied to pre-unified-<time>\.
internal static class PersonalNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_personal_open([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_personal_free(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_personal_library(IntPtr p, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_personal_vault(IntPtr p, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_personal_info_json(IntPtr p, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_personal_migration_json(IntPtr p, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_personal_rename(IntPtr p, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, out IntPtr err);

    /// <summary>LIB-01: Personal shown by hand heads Recents, so the next launch opens it.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_personal_note_shown(IntPtr p, out IntPtr err);
}

public sealed record PersonalInfoDto(string Id, string Path, string Name, bool Locked, bool HasMasterPassword);

public sealed record PersonalMigrationDto(uint Folders, uint Connections, uint Credentials, string? Backup);

/// <summary>The open Personal document. Its library and vault handles stay valid after it is disposed.</summary>
public sealed partial class PersonalDocument : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private IntPtr _handle;
    private readonly string _libraryPath;

    private PersonalDocument(IntPtr handle, string libraryPath)
    {
        _handle = handle;
        _libraryPath = libraryPath;
    }

    public static string DefaultPath =>
        TestHooks.PersonalPathOverride is { } p ? System.IO.Path.GetFullPath(p)
        // A test library that opts in keeps Personal next to it, with its device key: never the user's real document,
        // whose key lives in the real data folder ("no device key" otherwise, once the test folder is wiped).
        : TestHooks.LibraryOverride is { } lib ? System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(lib))!, "Personal.bastion")
        : AppRename.PersonalDocument(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppRename.NewName));

    /// <summary>Real launches use the document; a UI test library keeps the old files unless it opts in (test builds only).</summary>
    public static bool Enabled => TestHooks.LibraryOverride is null || TestHooks.PersonalDocumentOptIn;

    /// <summary>Open (or create, or migrate into) Personal.bastion. <paramref name="libraryPath"/> is the old
    /// library.json path: its folder is the data folder the old files move from.</summary>
    public static PersonalDocument Open(string libraryPath)
    {
        LibraryClient.CheckAbi();
        var dataDir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(libraryPath))!;
        var path = DefaultPath;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        var h = PersonalNative.bastion_personal_open(dataDir, path, out var err);
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not open Personal");
        return new PersonalDocument(h, libraryPath);
    }

    /// <summary>The tree, saving into the document.</summary>
    public LibraryClient Library()
    {
        var h = PersonalNative.bastion_personal_library(H, out var err);
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not open the Personal library");
        return LibraryClient.FromHandle(h, _libraryPath);
    }

    /// <summary>The credential vault inside the document; opening it needs no prompt.</summary>
    public CredentialStore Vault()
    {
        var h = PersonalNative.bastion_personal_vault(H, out var err);
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not open the Personal vault");
        return CredentialStore.FromHandle(h);
    }

    public PersonalInfoDto Info() =>
        JsonSerializer.Deserialize(TakeString(PersonalNative.bastion_personal_info_json(H, out var err), err), Json.Info<PersonalInfoDto>())
        ?? throw new BastionException("the core returned no Personal info");

    /// <summary>What this launch's one-time move did, or null when nothing moved.</summary>
    public PersonalMigrationDto? Migration() =>
        JsonSerializer.Deserialize(TakeString(PersonalNative.bastion_personal_migration_json(H, out var err), err), Json.Info<PersonalMigrationDto?>());

    public void Rename(string name)
    {
        if (PersonalNative.bastion_personal_rename(H, name, out var err) != 0) throw new BastionException(Take(err) ?? "could not rename Personal");
    }

    /// <summary>LIB-01: the user showed Personal by hand (never a lock); the next launch opens it.</summary>
    public void NoteShown()
    {
        if (PersonalNative.bastion_personal_note_shown(H, out var err) != 0) throw new BastionException(Take(err) ?? "could not update recent documents");
    }

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(PersonalDocument));

    private static string TakeString(IntPtr s, IntPtr err)
    {
        if (s == IntPtr.Zero) throw new BastionException(Take(err) ?? "the core returned no value");
        return Take(s) ?? "";
    }

    private static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { Native.bastion_string_free(s); }
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        PersonalNative.bastion_personal_free(_handle);
        _handle = IntPtr.Zero;
    }
}
