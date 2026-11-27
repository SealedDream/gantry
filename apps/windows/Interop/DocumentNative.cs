using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>What the core says about one open document (C ABI 27). Never carries a secret.</summary>
public sealed record DocumentInfoDto(string Id, string Name, string? Path, bool Protected, bool Locked, bool Biometric, bool Dirty,
    int LoadedVersion, int Credentials);

/// <summary>Result of an import from a <c>.bastion</c> file.</summary>
/// <param name="Duplicates">Names of connections skipped because Personal already has them.</param>
public sealed record DocumentImportDto(string SourceName, int Connections, IReadOnlyList<string> Duplicates, int Credentials, int CredentialsDropped, string? Folder);

internal static class DocumentNative
{
    private const string Lib = "bastion_cabi";
    private const CallingConvention C = CallingConvention.Cdecl;

    [DllImport(Lib, CallingConvention = C)]
    internal static extern IntPtr bastion_document_create([MarshalAs(UnmanagedType.LPUTF8Str)] string name, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern IntPtr bastion_document_open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern void bastion_document_free(IntPtr d);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern IntPtr bastion_document_info_json(IntPtr d, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern int bastion_document_unlock(IntPtr d, IntPtr password, nuint len, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern int bastion_document_unlock_biometric(IntPtr d, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern int bastion_document_lock(IntPtr d, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern IntPtr bastion_document_library(IntPtr d, out IntPtr err);

    /// <summary>LIB-01: this document shown by hand heads Recents, so the next launch opens it.</summary>
    [DllImport(Lib, CallingConvention = C)]
    internal static extern int bastion_document_note_opened(IntPtr d, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern int bastion_document_save(IntPtr d, [MarshalAs(UnmanagedType.LPUTF8Str)] string? path, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern int bastion_document_rename(IntPtr d, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern int bastion_document_set_password(IntPtr d, IntPtr password, nuint len, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern int bastion_document_set_biometric(IntPtr d, int on, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern IntPtr bastion_library_import_document_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, IntPtr password, nuint len, int apply,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = C)]
    internal static extern IntPtr bastion_documents_recent_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);
}

/// <summary>A document's tree is an ordinary library handle: every library call saves into the document.</summary>
public sealed partial class LibraryClient
{
    internal static LibraryClient Wrap(IntPtr handle, string path) => new(handle, path);
}

/// <summary>
/// One open Royal TS-style <c>.bastion</c> document (core <c>BastionDocument</c>, C ABI 27). Passwords cross the boundary
/// as zeroed UTF-8 buffers; the caller asks Windows Hello first, then <see cref="UnlockWithHello"/> unwraps the DPAPI
/// key. UI thread only.
/// </summary>
public sealed partial class DocumentClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private IntPtr _handle;
    private LibraryClient? _library;

    private DocumentClient(IntPtr handle) => _handle = handle;

    public static DocumentClient Create(string name, string dataDir) =>
        new(Check(DocumentNative.bastion_document_create(name, dataDir, out var err), err, "could not create the document"));

    public static DocumentClient Open(string path, string dataDir) =>
        new(Check(DocumentNative.bastion_document_open(path, dataDir, out var err), err, "could not open the document"));

    public static IReadOnlyList<string> Recent(string dataDir)
    {
        var text = GatewayNative.Take(DocumentNative.bastion_documents_recent_json(dataDir, out var err))
            ?? throw new BastionException(GatewayNative.Take(err) ?? "could not read recent documents");
        return JsonSerializer.Deserialize(text, AotJson.Options.Info<List<string>>()) ?? [];
    }

    public DocumentInfoDto Info
    {
        get
        {
            var text = GatewayNative.Take(DocumentNative.bastion_document_info_json(Live, out var err))
                ?? throw new BastionException(GatewayNative.Take(err) ?? "could not read the document");
            return JsonSerializer.Deserialize(text, Json.Info<DocumentInfoDto>()) ?? throw new BastionException("unreadable document info");
        }
    }

    /// <summary>The tree as a library; null while locked. Kept until <see cref="Lock"/>, Save As or <see cref="Dispose"/>.</summary>
    public LibraryClient? Library
    {
        get
        {
            if (_library is not null) return _library;
            var handle = DocumentNative.bastion_document_library(Live, out var err);
            if (handle == IntPtr.Zero) { GatewayNative.Take(err); return null; }
            var info = Info;
            return _library = LibraryClient.Wrap(handle, info.Path ?? info.Name + ".gantry");
        }
    }

    public void Unlock(string password)
    {
        var bytes = Encoding.UTF8.GetBytes(password);
        var len = bytes.Length;
        using var secret = new Utf8Secret(bytes);
        Ok(DocumentNative.bastion_document_unlock(Live, secret.Pointer, (nuint)len, out var err), err, "could not unlock");
    }

    public void UnlockWithHello() => Ok(DocumentNative.bastion_document_unlock_biometric(Live, out var err), err, "Windows Hello unlock failed");

    public void Lock()
    {
        DropLibrary();
        Ok(DocumentNative.bastion_document_lock(Live, out var err), err, "could not lock");
    }

    /// <summary>Save to its file, or Save As <paramref name="path"/>.</summary>
    public void Save(string? path = null)
    {
        Ok(DocumentNative.bastion_document_save(Live, path, out var err), err, "could not save the document");
        if (path is not null) DropLibrary(); // the next Library carries the new path
    }

    /// <summary>LIB-01: the user showed this document by hand (never a lock); the next launch opens it.</summary>
    public void NoteOpened() => Ok(DocumentNative.bastion_document_note_opened(Live, out var err), err, "could not update recent documents");

    public void Rename(string name) => Ok(DocumentNative.bastion_document_rename(Live, name, out var err), err, "could not rename");

    /// <summary>Set, change or (null/empty) remove the password.</summary>
    public void SetPassword(string? password)
    {
        var bytes = string.IsNullOrEmpty(password) ? null : Encoding.UTF8.GetBytes(password);
        var len = bytes?.Length ?? 0;
        using var secret = new Utf8Secret(bytes);
        Ok(DocumentNative.bastion_document_set_password(Live, secret.Pointer, (nuint)len, out var err), err, "could not set the password");
    }

    public void SetHello(bool on) => Ok(DocumentNative.bastion_document_set_biometric(Live, on ? 1 : 0, out var err), err, "could not change Windows Hello");

    /// <summary>Preview (<paramref name="apply"/> false) or import a document into the Personal library (no secrets come along).</summary>
    public static DocumentImportDto ImportIntoLibrary(LibraryClient library, string path, string? password, bool apply, string dataDir)
    {
        var bytes = string.IsNullOrEmpty(password) ? null : Encoding.UTF8.GetBytes(password);
        var len = bytes?.Length ?? 0;
        using var secret = new Utf8Secret(bytes);
        var text = GatewayNative.Take(DocumentNative.bastion_library_import_document_json(library.NativeHandle, path, secret.Pointer, (nuint)len, apply ? 1 : 0, dataDir, out var err))
            ?? throw new BastionException(GatewayNative.Take(err) ?? "could not import");
        return JsonSerializer.Deserialize(text, Json.Info<DocumentImportDto>()) ?? throw new BastionException("unreadable import result");
    }

    private void DropLibrary()
    {
        _library?.Dispose();
        _library = null;
    }

    internal IntPtr Live => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(DocumentClient));

    private static IntPtr Check(IntPtr handle, IntPtr err, string what) =>
        handle != IntPtr.Zero ? handle : throw new BastionException(GatewayNative.Take(err) ?? what);

    internal static void Ok(int rc, IntPtr err, string what)
    {
        if (rc != 0) throw new BastionException(GatewayNative.Take(err) ?? what);
    }

    public void Dispose()
    {
        DropLibrary();
        if (_handle == IntPtr.Zero) return;
        DocumentNative.bastion_document_free(_handle);
        _handle = IntPtr.Zero;
    }
}
