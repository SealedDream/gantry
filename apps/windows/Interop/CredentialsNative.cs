using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>A credential as listed by the core: never a secret, only what identifies it.</summary>
public sealed record CredentialDto(string Id, string Name, string? Folder, string Username, string Kind)
{
    public bool IsSshKey => Kind == "ssh-key";
    public string KindLabel => IsSshKey ? "SSH key" : "Password";
}

/// <summary>P/Invoke declarations for core-cabi/src/credentials.rs.</summary>
internal static class CredentialsNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_credentials_free(IntPtr v);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_list_json(IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_save_password(IntPtr v,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? id, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? folder, [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        byte[]? secret, UIntPtr secretLen, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_save_ssh_key(IntPtr v,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? id, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? folder, [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        byte[]? secret, UIntPtr secretLen, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_import_key_file(IntPtr v,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? id, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? folder, [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte[]? passphrase, UIntPtr passphraseLen, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_credentials_remove(IntPtr v, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_credentials_save(IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_rdp_login_json(IntPtr v, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? credentialId, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_credential(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? credentialId, out IntPtr err);
}

/// <summary>
/// The credential vault next to the library (<c>credentials.vault</c>), keyed by a DPAPI-wrapped random key for the
/// current Windows user. Secrets go in only: they are copied into a UTF-8 buffer that is zeroed right after the call,
/// and nothing here can read one back. Use from the UI thread, except calls that hold a lease (<see cref="Leased{T}"/>):
/// those may run on a worker, and a lock (<see cref="Dispose"/>) during one frees the vault only when it ends (SEC-1).
/// </summary>
public sealed partial class CredentialStore : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private readonly NativeLifetime _life;

    private CredentialStore(IntPtr handle) => _life = new NativeLifetime(handle, CredentialsNative.bastion_credentials_free, nameof(CredentialStore));

    /// <summary>The vault that belongs to the library at <paramref name="libraryPath"/>.</summary>
    public static string PathFor(string libraryPath) => System.IO.Path.Combine(System.IO.Path.GetDirectoryName(libraryPath)!, "credentials.vault");

    public static CredentialStore Open(string path)
    {
        var h = CredentialsNative.bastion_credentials_open(path, out var err);
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not open the credential vault");
        return new CredentialStore(h);
    }

    /// <summary>The vault inside the Personal document (ABI 94).</summary>
    internal static CredentialStore FromHandle(IntPtr handle) => new(handle);

    /// <summary>The saved RDP login for a connection (its own password, else the assigned credential's), or null.
    /// The core refuses a credential that is not the connection's own or inherited login (ABI 104).
    /// The release is audited by the core. Owner points 23, 26.</summary>
    public (string User, string Password)? RdpLogin(LibraryClient library, string connectionId, string? credentialId)
    {
        var json = TakeString(CredentialsNative.bastion_credentials_rdp_login_json(H, library.NativeHandle, connectionId, credentialId, out var err), err);
        if (json == "null") return null;
        using var doc = JsonDocument.Parse(json);
        var user = doc.RootElement.GetProperty("username").GetString() ?? "";
        var password = doc.RootElement.GetProperty("password").GetString() ?? "";
        return password.Length == 0 ? null : (user, password);
    }

    public IReadOnlyList<CredentialDto> List() =>
        JsonSerializer.Deserialize(TakeString(CredentialsNative.bastion_credentials_list_json(H, out var err), err), Json.Info<List<CredentialDto>>()) ?? [];

    /// <summary>Add (<paramref name="id"/> null) or update a password; an empty password on update keeps the stored one.</summary>
    public string SavePassword(string? id, string name, string? folder, string username, string password) =>
        WithSecret(password, (b, n) => TakeString(CredentialsNative.bastion_credentials_save_password(H, id, name, folder, username, b, n, out var err), err));

    /// <summary>Add or update an SSH private key (OpenSSH/PEM text). Passphrase-protected keys are refused by the core.</summary>
    public string SaveSshKey(string? id, string name, string? folder, string username, string privateKey) =>
        WithSecret(privateKey, (b, n) => TakeString(CredentialsNative.bastion_credentials_save_ssh_key(H, id, name, folder, username, b, n, out var err), err));

    /// <summary>
    /// Add or update an SSH key credential from a private key file. The core reads and (with
    /// <paramref name="passphrase"/>) decrypts it and stores it without the passphrase; the key text never comes here.
    /// </summary>
    public string ImportKeyFile(string? id, string name, string? folder, string username, string path, string passphrase) =>
        WithSecret(passphrase, (b, n) => TakeString(CredentialsNative.bastion_credentials_import_key_file(H, id, name, folder, username, path, b, n, out var err), err));

    public void Remove(string id)
    {
        if (CredentialsNative.bastion_credentials_remove(H, id, out var err) != 0) throw new BastionException(Take(err) ?? "could not remove the credential");
    }

    /// <summary>Seal and write the vault.</summary>
    public void Save()
    {
        if (CredentialsNative.bastion_credentials_save(H, out var err) != 0) throw new BastionException(Take(err) ?? "could not save the credential vault");
    }

    /// <summary>As <see cref="Save"/>, from a worker: the handle is leased, so a lock meanwhile waits for the write (SEC-1).
    /// Sealing derives the key with Argon2id (100-250 ms), too slow for the UI thread (WIN-SSH-OPEN-STALL).</summary>
    internal void SaveLeased() => Leased(h =>
    {
        if (CredentialsNative.bastion_credentials_save(h, out var err) != 0) throw new BastionException(Take(err) ?? "could not save the credential vault");
        return 0;
    });

    /// <summary>The secret as UTF-8 for the duration of one call, then zeroed.</summary>
    private static string WithSecret(string secret, Func<byte[]?, UIntPtr, string> call)
    {
        var bytes = secret.Length == 0 ? null : Encoding.UTF8.GetBytes(secret);
        try { return call(bytes, (UIntPtr)(bytes?.Length ?? 0)); }
        finally { if (bytes is not null) Array.Clear(bytes); }
    }

    private IntPtr H => _life.Handle;

    /// <summary>Run <paramref name="call"/> with the vault handle kept alive until it returns, even if the vault is
    /// locked meanwhile. Required for every call made off the UI thread (SEC-1).</summary>
    private T Leased<T>(Func<IntPtr, T> call)
    {
        NativeLifetime.Lease lease;
        try { lease = _life.Acquire(); }
        catch (ObjectDisposedException) { throw new BastionException("the vault is locked"); }
        using (lease) return call(lease.Handle);
    }

    /// <summary>As <see cref="Leased{T}"/>, for a call that also works without the vault: false, and no call, once the
    /// vault is locked. The folder dashboard reads its rows this way on a worker (WIN-STALL-USER).</summary>
    internal bool TryLeased<T>(Func<IntPtr, T> call, out T result)
    {
        NativeLifetime.Lease lease;
        try { lease = _life.Acquire(); }
        catch (ObjectDisposedException) { result = default!; return false; }
        using (lease) result = call(lease.Handle);
        return true;
    }

    /// <summary>The raw handle, for <c>bastion_session_set_credentials</c> (SessionNative.cs).</summary>
    internal IntPtr NativeHandle => H;

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

    /// <summary>Free the vault now, or when the last in-flight leased call ends. Never waits.</summary>
    public void Dispose() => _life.Release();
}
