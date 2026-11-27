using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>Result of an unlock or an item check (<c>PROVIDER_*</c> in core-cabi/src/providers.rs).</summary>
public enum ProviderCheck
{
    Ok = 0,
    /// <summary>The password, key file or token was refused (or the provider is signed out).</summary>
    AuthFailed = 1,
    /// <summary>The item does not exist (check only).</summary>
    NotFound = 2,
}

/// <summary><see cref="Status"/> is available, locked or unavailable; <see cref="Id"/> onepassword, keepass or hcvault.</summary>
public sealed record ProviderStatusDto(string Id, string Status, string? Reason);

/// <summary>A KeePass entry without its secret. <see cref="Group"/> runs from the root down, root excluded.</summary>
public sealed record ProviderItemDto(string Id, string Title, string? Username, List<string> Group);

internal static class ProviderNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_provider_open_onepassword([MarshalAs(UnmanagedType.LPUTF8Str)] string? opPath, [MarshalAs(UnmanagedType.LPUTF8Str)] string? account, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_provider_open_keepass([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_provider_open_hcvault([MarshalAs(UnmanagedType.LPUTF8Str)] string baseUrl, int kvVersion, [MarshalAs(UnmanagedType.LPUTF8Str)] string? ns, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_provider_unlock(IntPtr p, byte[]? secret, UIntPtr len, [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyfilePath, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_provider_lock(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_provider_status_json(IntPtr p, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_provider_items_json(IntPtr p, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_provider_check_item(IntPtr p, [MarshalAs(UnmanagedType.LPUTF8Str)] string item, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_provider_register(IntPtr p, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_providers_lock_all();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_provider_free(IntPtr p);
}

/// <summary>
/// An external credential provider (C ABI 63): 1Password through its CLI, a KeePass <c>.kdbx</c> file or a
/// HashiCorp Vault KV mount. Read-only, no decrypted cache. After <see cref="Register"/>, connect with
/// <see cref="SshLoginKind.Provider"/> and the reference <c>"&lt;id&gt;:&lt;item&gt;"</c> as the secret
/// (e.g. <c>keepass:&lt;entry uuid&gt;#password</c>): the core reads the secret at dial time.
/// </summary>
public sealed partial class CredentialProvider : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private IntPtr _handle;

    private CredentialProvider(IntPtr handle) => _handle = handle;

    /// <summary>1Password via <c>op</c>. Null <paramref name="opPath"/> searches PATH; null account = op's default.</summary>
    public static CredentialProvider OpenOnePassword(string? opPath = null, string? account = null) =>
        Wrap(ProviderNative.bastion_provider_open_onepassword(opPath, account, out var err), err);

    /// <summary>A KeePass file. It starts locked.</summary>
    public static CredentialProvider OpenKeePass(string path) => Wrap(ProviderNative.bastion_provider_open_keepass(path, out var err), err);

    /// <summary>A Vault KV mount (<paramref name="kvVersion"/> 1 or 2); https only, http on loopback. It starts locked.</summary>
    public static CredentialProvider OpenHcVault(string baseUrl, int kvVersion = 2, string? ns = null) =>
        Wrap(ProviderNative.bastion_provider_open_hcvault(baseUrl, kvVersion, string.IsNullOrEmpty(ns) ? null : ns, out var err), err);

    /// <summary>
    /// KeePass master password (may be empty with <paramref name="keyFilePath"/>), Vault token, or 1Password
    /// service-account token (empty clears it). The UTF-8 copy is zeroed before returning.
    /// </summary>
    public ProviderCheck Unlock(string? secret, string? keyFilePath = null)
    {
        var bytes = string.IsNullOrEmpty(secret) ? null : Encoding.UTF8.GetBytes(secret);
        try
        {
            var r = ProviderNative.bastion_provider_unlock(H, bytes, (UIntPtr)(bytes?.Length ?? 0), string.IsNullOrEmpty(keyFilePath) ? null : keyFilePath, out var err);
            return r >= 0 ? (ProviderCheck)r : throw new BastionException(LibraryClient.TakeError(err, "could not unlock the provider"));
        }
        finally
        {
            if (bytes is not null) Array.Clear(bytes);
        }
    }

    /// <summary>Forget the password, key file or token.</summary>
    public void Lock() => ProviderNative.bastion_provider_lock(H);

    public ProviderStatusDto Status() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(ProviderNative.bastion_provider_status_json(H, out var err), err), Json.Info<ProviderStatusDto>())
        ?? throw new BastionException("could not read the provider status");

    /// <summary>KeePass entries (no secrets); 1Password and Vault cannot list and give none.</summary>
    public IReadOnlyList<ProviderItemDto> Items()
    {
        var json = LibraryClient.TakeString(ProviderNative.bastion_provider_items_json(H, out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<ItemsDto>())?.Items ?? [];
    }

    /// <summary>Whether <paramref name="item"/> resolves, without returning the secret.</summary>
    public ProviderCheck CheckItem(string item)
    {
        var r = ProviderNative.bastion_provider_check_item(H, item, out var err);
        return r >= 0 ? (ProviderCheck)r : throw new BastionException(LibraryClient.TakeError(err, "could not check the item"));
    }

    /// <summary>Make <see cref="SshLoginKind.Provider"/> connects read from this provider under its id (replaces one with the same id).</summary>
    public void Register()
    {
        if (ProviderNative.bastion_provider_register(H, out var err) != 0) throw new BastionException(LibraryClient.TakeError(err, "could not register the provider"));
    }

    /// <summary>Lock Credentials: lock and unregister every provider. Open handles stay valid but locked.</summary>
    public static void LockAll() => ProviderNative.bastion_providers_lock_all();

    internal sealed record ItemsDto(List<ProviderItemDto> Items);

    private static CredentialProvider Wrap(IntPtr h, IntPtr err) =>
        h != IntPtr.Zero ? new CredentialProvider(h) : throw new BastionException(LibraryClient.TakeError(err, "could not open the provider"));

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(CredentialProvider));

    /// <summary>Release the handle; a registered provider stays registered until <see cref="LockAll"/>.</summary>
    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        var h = _handle;
        _handle = IntPtr.Zero;
        ProviderNative.bastion_provider_free(h);
    }
}
