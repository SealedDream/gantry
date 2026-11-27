using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>A Vaultwarden login item as listed by the core: id, name and user name, never the password.</summary>
public sealed record VaultwardenItemDto(string Id, string Name, string? Username)
{
    public string Label => Username is { Length: > 0 } u ? $"{Name} ({u})" : Name;
}

/// <summary>The items of an unlock, and how many organisation or undecryptable items were left out.</summary>
public sealed record VaultwardenItems(IReadOnlyList<VaultwardenItemDto> Items, int Skipped);

/// <summary>The remembered server and account (never the master password).</summary>
public sealed record VaultwardenConfig(string? ServerUrl, string? Email);

/// <summary>How an unlock ended (<c>VAULTWARDEN_*</c> in core-cabi/src/vaultwarden.rs).</summary>
public enum VaultwardenOutcome
{
    Ok = 0,
    /// <summary>The account uses two-step login: ask for the authenticator code and unlock again with it.</summary>
    TwoFactorRequired = 1,
    AuthFailed = 2,
    Failed = 3,
}

/// <summary>The result of one unlock attempt; <see cref="Items"/> is set only when it succeeded.</summary>
public sealed record VaultwardenUnlockResult(VaultwardenOutcome Outcome, VaultwardenItems? Items, string? Error);

/// <summary>P/Invoke declarations for core-cabi/src/vaultwarden.rs.</summary>
internal static class VaultwardenNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_vaultwarden_open([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_vaultwarden_free(IntPtr v);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_vaultwarden_config_json(IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_vaultwarden_unlock(IntPtr v,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string serverUrl, [MarshalAs(UnmanagedType.LPUTF8Str)] string email,
        byte[]? masterPassword, UIntPtr passwordLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string? totp,
        out int outcome, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_vaultwarden_resync(IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_vaultwarden_items_json(IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_vaultwarden_is_unlocked(IntPtr v);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_vaultwarden_lock(IntPtr v);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_session_set_vaultwarden(IntPtr m, IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_vaultwarden_item(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? itemId, out IntPtr err);
}

/// <summary>
/// The Vaultwarden session for the app's data directory. The master password is copied into a UTF-8 buffer that is
/// zeroed right after the unlock call; item passwords never leave the core. <see cref="Unlock"/> and
/// <see cref="Resync"/> block on the network: call them off the UI thread.
/// </summary>
public sealed partial class VaultwardenClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private IntPtr _handle;

    private VaultwardenClient(IntPtr handle) => _handle = handle;

    public static VaultwardenClient Open(string dataDir)
    {
        var h = VaultwardenNative.bastion_vaultwarden_open(dataDir, out var err);
        if (h == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not open Vaultwarden");
        return new VaultwardenClient(h);
    }

    public VaultwardenConfig Config =>
        JsonSerializer.Deserialize(TakeString(VaultwardenNative.bastion_vaultwarden_config_json(H, out var err), err), Json.Info<VaultwardenConfig>()) ?? new(null, null);

    public bool IsUnlocked => VaultwardenNative.bastion_vaultwarden_is_unlocked(H) == 1;

    public VaultwardenItems Items => Parse(TakeString(VaultwardenNative.bastion_vaultwarden_items_json(H, out var err), err));

    /// <summary>Log in and sync. Never throws for a refused login — read <see cref="VaultwardenUnlockResult.Outcome"/>.</summary>
    public VaultwardenUnlockResult Unlock(string serverUrl, string email, string masterPassword, string? totp)
    {
        var bytes = masterPassword.Length == 0 ? null : Encoding.UTF8.GetBytes(masterPassword);
        try
        {
            var json = VaultwardenNative.bastion_vaultwarden_unlock(H, serverUrl, email, bytes, (UIntPtr)(bytes?.Length ?? 0),
                string.IsNullOrWhiteSpace(totp) ? null : totp.Trim(), out var outcome, out var err);
            var message = Take(err);
            return json == IntPtr.Zero
                ? new((VaultwardenOutcome)outcome, null, message)
                : new(VaultwardenOutcome.Ok, Parse(Take(json) ?? "{}"), null);
        }
        finally { if (bytes is not null) Array.Clear(bytes); }
    }

    /// <summary>Fetch the items again without the master password; throws when locked or refused.</summary>
    public VaultwardenItems Resync() => Parse(TakeString(VaultwardenNative.bastion_vaultwarden_resync(H, out var err), err));

    public void Lock() => VaultwardenNative.bastion_vaultwarden_lock(H);

    /// <summary>The raw handle, for <c>bastion_session_set_vaultwarden</c>.</summary>
    internal IntPtr NativeHandle => H;

    private static VaultwardenItems Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var items = doc.RootElement.TryGetProperty("items", out var list)
            ? list.Deserialize(Json.Info<List<VaultwardenItemDto>>()) ?? []
            : [];
        var skipped = doc.RootElement.TryGetProperty("skipped", out var s) ? s.GetInt32() : 0;
        return new VaultwardenItems(items, skipped);
    }

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(VaultwardenClient));

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
        VaultwardenNative.bastion_vaultwarden_free(_handle);
        _handle = IntPtr.Zero;
    }
}
