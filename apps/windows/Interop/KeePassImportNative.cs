using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>One entry of a KeePass preview: never a secret. <c>Status</c> is <c>new</c>, <c>duplicate</c> or <c>no-password</c>.</summary>
public sealed record KeePassImportRow(string Title, string Username, string Folder, string Status);

/// <summary>What a KeePass import did (B8).</summary>
public sealed record KeePassImportResult(int Added, int Replaced, int SkippedDuplicates, int SkippedNoPassword, string Folder);

/// <summary>The preview envelope: <c>{"rows":[...]}</c>.</summary>
public sealed record KeePassPreviewDto(List<KeePassImportRow> Rows);

/// <summary>P/Invoke for core-cabi/src/credentials.rs, B8 (ABI 127).</summary>
internal static class KeePassImportNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_keepass_preview_json(IntPtr v, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        byte[]? password, UIntPtr passwordLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyfile, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_keepass_import_json(IntPtr v, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        byte[]? password, UIntPtr passwordLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyfile,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string duplicates, out IntPtr err);
}

public sealed partial class CredentialStore
{
    /// <summary>Duplicate rules the core accepts.</summary>
    public static readonly string[] KeePassDuplicateRules = ["skip", "replace", "keep-both"];

    // Both calls run on a worker (MainWindow.KeePassImport.cs) and hold a lease: a lock meanwhile cannot free the vault (SEC-1).

    /// <summary>
    /// What importing <paramref name="path"/> would do: titles, usernames, target folders and status only. The core
    /// decrypts in memory; the master password goes in as UTF-8 bytes that are zeroed right after the call.
    /// </summary>
    public IReadOnlyList<KeePassImportRow> KeePassPreview(string path, string password, string? keyFile)
    {
        var json = Leased(h => WithSecret(password, (b, n) => TakeString(KeePassImportNative.bastion_credentials_keepass_preview_json(h, path, b, n, keyFile, out var err), err)));
        return JsonSerializer.Deserialize(json, KeePassJsonContext.Default.KeePassPreviewDto)?.Rows ?? [];
    }

    /// <summary>Import every entry with a password and seal the vault. <paramref name="duplicates"/>: skip, replace or keep-both.</summary>
    public KeePassImportResult KeePassImport(string path, string password, string? keyFile, string duplicates)
    {
        if (Array.IndexOf(KeePassDuplicateRules, duplicates) < 0) throw new BastionException("unknown duplicate rule");
        var json = Leased(h => WithSecret(password, (b, n) => TakeString(KeePassImportNative.bastion_credentials_keepass_import_json(h, path, b, n, keyFile, duplicates, out var err), err)));
        return JsonSerializer.Deserialize(json, KeePassJsonContext.Default.KeePassImportResult) ?? throw new BastionException("the core returned no import result");
    }
}
