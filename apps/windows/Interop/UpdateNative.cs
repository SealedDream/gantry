using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>The latest release as the core read it (C ABI 24): its manifest's signature, expiry, channel and
/// version were already checked, so <see cref="Available"/> is only true for a newer, valid release.</summary>
public sealed record UpdateCheckDto(
    string Installed, string Latest, bool Available, string? Notes, string? Url, ulong? ManifestExpires, List<UpdateFileDto> Files);

public sealed record UpdateFileDto(string Name, ulong Size);

internal static class UpdateNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_update_check_json(out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_update_download(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string fileName, [MarshalAs(UnmanagedType.LPUTF8Str)] string destDir, out IntPtr err);
}

/// <summary>Updates from GitHub releases. Both calls block on the network: run them off the UI thread.</summary>
public static class UpdateClient
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    public static UpdateCheckDto Check()
    {
        var s = GatewayNative.Take(UpdateNative.bastion_update_check_json(out var err));
        if (s is null) throw new BastionException(GatewayNative.Take(err) ?? "could not check for updates");
        return JsonSerializer.Deserialize(s, Json.Info<UpdateCheckDto>()) ?? throw new BastionException("could not read the update information");
    }

    /// <summary>Download <paramref name="fileName"/> into <paramref name="destDir"/>, verified against the signed size and SHA-256.</summary>
    public static string Download(string fileName, string destDir) =>
        GatewayNative.Take(UpdateNative.bastion_update_download(fileName, destDir, out var err))
        ?? throw new BastionException(GatewayNative.Take(err) ?? "could not download the update");
}
