using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

/// <summary>What <see cref="ConnectOutcome.NoCommonAlgorithm"/> carried (C ABI 33): the list kind, what the server offers, and the weak names "Allow for this host" may turn on.</summary>
public sealed record NoCommonAlgorithmDto(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("serverOffers")] IReadOnlyList<string> ServerOffers,
    [property: JsonPropertyName("weakAllowable")] IReadOnlyList<string> WeakAllowable)
{
    public static NoCommonAlgorithmDto? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize(json, AotJson.Options.Info<NoCommonAlgorithmDto>()); }
        catch (JsonException) { return null; }
    }
}

/// <summary>Properties → Advanced → Algorithms preview (C ABI 33): the lists a connection would offer.</summary>
public sealed record AlgorithmPreviewDto(
    [property: JsonPropertyName("kex")] IReadOnlyList<string> Kex,
    [property: JsonPropertyName("ciphers")] IReadOnlyList<string> Ciphers,
    [property: JsonPropertyName("macs")] IReadOnlyList<string> Macs,
    [property: JsonPropertyName("hostKeys")] IReadOnlyList<string> HostKeys,
    [property: JsonPropertyName("weakEnabled")] IReadOnlyList<string> WeakEnabled,
    [property: JsonPropertyName("warnings")] IReadOnlyList<string> Warnings,
    [property: JsonPropertyName("error")] string? Error,
    [property: JsonPropertyName("forbidWeak")] bool ForbidWeak);

internal static class AlgorithmsNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_allow_weak_algorithms(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string kind, [MarshalAs(UnmanagedType.LPUTF8Str)] string namesJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_ssh_algorithms_preview_json([MarshalAs(UnmanagedType.LPUTF8Str)] string? settingsJson, out IntPtr err);
}

public sealed partial class LibraryClient
{
    /// <summary>"Allow for this host": turn on the weak names the failed connect offered. Policy is still checked on the next connect.</summary>
    public void AllowWeakAlgorithms(string id, NoCommonAlgorithmDto outcome)
    {
        var names = AotJson.Write<IReadOnlyList<string>>(outcome.WeakAllowable, AotJson.Options);
        if (AlgorithmsNative.bastion_library_allow_weak_algorithms(NativeHandle, id, outcome.Kind, names, out var err) != 0)
            throw new BastionException(TakeError(err, "could not allow these algorithms"));
    }

    /// <summary>The resolved lists for an <c>ssh_algorithms</c> value (null or blank = defaults). Unusable settings come back with <see cref="AlgorithmPreviewDto.Error"/> set.</summary>
    public static AlgorithmPreviewDto AlgorithmPreview(string? settingsJson)
    {
        var json = TakeString(AlgorithmsNative.bastion_ssh_algorithms_preview_json(settingsJson, out var err), err);
        return JsonSerializer.Deserialize(json, AotJson.Options.Info<AlgorithmPreviewDto>())
            ?? throw new BastionException("the algorithm preview was empty");
    }
}
