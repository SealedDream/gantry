using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>The variables a connection's text may use (C ABI 26). Secret ones come by name only and are refused by substitution.</summary>
public sealed record VariablesDto(List<VariableDto> Plain, List<string> Secret);

public sealed record VariableDto(string Name, string Value);

internal static class TextGenNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_generate_password(uint length, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern double bastion_password_strength_bits([MarshalAs(UnmanagedType.LPUTF8Str)] string? password);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_variables_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_substitute(
        IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string template, out IntPtr err);
}

/// <summary>The core's password generator. The generated text is not kept by the core.</summary>
public static class PasswordGenerator
{
    public const int MinLength = 12, MaxLength = 128, DefaultLength = 24;

    public static string Generate(int length) =>
        GatewayNative.Take(TextGenNative.bastion_generate_password((uint)length, out var err))
        ?? throw new BastionException(GatewayNative.Take(err) ?? "could not generate a password");

    public static double StrengthBits(string password) => TextGenNative.bastion_password_strength_bits(password);

    /// <summary>A word for the indicator, from the core's estimate.</summary>
    public static string StrengthLabel(double bits) => bits switch
    {
        < 40 => "Weak",
        < 64 => "Fair",
        < 100 => "Strong",
        _ => "Very strong",
    };
}

public sealed partial class LibraryClient
{
    private static readonly JsonSerializerOptions VariablesJson = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    public VariablesDto Variables(string connectionId) =>
        JsonSerializer.Deserialize(TakeString(TextGenNative.bastion_library_variables_json(NativeHandle, connectionId, out var err), err), VariablesJson.Info<VariablesDto>())
        ?? throw new BastionException("could not read the variables");

    /// <summary><paramref name="template"/> with <c>$Name$</c> filled in; an unknown or secret variable throws.</summary>
    public string Substitute(string connectionId, string template) =>
        TakeString(TextGenNative.bastion_library_substitute(NativeHandle, connectionId, template, out var err), err);
}
