using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>The core's answer to one "Fill sign-in" click (B13). With <see cref="Script"/> set, run it once in the top frame.</summary>
public sealed record WebAutofillDto(string? Script, string Code, string Message);

/// <summary>P/Invoke for B13 web sign-in fill (core-cabi/src/credentials.rs, ABI_TBD_WEBFILL).</summary>
internal static class WebAutofillNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_web_autofill_offered(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_web_autofill_json(IntPtr v, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? credentialId, [MarshalAs(UnmanagedType.LPUTF8Str)] string pageUrl, int isMainFrame, int isSecure, out IntPtr err);
}

public sealed partial class LibraryClient
{
    /// <summary>Show "Fill sign-in" for this connection: policy allows it and its (inherited) switch is on.</summary>
    public bool WebAutofillOffered(string connectionId)
    {
        var r = WebAutofillNative.bastion_web_autofill_offered(Handle, connectionId, out var err);
        if (r < 0) throw new BastionException(TakeError(err, "could not read the sign-in fill setting"));
        return r == 1;
    }
}

public sealed partial class CredentialStore
{
    private static readonly JsonSerializerOptions WebJson = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    /// <summary>The core decides (exact https origin, top frame, secure page, switch, policy) and audits the attempt.</summary>
    public WebAutofillDto WebAutofill(LibraryClient library, string connectionId, string? credentialId, string pageUrl, bool isSecure)
    {
        var json = LibraryClient.TakeString(WebAutofillNative.bastion_credentials_web_autofill_json(H, library.NativeHandle, connectionId, credentialId, pageUrl, 1, isSecure ? 1 : 0, out var err), err);
        return JsonSerializer.Deserialize(json, WebJson.Info<WebAutofillDto>()) ?? throw new BastionException("the core returned no sign-in fill decision");
    }
}
