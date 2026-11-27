using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>
/// One login a connection can use (no secret). <see cref="Source"/>: <c>default</c>, <c>connection</c>, <c>named</c>,
/// <c>inherited</c> (from folder <see cref="SourceId"/>, or a type default when null) or <c>same-host</c> (saved for
/// connection <see cref="SourceId"/>, named <see cref="SourceName"/>). Owner point W23, ABI 95.
/// <see cref="AutoUse"/> (ABI 96, owner decision D1): the connection's own or inherited login, which connects without
/// asking. False for a login saved for another connection: it is offered in the sheet and used only on the user's
/// Connect. A core that does not send the field leaves it false, so the sheet asks.
/// </summary>
public sealed record LoginCandidateDto(string CredentialId, string Name, string Username, string Kind, string Source, string? SourceId, string SourceName, bool AutoUse = false)
{
    public bool IsOwn => Source is "default" or "connection";

    /// <summary>Where it comes from, for pickers and announcements.</summary>
    public string Origin => Source switch
    {
        "default" => "Default",
        "connection" => "This connection",
        "named" => "Named by this connection",
        "inherited" => "From " + SourceName,
        "same-host" => "Saved for " + SourceName,
        _ => "",
    };

    /// <summary>"appuser · Saved for K8s SSH".</summary>
    public string Label => $"{(Username.Length > 0 ? Username : Name)}  ·  {Origin}";
}

/// <summary>
/// The one rule every sign-in path shares (SSH, RDP, Services / Processes / Event Log), on the core's ordered list
/// (owner decision D1, A1-NW-01). Pure: no vault, no window. Checked by tests\a1-logins-console.
/// </summary>
public static class LoginRule
{
    /// <summary>The login to select first: the one the user confirmed earlier this run while the core still lists
    /// it, else the core's first. -1 when there is none.</summary>
    public static int Preferred(IReadOnlyList<LoginCandidateDto> logins, string? confirmedId)
    {
        if (logins.Count == 0) return -1;
        if (confirmedId is null) return 0;
        for (var i = 0; i < logins.Count; i++)
            if (logins[i].CredentialId == confirmedId) return i;
        return 0;
    }

    /// <summary>True when the preferred login may sign in with no sheet: the core marks it auto-use, or the user
    /// picked it for this connection earlier this run. A login saved for another connection never passes on its own.</summary>
    public static bool MayUseUnasked(IReadOnlyList<LoginCandidateDto> logins, string? confirmedId) =>
        Preferred(logins, confirmedId) is >= 0 and var i && (logins[i].AutoUse || logins[i].CredentialId == confirmedId);

    /// <summary>The sheet shows its Login picker for a choice, and for a single offered login so its label
    /// ("Saved for …") is on screen before Connect.</summary>
    public static bool ShowsPicker(IReadOnlyList<LoginCandidateDto> logins) =>
        logins.Count > 1 || (logins.Count == 1 && !logins[0].AutoUse);

    /// <summary>After a successful connect: ask "use this login from now on?" only for an offered login, and only
    /// once per connection in a run (<paramref name="askedThisRun"/>): a No is not asked again.</summary>
    public static bool AsksToKeep(LoginCandidateDto? used, bool askedThisRun) => used is { AutoUse: false } && !askedThisRun;
}

/// <summary>P/Invoke for core-cabi/src/credtree.rs logins (ABI 95).</summary>
internal static class LoginsNative
{
    private const string Lib = "bastion_cabi";
    private const UnmanagedType U8 = UnmanagedType.LPUTF8Str;

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_logins_json(IntPtr v, IntPtr lib, [MarshalAs(U8)] string connectionId, int passwordsOnly, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_credentials_edit_login(IntPtr v, IntPtr lib, [MarshalAs(U8)] string connectionId, [MarshalAs(U8)] string credentialId, int op, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_release_login_json(IntPtr v, IntPtr lib, [MarshalAs(U8)] string connectionId, [MarshalAs(U8)] string credentialId, out IntPtr err);
}

public sealed partial class CredentialStore
{
    private const int LoginAdd = 0, LoginRemove = 1, LoginMakeDefault = 2;

    /// <summary>The logins a connection can use, best first: its own, the inherited one, then the same host's.</summary>
    public IReadOnlyList<LoginCandidateDto> Logins(LibraryClient library, string connectionId, bool passwordsOnly) =>
        JsonSerializer.Deserialize(
            TakeString(LoginsNative.bastion_credentials_logins_json(H, library.NativeHandle, connectionId, passwordsOnly ? 1 : 0, out var err), err), TreeJson.Info<List<LoginCandidateDto>>()) ?? [];

    /// <summary>Add a saved credential to the connection's logins (the default when it has none). Save the library.</summary>
    public void AddLogin(LibraryClient library, string connectionId, string credentialId) => EditLogin(library, connectionId, credentialId, LoginAdd);

    /// <summary>Remove a login from the connection; the credential stays in the vault. Save the library.</summary>
    public void RemoveLogin(LibraryClient library, string connectionId, string credentialId) => EditLogin(library, connectionId, credentialId, LoginRemove);

    /// <summary>Make a login the connection's default. Save the library.</summary>
    public void MakeDefaultLogin(LibraryClient library, string connectionId, string credentialId) => EditLogin(library, connectionId, credentialId, LoginMakeDefault);

    private void EditLogin(LibraryClient library, string connectionId, string credentialId, int op) =>
        Check(LoginsNative.bastion_credentials_edit_login(H, library.NativeHandle, connectionId, credentialId, op, out var err), err, "could not change the logins");

    /// <summary>The password of one of the connection's offered password logins, for RDP. The core refuses any other and audits it.</summary>
    public (string User, string Password) ReleaseLogin(LibraryClient library, string connectionId, string credentialId)
    {
        var json = TakeString(LoginsNative.bastion_credentials_release_login_json(H, library.NativeHandle, connectionId, credentialId, out var err), err);
        using var doc = JsonDocument.Parse(json);
        return (doc.RootElement.GetProperty("username").GetString() ?? "", doc.RootElement.GetProperty("password").GetString() ?? "");
    }
}
