using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>Which kind of secret the connect call carries (<c>LOGIN_*</c> in core-cabi/src/session.rs).</summary>
public enum SshLoginKind
{
    Password = 0,
    /// <summary>A private key file; the secret, if any, is its passphrase.</summary>
    KeyFile = 1,
    /// <summary>A credential from the vault; the "secret" is the credential id and the secret itself stays in the core.</summary>
    Vault = 2,
    /// <summary>An item of the unlocked Vaultwarden session; the "secret" is the item id and the password stays in the core.</summary>
    Vaultwarden = 3,
    /// <summary>Keys held by the SSH agent (on Windows the OpenSSH agent service pipe). No secret is typed.</summary>
    Agent = 4,
    /// <summary>The password plus a one-time code, after <see cref="ConnectOutcome.TwoFactorRequired"/>. Never a form choice.</summary>
    PasswordAndCode = 5,
    /// <summary>A registered <see cref="CredentialProvider"/> (C ABI 63); the "secret" is <c>"&lt;provider&gt;:&lt;item&gt;"</c>, read inside the core.</summary>
    Provider = 6,
}

/// <summary>A jump host's own login (the <c>jump_logins_json</c> entry). <see cref="Secret"/> is the password or the key's passphrase.</summary>
public sealed record JumpLoginInput(SshLoginKind Kind, string? Secret, string? KeyPath);

/// <summary>How a connect attempt ended (<c>CONNECT_*</c> in core-cabi/src/session.rs).</summary>
public enum ConnectOutcome
{
    Ok = 0,
    /// <summary>The server's (or a jump host's) key is not trusted yet. Show the fingerprint and ask.</summary>
    HostKeyUnknown = 1,
    AuthFailed = 2,
    NeedsConfiguration = 3,
    Failed = 4,
    /// <summary>The server asked for a second factor (keyboard-interactive). Ask for the code and retry with it.</summary>
    TwoFactorRequired = 5,
    /// <summary>No key exchange, cipher, MAC or host key in common (C ABI 33). <see cref="SshConnectResult.Fingerprint"/> holds the JSON for <see cref="NoCommonAlgorithmDto"/>.</summary>
    NoCommonAlgorithm = 6,
}

/// <summary>A jump host of a connection, in connect order. No secrets.</summary>
public sealed record JumpHostDto(string Key, string Username);

/// <summary>One <c>@cert-authority</c> line of the app's known_hosts (public key only).</summary>
public sealed record HostCaDto(string Patterns, string Fingerprint, string Algorithm, string Comment);

/// <summary>
/// The result of one connect attempt. <see cref="Session"/> is set only for <see cref="ConnectOutcome.Ok"/>;
/// <see cref="Fingerprint"/> only for <see cref="ConnectOutcome.HostKeyUnknown"/>, where <see cref="Hop"/>
/// names the jump host when the unknown key is not the target's. Never carries a secret.
/// </summary>
public sealed record SshConnectResult(ConnectOutcome Outcome, TerminalSession? Session, string? Fingerprint, string? Hop, string? Error, SftpSession? Files = null)
{
    /// <summary>A shell (<see cref="Session"/>) or, for a files-only connection, a browser (<see cref="Files"/>) is open.</summary>
    public bool IsConnected => Outcome == ConnectOutcome.Ok && (Session is not null || Files is not null);
}

internal static class SessionNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_session_manager_new([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_session_manager_free(IntPtr m);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_session_lock_credentials(IntPtr m, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_host_cas_json(IntPtr m, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_host_ca_add(IntPtr m, [MarshalAs(UnmanagedType.LPUTF8Str)] string patterns, [MarshalAs(UnmanagedType.LPUTF8Str)] string publicKey, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_host_ca_remove(IntPtr m, [MarshalAs(UnmanagedType.LPUTF8Str)] string patterns, [MarshalAs(UnmanagedType.LPUTF8Str)] string fingerprint, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_session_set_credentials(IntPtr m, IntPtr creds, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_session_jump_hosts_json(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);

    // The secrets go over as raw pointers, not marshalled strings: the caller owns those buffers and
    // zeroes them (see Utf8Secret), which a runtime-marshalled copy would not let us do. The jump logins
    // carry secrets too, so their JSON travels the same way.
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_session_connect_ssh_mfa(
        IntPtr m,
        IntPtr lib,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        int loginKind,
        IntPtr password,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath,
        IntPtr code,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? trustFingerprint,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? jumpTrustJson,
        IntPtr jumpLoginsJson,
        ushort cols,
        ushort rows,
        out int outcome,
        out IntPtr fingerprint,
        out IntPtr hop,
        out IntPtr err);
    /// <summary>An sftp/scp connection straight into the files browser (C ABI 87); secrets as for the shell.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_session_connect_files(
        IntPtr m,
        IntPtr lib,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        int loginKind,
        IntPtr password,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath,
        IntPtr code,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? trustFingerprint,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? jumpTrustJson,
        IntPtr jumpLoginsJson,
        out int outcome,
        out IntPtr fingerprint,
        out IntPtr hop,
        out IntPtr err);

    /// <summary>FTPS sign-in into the files browser (C ABI 87); an unknown certificate comes back as HostKeyUnknown.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_session_connect_ftps(
        IntPtr m,
        IntPtr lib,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        IntPtr password,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? trustedFingerprint,
        out int outcome,
        out IntPtr fingerprint,
        out IntPtr err);
}

/// <summary>
/// A NUL-terminated UTF-8 copy of a secret in unmanaged memory, overwritten with zeros before it is
/// freed. <see cref="Utf8Secret"/> is what crosses the ABI, so nothing the GC moves or keeps holds the
/// bytes after the call.
/// </summary>
/// <remarks>
/// The .NET <c>string</c> a password control hands us cannot itself be wiped (the runtime may have
/// copied or interned it), so callers should also clear the control. This covers everything after that
/// point: the intermediate byte array and the unmanaged buffer are both zeroed.
/// </remarks>
internal sealed partial class Utf8Secret : IDisposable
{
    private IntPtr _ptr;
    private readonly int _bytes;

    /// <summary>NULL for a null or empty secret, which the ABI reads as "no secret".</summary>
    public IntPtr Pointer => _ptr;

    public Utf8Secret(string? secret)
        : this(string.IsNullOrEmpty(secret) ? null : Encoding.UTF8.GetBytes(secret)) { }

    /// <summary>Take a UTF-8 buffer (no terminator); the buffer is zeroed once copied.</summary>
    public Utf8Secret(byte[]? buffer)
    {
        if (buffer is null || buffer.Length == 0) return;
        try
        {
            _bytes = buffer.Length;
            _ptr = Marshal.AllocHGlobal(_bytes + 1);
            Marshal.Copy(buffer, 0, _ptr, _bytes);
            Marshal.WriteByte(_ptr, _bytes, 0);
        }
        finally { Array.Clear(buffer); }
    }

    public void Dispose()
    {
        if (_ptr == IntPtr.Zero) return;
        var p = _ptr;
        _ptr = IntPtr.Zero;
        // Zero the bytes and the terminator, then release.
        for (var i = 0; i <= _bytes; i++) Marshal.WriteByte(p, i, 0);
        Marshal.FreeHGlobal(p);
    }
}

/// <summary>
/// One session manager: the broker, audit log and known_hosts for an app data directory. Use from the
/// UI thread, but run <see cref="ConnectSsh"/> on a background thread — it blocks while it connects.
/// </summary>
public sealed partial class SessionManagerClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private readonly NativeLifetime _life;

    private SessionManagerClient(IntPtr handle) =>
        _life = new NativeLifetime(handle, SessionNative.bastion_session_manager_free, nameof(SessionManagerClient));

    /// <summary>Open a manager for <paramref name="dataDir"/>, creating the directory when missing.</summary>
    public static SessionManagerClient Open(string dataDir)
    {
        var handle = SessionNative.bastion_session_manager_new(dataDir, out var err);
        if (handle == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not start the session manager");
        return new SessionManagerClient(handle);
    }

    private IntPtr H => _life.Handle;

    /// <summary>Hold the manager for a blocking call made off the UI thread (connect, tunnel start).</summary>
    internal NativeLifetime.Lease AcquireLease() => _life.Acquire();

    /// <summary>True once the window disposed this manager; an in-flight connect may still hold it.</summary>
    public bool IsDisposed => _life.IsReleased;

    internal IntPtr NativeHandle => H;

    /// <summary>The connection's jump hosts in connect order; empty for a direct connection.</summary>
    public IReadOnlyList<JumpHostDto> JumpHosts(LibraryClient library, string connectionId)
    {
        var p = SessionNative.bastion_session_jump_hosts_json(H, library.NativeHandle, connectionId, out var err);
        if (p == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not resolve the jump hosts");
        return JsonSerializer.Deserialize(Take(p) ?? "[]", Json.Info<List<JumpHostDto>>()) ?? [];
    }

    /// <summary>Let <see cref="SshLoginKind.Vault"/> connects read from this vault (shared, not copied; no secret comes back).</summary>
    public void SetCredentials(CredentialStore store)
    {
        if (SessionNative.bastion_session_set_credentials(H, store.NativeHandle, out var err) != 0)
            throw new BastionException(Take(err) ?? "could not attach the credential vault");
    }

    /// <summary>Let <see cref="SshLoginKind.Vaultwarden"/> connects read from this Vaultwarden session (shared; no secret comes back).</summary>
    public void SetVaultwarden(VaultwardenClient vaultwarden)
    {
        if (VaultwardenNative.bastion_session_set_vaultwarden(H, vaultwarden.NativeHandle, out var err) != 0)
            throw new BastionException(Take(err) ?? "could not attach Vaultwarden");
    }

    /// <summary>The host certificate authorities trusted in known_hosts.</summary>
    public IReadOnlyList<HostCaDto> HostCas()
    {
        var p = SessionNative.bastion_host_cas_json(H, out var err);
        if (p == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not read the certificate authorities");
        return JsonSerializer.Deserialize(Take(p) ?? "[]", Json.Info<List<HostCaDto>>()) ?? [];
    }

    /// <summary>Trust <paramref name="publicKey"/> to sign host certificates for <paramref name="patterns"/>; the core validates both.</summary>
    public HostCaDto AddHostCa(string patterns, string publicKey)
    {
        var p = SessionNative.bastion_host_ca_add(H, patterns, publicKey, out var err);
        if (p == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not add the certificate authority");
        return JsonSerializer.Deserialize(Take(p)!, Json.Info<HostCaDto>())!;
    }

    public void RemoveHostCa(string patterns, string fingerprint)
    {
        if (SessionNative.bastion_host_ca_remove(H, patterns, fingerprint, out var err) != 0)
            throw new BastionException(Take(err) ?? "could not remove the certificate authority");
    }

    /// <summary>Forget every unlocked credential now (Vaultwarden included).</summary>
    public void LockCredentials()
    {
        if (SessionNative.bastion_session_lock_credentials(H, out var err) != 0)
            throw new BastionException(Take(err) ?? "could not lock the credentials");
    }

    /// <summary>
    /// Connect <paramref name="connectionId"/> and open a shell. Blocking: call it off the UI thread.
    /// Never throws for a connection failure — read <see cref="SshConnectResult.Outcome"/>.
    /// </summary>
    /// <param name="secret">The password, or the key file's passphrase. Copied into a buffer that is
    /// zeroed before this method returns.</param>
    /// <param name="trustFingerprint">Only a fingerprint the user has verified, after a
    /// <see cref="ConnectOutcome.HostKeyUnknown"/> result. Never a value from the server.</param>
    /// <param name="jumpTrust">Verified fingerprints for jump hosts, keyed <c>host:port</c>.</param>
    public SshConnectResult ConnectSsh(
        LibraryClient library,
        string connectionId,
        string? username,
        SshLoginKind kind,
        string? secret,
        string? keyPath,
        string? trustFingerprint,
        IReadOnlyDictionary<string, string>? jumpTrust,
        int cols,
        int rows,
        string? code = null,
        IReadOnlyDictionary<string, JumpLoginInput>? jumpLogins = null)
    {
        var jumpJson = jumpTrust is { Count: > 0 } ? AotJson.Write<IReadOnlyDictionary<string, string>>(jumpTrust, AotJson.Options) : null;
        using var password = new Utf8Secret(secret);
        using var oneTimeCode = new Utf8Secret(code);
        using var hopLogins = new Utf8Secret(jumpLogins is { Count: > 0 }
            ? JsonSerializer.SerializeToUtf8Bytes(jumpLogins.ToDictionary(
                p => p.Key,
                p => new ProbeLogin((int)p.Value.Kind, p.Value.Secret, p.Value.KeyPath)), ProbeJsonContext.Default.DictionaryStringProbeLogin)
            : null);
        using var manager = AcquireLease();
        using var lib = library.AcquireLease();
        var handle = SessionNative.bastion_session_connect_ssh_mfa(
            manager.Handle, lib.Handle, connectionId, string.IsNullOrWhiteSpace(username) ? null : username,
            (int)kind, password.Pointer, string.IsNullOrWhiteSpace(keyPath) ? null : keyPath, oneTimeCode.Pointer,
            string.IsNullOrWhiteSpace(trustFingerprint) ? null : trustFingerprint, jumpJson, hopLogins.Pointer,
            (ushort)cols, (ushort)rows, out var outcome, out var fingerprint, out var hop, out var err);

        var fp = Take(fingerprint);
        var h = Take(hop);
        var message = Take(err);
        var status = Enum.IsDefined(typeof(ConnectOutcome), outcome) ? (ConnectOutcome)outcome : ConnectOutcome.Failed;
        if (handle == IntPtr.Zero)
            return new SshConnectResult(status == ConnectOutcome.Ok ? ConnectOutcome.Failed : status, null, fp, h, message ?? "the connection failed");
        return new SshConnectResult(ConnectOutcome.Ok, TerminalSession.Adopt(handle), null, null, null);
    }

    /// <summary>
    /// Dial an sftp/scp connection and open its files browser, no shell (C ABI 87). Blocking; never throws for a
    /// connection failure. Logins, trust and jump hosts as for <see cref="ConnectSsh"/>.
    /// </summary>
    public SshConnectResult ConnectFiles(
        LibraryClient library,
        string connectionId,
        string? username,
        SshLoginKind kind,
        string? secret,
        string? keyPath,
        string? trustFingerprint,
        IReadOnlyDictionary<string, string>? jumpTrust,
        string? code = null,
        IReadOnlyDictionary<string, JumpLoginInput>? jumpLogins = null)
    {
        var jumpJson = jumpTrust is { Count: > 0 } ? AotJson.Write<IReadOnlyDictionary<string, string>>(jumpTrust, AotJson.Options) : null;
        using var password = new Utf8Secret(secret);
        using var oneTimeCode = new Utf8Secret(code);
        using var hopLogins = new Utf8Secret(jumpLogins is { Count: > 0 }
            ? JsonSerializer.SerializeToUtf8Bytes(jumpLogins.ToDictionary(
                p => p.Key,
                p => new ProbeLogin((int)p.Value.Kind, p.Value.Secret, p.Value.KeyPath)), ProbeJsonContext.Default.DictionaryStringProbeLogin)
            : null);
        using var manager = AcquireLease();
        using var lib = library.AcquireLease();
        var handle = SessionNative.bastion_session_connect_files(
            manager.Handle, lib.Handle, connectionId, string.IsNullOrWhiteSpace(username) ? null : username,
            (int)kind, password.Pointer, string.IsNullOrWhiteSpace(keyPath) ? null : keyPath, oneTimeCode.Pointer,
            string.IsNullOrWhiteSpace(trustFingerprint) ? null : trustFingerprint, jumpJson, hopLogins.Pointer,
            out var outcome, out var fingerprint, out var hop, out var err);
        return FilesResult(handle, outcome, Take(fingerprint), Take(hop), Take(err));
    }

    /// <summary>
    /// Sign in to an FTPS connection and open its files browser (C ABI 87). Blocking; never throws for a connection
    /// failure. <paramref name="trustedFingerprint"/> only after the user verified the certificate.
    /// </summary>
    public SshConnectResult ConnectFtps(LibraryClient library, string connectionId, string? username, string? secret, string? trustedFingerprint)
    {
        using var password = new Utf8Secret(secret);
        using var manager = AcquireLease();
        using var lib = library.AcquireLease();
        var handle = SessionNative.bastion_session_connect_ftps(
            manager.Handle, lib.Handle, connectionId, string.IsNullOrWhiteSpace(username) ? null : username, password.Pointer,
            string.IsNullOrWhiteSpace(trustedFingerprint) ? null : trustedFingerprint, out var outcome, out var fingerprint, out var err);
        return FilesResult(handle, outcome, Take(fingerprint), null, Take(err));
    }

    private static SshConnectResult FilesResult(IntPtr handle, int outcome, string? fingerprint, string? hop, string? message)
    {
        var status = Enum.IsDefined(typeof(ConnectOutcome), outcome) ? (ConnectOutcome)outcome : ConnectOutcome.Failed;
        if (handle == IntPtr.Zero)
            return new SshConnectResult(status == ConnectOutcome.Ok ? ConnectOutcome.Failed : status, null, fingerprint, hop, message ?? "the connection failed");
        return new SshConnectResult(ConnectOutcome.Ok, null, null, null, null, SftpSession.Adopt(handle));
    }

    internal static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { Native.bastion_string_free(s); }
    }

    /// <summary>
    /// Never blocks: a connect still running on a pool thread keeps the native manager alive and frees it when it
    /// returns (Codex W02). Terminals opened from this manager keep their own SSH connections alive.
    /// </summary>
    public void Dispose() => _life.Release();
}
