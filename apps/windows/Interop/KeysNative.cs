using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for core-cabi/src/keys.rs (C ABI 39) and agent.rs (C ABI 60).</summary>
internal static class KeysNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_keys_generate_json([MarshalAs(UnmanagedType.LPUTF8Str)] string? comment, [MarshalAs(UnmanagedType.LPUTF8Str)] string? passphrase, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_keys_inspect_json([MarshalAs(UnmanagedType.LPUTF8Str)] string keyText, [MarshalAs(UnmanagedType.LPUTF8Str)] string? passphrase, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_keys_convert_json([MarshalAs(UnmanagedType.LPUTF8Str)] string keyText, [MarshalAs(UnmanagedType.LPUTF8Str)] string? passphrase,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? newPassphrase, [MarshalAs(UnmanagedType.LPUTF8Str)] string? comment, out IntPtr err);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int AgentConfirm(IntPtr ctx, IntPtr comment, IntPtr fingerprint);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_agent_start([MarshalAs(UnmanagedType.LPUTF8Str)] string socket, [MarshalAs(UnmanagedType.LPUTF8Str)] string keysJson,
        AgentConfirm? confirm, IntPtr ctx, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_agent_socket(IntPtr agent);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_agent_free(IntPtr agent);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void AgentStopped(IntPtr ctx);

    /// <summary>ABI 83: stop now; <c>stopped(ctx)</c> runs once no confirm callback is running.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_agent_stop(IntPtr agent, AgentStopped? stopped, IntPtr ctx);
}

/// <summary>A key as the core describes it. <see cref="PrivateOpenssh"/> is set only by Generate/Convert: store it in the vault, never log it.</summary>
public sealed record KeyInfoDto(
    string Algorithm, string Fingerprint, string Comment,
    [property: JsonPropertyName("public_openssh")] string PublicOpenssh,
    string Format, bool Hardware,
    [property: JsonPropertyName("private_openssh")] string? PrivateOpenssh = null);

/// <summary>Key manager: generate ed25519, inspect and convert OpenSSH / PEM / PuTTY keys by the core's rules.</summary>
public static class KeyManager
{
    private static KeyInfoDto Read(IntPtr ptr, IntPtr err) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(ptr, err), new JsonSerializerOptions { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true }.Info<KeyInfoDto>())
        ?? throw new BastionException("key manager returned no result");

    /// <summary>A new ed25519 key; empty <paramref name="passphrase"/> = unencrypted.</summary>
    public static KeyInfoDto Generate(string? comment, string? passphrase) =>
        Read(KeysNative.bastion_keys_generate_json(comment, passphrase, out var err), err);

    /// <summary>Describes a private key without returning key material.</summary>
    public static KeyInfoDto Inspect(string keyText, string? passphrase) =>
        Read(KeysNative.bastion_keys_inspect_json(keyText, passphrase, out var err), err);

    /// <summary>Re-encodes a key as OpenSSH under <paramref name="newPassphrase"/>; empty comment keeps the key's own.</summary>
    public static KeyInfoDto Convert(string keyText, string? passphrase, string? newPassphrase, string? comment) =>
        Read(KeysNative.bastion_keys_convert_json(keyText, passphrase, newPassphrase, comment, out var err), err);
}

/// <summary>One key to serve from <see cref="SshAgent"/>.</summary>
public sealed record AgentKey(string Key, string? Passphrase = null);

/// <summary>
/// Bastion's own SSH agent on an owner-only named pipe (<c>\\.\pipe\...</c>). <paramref name="confirm"/> is asked
/// (comment, fingerprint) before each signature when given. Dispose to stop serving.
/// </summary>
public sealed partial class SshAgent : IDisposable
{
    private IntPtr _handle;
    // Kept alive for the agent's lifetime: the core calls it from its own threads.
    private readonly KeysNative.AgentConfirm? _confirm;

    private SshAgent(IntPtr handle, KeysNative.AgentConfirm? confirm) => (_handle, _confirm) = (handle, confirm);

    public static SshAgent Start(string pipe, IReadOnlyList<AgentKey> keys, Func<string, string, bool>? confirm = null)
    {
        KeysNative.AgentConfirm? cb = confirm is null ? null : (_, c, f) =>
        {
            try { return confirm(Marshal.PtrToStringUTF8(c) ?? "", Marshal.PtrToStringUTF8(f) ?? "") ? 1 : 0; }
            catch { return 0; } // an exception must not cross into the core; refuse the signature
        };
        var json = AotJson.Write<IReadOnlyList<AgentKey>>(keys, new JsonSerializerOptions { TypeInfoResolver = AotJson.Resolver, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
        var h = KeysNative.bastion_agent_start(pipe, json, cb, IntPtr.Zero, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "the SSH agent did not start"));
        return new SshAgent(h, cb);
    }

    /// <summary>The pipe the agent listens on (for SSH_AUTH_SOCK-style settings).</summary>
    public string Socket => LibraryClient.TakeString(KeysNative.bastion_agent_socket(H), IntPtr.Zero);

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(SshAgent));

    // Called by the core once no confirm callback runs any more: only then may the confirm
    // delegate be collected. Static, so the stop delegate itself is never collected.
    private static readonly KeysNative.AgentStopped s_stopped = ctx => GCHandle.FromIntPtr(ctx).Free();

    /// <summary>Stops serving at once without blocking (a confirm dialog may be waiting on this thread).</summary>
    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        // The handle keeps the confirm delegate alive until the core reports it is unused (F02).
        var keep = GCHandle.Alloc(_confirm);
        KeysNative.bastion_agent_stop(_handle, s_stopped, GCHandle.ToIntPtr(keep));
        _handle = IntPtr.Zero;
    }
}
