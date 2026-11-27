using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

// The Test Connection wire format and what a report means. Nothing here touches the native library or the
// UI, so tests\probe-console compiles this file alone and checks it without a window.

/// <summary>One step of a Test Connection report (C ABI 29). <see cref="Status"/> is ok, warn, failed or skipped;
/// <see cref="Fix"/> says what to do when the step failed. Never carries a secret.</summary>
public sealed record ProbeStepDto(string Kind, string Status, string Detail, string? Fix, ulong Millis);

/// <summary>The whole Test Connection report. Read <see cref="NeedsHostKeyConfirmation"/> before
/// <see cref="Ok"/> (SEC-07): when it is set the test stopped before the login and is not a success.
/// <see cref="ProbeVerdict.Of"/> does that; nothing else should look at <see cref="Ok"/>.</summary>
public sealed record ProbeReportDto(bool Ok, bool Cancelled, List<ProbeStepDto> Steps,
    [property: JsonPropertyName("needs_host_key_confirmation")] string? NeedsHostKeyConfirmation = null,
    [property: JsonPropertyName("host_key_failure")] string? HostKeyFailure = null);

/// <summary>What Test Connection signs in with: a login kind (SshLoginKind) plus its secret or key file.</summary>
public sealed record ProbeLogin(
    [property: JsonPropertyName("kind")] int Kind,
    [property: JsonPropertyName("secret")] string? Secret,
    [property: JsonPropertyName("key_path")] string? KeyPath);

/// <summary>The JSON of <c>bastion_probe_start</c> and <c>bastion_probe_wait_json</c>.</summary>
/// <summary>The Test Connection request, in the order and with the names the core reads.</summary>
public sealed record ProbeRequest(
    [property: JsonPropertyName("protocol")] string Protocol,
    [property: JsonPropertyName("host")] string Host,
    [property: JsonPropertyName("port")] int Port,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("login")] ProbeLogin? Login,
    [property: JsonPropertyName("jumps")] IReadOnlyList<ProbeHop> Jumps,
    [property: JsonPropertyName("trusted_fingerprint"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TrustedFingerprint,
    [property: JsonPropertyName("connection_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ConnectionId);

/// <summary>Source-generated JSON for the probe wire (WIN-AOT); case-insensitive reads as before.</summary>
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(ProbeRequest))]
[JsonSerializable(typeof(ProbeReportDto))]
[JsonSerializable(typeof(Dictionary<string, ProbeLogin>))]
internal sealed partial class ProbeJsonContext : JsonSerializerContext;

public static class ProbeWire
{
    public static byte[] Request(string protocol, string host, int port, string? username, ProbeLogin? login, string? trustedFingerprint, string? connectionId = null,
        IReadOnlyList<ProbeHop>? jumps = null) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new ProbeRequest(protocol, host, port, username ?? "", login, jumps ?? Array.Empty<ProbeHop>(),
                string.IsNullOrEmpty(trustedFingerprint) ? null : trustedFingerprint, string.IsNullOrEmpty(connectionId) ? null : connectionId),
            ProbeJsonContext.Default.ProbeRequest);

    /// <summary>Parse a report; null when the text is not one.</summary>
    public static ProbeReportDto? Report(string json)
    {
        try { return JsonSerializer.Deserialize(json, ProbeJsonContext.Default.ProbeReportDto) is { Steps: not null } report ? report : null; }
        catch (JsonException) { return null; }
    }
}

public enum ProbeState
{
    /// <summary>The test stopped before the login: the host key is new and the user has not confirmed it.</summary>
    WaitingForHostKey,
    Cancelled,
    Passed,
    Failed,
}

/// <summary>What a report means for the panel: its state, the one-line summary, and the fingerprint to confirm.</summary>
public sealed record ProbeVerdict(ProbeState State, string Summary, string? Fingerprint = null)
{
    public const string Waiting = "Sign-in not tested yet: the host key is new. Confirm it below to test the sign-in.";
    public const string WaitingAgain = "The server showed a different key this time, so the sign-in was not tested. Confirm the key below to try again.";
    public const string Declined = "Sign-in not tested: the host key was not confirmed. No login was sent and nothing was saved.";
    public const string ChangedKey = " A changed key cannot be confirmed from a test.";
    // SEC-07-FU1: the core says which host-key failure it was (host_key_failure).
    public const string KeyChanged = "Test failed: the server's host key has changed since the last connection. Do not connect until the administrator confirms the new key; no sign-in was sent.";
    public const string KnownHostsUnreadable = "Test failed: the known_hosts file could not be read, so the host key was not checked. Check the file's permissions; no sign-in was sent.";

    /// <param name="sentTrust">The fingerprint this run was started with, if the user had confirmed one.</param>
    public static ProbeVerdict Of(ProbeReportDto report, string? sentTrust = null)
    {
        // First, before Ok: a waiting report has Ok true, and it is not a success.
        if (report.NeedsHostKeyConfirmation is { Length: > 0 } fingerprint)
            return new(ProbeState.WaitingForHostKey, string.IsNullOrEmpty(sentTrust) ? Waiting : WaitingAgain, fingerprint);
        if (report.Cancelled) return new(ProbeState.Cancelled, "Test cancelled.");
        if (report.Ok)
        {
            var total = report.Steps.Aggregate(0UL, (sum, s) => sum + s.Millis);
            return new(ProbeState.Passed, $"Everything works ({total} ms).");
        }
        var failed = report.Steps.FirstOrDefault(s => s.Status == "failed");
        if (failed is { Kind: "host_key" })
        {
            if (report.HostKeyFailure == "changed") return new(ProbeState.Failed, KeyChanged);
            if (report.HostKeyFailure == "known_hosts_unreadable") return new(ProbeState.Failed, KnownHostsUnreadable);
        }
        // An older core sends no kind: keep the text-based reading.
        var changed = failed is { Kind: "host_key" } && failed.Detail.Contains("CHANGED", StringComparison.Ordinal);
        return new(ProbeState.Failed, "Test failed: " + (failed?.Detail ?? "see the steps below") + (changed ? "." + ChangedKey : ""));
    }
}

/// <summary>
/// A new host key shown to the user and not yet answered. The only source of a request's
/// <c>trusted_fingerprint</c>: <see cref="TrustFor"/> hands the fingerprint out after the user's yes, and only
/// for the host and port it was shown for (the form can be edited while the question is open).
/// </summary>
public sealed record PendingHostKey(string Host, int Port, string Fingerprint)
{
    public string Target => $"{Host}:{Port}";

    public string? TrustFor(string host, int port) =>
        port == Port && string.Equals(host.Trim(), Host.Trim(), StringComparison.OrdinalIgnoreCase) ? Fingerprint : null;
}
