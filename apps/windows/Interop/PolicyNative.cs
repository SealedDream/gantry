using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>The policy in force (C ABI 23). <see cref="Source"/> is null without a managed policy; <see cref="Error"/>
/// is set when one is installed but cannot be used, and then every connect is refused.</summary>
public sealed record PolicyStateDto(
    string ManagedPath, string? Source, string? Error, List<string> DeniedProtocols, List<string> AllowedLegacy,
    bool ForbidLegacy, bool AllowCrossCustomerCredentials, uint BulkConfirmThreshold, ulong? InactivityLockSecs,
    bool AllowSessionRecording, bool LockCredentialsOnOsLock, bool ForbidOsc52Write, bool RequireRdpNla,
    uint? DocumentAutoLockMaxMinutes = null, bool PasswordOnlyDocumentUnlock = false);

internal static class PolicyNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_policy_state_json();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_policy_check_protocol([MarshalAs(UnmanagedType.LPUTF8Str)] string protocol, out IntPtr err);
}

/// <summary>Read-only access to the administrator's managed policy (<c>%ProgramData%\Bastion\policy.json</c>).</summary>
public static class PolicyClient
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    public static PolicyStateDto State() =>
        JsonSerializer.Deserialize(GatewayNative.Take(PolicyNative.bastion_policy_state_json()) ?? "null", Json.Info<PolicyStateDto>())
        ?? throw new BastionException("could not read the managed policy state");

    /// <summary>Throws with the policy's reason when <paramref name="protocol"/> (<c>rdp</c>, <c>web</c>) is refused.</summary>
    public static void CheckProtocol(string protocol)
    {
        if (PolicyNative.bastion_policy_check_protocol(protocol, out var err) != 0)
            throw new BastionException(GatewayNative.Take(err) ?? $"the managed policy refuses {protocol}");
    }
}
