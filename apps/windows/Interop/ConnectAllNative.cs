using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>
/// The core's plan for Connect All on a folder and its subfolders (B4, ABI 97), in tree order; every connection is in
/// exactly one list. <see cref="Ready"/> have a login of their own (or their type takes none): open them without asking.
/// <see cref="NeedsLogin"/> have none: never connect these with a login the app picked; open them one by one through the
/// sign-in sheet. <see cref="SkippedBlocked"/> (ABI 109) are types the managed policy forbids: never connect them, only
/// name them. Ask before starting when <see cref="NeedsConfirmation"/>. Ids and counts only, no secret.
/// </summary>
public sealed record ConnectAllPlanDto(
    IReadOnlyList<string> Ready, IReadOnlyList<string> NeedsLogin, IReadOnlyList<string> SkippedOpen,
    IReadOnlyList<string> SkippedUnsupported, IReadOnlyList<string>? SkippedBlocked, int ToConnect, bool NeedsConfirmation);

/// <summary>P/Invoke for core-cabi/src/bulk.rs (ABI 97; <c>skippedBlocked</c> since 109).</summary>
internal static class ConnectAllNative
{
    [DllImport("bastion_cabi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_credentials_plan_connect_all_json(IntPtr v, IntPtr lib,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? folderId, [MarshalAs(UnmanagedType.LPUTF8Str)] string? openIdsJson, out IntPtr err);
}

public sealed partial class CredentialStore
{
    private static readonly JsonSerializerOptions PlanJson = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    /// <summary>The Connect All plan for <paramref name="folderId"/> (null: the whole library); <paramref name="openIds"/> have a session now.</summary>
    public ConnectAllPlanDto PlanConnectAll(LibraryClient library, string? folderId, IEnumerable<string> openIds) =>
        JsonSerializer.Deserialize(
            TakeString(ConnectAllNative.bastion_credentials_plan_connect_all_json(H, library.NativeHandle, folderId,
                AotJson.Write<List<string>>(openIds.ToList(), AotJson.Options), out var err), err), PlanJson.Info<ConnectAllPlanDto>())
        ?? throw new BastionException("the core returned no Connect All plan");
}
