using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>The icon the core picked for a dashboard row.</summary>
public sealed record OverviewIconDto(string Id, string Label, string? Tint);

/// <summary>
/// One row of the folder dashboard (C ABI 97, core <c>overview::folder_overview</c>). Names and states only: the core
/// returns no secret and no credential id. <c>Login</c> is none, saved, inherited or offered; <c>LoginFrom</c> names the
/// folder or connection it comes from. <c>LastConnectedAt</c> is Unix seconds.
/// </summary>
public sealed record OverviewRowDto(string Id, string Kind, string Name, string Address, string? Protocol, string TypeLabel,
    string? Username, string Login, string? LoginFrom, long? LastConnectedAt, string? LastResult, List<string>? Tags,
    List<string>? FolderPath, bool Favorite, string? HostColor, OverviewIconDto? Icon)
{
    public bool IsFolder => Kind == "folder";
}

/// <summary>P/Invoke for core-cabi/src/overview.rs (ABI 97), the call Native Mac makes for the same page.</summary>
internal static class OverviewNative
{
    private const string Lib = "bastion_cabi";
    private const UnmanagedType U8 = UnmanagedType.LPUTF8Str;

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_folder_overview_json(IntPtr lib, IntPtr v, [MarshalAs(U8)] string? dataDir,
        [MarshalAs(U8)] string folderId, int includeSubfolders, out IntPtr err);
}

public static class FolderOverview
{

    /// <summary>
    /// The rows of <paramref name="folderId"/>. Pass <paramref name="vault"/> only while credentials are open: with null
    /// the login state comes from the library alone and the vault is never touched (no prompt from opening the page).
    /// </summary>
    /// <remarks>
    /// The dashboard calls this on a worker thread (WIN-STALL-USER). The vault is leased for the call
    /// (<see cref="CredentialStore.TryLeased"/>, the SEC-1 lease), so Lock Credentials on the UI thread frees it only
    /// when the call ends. A vault locked before the call reads as no vault.
    /// </remarks>
    public static List<OverviewRowDto> Rows(LibraryClient library, CredentialStore? vault, string? dataDir, string folderId, bool includeSubfolders)
    {
        string Query(IntPtr v)
        {
            var ptr = OverviewNative.bastion_library_folder_overview_json(library.NativeHandle, v, dataDir, folderId, includeSubfolders ? 1 : 0, out var err);
            return LibraryClient.TakeString(ptr, err);
        }
        var json = vault is not null && vault.TryLeased(Query, out var leased) ? leased : Query(IntPtr.Zero);
        return JsonSerializer.Deserialize(json, OverviewJsonContext.Default.ListOverviewRowDto) ?? [];
    }
}
