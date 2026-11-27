using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>Wrong passwords so far and seconds before the next try (C ABI 81).</summary>
public sealed record UnlockStatusDto(int Failures, long WaitSecs);

/// <summary>A Welcome screen recent document; <c>Present</c> false shows "Locate…". <c>LastOpenedAt</c> is Unix seconds.</summary>
public sealed record RecentDocumentDto(string Path, string? Name, string? Id, bool Present, bool Protected, bool Biometric, long? LastOpenedAt, int? ConnectionCount = null);

/// <summary>Why the document should lock now.</summary>
public enum AutoLockReason { None = 0, Idle = 1, ScreenLocked = 2, Sleep = 3 }

/// <summary>P/Invoke for core-cabi/src/docunlock.rs (ABI 81).</summary>
internal static class DocumentUnlockNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_document_unlock_status_json(IntPtr d, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_document_export_wrapped_key(IntPtr d, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_document_unlock_wrapped_key(IntPtr d, [MarshalAs(UnmanagedType.LPUTF8Str)] string wrapped, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_document_state_dir(IntPtr d, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_documents_recent_details_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    /// <summary>ABI 145.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_documents_forget_recent([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_document_auto_lock_due(uint minutes, ulong idleSecs, int screenLocked, int asleep, int rememberUntilQuit);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bastion_effective_auto_lock_minutes(uint userMinutes, uint policyMax);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint bastion_document_auto_lock_minutes(uint userMinutes);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_document_biometric_unlock_allowed();
}

public sealed partial class DocumentClient
{
    private static readonly JsonSerializerOptions UnlockJson = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    /// <summary>Settings ids for §5 (Security category).</summary>
    public const string AutoLockSettingId = "document.auto-lock-minutes";
    public const string CloseSessionsOnLockSettingId = "document.close-sessions-on-lock";
    public const string RememberUnlockSettingId = "document.remember-unlock";

    /// <summary>For the Unlock screen; <see cref="Unlock"/> fails without trying while <c>WaitSecs</c> &gt; 0.</summary>
    public UnlockStatusDto UnlockStatus() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(DocumentUnlockNative.bastion_document_unlock_status_json(Live, out var err), err), UnlockJson.Info<UnlockStatusDto>())
        ?? new(0, 0);

    /// <summary>The unlocked key wrapped for this device; keep it behind Windows Hello. Never contains the password.</summary>
    public string ExportWrappedKey() => LibraryClient.TakeString(DocumentUnlockNative.bastion_document_export_wrapped_key(Live, out var err), err);

    public void UnlockWithWrappedKey(string wrapped) =>
        Ok(DocumentUnlockNative.bastion_document_unlock_wrapped_key(Live, wrapped, out var err), err, "biometric unlock failed");

    /// <summary>This document's own state folder: the data dir for <see cref="SessionRestore"/> and <see cref="ConnectionHistory"/>.</summary>
    public string StateDir() => LibraryClient.TakeString(DocumentUnlockNative.bastion_document_state_dir(Live, out var err), err);

    /// <summary>Remove <paramref name="path"/> from Recent documents; the file stays (ABI 145).</summary>
    public static void ForgetRecent(string dataDir, string path)
    {
        if (DocumentUnlockNative.bastion_documents_forget_recent(dataDir, path, out var err) != 0)
            throw new BastionException(GatewayNative.Take(err) ?? "could not update recent documents");
    }

    /// <summary>Newest first; the first with <c>Present</c> is the last-used document.</summary>
    public static IReadOnlyList<RecentDocumentDto> RecentDetails(string dataDir) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(DocumentUnlockNative.bastion_documents_recent_details_json(dataDir, out var err), err), UnlockJson.Info<List<RecentDocumentDto>>()) ?? [];

    public static AutoLockReason AutoLockDue(uint minutes, ulong idleSecs, bool screenLocked, bool asleep, bool rememberUntilQuit) =>
        (AutoLockReason)DocumentUnlockNative.bastion_document_auto_lock_due(minutes, idleSecs, screenLocked ? 1 : 0, asleep ? 1 : 0, rememberUntilQuit ? 1 : 0);

    /// <summary>The user's minutes (0 = never) capped by a policy maximum (0 = none).</summary>
    public static uint EffectiveAutoLockMinutes(uint userMinutes, uint policyMax = 0) => DocumentUnlockNative.bastion_effective_auto_lock_minutes(userMinutes, policyMax);

    /// <summary>The user's minutes capped by the managed policy in force (ABI 82).</summary>
    public static uint PolicyAutoLockMinutes(uint userMinutes) => DocumentUnlockNative.bastion_document_auto_lock_minutes(userMinutes);

    /// <summary>False when the managed policy requires the document password (hide Windows Hello).</summary>
    public static bool BiometricUnlockAllowed => DocumentUnlockNative.bastion_document_biometric_unlock_allowed() != 0;
}
