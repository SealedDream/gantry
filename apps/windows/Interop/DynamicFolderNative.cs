using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

/// <summary>A task that may feed a dynamic folder (a saved local custom task, no tokens).</summary>
public sealed record DynamicTaskChoiceDto(string Id, string Name);

/// <summary>The consent sheet for a folder's task (B15 C1). Pass <see cref="Sha256"/> back to trust exactly what was shown.</summary>
public sealed record DynamicReviewDto(string TaskId, string TaskName, string Program, List<string> Args, uint TimeoutSecs,
    bool Trusted, string Sha256, List<string> Warnings);

/// <summary>One generated item; never in the document until Make Permanent.</summary>
public sealed record DynamicItemDto(string Id, string Name, string Protocol, string Host, int? Port, string? Username,
    string? CredentialName, string Notes, List<string> Path);

/// <summary>A Refresh: <see cref="State"/> is running, done, failed, timed_out or cancelled.</summary>
public sealed record DynamicRunDto(bool Finished, string State, List<DynamicItemDto> Items, List<string> Skipped, string? Error,
    int? Exit, ulong Millis);

/// <summary>P/Invoke for core-cabi/src/dynfolder.rs (B15, C ABI 130).</summary>
internal static class DynamicFolderNative
{
    private const string L = "bastion_cabi";

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_dynamic_folders_allowed();

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_dynamic_folder_task_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string folderId, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_dynamic_folder_set_task(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string folderId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? taskId, int userEnabled, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_dynamic_folder_task_choices_json(IntPtr lib, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_dynamic_folder_review_json(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string folderId, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_dynamic_folder_trust(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string folderId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string reviewedSha256, int userEnabled, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_dynamic_folder_revoke(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string folderId, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_dynamic_folder_run_start(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string folderId, int userEnabled, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_dynamic_folder_run_output_json(IntPtr r, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_dynamic_folder_run_cancel(IntPtr r, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_dynamic_folder_make_permanent(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string folderId, IntPtr r, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_dynamic_folder_run_free(IntPtr r);
}

/// <summary>Dynamic folders (B15). Policy, trust, caps and audit are the core's; this only forwards.
/// <c>userEnabled</c> is the user's own switch; a managed ban wins in core whatever it says.</summary>
public static class DynamicFolderClient
{
    /// <summary>False under a managed ban: hide every dynamic-folder control.</summary>
    public static bool Allowed() => DynamicFolderNative.bastion_dynamic_folders_allowed() == 1;

    /// <summary>The task bound to <paramref name="folderId"/>, or null for a plain folder.</summary>
    public static string? TaskId(LibraryClient library, string folderId) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(DynamicFolderNative.bastion_dynamic_folder_task_json(library.NativeHandle, folderId, out var err), err),
            DynamicFolderJsonContext.Default.String);

    /// <summary>Bind a task (null: make the folder plain). Throws with the core's reason.</summary>
    public static void SetTask(LibraryClient library, string folderId, string? taskId, bool userEnabled)
    {
        if (DynamicFolderNative.bastion_dynamic_folder_set_task(library.NativeHandle, folderId, taskId, userEnabled ? 1 : 0, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not set the folder's task"));
    }

    public static List<DynamicTaskChoiceDto> Choices(LibraryClient library) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(DynamicFolderNative.bastion_dynamic_folder_task_choices_json(library.NativeHandle, out var err), err),
            DynamicFolderJsonContext.Default.ListDynamicTaskChoiceDto) ?? [];

    public static DynamicReviewDto Review(SessionManagerClient sessions, LibraryClient library, string folderId) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(DynamicFolderNative.bastion_dynamic_folder_review_json(sessions.NativeHandle, library.NativeHandle, folderId, out var err), err),
            DynamicFolderJsonContext.Default.DynamicReviewDto) ?? throw new BastionException("the core returned no review");

    /// <summary>Only from the user's Trust and Run, with the hash of the review they saw.</summary>
    public static void Trust(SessionManagerClient sessions, LibraryClient library, string folderId, string reviewedSha256, bool userEnabled)
    {
        if (DynamicFolderNative.bastion_dynamic_folder_trust(sessions.NativeHandle, library.NativeHandle, folderId, reviewedSha256, userEnabled ? 1 : 0, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not trust the task"));
    }

    /// <summary>True when a trust was removed.</summary>
    public static bool Revoke(SessionManagerClient sessions, LibraryClient library, string folderId)
    {
        var r = DynamicFolderNative.bastion_dynamic_folder_revoke(sessions.NativeHandle, library.NativeHandle, folderId, out var err);
        if (r < 0) throw new BastionException(LibraryClient.TakeError(err, "could not remove the trust"));
        return r == 1;
    }
}

/// <summary>One Refresh. Disposing a run still going cancels it (the core kills its process tree).</summary>
public sealed class DynamicFolderRunClient : IDisposable
{
    private IntPtr _handle;

    private DynamicFolderRunClient(IntPtr handle) => _handle = handle;

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(DynamicFolderRunClient));

    /// <summary>Start in the background; throws with the core's refusal (policy, task, path, trust).</summary>
    public static DynamicFolderRunClient Start(SessionManagerClient sessions, LibraryClient library, string folderId, bool userEnabled)
    {
        var h = DynamicFolderNative.bastion_dynamic_folder_run_start(sessions.NativeHandle, library.NativeHandle, folderId, userEnabled ? 1 : 0, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "could not start the refresh"));
        return new DynamicFolderRunClient(h);
    }

    public DynamicRunDto Output() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(DynamicFolderNative.bastion_dynamic_folder_run_output_json(H, out var err), err),
            DynamicFolderJsonContext.Default.DynamicRunDto) ?? throw new BastionException("the core returned no output");

    public void Cancel()
    {
        if (DynamicFolderNative.bastion_dynamic_folder_run_cancel(H, out var err) != 0) throw new BastionException(LibraryClient.TakeError(err, "could not cancel"));
    }

    /// <summary>Copy this finished run's items into the folder as ordinary connections; returns the count.</summary>
    public int MakePermanent(LibraryClient library, string folderId)
    {
        var n = DynamicFolderNative.bastion_dynamic_folder_make_permanent(library.NativeHandle, folderId, H, out var err);
        if (n < 0) throw new BastionException(LibraryClient.TakeError(err, "could not add the items"));
        return n;
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        DynamicFolderNative.bastion_dynamic_folder_run_free(_handle);
        _handle = IntPtr.Zero;
    }
}

/// <summary>Dynamic folders (B15): camelCase, as core-cabi/src/dynfolder.rs writes them.</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(List<DynamicTaskChoiceDto>))]
[JsonSerializable(typeof(DynamicReviewDto))]
[JsonSerializable(typeof(DynamicRunDto))]
internal sealed partial class DynamicFolderJsonContext : JsonSerializerContext;
