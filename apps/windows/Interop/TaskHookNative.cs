using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

/// <summary>
/// A task hook on a connection or folder (B5). <see cref="When"/> is <c>before_connect</c>, <c>after_connect</c> or
/// <c>after_disconnect</c>; <see cref="Target"/> is <c>task</c>, <c>snippet</c> (after connect only) or <c>multi_host</c>
/// (folders only). A snippet hook names the snippet in <see cref="SnippetId"/> and has an empty <see cref="TaskId"/>.
/// </summary>
public sealed record TaskHookDto(string TaskId, string When, string Target = "task", string? SnippetId = null)
{
    [JsonIgnore] public string TargetOrTask => string.IsNullOrEmpty(Target) ? "task" : Target;
}

/// <summary>A hook to run for one connection, in core order (outer folder first). <see cref="Untrusted"/>: a local-program
/// task from a document that the user has not saved in Tasks on this computer (trust rule T01).</summary>
public sealed record ResolvedHookDto(TaskHookDto Hook, string OwnerId, bool Runnable, bool Untrusted);

/// <summary>P/Invoke for the hook calls in core-cabi/src/tasks.rs (B5).</summary>
internal static class TaskHookNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_task_hooks_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_task_set_hooks_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string hooksJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_task_resolved_hooks_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string when, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_task_trust(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string taskId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);
}

/// <summary>Task hooks and the trust rule. Validation (snippet only after connect, multi-host only on folders) is the core's.</summary>
public static class TaskHookClient
{
    /// <summary>The hooks set on a connection or folder (not inherited ones).</summary>
    public static List<TaskHookDto> Hooks(LibraryClient library, string ownerId) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(TaskHookNative.bastion_task_hooks_json(library.NativeHandle, ownerId, out var err), err),
            TaskHookJsonContext.Default.ListTaskHookDto) ?? [];

    /// <summary>Replace the hooks on a connection or folder; throws with the core's reason when one is refused.</summary>
    public static void SetHooks(LibraryClient library, string ownerId, IReadOnlyList<TaskHookDto> hooks)
    {
        var json = JsonSerializer.Serialize(hooks.ToList(), TaskHookJsonContext.Default.ListTaskHookDto);
        if (TaskHookNative.bastion_task_set_hooks_json(library.NativeHandle, ownerId, json, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not save the attached tasks"));
    }

    /// <summary>The hooks to run for <paramref name="connectionId"/> at <paramref name="when"/>, folder hooks first.</summary>
    public static List<ResolvedHookDto> Resolved(LibraryClient library, string connectionId, string when, string dataDir) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(TaskHookNative.bastion_task_resolved_hooks_json(library.NativeHandle, connectionId, when, dataDir, out var err), err),
            TaskHookJsonContext.Default.ListResolvedHookDto) ?? [];

    /// <summary>The user saved this task in Tasks on this computer: its exact content may run as a hook (T01).</summary>
    public static void Trust(LibraryClient library, string taskId, string dataDir)
    {
        if (TaskHookNative.bastion_task_trust(library.NativeHandle, taskId, dataDir, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not record the task as trusted"));
    }
}
