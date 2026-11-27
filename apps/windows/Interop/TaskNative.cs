using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>
/// A saved task. <see cref="Kind"/> is <c>ping</c>, <c>trace_route</c>, <c>dns_lookup</c>, <c>tcp_check</c> (built in) or
/// <c>custom</c>; <see cref="RunOn"/> is <c>local</c> or <c>ssh</c>.
/// </summary>
public sealed record TaskDto(string Id, string Name, bool Favorite, bool Builtin, string Kind, string Program, List<string> Args, string RunOn, uint TimeoutSecs);

public sealed record TaskReviewDto(string Display, bool NeedsConfirmation);

/// <summary>A run's progress. <see cref="State"/> is <c>running</c>, <c>done</c>, <c>failed</c>, <c>timed_out</c> or <c>cancelled</c>.</summary>
public sealed record TaskRunDto(string Display, bool Finished, string State, int? Exit, string Stdout, string Stderr, string? Error, long Millis);

/// <summary>P/Invoke for core-cabi/src/tasks.rs (ABI 92).</summary>
internal static class TaskNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_tasks_json(IntPtr lib, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_tasks_save_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string taskJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_tasks_remove(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_tasks_set_favorite(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, int favorite, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_task_review_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string taskId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_task_ask_labels_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string taskId, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_task_review_with_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string taskId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, [MarshalAs(UnmanagedType.LPUTF8Str)] string? answersJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_task_run_start_with(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string taskId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        int loginKind, IntPtr password, [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath, int confirmed,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? answersJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_task_run_start(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string taskId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        int loginKind, IntPtr password, [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath, int confirmed, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_task_run_output_json(IntPtr r, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_task_run_cancel(IntPtr r, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_task_run_free(IntPtr r);
}

/// <summary>The library's saved tasks (built-ins first). Validation, policy and audit live in the core.</summary>
public static class TaskClient
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static List<TaskDto> List(LibraryClient library) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(TaskNative.bastion_tasks_json(library.NativeHandle, out var err), err), Json.Info<List<TaskDto>>()) ?? [];

    /// <summary>Add (empty id) or replace a custom task; returns its id. Throws with the core's reason when refused.</summary>
    public static string Save(LibraryClient library, TaskDto task) =>
        LibraryClient.TakeString(TaskNative.bastion_tasks_save_json(library.NativeHandle, AotJson.Write<TaskDto>(task, Json), out var err), err);

    public static void Remove(LibraryClient library, string id)
    {
        if (TaskNative.bastion_tasks_remove(library.NativeHandle, id, out var err) != 0) throw new BastionException(LibraryClient.TakeError(err, "could not remove the task"));
    }

    public static void SetFavorite(LibraryClient library, string id, bool favorite)
    {
        if (TaskNative.bastion_tasks_set_favorite(library.NativeHandle, id, favorite ? 1 : 0, out var err) != 0) throw new BastionException(LibraryClient.TakeError(err, "could not change the favourite"));
    }

    /// <summary>What a run would execute with these <c>$Ask:Label$</c> answers (C ABI 135), and whether to confirm first.</summary>
    public static TaskReviewDto Review(LibraryClient library, string taskId, string connectionId, IReadOnlyDictionary<string, string>? answers = null) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(TaskNative.bastion_task_review_with_json(library.NativeHandle, taskId, connectionId, AnswersJson(answers), out var err), err), Json.Info<TaskReviewDto>())
        ?? throw new BastionException("the core returned no review");

    /// <summary>The <c>$Ask:Label$</c> labels a run must ask for, once per run, first use first (C ABI 135).</summary>
    public static List<string> AskLabels(LibraryClient library, string taskId) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(TaskNative.bastion_task_ask_labels_json(library.NativeHandle, taskId, out var err), err), Json.Info<List<string>>()) ?? [];

    internal static string? AnswersJson(IReadOnlyDictionary<string, string>? answers) =>
        answers is { Count: > 0 } ? JsonSerializer.Serialize(new Dictionary<string, string>(answers), Json.Info<Dictionary<string, string>>()) : null;
}

/// <summary>One task run in the background. Disposing releases the handle (a run still going finishes and is audited).</summary>
public sealed partial class TaskRunClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private IntPtr _handle;

    private TaskRunClient(IntPtr handle) => _handle = handle;

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(TaskRunClient));

    /// <summary>Start a task; <paramref name="secret"/> (SSH tasks only) is copied and zeroed. <paramref name="answers"/> fill
    /// <c>$Ask:Label$</c> (C ABI 135) and are not stored.</summary>
    public static TaskRunClient Start(SessionManagerClient sessions, LibraryClient library, string taskId, string connectionId,
        string? username, SshLoginKind kind, string? secret, string? keyPath, bool confirmed, IReadOnlyDictionary<string, string>? answers = null)
    {
        using var password = new Utf8Secret(secret);
        var h = TaskNative.bastion_task_run_start_with(sessions.NativeHandle, library.NativeHandle, taskId, connectionId,
            string.IsNullOrWhiteSpace(username) ? null : username, (int)kind, password.Pointer,
            string.IsNullOrWhiteSpace(keyPath) ? null : keyPath, confirmed ? 1 : 0, TaskClient.AnswersJson(answers), out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "could not start the task"));
        return new TaskRunClient(h);
    }

    public TaskRunDto Output() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(TaskNative.bastion_task_run_output_json(H, out var err), err), Json.Info<TaskRunDto>())
        ?? throw new BastionException("the core returned no output");

    public void Cancel()
    {
        if (TaskNative.bastion_task_run_cancel(H, out var err) != 0) throw new BastionException(LibraryClient.TakeError(err, "could not cancel"));
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        var h = _handle;
        _handle = IntPtr.Zero;
        TaskNative.bastion_task_run_free(h);
    }
}
