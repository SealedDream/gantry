using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

internal static class TransferNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_transfers_new(uint parallel);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_transfers_free(IntPtr q);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern ulong bastion_transfers_add(IntPtr q, [MarshalAs(UnmanagedType.LPUTF8Str)] string direction,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string source, [MarshalAs(UnmanagedType.LPUTF8Str)] string target, ulong total,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string overwrite, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_transfers_start_next(IntPtr q, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_transfers_resolve(IntPtr q, ulong id, [MarshalAs(UnmanagedType.LPUTF8Str)] string info, [MarshalAs(UnmanagedType.LPUTF8Str)] string? taken, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_transfers_progress(IntPtr q, ulong id, ulong done, ulong elapsedMs, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_transfers_update(IntPtr q, ulong id, [MarshalAs(UnmanagedType.LPUTF8Str)] string action, [MarshalAs(UnmanagedType.LPUTF8Str)] string? detail, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_transfers_clear_finished(IntPtr q);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_transfers_json(IntPtr q, out IntPtr err);
}

/// <summary>One job of the core transfer queue (<c>bastion_transfers_json</c>).</summary>
public sealed record TransferJob(
    [property: JsonPropertyName("id")] ulong Id,
    [property: JsonPropertyName("direction")] string Direction,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("target")] string Target,
    [property: JsonPropertyName("overwrite")] string Overwrite,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("total")] ulong Total,
    [property: JsonPropertyName("done")] ulong Done,
    [property: JsonPropertyName("attempts")] uint Attempts,
    [property: JsonPropertyName("error")] string? Error)
{
    public bool IsUpload => Direction == "upload";
    public bool IsFinished => State is "done" or "skipped" or "failed" or "cancelled";
}

/// <summary>The core's decision for a probed job: copy (to <see cref="Target"/>, replacing or not), skip, or ask.</summary>
public sealed record TransferResolution(
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("target")] string? Target,
    [property: JsonPropertyName("replace")] bool Replace);

/// <summary>
/// The core transfer queue: state only (order, overwrite rules, conflicts, retries). The host copies the bytes and
/// reports back. Thread-safe: the core locks it.
/// </summary>
public sealed partial class TransferQueue : IDisposable
{
    /// <summary>The overwrite rules the core knows, with their labels.</summary>
    public static readonly (string Rule, string Label)[] Rules =
    [
        ("ask", "Ask"), ("replace", "Replace"), ("skip", "Skip"), ("replace_if_newer", "Replace if newer"), ("rename", "Keep both"),
    ];

    private IntPtr _q;

    public TransferQueue(uint parallel = 1) => _q = TransferNative.bastion_transfers_new(parallel);

    private IntPtr Q => _q != IntPtr.Zero ? _q : throw new ObjectDisposedException(nameof(TransferQueue));

    public ulong Add(bool upload, string source, string target, ulong total, string overwrite)
    {
        var id = TransferNative.bastion_transfers_add(Q, upload ? "upload" : "download", source, target, total, overwrite, out var err);
        return id != 0 ? id : throw new BastionException(Take(err) ?? "could not queue the transfer");
    }

    /// <summary>The next queued job, now running, or null when none can start.</summary>
    public TransferJob? StartNext()
    {
        var p = TransferNative.bastion_transfers_start_next(Q, out var err);
        if (p == IntPtr.Zero) return err == IntPtr.Zero ? null : throw new BastionException(Take(err)!);
        return JsonSerializer.Deserialize(Take(p)!, AotJson.Options.Info<TransferJob>());
    }

    /// <summary>Apply the job's overwrite rule to what the target looks like. <paramref name="taken"/>: paths in use, for "rename".</summary>
    public TransferResolution Resolve(ulong id, bool exists, long? targetModified, long? sourceModified, IEnumerable<string> taken)
    {
        var info = new System.Text.Json.Nodes.JsonObject { ["exists"] = exists, ["target_modified"] = targetModified, ["source_modified"] = sourceModified }.ToJsonString();
        var p = TransferNative.bastion_transfers_resolve(Q, id, info, AotJson.Write<IEnumerable<string>>(taken, AotJson.Options), out var err);
        if (p == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not resolve the transfer");
        return JsonSerializer.Deserialize(Take(p)!, AotJson.Options.Info<TransferResolution>())!;
    }

    public void Progress(ulong id, ulong done, ulong elapsedMs)
    {
        if (TransferNative.bastion_transfers_progress(Q, id, done, elapsedMs, out var err) != 0) throw new BastionException(Take(err) ?? "progress refused");
    }

    /// <summary>"finish"|"fail"|"pause"|"resume"|"retry"|"cancel", or a conflict answer ("replace"|"skip"|"rename"|…).</summary>
    public void Update(ulong id, string action, string? detail = null)
    {
        if (TransferNative.bastion_transfers_update(Q, id, action, detail, out var err) != 0) throw new BastionException(Take(err) ?? $"could not {action} the transfer");
    }

    public void ClearFinished() => TransferNative.bastion_transfers_clear_finished(Q);

    public IReadOnlyList<TransferJob> Jobs()
    {
        var p = TransferNative.bastion_transfers_json(Q, out var err);
        if (p == IntPtr.Zero) throw new BastionException(Take(err) ?? "could not read the queue");
        using var doc = JsonDocument.Parse(Take(p)!);
        return doc.RootElement.GetProperty("jobs").Deserialize(AotJson.Options.Info<List<TransferJob>>()) ?? [];
    }

    private static string? Take(IntPtr s)
    {
        if (s == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUTF8(s); }
        finally { Native.bastion_string_free(s); }
    }

    public void Dispose()
    {
        if (_q == IntPtr.Zero) return;
        TransferNative.bastion_transfers_free(_q);
        _q = IntPtr.Zero;
    }
}
