using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>The core's verdict on a plan: which hosts are production / sensitive and need an explicit acknowledgement.</summary>
public sealed record ExecReviewDto(List<string> Sensitive, bool NeedsProductionAck);

/// <summary>One host of a run. <see cref="State"/> is <c>waiting</c>, <c>running</c>, <c>done</c>, <c>failed</c> or <c>cancelled</c>.</summary>
public sealed record ExecHostDto(string Host, string State, int? Exit, string Stdout, string Stderr, string? Error, long Millis);

public sealed record ExecResultsDto(bool Finished, List<ExecHostDto> Hosts);

/// <summary>P/Invoke for core-cabi/src/multiexec.rs (ABI 73).</summary>
internal static class MultiExecNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_multiexec_review_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string idsJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string command, uint concurrency, out IntPtr err);

    // The password goes over as a raw pointer the caller zeroes (see Utf8Secret).
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_multiexec_new(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string idsJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string command, uint concurrency, [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        int loginKind, IntPtr password, [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath, int productionAck, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_multiexec_run(IntPtr x, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_multiexec_retry_failed(IntPtr x, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_multiexec_cancel(IntPtr x, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_multiexec_results_json(IntPtr x, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_multiexec_export(IntPtr x, [MarshalAs(UnmanagedType.LPUTF8Str)] string format, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_multiexec_free(IntPtr x);
}

/// <summary>
/// One multi-host run: a reviewed single-line command on several SSH connections, run in the background by the core.
/// Unknown host keys fail that host (no prompt). Disposing cancels hosts not yet started.
/// </summary>
public sealed partial class MultiExecRun : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private IntPtr _handle;

    private MultiExecRun(IntPtr handle) => _handle = handle;

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(MultiExecRun));

    /// <summary>Throws <see cref="BastionException"/> with the core's reason when the plan is refused.</summary>
    public static ExecReviewDto Review(LibraryClient library, IReadOnlyList<string> connectionIds, string command, int concurrency) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(MultiExecNative.bastion_multiexec_review_json(
            library.NativeHandle, AotJson.Write<IReadOnlyList<string>>(connectionIds, AotJson.Options), command, (uint)concurrency, out var err), err), Json.Info<ExecReviewDto>())
        ?? throw new BastionException("the core returned no review");

    /// <summary>Prepare a run; nothing connects until <see cref="Run"/>. <paramref name="secret"/> is copied and zeroed.</summary>
    public static MultiExecRun Create(SessionManagerClient sessions, LibraryClient library, IReadOnlyList<string> connectionIds, string command,
        int concurrency, string? username, SshLoginKind kind, string? secret, string? keyPath, bool productionAck)
    {
        using var password = new Utf8Secret(secret);
        var h = MultiExecNative.bastion_multiexec_new(sessions.NativeHandle, library.NativeHandle, AotJson.Write<IReadOnlyList<string>>(connectionIds, AotJson.Options), command,
            (uint)concurrency, string.IsNullOrWhiteSpace(username) ? null : username, (int)kind, password.Pointer,
            string.IsNullOrWhiteSpace(keyPath) ? null : keyPath, productionAck ? 1 : 0, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "could not prepare the run"));
        return new MultiExecRun(h);
    }

    private static void Check(int rc, IntPtr err, string what)
    {
        if (rc != 0) throw new BastionException(LibraryClient.TakeError(err, what));
    }

    public void Run() => Check(MultiExecNative.bastion_multiexec_run(H, out var err), err, "could not start the run");

    public void RetryFailed() => Check(MultiExecNative.bastion_multiexec_retry_failed(H, out var err), err, "could not retry");

    public void Cancel() => Check(MultiExecNative.bastion_multiexec_cancel(H, out var err), err, "could not cancel");

    public ExecResultsDto Results() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(MultiExecNative.bastion_multiexec_results_json(H, out var err), err), Json.Info<ExecResultsDto>())
        ?? throw new BastionException("the core returned no results");

    /// <summary><paramref name="format"/> is <c>csv</c> or <c>json</c>.</summary>
    public string Export(string format) => LibraryClient.TakeString(MultiExecNative.bastion_multiexec_export(H, format, out var err), err);

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        var h = _handle;
        _handle = IntPtr.Zero;
        MultiExecNative.bastion_multiexec_free(h);
    }
}
