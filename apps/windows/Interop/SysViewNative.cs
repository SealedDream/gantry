using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

public sealed record SysServiceDto(string Name, string Description, string State, string Sub, string StartType);

public sealed record SysProcessDto(uint Pid, string User, double? CpuPercent, double? CpuSeconds, ulong MemBytes, string Name);

public sealed record SysEventDto(string Cursor, string Time, string Level, string Source, string Message);

public sealed record SysViewInfoDto(string Os, string View);

/// <summary>P/Invoke for core-cabi/src/sysview.rs (ABI 93, owner point 11).</summary>
internal static class SysViewNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_sysview_open(IntPtr m, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? view, [MarshalAs(UnmanagedType.LPUTF8Str)] string? username, int loginKind, IntPtr password,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? keyPath, [MarshalAs(UnmanagedType.LPUTF8Str)] string? trustFingerprint,
        out int outcome, out IntPtr fingerprint, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_sysview_info_json(IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_sysview_services_json(IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_sysview_processes_json(IntPtr v, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_sysview_tail_json(IntPtr v, [MarshalAs(UnmanagedType.LPUTF8Str)] string? filterJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_sysview_close(IntPtr v);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_sysview_free(IntPtr v);
}

/// <summary>Result of <see cref="SysViewClient.Open"/>: the view, or why not (with the fingerprint to verify for an unknown host key).</summary>
public sealed record SysViewOpenResult(SysViewClient? View, ConnectOutcome Outcome, string? Fingerprint, string? Error);

/// <summary>One open Services, Processes or Event Log view over SSH. Every call blocks on the network: call it off the UI thread.</summary>
public sealed partial class SysViewClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };
    private IntPtr _handle;

    private SysViewClient(IntPtr handle) => _handle = handle;

    private IntPtr H => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(SysViewClient));

    /// <summary>Open <paramref name="view"/> (services, processes, eventlog) on a connection; <paramref name="secret"/> is copied and zeroed.</summary>
    public static SysViewOpenResult Open(SessionManagerClient sessions, LibraryClient library, string connectionId, string view,
        string? username, SshLoginKind kind, string? secret, string? keyPath, string? trustFingerprint)
    {
        using var password = new Utf8Secret(secret);
        var h = SysViewNative.bastion_sysview_open(sessions.NativeHandle, library.NativeHandle, connectionId, view,
            string.IsNullOrWhiteSpace(username) ? null : username, (int)kind, password.Pointer,
            string.IsNullOrWhiteSpace(keyPath) ? null : keyPath, trustFingerprint, out var outcome, out var fp, out var err);
        var fingerprint = fp == IntPtr.Zero ? null : LibraryClient.TakeString(fp, IntPtr.Zero);
        if (h != IntPtr.Zero) return new SysViewOpenResult(new SysViewClient(h), ConnectOutcome.Ok, null, null);
        var error = LibraryClient.TakeError(err, "could not open the view");
        return new SysViewOpenResult(null, (ConnectOutcome)outcome, fingerprint, error);
    }

    private T Read<T>(IntPtr s, IntPtr err) => JsonSerializer.Deserialize(LibraryClient.TakeString(s, err), Json.Info<T>()) ?? throw new BastionException("the core returned no rows");

    public SysViewInfoDto Info() => Read<SysViewInfoDto>(SysViewNative.bastion_sysview_info_json(H, out var err), err);
    public List<SysServiceDto> Services() => Read<List<SysServiceDto>>(SysViewNative.bastion_sysview_services_json(H, out var err), err);
    public List<SysProcessDto> Processes() => Read<List<SysProcessDto>>(SysViewNative.bastion_sysview_processes_json(H, out var err), err);

    /// <summary>Events new since the last call with the same filter (Windows: <paramref name="log"/> System, Application, Setup, Security).</summary>
    public List<SysEventDto> Tail(string? log, string? unit) =>
        Read<List<SysEventDto>>(SysViewNative.bastion_sysview_tail_json(H, AotJson.Write<Dictionary<string, string?>>(new() { ["log"] = log, ["unit"] = unit }, AotJson.Options), out var err), err);

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        var h = _handle;
        _handle = IntPtr.Zero;
        SysViewNative.bastion_sysview_close(h);
        SysViewNative.bastion_sysview_free(h);
    }
}
