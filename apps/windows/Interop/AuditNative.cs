using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

/// <summary>One audit record (core `audit::AuditEvent`, snake_case JSON). Details were redacted when written.</summary>
public sealed record AuditRecordDto(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("ts_unix_ms")] long TsUnixMs,
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("target")] string? Target,
    [property: JsonPropertyName("outcome")] string Outcome,
    [property: JsonPropertyName("details")] Dictionary<string, string>? Details);

public sealed record AuditPageDto(int Total, List<AuditRecordDto> Records);

/// <summary>The hash chain: intact, or the first record (1-based) that does not follow from the one before it.</summary>
public sealed record AuditCheckDto(bool Intact, int Records, int? ChangedAt);

/// <summary>P/Invoke for core-cabi/src/audit_view.rs (C ABI 123). Read-only. Call off the UI thread.</summary>
internal static class AuditNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_audit_read_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, uint offset, uint limit, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_audit_verify_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);
}

public static class AuditClient
{
    public const int PageSize = 500;
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static AuditPageDto Read(string dataDir, int offset, int limit = PageSize) =>
        ParsePage(LibraryClient.TakeString(AuditNative.bastion_audit_read_json(dataDir, (uint)Math.Max(0, offset), (uint)Math.Clamp(limit, 1, PageSize), out var err), err));

    public static AuditCheckDto Verify(string dataDir) =>
        ParseCheck(LibraryClient.TakeString(AuditNative.bastion_audit_verify_json(dataDir, out var err), err));

    public static AuditPageDto ParsePage(string json) => JsonSerializer.Deserialize(json, Json.Info<AuditPageDto>()) ?? new(0, []);
    public static AuditCheckDto ParseCheck(string json) => JsonSerializer.Deserialize(json, Json.Info<AuditCheckDto>()) ?? new(false, 0, null);
}

/// <summary>The Audit log page's words; no WinUI here, so the console test checks them.</summary>
public static class AuditFormat
{
    /// <summary>"Log intact", "Changed at record N", or "No records".</summary>
    public static string Status(AuditCheckDto c) =>
        c.ChangedAt is { } n ? $"Changed at record {n}" : c.Records == 0 ? "No records" : "Log intact";

    /// <summary>"credential_access" → "Credential access".</summary>
    public static string Category(string c) => c.Length == 0 ? c : char.ToUpperInvariant(c[0]) + c[1..].Replace('_', ' ');

    /// <summary>"success" → "Success".</summary>
    public static string Outcome(string o) => o.Length == 0 ? o : char.ToUpperInvariant(o[0]) + o[1..];

    /// <summary>"key=value, key=value" in key order; empty when there are none.</summary>
    public static string Details(IReadOnlyDictionary<string, string>? d) =>
        d is null || d.Count == 0 ? "" : string.Join(", ", d.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"{p.Key}={p.Value}"));

    public static string Time(long ms) =>
        DateTimeOffset.FromUnixTimeMilliseconds(ms).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    /// <summary>The free-text filter over action, target, category and details, ignoring case.</summary>
    public static bool Matches(AuditRecordDto r, string text) =>
        text.Length == 0
        || r.Action.Contains(text, StringComparison.CurrentCultureIgnoreCase)
        || (r.Target?.Contains(text, StringComparison.CurrentCultureIgnoreCase) ?? false)
        || r.Category.Replace('_', ' ').Contains(text, StringComparison.CurrentCultureIgnoreCase)
        || Details(r.Details).Contains(text, StringComparison.CurrentCultureIgnoreCase);
}
