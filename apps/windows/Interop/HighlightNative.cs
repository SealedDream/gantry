using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>One coloured span of a line. Offsets are UTF-16 units from the line's start (as a .NET string counts).
/// <see cref="Kind"/>: keyword, identifier, quoted-identifier, string, number, comment, operator, punctuation,
/// parameter, type, function, text, error.</summary>
public readonly record struct HighlightToken(string Kind, int Start, int Length);

/// <summary>A line's tokens and the state the next line starts from (an opaque, comparable string; "" = normal).</summary>
public sealed record HighlightLine(IReadOnlyList<HighlightToken> Tokens, string EndState);

/// <summary>Whether to ask a plugin for completions at the cursor, the prefix being typed, and the UTF-16 range a
/// chosen item replaces. <see cref="CharOffset"/> is the cursor in characters, the offset a plugin is sent.</summary>
public sealed record CompletionContext(bool Ask, string Prefix, int ReplaceStart, int ReplaceLength, long CharOffset);

/// <summary>One completion item, as a plugin's provide-completions answer carries it (after the core's checks).</summary>
public sealed record CompletionItemDto(string Label, string Insert, string Detail);

/// <summary>P/Invoke for core-cabi highlight.rs (PLUG-06c, C ABI 136). Pure functions over text: no disk, no network,
/// safe to call on the UI thread for one line.</summary>
internal static class HighlightNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_highlight_line_json([MarshalAs(UnmanagedType.LPUTF8Str)] string language, [MarshalAs(UnmanagedType.LPUTF8Str)] string line, [MarshalAs(UnmanagedType.LPUTF8Str)] string? state, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_highlight_text_json([MarshalAs(UnmanagedType.LPUTF8Str)] string language, [MarshalAs(UnmanagedType.LPUTF8Str)] string text, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_completion_context_json([MarshalAs(UnmanagedType.LPUTF8Str)] string language, [MarshalAs(UnmanagedType.LPUTF8Str)] string text, ulong cursorUtf16, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_completions_rank_json([MarshalAs(UnmanagedType.LPUTF8Str)] string itemsJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string prefix, out IntPtr err);
}

/// <summary>The code editor's calls into the core. JSON is read with JsonDocument (no reflection, AOT safe).</summary>
public static class HighlightClient
{
    /// <summary>One line (no line break) after the line whose end state is <paramref name="state"/>.</summary>
    public static HighlightLine Line(string language, string line, string state) =>
        Spans(LibraryClient.TakeString(HighlightNative.bastion_highlight_line_json(language, StripNul(line), state, out var err), err));

    /// <summary>A whole text, offsets from its start. For tests and small inputs.</summary>
    public static HighlightLine Text(string language, string text) =>
        Spans(LibraryClient.TakeString(HighlightNative.bastion_highlight_text_json(language, StripNul(text), out var err), err));

    public static CompletionContext Context(string language, string text, int cursor)
    {
        // A NUL would end the C string early; it is replaced one for one so the cursor still lines up.
        var json = LibraryClient.TakeString(HighlightNative.bastion_completion_context_json(language, StripNul(text), (ulong)Math.Max(0, cursor), out var err), err);
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        return new(r.GetProperty("ask").GetBoolean(), r.GetProperty("prefix").GetString() ?? "",
            r.GetProperty("replaceUtf16Start").GetInt32(), r.GetProperty("replaceUtf16Len").GetInt32(), r.GetProperty("charOffset").GetInt64());
    }

    /// <summary>The core's filter and order (the same in every app), at most 200.</summary>
    public static IReadOnlyList<CompletionItemDto> Rank(IEnumerable<CompletionItemDto> items, string prefix)
    {
        var buffer = new System.IO.MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartArray();
            foreach (var i in items)
            {
                w.WriteStartObject();
                w.WriteString("label", i.Label);
                w.WriteString("insert", i.Insert);
                w.WriteString("detail", i.Detail);
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }
        var json = LibraryClient.TakeString(HighlightNative.bastion_completions_rank_json(System.Text.Encoding.UTF8.GetString(buffer.ToArray()), StripNul(prefix), out var err), err);
        using var doc = JsonDocument.Parse(json);
        var list = new List<CompletionItemDto>();
        foreach (var e in doc.RootElement.EnumerateArray())
            list.Add(new(Str(e, "label"), Str(e, "insert"), Str(e, "detail")));
        return list;
    }

    private static string StripNul(string s) => s.Contains('\0') ? s.Replace('\0', ' ') : s;

    private static string Str(JsonElement e, string key) => e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static HighlightLine Spans(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        var tokens = new List<HighlightToken>();
        foreach (var t in r.GetProperty("tokens").EnumerateArray())
            tokens.Add(new(t.GetProperty("kind").GetString() ?? "text", t.GetProperty("utf16Start").GetInt32(), t.GetProperty("utf16Len").GetInt32()));
        return new(tokens, r.GetProperty("endState").GetString() ?? "");
    }
}
