using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>One terminal colour theme from the core store (core-cabi <c>bastion_termthemes_list_json</c>).</summary>
public sealed record TermThemeDto(string Id, string Name, bool Bundled, string? Source, string? License,
    string Foreground, string Background, List<string> Ansi, double Contrast);

/// <summary>UI-06 window tones as "#rrggbb" (core-cabi <c>bastion_termtheme_window_tones</c>).</summary>
public sealed record WindowTonesDto(string ActiveTab, string TabStrip, string Toolbar, string Sidebar, string Separator,
    string Text, string SecondaryText, bool IsDark, bool AccentUsable);

/// <summary>The core's terminal theme store: the 13 bundled themes plus the user's own (ABI 88).</summary>
public static class TermThemes
{
    private static readonly JsonSerializerOptions Camel = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true };

    [DllImport(TerminalNative.Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_termthemes_list_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, out IntPtr err);
    [DllImport(TerminalNative.Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_termthemes_duplicate([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string source, out IntPtr err);
    [DllImport(TerminalNative.Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_termthemes_put([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);
    [DllImport(TerminalNative.Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern int bastion_termthemes_remove([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(TerminalNative.Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_termtheme_window_tones(uint background, uint foreground, uint accent, int increasedContrast);

    /// <summary>UI-06 (ABI 143): window colours derived from a terminal theme; never fails.</summary>
    public static WindowTonesDto WindowTones(uint background, uint foreground, uint accent) =>
        JsonSerializer.Deserialize(Take(bastion_termtheme_window_tones(background, foreground, accent, 0), IntPtr.Zero), Camel.Info<WindowTonesDto>())
        ?? throw new BastionException("the core returned no window tones");

    /// <summary>The folder holding the custom themes file; set once at start-up (the library's folder).</summary>
    public static string? DataDir { get; set; }

    private static string Dir => DataDir ?? throw new BastionException("the theme folder is not set");

    public static List<TermThemeDto> List() =>
        JsonSerializer.Deserialize(Take(bastion_termthemes_list_json(Dir, out var err), err), Camel.Info<List<TermThemeDto>>()) ?? [];

    public static TermThemeDto Duplicate(string sourceId) =>
        JsonSerializer.Deserialize(Take(bastion_termthemes_duplicate(Dir, sourceId, out var err), err), Camel.Info<TermThemeDto>())
        ?? throw new BastionException("the core returned no theme");

    /// <summary>Save an edited custom theme; returns the contrast warning, or null when the colours read well.</summary>
    public static string? Put(TermThemeDto theme)
    {
        var json = new System.Text.Json.Nodes.JsonObject
        {
            ["id"] = theme.Id, ["name"] = theme.Name, ["foreground"] = theme.Foreground, ["background"] = theme.Background,
            ["ansi"] = new System.Text.Json.Nodes.JsonArray(theme.Ansi.Select(c => (System.Text.Json.Nodes.JsonNode?)c).ToArray()),
        }.ToJsonString();
        using var doc = JsonDocument.Parse(Take(bastion_termthemes_put(Dir, json, out var err), err));
        return doc.RootElement.TryGetProperty("warning", out var w) && w.ValueKind == JsonValueKind.String ? w.GetString() : null;
    }

    public static void Remove(string id)
    {
        if (bastion_termthemes_remove(Dir, id, out var err) != 0) throw new BastionException(TakeErr(err));
    }

    private static string Take(IntPtr s, IntPtr err)
    {
        if (s == IntPtr.Zero) throw new BastionException(TakeErr(err));
        try { return Marshal.PtrToStringUTF8(s) ?? ""; }
        finally { Native.bastion_string_free(s); }
    }

    private static string TakeErr(IntPtr err)
    {
        if (err == IntPtr.Zero) return "the theme store failed";
        try { return Marshal.PtrToStringUTF8(err) ?? "the theme store failed"; }
        finally { Native.bastion_string_free(err); }
    }
}
