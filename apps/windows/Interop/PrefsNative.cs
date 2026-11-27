using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

public sealed record SettingCategoryDto(string Id, string Label, string Icon);

public sealed record SettingOptionDto(string Id, string Label);

/// <summary>One setting from the core registry (core/src/settings.rs): <c>choice</c>, <c>toggle</c>, <c>integer</c> or <c>link</c>.</summary>
public sealed record SettingDefDto(string Id, string Category, string Label, string Help, string Kind, List<SettingOptionDto> Options,
    long Min, long Max, string Unit, string Default, string? Link);

/// <summary>A command with its chord on this platform; chords are neutral (<c>primary+shift+p</c>), null = none.</summary>
public sealed record ShortcutDto(string Id, string Label, string Group, string GroupLabel, string? Chord, string? DefaultChord, bool IsDefault);

/// <summary>Who already holds a chord: another command (<see cref="CommandId"/> set) or the system (null: refused).</summary>
public sealed record ShortcutConflictDto(string? CommandId, string Label);

/// <summary>A command-palette row as the core ranks it; <c>kind</c> as core/src/palette.rs.</summary>
public sealed record PaletteEntryDto(string Kind, string Title, string Detail = "", string Keywords = "");

/// <summary>P/Invoke for core-cabi/src/prefs.rs and the other ABI 16 entry points.</summary>
internal static class PrefsNative
{
    private const string L = "bastion_cabi";

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_setting_categories_json([MarshalAs(UnmanagedType.LPUTF8Str)] string? links, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_setting_definitions_json([MarshalAs(UnmanagedType.LPUTF8Str)] string? links, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_settings_search_json([MarshalAs(UnmanagedType.LPUTF8Str)] string query, [MarshalAs(UnmanagedType.LPUTF8Str)] string? links, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_settings_auto_lock_due([MarshalAs(UnmanagedType.LPUTF8Str)] string? value, ulong idleSecs);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_settings_open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_settings_free(IntPtr s);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_settings_get(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_settings_set(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string value, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_shortcuts_open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_shortcuts_free(IntPtr s);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_shortcuts_list_json(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string platform, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_shortcuts_conflict_json(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string id,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string chord, [MarshalAs(UnmanagedType.LPUTF8Str)] string platform, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_shortcuts_set(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string? chord,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string platform, int replace, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_shortcuts_reset(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string? id, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_shortcuts_shadowed_json(IntPtr s, [MarshalAs(UnmanagedType.LPUTF8Str)] string platform, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_shortcuts_search_json([MarshalAs(UnmanagedType.LPUTF8Str)] string query, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_palette_new([MarshalAs(UnmanagedType.LPUTF8Str)] string entries, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_palette_free(IntPtr p);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_palette_rank_json(IntPtr p, [MarshalAs(UnmanagedType.LPUTF8Str)] string query, uint limit, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_quick_connect([MarshalAs(UnmanagedType.LPUTF8Str)] string target, out IntPtr err);

    internal static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    internal static T Read<T>(IntPtr s, IntPtr err) where T : new() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(s, err), Json.Info<T>()) ?? new T();
}

/// <summary>The settings registry and <c>settings.json</c> (core/src/settings.rs), the same file and rules as macOS.</summary>
public sealed partial class SettingsClient : IDisposable
{
    private IntPtr _handle;

    /// <summary>Link targets this app opens; settings that link elsewhere are hidden by the core.</summary>
    public static readonly string[] HandledLinks = ["credential-manager", "vaultwarden", "workspace-manager", "keyboard-shortcuts", "lock-credentials", "ssh-import", "defaults:ssh", "defaults:rdp", "defaults:vnc", "defaults:web", "window-current-size",
        // Capabilities: Settings › General › Window at launch (MainWindow.WindowLaunch.cs).
        "window-launch",
        // Capabilities: settings only this frontend honours.
        "terminal-font-family", "terminal-ligatures", "terminal-bell", "terminal-program-notifications", "terminal-copy-on-select", "terminal-confirm-close", "terminal-session-bar",
        "terminal-cursor-style", "terminal-scrollback", "ui-zoom", "vertical-tabs", "tab-previews", "terminal-new-tab",
        // UI-06: window colours follow the terminal theme (MainWindow.WindowTones.cs).
        "window-tones",
        // LOG-ERRCODES: Detailed logging (MainWindow.DetailedLog.cs).
        "detailed-log",
        // The Windows Hello vault gate (MainWindow.Hello.cs). No "touch-id-library-unlock": that is macOS only.
        "vault-open-confirm",
        // Settings › Security › Allow Telnet, confirmed once when turned on (B7, MainWindow.TelnetSerial.cs).
        "allow-telnet",
        // SecretClipboard clears a copied password after this setting's time (A3-S1).
        SecretClipboardLifetime.Capability,
        // Remembered logins expire after this many minutes (SEC-03, LoginReuseTimes).
        LoginReuseTimes.Capability,
        // Session log folder, time stamps, retention and redaction (LOG-CORE-02, MainWindow.SessionLog.cs).
        SessionLogV2.Capability,
        // Delete goes to Recently Deleted for this long (B10, MainWindow.RecentlyDeleted.cs).
        "restore-deleted"];

    private static string Links => AotJson.Write<string[]>(HandledLinks, AotJson.Options);

    private SettingsClient(IntPtr handle) => _handle = handle;

    public static SettingsClient Open(string path)
    {
        var h = PrefsNative.bastion_settings_open(path, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "could not read the settings"));
        return new SettingsClient(h);
    }

    private IntPtr Handle => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(SettingsClient));
    /// <summary>The raw handle, for interop calls that read a setting in the core (Allow Telnet, B7).</summary>
    internal IntPtr NativeHandle => Handle;

    public static List<SettingCategoryDto> Categories() => PrefsNative.Read<List<SettingCategoryDto>>(PrefsNative.bastion_setting_categories_json(Links, out var err), err);

    public static List<SettingDefDto> Definitions() => PrefsNative.Read<List<SettingDefDto>>(PrefsNative.bastion_setting_definitions_json(Links, out var err), err);

    /// <summary>Ids of the settings matching <paramref name="query"/>, best first.</summary>
    public static List<string> Search(string query) => PrefsNative.Read<List<string>>(PrefsNative.bastion_settings_search_json(query, Links, out var err), err);

    public static bool AutoLockDue(string value, TimeSpan idle) => PrefsNative.bastion_settings_auto_lock_due(value, (ulong)Math.Max(0, idle.TotalSeconds)) == 1;

    public string Get(string id) => LibraryClient.TakeString(PrefsNative.bastion_settings_get(Handle, id, out var err), err);

    /// <summary>Validated by the core; an invalid value throws and nothing is written.</summary>
    public void Set(string id, string value) => LibraryClient.Check(PrefsNative.bastion_settings_set(Handle, id, value, out var err), err, "could not save the setting");

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        PrefsNative.bastion_settings_free(_handle);
        _handle = IntPtr.Zero;
    }
}

/// <summary>Configurable shortcuts (core/src/shortcuts.rs, <c>shortcuts.json</c>), read for the <c>windows</c> platform.</summary>
public sealed partial class ShortcutsClient : IDisposable
{
    public const string Platform = "windows";
    private IntPtr _handle;

    private ShortcutsClient(IntPtr handle) => _handle = handle;

    public static ShortcutsClient Open(string path)
    {
        var h = PrefsNative.bastion_shortcuts_open(path, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "could not read the keyboard shortcuts"));
        return new ShortcutsClient(h);
    }

    private IntPtr Handle => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(ShortcutsClient));

    public List<ShortcutDto> List() => PrefsNative.Read<List<ShortcutDto>>(PrefsNative.bastion_shortcuts_list_json(Handle, Platform, out var err), err);

    /// <summary>Null when <paramref name="chord"/> is free for <paramref name="id"/>. Throws for a chord that does not parse.</summary>
    public ShortcutConflictDto? Conflict(string id, string chord)
    {
        var json = LibraryClient.TakeString(PrefsNative.bastion_shortcuts_conflict_json(Handle, id, chord, Platform, out var err), err);
        return JsonSerializer.Deserialize(json, PrefsNative.Json.Info<ShortcutConflictDto?>());
    }

    /// <summary>Give <paramref name="id"/> the chord (null = none); <paramref name="replace"/> takes it from another command.</summary>
    public void Set(string id, string? chord, bool replace) =>
        LibraryClient.Check(PrefsNative.bastion_shortcuts_set(Handle, id, chord, Platform, replace ? 1 : 0, out var err), err, "could not change the shortcut");

    /// <summary>Restore one command's default, or every command's (<paramref name="id"/> null).</summary>
    public void Reset(string? id) => LibraryClient.Check(PrefsNative.bastion_shortcuts_reset(Handle, id, out var err), err, "could not restore the shortcut");

    public List<string> Shadowed() => PrefsNative.Read<List<string>>(PrefsNative.bastion_shortcuts_shadowed_json(Handle, Platform, out var err), err);

    public static List<string> Search(string query) => PrefsNative.Read<List<string>>(PrefsNative.bastion_shortcuts_search_json(query, out var err), err);

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        PrefsNative.bastion_shortcuts_free(_handle);
        _handle = IntPtr.Zero;
    }
}

/// <summary>The command palette's index, ranked by the core (core/src/palette.rs). Built once per opening.</summary>
public sealed partial class PaletteRanker : IDisposable
{
    private IntPtr _handle;

    public PaletteRanker(IReadOnlyList<PaletteEntryDto> entries)
    {
        _handle = PrefsNative.bastion_palette_new(AotJson.Write<IReadOnlyList<PaletteEntryDto>>(entries, PrefsNative.Json), out var err);
        if (_handle == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "could not index the palette"));
    }

    /// <summary>Indexes into the entries, best first.</summary>
    public List<int> Rank(string query, int limit)
    {
        if (_handle == IntPtr.Zero) throw new ObjectDisposedException(nameof(PaletteRanker));
        return PrefsNative.Read<List<int>>(PrefsNative.bastion_palette_rank_json(_handle, query, (uint)limit, out var err), err);
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        PrefsNative.bastion_palette_free(_handle);
        _handle = IntPtr.Zero;
    }
}
