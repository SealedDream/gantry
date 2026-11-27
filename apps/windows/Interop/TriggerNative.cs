using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

/// <summary>Highlight colours are 0xRRGGBB numbers.</summary>
public sealed record TriggerHighlightDto(uint? Fg = null, uint? Bg = null, bool? Bold = null);

/// <summary>A trigger rule. Leave <see cref="Id"/> null to add a new one.</summary>
public sealed record TriggerDto(
    string? Id, string Name, string Pattern,
    bool CaseInsensitive = false, bool Enabled = true, TriggerHighlightDto? Highlight = null, bool Notify = false);

/// <summary>A notification raised by a trigger in a terminal.</summary>
public sealed record TriggerEventDto(string TriggerId, string Name, string Line);

internal static class TriggerNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_triggers_list_json([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_triggers_save_json([MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string triggerJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_triggers_remove([MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_triggers_export_json([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_triggers_import_json([MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_terminal_set_triggers(IntPtr terminal, [MarshalAs(UnmanagedType.LPUTF8Str)] string? path, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_terminal_take_trigger_events_json(IntPtr terminal, out IntPtr err);
}

/// <summary>Per-user triggers in <c>triggers.json</c> (C ABI 69), shared with the Mac and Tauri apps.</summary>
public sealed class TriggerStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        TypeInfoResolver = AotJson.Resolver,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Path of <c>triggers.json</c>.</summary>
    public string Path { get; }

    public TriggerStore(string path) => Path = path;

    public IReadOnlyList<TriggerDto> List() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(TriggerNative.bastion_triggers_list_json(Path, out var err), err), Json.Info<List<TriggerDto>>()) ?? [];

    /// <summary>Adds or replaces a trigger; returns its id. A bad pattern is refused by the core.</summary>
    public string Save(TriggerDto trigger) =>
        LibraryClient.TakeString(TriggerNative.bastion_triggers_save_json(Path, AotJson.Write<TriggerDto>(trigger, Json), out var err), err);

    public void Remove(string id)
    {
        if (TriggerNative.bastion_triggers_remove(Path, id, out var err) != 0) throw new BastionException(LibraryClient.TakeError(err, "could not remove the trigger"));
    }

    public string Export() => LibraryClient.TakeString(TriggerNative.bastion_triggers_export_json(Path, out var err), err);

    /// <summary>Imports an exported file, all or nothing. Returns how many triggers it held.</summary>
    public int Import(string json)
    {
        var n = TriggerNative.bastion_triggers_import_json(Path, json, out var err);
        if (n < 0) throw new BastionException(LibraryClient.TakeError(err, "could not import the triggers"));
        return n;
    }

    /// <summary>Applies the enabled triggers to a terminal (call again after edits); null store turns them off.</summary>
    public static void Apply(TerminalSession terminal, TriggerStore? store)
    {
        if (TriggerNative.bastion_terminal_set_triggers(terminal.NativeHandle, store?.Path, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not apply the triggers"));
    }

    /// <summary>Notifications raised in the terminal since the last call.</summary>
    public static IReadOnlyList<TriggerEventDto> TakeEvents(TerminalSession terminal) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(TriggerNative.bastion_terminal_take_trigger_events_json(terminal.NativeHandle, out var err), err), Json.Info<List<TriggerEventDto>>()) ?? [];
}
