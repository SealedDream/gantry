using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;

namespace Bastion.Shell.Interop;

/// <summary>One installed plugin (core-cabi plugins.rs). <see cref="Tier"/>: official, external or unverified.</summary>
public sealed record InstalledPluginDto(string Id, string Version, string Tier, string? PreviousVersion);

/// <summary>One update the cached catalogue offers. <see cref="NeedsConsent"/>: the new version asks for more permissions.</summary>
public sealed record PluginUpdateDto(string Id, string From, string To, string Tier, bool NeedsConsent);

/// <summary>The plugin keys of the policy in force (core-cabi pluginbroker.rs). <see cref="AllowedIds"/> null = no list.</summary>
public sealed record PluginPolicyDto(string? Error, bool PluginsDisabled, bool OfficialOnly, List<string>? AllowedIds,
    bool ForbidUnverified, bool StopHelpersOnCredentialsLock, bool ForbidUnencrypted, bool ForbidTlsOff);

/// <summary>P/Invoke for core-cabi plugins.rs (C ABI 120) and pluginbroker.rs. Call off the UI thread: the catalogue
/// refresh reaches the network.</summary>
internal static class PluginNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugins_installed_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_install_file([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int allowUnverified, out IntPtr err);

    /// <summary>Stable code of this thread's last error (C ABI 85); static storage, never freed.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_last_error_code();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_plugin_remove([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, int deleteData, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugins_refresh([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string? mirror, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugins_updates_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_policy_state_json();

    // PLUG-VIEW-CABI (C ABI 137): plugin view sessions, core-cabi pluginview.rs. Open off the UI thread.
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_plugin_host_set_helper_path([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out IntPtr err);

    /// <summary>Returns a view handle or IntPtr.Zero with <paramref name="err"/> set. <paramref name="entryJson"/>: null for no entry.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_view_open([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string pluginId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string viewName, [MarshalAs(UnmanagedType.LPUTF8Str)] string? entryJson, int allowUnverified, int safeMode, out IntPtr err);

    /// <summary>Next update JSON (free with bastion_string_free) or IntPtr.Zero when none came; check <paramref name="err"/> first.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_view_next_update(IntPtr view, uint timeoutMs, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_plugin_view_send_event(IntPtr view, [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_plugin_view_close(IntPtr view);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void bastion_plugin_view_free(IntPtr view);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_may_load([MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string tier, int allowUnverified, int safeMode, out IntPtr err);
}

public static class PluginClient
{
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static List<InstalledPluginDto> Installed(string dataDir) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(PluginNative.bastion_plugins_installed_json(dataDir, out var err), err), Json.Info<List<InstalledPluginDto>>()) ?? [];

    public static List<PluginUpdateDto> Updates(string dataDir) =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(PluginNative.bastion_plugins_updates_json(dataDir, out var err), err), Json.Info<List<PluginUpdateDto>>()) ?? [];

    /// <summary>installed, updated, restored or unchanged.</summary>
    public static string InstallFile(string dataDir, string path, bool allowUnverified) =>
        LibraryClient.TakeString(PluginNative.bastion_plugin_install_file(dataDir, path, allowUnverified ? 1 : 0, out var err), err);

    /// <summary>PLUG-12: installs a package whose signed record lies beside it (<c>name.sig</c>) with no question.
    /// Returns null when the core refuses it only for being unverified (no record): the caller asks the user.</summary>
    public static string? InstallSigned(string dataDir, string path)
    {
        var s = PluginNative.bastion_plugin_install_file(dataDir, path, 0, out var err);
        // Read on this thread, straight after the call.
        if (s == IntPtr.Zero && Marshal.PtrToStringUTF8(PluginNative.bastion_last_error_code()) == "unverified")
        {
            LibraryClient.TakeError(err, "");
            return null;
        }
        return LibraryClient.TakeString(s, err);
    }

    public static void Remove(string dataDir, string id, bool deleteData)
    {
        if (PluginNative.bastion_plugin_remove(dataDir, id, deleteData ? 1 : 0, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "could not remove the plugin"));
    }

    /// <summary>accepted, expired, clock-wrong, refused: … or unreachable: …; nothing changes unless accepted.</summary>
    public static string Refresh(string dataDir, string? mirror) =>
        LibraryClient.TakeString(PluginNative.bastion_plugins_refresh(dataDir, mirror, out var err), err);

    /// <summary>The policy in force. An unreadable answer counts as plugins off (fail closed).</summary>
    public static PluginPolicyDto Policy() =>
        JsonSerializer.Deserialize(LibraryClient.TakeString(PluginNative.bastion_plugin_policy_state_json(), IntPtr.Zero), Json.Info<PluginPolicyDto>())
        ?? new("unreadable", true, false, null, true, true, true, true);

    /// <summary>Null when the plugin may load, else the core's reason.</summary>
    public static string? MayLoad(string id, string tier, bool allowUnverified, bool safeMode)
    {
        var s = PluginNative.bastion_plugin_may_load(id, tier, allowUnverified ? 1 : 0, safeMode ? 1 : 0, out var err);
        if (err != IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "bad plugin argument"));
        return s == IntPtr.Zero ? null : LibraryClient.TakeString(s, IntPtr.Zero);
    }
}

/// <summary>The Plugins page's words (same as Native Mac's PluginsText); no WinUI, so the console test checks them.</summary>
public static class PluginsText
{
    public static string? PolicyBanner(PluginPolicyDto p)
    {
        if (p.Error is { } e) return $"Managed policy unreadable, plugins off: {e}";
        if (p.PluginsDisabled) return "Plugins are turned off by policy";
        if (p.OfficialOnly) return "Policy: Official plugins only";
        if (p.ForbidUnverified) return "Policy: unverified plugins forbidden";
        if (p.AllowedIds is not null) return "Policy: listed plugins only";
        return null;
    }

    public static string Badge(string tier) => tier switch
    {
        "official" => "Official",
        "external" => "External",
        _ => "Unverified",
    };

    public static string Catalogue(string? outcome)
    {
        if (outcome is null) return "Catalogue not checked yet";
        return outcome switch
        {
            "accepted" => "Catalogue up to date",
            "expired" => "Catalogue expired: revocation status unknown",
            "clock-wrong" => "Catalogue checked; this PC's clock looks wrong",
            _ when outcome.StartsWith("unreachable", StringComparison.Ordinal) => "Catalogue unreachable; nothing changed",
            _ when outcome.StartsWith("refused", StringComparison.Ordinal) => "Catalogue refused; nothing changed",
            _ => $"Catalogue: {outcome}",
        };
    }

    public static string Install(string kind, string file) => kind switch
    {
        "installed" => $"Installed {file}",
        "updated" => $"Updated from {file}",
        "restored" => "Restored the previous version",
        "unchanged" => "Already installed",
        _ => $"{kind}: {file}",
    };

    /// <summary>A file install carries no signed record, so it is Unverified: policy may refuse it outright.</summary>
    public static bool FileInstallForbidden(PluginPolicyDto p) => p.PluginsDisabled || p.OfficialOnly || p.ForbidUnverified;

    public static string UpdateNote(PluginUpdateDto u) => u.NeedsConsent ? "Asks for new permissions" : "";
}

/// <summary>PLUG-VIEW-WIN: one open plugin view session over C ABI 137. One reader thread owns the handle: it polls
/// <c>next_update</c> and frees the handle when it stops, so a free never races a poll. <see cref="Close"/> and
/// <see cref="Send"/> may come from any thread; after the free they are no-ops.</summary>
public sealed class PluginViewSession
{
    public const uint PollMs = 250;
    private static readonly object HelperLock = new();
    private static bool _helperSet;
    private readonly object _lock = new();
    private IntPtr _view;
    private volatile bool _closing;

    private PluginViewSession(IntPtr view) => _view = view;

    /// <summary>Hands the core the helper beside Bastion.exe, once, just before the first plugin opens.</summary>
    public static void EnsureHelper(string path)
    {
        lock (HelperLock)
        {
            if (_helperSet) return;
            if (PluginNative.bastion_plugin_host_set_helper_path(path, out var err) != 0)
                throw new BastionException(LibraryClient.TakeError(err, "plugin helper refused"));
            _helperSet = true;
        }
    }

    /// <summary>Opens a view (a cold open compiles the plugin): call off the UI thread.</summary>
    public static PluginViewSession Open(string dataDir, string pluginId, string viewName, string? entryJson, bool allowUnverified, bool safeMode)
    {
        var h = PluginNative.bastion_plugin_view_open(dataDir, pluginId, viewName, entryJson, allowUnverified ? 1 : 0, safeMode ? 1 : 0, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "plugin view not opened"));
        return new PluginViewSession(h);
    }

    /// <summary>PLUG-08-WIN: opens the view of the plugin that owns entry <paramref name="connectionId"/>'s type, on that
    /// entry. With <paramref name="vault"/> open the core reads the entry's login itself; it never reaches the app.
    /// Call off the UI thread.</summary>
    /// <paramref name="routeKind"/>: 0 direct, 1 a loopback forward on <paramref name="port"/> whose SSH server reaches
    /// <paramref name="target"/>, 2 a loopback SOCKS proxy on <paramref name="port"/>.
    public static PluginViewSession OpenEntry(IntPtr library, IntPtr vault, string connectionId, string dataDir, bool allowUnverified,
        int routeKind = 0, ushort port = 0, string? target = null)
    {
        var h = PluginEntriesNative.bastion_plugin_entry_view_open(library, vault, connectionId, dataDir, allowUnverified ? 1 : 0, 0, routeKind, port, target, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "plugin view not opened"));
        return new PluginViewSession(h);
    }

    /// <summary>PLUG-API-13: as <see cref="OpenEntry"/>, for the entry's tree in the library (the view <c>sidebar</c>).
    /// Direct route only: a gateway entry's tree waits for the entry's own Connect. Call off the UI thread.</summary>
    public static PluginViewSession OpenSidebar(IntPtr library, IntPtr vault, string connectionId, string dataDir, bool allowUnverified)
    {
        var h = PluginEntriesNative.bastion_plugin_entry_sidebar_open(library, vault, connectionId, dataDir, allowUnverified ? 1 : 0, 0, 0, 0, null, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "plugin tree not opened"));
        return new PluginViewSession(h);
    }

    /// <summary>Reads updates on a background thread until <c>ended</c> or <see cref="Close"/>, then frees the handle.
    /// <paramref name="onUpdate"/> runs on that thread; it returns true to stop.</summary>
    public void StartReading(Func<string, bool> onUpdate) => new Thread(() =>
    {
        try
        {
            while (!_closing)
            {
                var s = PluginNative.bastion_plugin_view_next_update(_view, PollMs, out var err);
                if (err != IntPtr.Zero) { onUpdate("""{"type":"ended","reason":"crash"}"""); LibraryClient.TakeError(err, ""); break; }
                if (s == IntPtr.Zero) continue;
                if (onUpdate(LibraryClient.TakeString(s, IntPtr.Zero))) break;
            }
        }
        finally { Free(); }
    }) { IsBackground = true, Name = "plugin-view" }.Start();

    /// <summary>Sends one event (JSON). Throws <see cref="BastionException"/> when the core refuses it.</summary>
    public void Send(string json)
    {
        lock (_lock)
        {
            if (_view == IntPtr.Zero) return;
            if (PluginNative.bastion_plugin_view_send_event(_view, json, out var err) != 0)
                throw new BastionException(LibraryClient.TakeError(err, "event refused"));
        }
    }

    /// <summary>Stops the plugin (its helper gets 2 s); the reader then frees the handle.</summary>
    public void Close()
    {
        _closing = true;
        lock (_lock) { if (_view != IntPtr.Zero) PluginNative.bastion_plugin_view_close(_view); }
    }

    /// <summary>Frees a session whose reader never started (the tab closed during a cold open).</summary>
    public void Free()
    {
        lock (_lock)
        {
            if (_view == IntPtr.Zero) return;
            PluginNative.bastion_plugin_view_free(_view);
            _view = IntPtr.Zero;
        }
    }
}
