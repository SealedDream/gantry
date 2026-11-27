using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;

namespace Bastion.Shell.Interop;

/// <summary>One installed plugin's connection type. <see cref="Id"/> is <c>&lt;plugin id&gt;/&lt;type id&gt;</c>, the
/// entry's stored protocol. <see cref="Tier"/>: Official, External or Unverified.</summary>
public sealed record PluginTypeDto(string Id, string PluginId, string PluginName, string Tier, string Name, int? DefaultPort, bool SidebarTree = false);


/// <summary>A plugin entry's TLS rule: <c>verify-full</c> or <c>pinned</c> with the SHA-256 pin.</summary>
public sealed record PluginEntryTlsDto(string Mode, string? PinSha256, bool Damaged = false);

/// <summary>PLUG-08-WIN (C ABI 139): plugin entries, core-cabi pluginentries.rs. The login of an entry is read from the
/// vault inside the core and never reaches the app.</summary>
internal static class PluginEntriesNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_connection_types_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_add_plugin_connection(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string? parent,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string name, [MarshalAs(UnmanagedType.LPUTF8Str)] string host, [MarshalAs(UnmanagedType.LPUTF8Str)] string typeId, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_plugin_entry_tls_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_plugin_entry_tls(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string mode,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? pinSha256, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_certificate_probe([MarshalAs(UnmanagedType.LPUTF8Str)] string host, ushort port, out IntPtr err);

    /// <summary>PVE-TLS (ABI 142): 0 = the handshake passed the entry's rule.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_plugin_certificate_check([MarshalAs(UnmanagedType.LPUTF8Str)] string host, ushort port, [MarshalAs(UnmanagedType.LPUTF8Str)] string? pinSha256, out IntPtr err);

    /// <summary>ABI 141: the entry's plugin fields with their values.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_plugin_entry_fields_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_plugin_field(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, [MarshalAs(UnmanagedType.LPUTF8Str)] string id,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string key, [MarshalAs(UnmanagedType.LPUTF8Str)] string? value, out IntPtr err);

    /// <summary>The entry's gateway id, or IntPtr.Zero when it goes direct (check <paramref name="err"/>).</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_plugin_entry_gateway(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    /// <summary>Returns a view handle (free with bastion_plugin_view_free) or IntPtr.Zero with <paramref name="err"/> set.
    /// <paramref name="vault"/>: IntPtr.Zero when the vault is not open (the view opens with no login).
    /// <paramref name="routeKind"/>: 0 direct, 1 loopback forward on <paramref name="port"/> to <paramref name="target"/>, 2 SOCKS.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_entry_view_open(IntPtr lib, IntPtr vault, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, int allowUnverified, int safeMode, int routeKind, ushort port,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? target, out IntPtr err);

    /// <summary>PVE-AUTH: Test Connection's login step: the plugin's own calls with the entry's login. JSON
    /// <c>{ok, message}</c>; free it. Blocks up to 45 s.</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_entry_test_json(IntPtr lib, IntPtr vault, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, int allowUnverified, int routeKind, ushort port,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? target, out IntPtr err);

    // Plugin API 1.3 (C ABI 141), core-cabi pluginentries.rs.
    /// <summary>As <see cref="bastion_plugin_entry_view_open"/>, for the entry's tree in the library (view <c>sidebar</c>).</summary>
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_entry_sidebar_open(IntPtr lib, IntPtr vault, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir, int allowUnverified, int safeMode, int routeKind, ushort port,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? target, out IntPtr err);

    // PLUG-OPEN-WIN (C ABI 140), core-cabi pluginopen.rs.
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_plugin_open_resolve_json([MarshalAs(UnmanagedType.LPUTF8Str)] string host, ushort port, [MarshalAs(UnmanagedType.U1)] bool loopbackOk, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_plugin_open_library(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string entryId, [MarshalAs(UnmanagedType.LPUTF8Str)] string protocol,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string host, ushort port, [MarshalAs(UnmanagedType.LPUTF8Str)] string label, [MarshalAs(UnmanagedType.U1)] bool viaEntryRoute, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_plugin_open_save(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string entryId, [MarshalAs(UnmanagedType.LPUTF8Str)] string protocol,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string host, ushort port, [MarshalAs(UnmanagedType.LPUTF8Str)] string label, [MarshalAs(UnmanagedType.U1)] bool viaEntryRoute, out IntPtr err);

    // ABI 149: Save as Connection (plugin API 1.6).
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_plugin_propose_duplicates_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string? folderId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string rowsJson, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_plugin_propose_save_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string? folderId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? newFolder, [MarshalAs(UnmanagedType.LPUTF8Str)] string rowsJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? credentialId, out IntPtr err);
}

/// <summary>Calls over <see cref="PluginEntriesNative"/>. Each throws <see cref="BastionException"/> with the core's text.</summary>
public static class PluginEntryClient
{
    public static List<PluginTypeDto> Types(string dataDir) =>
        ParseTypes(LibraryClient.TakeString(PluginEntriesNative.bastion_plugin_connection_types_json(dataDir, out var err), err));

    /// <summary>Parses the types JSON (pure, for the console test).</summary>
    public static List<PluginTypeDto> ParseTypes(string json)
    {
        var list = new List<PluginTypeDto>();
        if (JsonNode.Parse(json) is not JsonArray a) return list;
        foreach (var n in a)
        {
            if (n is not JsonObject o) continue;
            string S(string k) => o[k] is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
            int? port = o["defaultPort"] is JsonValue p && p.TryGetValue<int>(out var i) ? i : null;
            var sidebar = o["sidebarTree"] is JsonValue sb && sb.TryGetValue<bool>(out var tree) && tree;
            var t = new PluginTypeDto(S("id"), S("pluginId"), S("pluginName"), S("tier"), S("name"), port, sidebar);
            if (t.Id.Length > 0) list.Add(t);
        }
        return list;
    }

    public static string Add(LibraryClient lib, string dataDir, string? parent, string name, string host, string typeId) =>
        LibraryClient.TakeString(PluginEntriesNative.bastion_library_add_plugin_connection(lib.NativeHandle, dataDir, parent, name, host, typeId, out var err), err);

    public static PluginEntryTlsDto Tls(LibraryClient lib, string id)
    {
        var o = JsonNode.Parse(LibraryClient.TakeString(PluginEntriesNative.bastion_library_plugin_entry_tls_json(lib.NativeHandle, id, out var err), err)) as JsonObject;
        var mode = o?["mode"]?.GetValue<string>() ?? "verify-full";
        var pin = o?["pinSha256"] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
        var damaged = o?["damaged"] is JsonValue d && d.TryGetValue<bool>(out var b) && b;
        return new PluginEntryTlsDto(mode, pin, damaged);
    }

    public static void SetTls(LibraryClient lib, string id, string mode, string? pin)
    {
        if (PluginEntriesNative.bastion_library_set_plugin_entry_tls(lib.NativeHandle, id, mode, pin, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "TLS setting not saved"));
    }

    /// <summary>The id of the gateway the entry goes through (own or a folder's), or null when it goes direct.</summary>
    public static string? Gateway(LibraryClient lib, string id)
    {
        var s = PluginEntriesNative.bastion_library_plugin_entry_gateway(lib.NativeHandle, id, out var err);
        if (err != IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "gateway not read"));
        return s == IntPtr.Zero ? null : LibraryClient.TakeString(s, IntPtr.Zero);
    }

    /// <summary>PLUG-OPEN-WIN: resolves <paramref name="host"/> once and checks every address; off the UI thread.</summary>
    public static List<string> OpenResolve(string host, int port, bool loopbackOk)
    {
        var json = LibraryClient.TakeString(PluginEntriesNative.bastion_plugin_open_resolve_json(host, (ushort)port, loopbackOk, out var err), err);
        return (JsonNode.Parse(json) as JsonArray ?? []).Select(n => n?.GetValue<string>()).OfType<string>().ToList();
    }

    /// <summary>PLUG-OPEN-WIN: an unsaved one-connection library for an <c>open-go</c> (the entry's gateway when asked).</summary>
    public static LibraryClient OpenLibrary(LibraryClient lib, string entryId, string protocol, string host, int port, string label, bool viaEntryRoute)
    {
        var h = PluginEntriesNative.bastion_library_plugin_open_library(lib.NativeHandle, entryId, protocol, host, (ushort)port, label, viaEntryRoute, out var err);
        if (h == IntPtr.Zero) throw new BastionException(LibraryClient.TakeError(err, "connection not made"));
        return LibraryClient.FromUnsavedHandle(h);
    }

    /// <summary>PLUG-OPEN-WIN: "Save as a library entry" beside the plugin entry; returns the new id.</summary>
    public static string OpenSave(LibraryClient lib, string entryId, string protocol, string host, int port, string label, bool viaEntryRoute) =>
        LibraryClient.TakeString(PluginEntriesNative.bastion_library_plugin_open_save(lib.NativeHandle, entryId, protocol, host, (ushort)port, label, viaEntryRoute, out var err), err);

    /// <summary>Save as Connection: per row, whether the folder (null: top level) already has the same host and protocol.</summary>
    public static List<bool> ProposeDuplicates(LibraryClient lib, string? folderId, string rowsJson)
    {
        var json = LibraryClient.TakeString(PluginEntriesNative.bastion_library_plugin_propose_duplicates_json(lib.NativeHandle, folderId, rowsJson, out var err), err);
        return (JsonNode.Parse(json) as JsonArray ?? []).Select(n => n?.GetValue<bool>() ?? false).ToList();
    }

    /// <summary>Save as Connection: saves the rows (duplicates skipped); returns the new ids.</summary>
    public static List<string> ProposeSave(LibraryClient lib, string? folderId, string? newFolder, string rowsJson, string? credentialId)
    {
        var json = LibraryClient.TakeString(PluginEntriesNative.bastion_library_plugin_propose_save_json(lib.NativeHandle, folderId, newFolder, rowsJson, credentialId, out var err), err);
        return ((JsonNode.Parse(json) as JsonObject)?["ids"] as JsonArray ?? []).Select(n => n?.GetValue<string>()).OfType<string>().ToList();
    }

    /// <summary>PVE-TLS: Test Connection for a plugin entry, a full TLS handshake under its rule (<paramref name="pin"/>
    /// set: exactly that certificate; null: system trust and the host name). Up to 10 s: call off the UI thread.</summary>
    public static void CheckCertificate(string host, int port, string? pin)
    {
        if (PluginEntriesNative.bastion_plugin_certificate_check(host, (ushort)port, pin, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "certificate not checked"));
    }

    /// <summary>PVE-AUTH: the login step of Test Connection on a saved plugin entry: the plugin loads its view with the
    /// entry's login (direct route), and its error banner, if any, is the reason. Up to 45 s: call off the UI thread.</summary>
    public static ProbeStepDto TestLogin(IntPtr library, IntPtr vault, string connectionId, string dataDir, bool allowUnverified)
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            // The core starts the plugin helper: hand it the path first, as a plugin tab does (runner 34, q-pveauth).
            PluginViewSession.EnsureHelper(System.IO.Path.Combine(AppContext.BaseDirectory, "bastion-plugin-host.exe"));
            var json = LibraryClient.TakeString(PluginEntriesNative.bastion_plugin_entry_test_json(library, vault, connectionId, dataDir, allowUnverified ? 1 : 0, 0, 0, null, out var err), err);
            var o = JsonNode.Parse(json) as JsonObject;
            var ok = o?["ok"] is JsonValue v && v.TryGetValue<bool>(out var b) && b;
            var message = o?["message"] is JsonValue m && m.TryGetValue<string>(out var t) ? t : "";
            var ms = (ulong)watch.ElapsedMilliseconds;
            return ok ? new ProbeStepDto("login", "ok", message.Length == 0 ? "Logged in and listed" : message, null, ms)
                      : new ProbeStepDto("login", "failed", message, null, ms);
        }
        catch (BastionException ex) { return new ProbeStepDto("login", "failed", ex.Message, null, (ulong)watch.ElapsedMilliseconds); }
    }

    /// <summary>PVE-AUTH: the login step when the entry goes through a gateway: not tested here.</summary>
    public static ProbeStepDto LoginNotTested() =>
        new("login", "skipped", "Not tested: the entry goes through a gateway. Open it to test the login.", null, 0);

    /// <summary>The entry's fields of its installed plugin type, with their saved values (ABI 141).</summary>
    public static List<PluginFieldDto> Fields(LibraryClient lib, string dataDir, string id)
    {
        var json = LibraryClient.TakeString(PluginEntriesNative.bastion_library_plugin_entry_fields_json(lib.NativeHandle, dataDir, id, out var err), err);
        var list = new List<PluginFieldDto>();
        // ABI 141 shape: {heading, typeId, fields: [{key, label, kind, value}]}.
        foreach (var n in (JsonNode.Parse(json) as JsonObject)?["fields"] as JsonArray ?? [])
        {
            if (n is not JsonObject o) continue;
            string? S(string k) => o[k] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
            if (S("key") is { Length: > 0 } key) list.Add(new PluginFieldDto(key, S("label") ?? key, S("kind") ?? "text", S("value")));
        }
        return list;
    }

    /// <summary>PVE-TLS: set (or clear, with null or empty) one plugin field.</summary>
    public static void SetField(LibraryClient lib, string dataDir, string id, string key, string? value)
    {
        if (PluginEntriesNative.bastion_library_set_plugin_field(lib.NativeHandle, dataDir, id, key, value, out var err) != 0)
            throw new BastionException(LibraryClient.TakeError(err, "field not saved"));
    }

    /// <summary>TLS handshake only, up to 10 s: call off the UI thread.</summary>
    public static string ProbeCertificate(string host, int port) =>
        LibraryClient.TakeString(PluginEntriesNative.bastion_plugin_certificate_probe(host, (ushort)port, out var err), err);
}

/// <summary>PVE-TLS: one field of a plugin entry's type with its saved value (<see cref="Kind"/> text, number or toggle).</summary>
public sealed record PluginFieldDto(string Key, string Label, string Kind, string? Value);
