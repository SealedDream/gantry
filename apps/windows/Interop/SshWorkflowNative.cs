using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bastion.Shell.Interop;

public sealed record SshWorkflowSettings(bool ScanConfigD, bool Placeholders, bool Overrides, bool ChangeDetection, string? SshDir);
public sealed record SshPlaceholders(Dictionary<string, string> Values, Dictionary<string, int> Used);
public sealed record SshFieldChange(string Field, string? Old, string? New);
public sealed record SshHostChange(string Identity, string Alias, string? Group, string? SourceFile, string Kind, List<SshFieldChange> Fields);
public sealed record SshChanges(string? Root, bool HasBaseline, List<string> Files, List<SshHostChange> Hosts, long? LastSyncedSecs = null);
public sealed record SshRefreshResult(int Added, int Updated, int MarkedRemoved);

/// <summary>The shared-config workflow over the C ABI (89): sources, placeholders, change preview and refresh.</summary>
public static class SshWorkflow
{
    private const string Lib = "bastion_cabi";
    private static readonly JsonSerializerOptions Json = new() { TypeInfoResolver = AotJson.Resolver, PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_ssh_workflow_settings_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern int bastion_ssh_workflow_set_settings([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_ssh_workflow_placeholders_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern int bastion_ssh_workflow_set_placeholder([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, [MarshalAs(UnmanagedType.LPUTF8Str)] string value, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern int bastion_ssh_workflow_import_hosts([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string identities, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_ssh_workflow_changes_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, out IntPtr err);
    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr bastion_ssh_workflow_apply_refresh_json([MarshalAs(UnmanagedType.LPUTF8Str)] string dir, IntPtr lib, int importAdded, out IntPtr err);

    public static SshWorkflowSettings Settings(string dir) =>
        JsonSerializer.Deserialize(Take(bastion_ssh_workflow_settings_json(dir, out var e), e), Json.Info<SshWorkflowSettings>()) ?? throw new BastionException("no settings");

    public static void SetSettings(string dir, SshWorkflowSettings s) =>
        Check(bastion_ssh_workflow_set_settings(dir, AotJson.Write<SshWorkflowSettings>(s, Json), out var e), e);

    public static SshPlaceholders Placeholders(string dir) =>
        JsonSerializer.Deserialize(Take(bastion_ssh_workflow_placeholders_json(dir, out var e), e), Json.Info<SshPlaceholders>()) ?? throw new BastionException("no placeholders");

    /// <summary>The OpenSSH directory to read: the shared-config setting when one is set, else %USERPROFILE%\.ssh.</summary>
    public static string UserDir(string dir)
    {
        try { return Settings(dir).SshDir is { Length: > 0 } d ? Environment.ExpandEnvironmentVariables(d) : SshConfigLocation.UserDir; }
        catch (BastionException) { return SshConfigLocation.UserDir; }
    }

    public static void SetPlaceholder(string dir, string name, string value) =>
        Check(bastion_ssh_workflow_set_placeholder(dir, name, value, out var e), e);

    /// <summary>Import the chosen hosts and record the baseline that change detection compares against.</summary>
    public static int ImportHosts(string dir, LibraryClient lib, IEnumerable<string> identities)
    {
        var n = bastion_ssh_workflow_import_hosts(dir, lib.NativeHandle, AotJson.Write<IEnumerable<string>>(identities, AotJson.Options), out var e);
        if (n < 0) throw new BastionException(TakeErr(e));
        return n;
    }

    public static SshChanges Changes(string dir) =>
        JsonSerializer.Deserialize(Take(bastion_ssh_workflow_changes_json(dir, out var e), e), Json.Info<SshChanges>()) ?? throw new BastionException("no changes");

    public static SshRefreshResult ApplyRefresh(string dir, LibraryClient lib, bool importAdded) =>
        JsonSerializer.Deserialize(Take(bastion_ssh_workflow_apply_refresh_json(dir, lib.NativeHandle, importAdded ? 1 : 0, out var e), e), Json.Info<SshRefreshResult>()) ?? throw new BastionException("no result");

    private static void Check(int rc, IntPtr err) { if (rc != 0) throw new BastionException(TakeErr(err)); }

    private static string Take(IntPtr s, IntPtr err)
    {
        if (s == IntPtr.Zero) throw new BastionException(TakeErr(err));
        try { return Marshal.PtrToStringUTF8(s) ?? ""; }
        finally { Native.bastion_string_free(s); }
    }

    private static string TakeErr(IntPtr err)
    {
        if (err == IntPtr.Zero) return "the SSH workflow failed";
        try { return Marshal.PtrToStringUTF8(err) ?? "the SSH workflow failed"; }
        finally { Native.bastion_string_free(err); }
    }
}
