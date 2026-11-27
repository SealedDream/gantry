using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>What an Ansible inventory export wrote (<see cref="Skipped"/> holds "name: reason").</summary>
public sealed record AnsibleExportDto(int Exported, List<string> Skipped);

/// <summary>A checked run: <see cref="Argv"/>[0] is <c>ansible</c> or <c>ansible-playbook</c>.</summary>
public sealed record AnsiblePlanDto(List<string> Argv, List<string> Warnings, AnsibleRemoteDto? Remote = null, AnsibleTaskDto? Task = null);

/// <summary>Save as Task: the custom task for a run (<see cref="RunOn"/> "local" or "ssh"; an "ssh" one runs on the control host).</summary>
public sealed record AnsibleTaskDto(string Name, string Program, List<string> Args, string RunOn);

/// <summary>Ask the plan for a task too: <see cref="Mode"/> "wsl" (this PC) or "host" (the control host named <see cref="HostName"/>).</summary>
public sealed record AnsibleTaskSpec(string Mode, string? HostName);

/// <summary>A control-host run: make <see cref="Dirs"/>, upload <see cref="Uploads"/> over SFTP, type <see cref="Command"/> (it removes <see cref="Dir"/>).</summary>
public sealed record AnsibleRemoteDto(string Dir, List<string> Dirs, List<AnsibleUploadDto> Uploads, List<string> Argv, string Command);

public sealed record AnsibleUploadDto(string Local, string Remote);

/// <summary>Where a control-host run goes: the SFTP home there, a per-run hex id, and whether the playbook's folder is copied.</summary>
public sealed record AnsibleRemoteSpec(string Home, string RunId, bool UploadFolder);

/// <summary>The run sheet's fields, sent to the core as JSON (core-cabi/src/ansible.rs).</summary>
public sealed record AnsibleRunInput(string Kind, string Inventory, string Pattern, string Module, string ModuleArgs,
    string Playbook, string? Limit, bool Check, bool Diff, bool Become, int? Forks, int Verbosity,
    string? Tags = null, string? ExtraVars = null, AnsibleRemoteSpec? Remote = null, AnsibleTaskSpec? Task = null);

/// <summary>P/Invoke for Ansible (core-cabi/src/ansible.rs, C ABI 90).</summary>
internal static class AnsibleNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_export_ansible_inventory_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? idsJson, int yaml, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_ansible_run_plan_json([MarshalAs(UnmanagedType.LPUTF8Str)] string inputJson, out IntPtr err);
}

public sealed partial class LibraryClient
{
    private static readonly JsonSerializerOptions CamelJson = new() { TypeInfoResolver = AotJson.Resolver, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>Write the SSH connections (all when <paramref name="ids"/> is null) as an Ansible inventory, YAML or INI (owner-only, atomic, no secrets).</summary>
    public AnsibleExportDto ExportAnsibleInventory(string path, IEnumerable<string>? ids, bool yaml)
    {
        var json = TakeString(AnsibleNative.bastion_library_export_ansible_inventory_json(Handle, path, ids is null ? null : AotJson.Write<IEnumerable<string>>(ids, AotJson.Options), yaml ? 1 : 0, out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<AnsibleExportDto>()) ?? throw new BastionException("the core returned an empty export result");
    }

    /// <summary>Check a run sheet; throws with the first problem. Nothing is started.</summary>
    public static AnsiblePlanDto AnsiblePlan(AnsibleRunInput input)
    {
        var json = TakeString(AnsibleNative.bastion_ansible_run_plan_json(AotJson.Write<AnsibleRunInput>(input, CamelJson), out var err), err);
        return JsonSerializer.Deserialize(json, Json.Info<AnsiblePlanDto>()) ?? throw new BastionException("the core returned an empty run plan");
    }
}
