using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>A connection template (B9). <see cref="Tokens"/> are asked for once each by New from Template.</summary>
public sealed record TemplateDto(string Id, string Name, string Protocol, string Host, string? Port, string? Username, string Notes, List<string> Tokens);

/// <summary>C ABI 116: connection templates (core-cabi/src/templates.rs). No secrets cross.</summary>
internal static partial class Native
{
    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_templates_json(IntPtr lib, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_template_save_from(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string connectionId, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_template_instantiate(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string templateId, [MarshalAs(UnmanagedType.LPUTF8Str)] string valuesJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? parent, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_template_update(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string name,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string host, [MarshalAs(UnmanagedType.LPUTF8Str)] string? port, [MarshalAs(UnmanagedType.LPUTF8Str)] string? username,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string notes, out IntPtr err);

    [DllImport(L, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_template_delete(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);
}

public sealed partial class LibraryClient
{
    public List<TemplateDto> Templates() =>
        JsonSerializer.Deserialize(TakeString(Native.bastion_templates_json(Handle, out var err), err), PrefsNative.Json.Info<List<TemplateDto>>()) ?? [];

    /// <summary>Save as Template: returns the template's id (login reference only).</summary>
    public string SaveAsTemplate(string connectionId, string name) => TakeString(Native.bastion_template_save_from(Handle, connectionId, name, out var err), err);

    /// <summary>New from Template: returns the new connection's id. <see cref="Save"/> writes it.</summary>
    public string NewFromTemplate(string templateId, IReadOnlyDictionary<string, string> values, string? parentId) =>
        TakeString(Native.bastion_template_instantiate(Handle, templateId, AotJson.Write<IReadOnlyDictionary<string, string>>(values, AotJson.Options), parentId, out var err), err);

    public void UpdateTemplate(string id, string name, string host, string? port, string? username, string notes) =>
        Check(Native.bastion_template_update(Handle, id, name, host, string.IsNullOrWhiteSpace(port) ? null : port,
            string.IsNullOrWhiteSpace(username) ? null : username, notes, out var err), err, "could not save the template");

    public void DeleteTemplate(string id) => Check(Native.bastion_template_delete(Handle, id, out var err), err, "could not delete the template");
}
