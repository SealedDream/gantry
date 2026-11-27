using System.Runtime.InteropServices;
using System.Text.Json;

namespace Bastion.Shell.Interop;

/// <summary>P/Invoke for the per-item icon and custom properties (core-cabi/src/properties.rs, ABI_TBD_ICON and ABI_TBD_CUSTOMPROPS).</summary>
internal static class ItemExtrasNative
{
    private const string Lib = "bastion_cabi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_connection_icon_names_json();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_icon(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string? icon, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr bastion_library_custom_properties_json(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, out IntPtr err);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int bastion_library_set_custom_property(IntPtr lib, [MarshalAs(UnmanagedType.LPUTF8Str)] string id, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, [MarshalAs(UnmanagedType.LPUTF8Str)] string? value, out IntPtr err);
}

public sealed partial class LibraryClient
{
    /// <summary>The icon names an item may carry (core <c>model::ICONS</c>).</summary>
    public static IReadOnlyList<string> ConnectionIconNames() =>
        JsonSerializer.Deserialize(TakeString(ItemExtrasNative.bastion_connection_icon_names_json(), IntPtr.Zero), StringListJsonContext.Default.ListString) ?? [];

    /// <summary>Set a connection's own icon, or with null use the type icon. Call <see cref="Save"/> afterwards.</summary>
    public void SetIcon(string id, string? icon)
    {
        if (ItemExtrasNative.bastion_library_set_icon(Handle, id, icon, out var err) != 0) throw new BastionException(TakeError(err, "could not set the icon"));
    }

    public IReadOnlyList<CustomPropertyRow> CustomProperties(string id) =>
        JsonSerializer.Deserialize(TakeString(ItemExtrasNative.bastion_library_custom_properties_json(Handle, id, out var err), err), CustomPropertyJsonContext.Default.ListCustomPropertyRow) ?? [];

    /// <summary>Set (value) or remove (null) one custom property. Call <see cref="Save"/> afterwards.</summary>
    public void SetCustomProperty(string id, string name, string? value)
    {
        if (ItemExtrasNative.bastion_library_set_custom_property(Handle, id, name, value, out var err) != 0)
            throw new BastionException(TakeError(err, "could not set " + name));
    }
}
