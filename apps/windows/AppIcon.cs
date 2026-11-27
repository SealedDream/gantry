using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// A 16 px vector icon for shapes the Windows 10 symbol font gets wrong (Segoe MDL2 Assets draws its folder glyphs
/// E8B7 and E8F4 as pages; Themes/Icons.xaml). Outline style with 1 px strokes on whole pixels, to sit next to the
/// font glyphs. Each instance parses its own Geometry because WinUI geometries cannot be shared between elements.
/// </summary>
public sealed partial class AppIcon : PathIcon
{
    private static readonly Dictionary<string, string> Paths = new()
    {
        ["Folder"] = "F0 M2,2 H5.6 L7.6,4 H14 A1,1 0 0 1 15,5 V13 A1,1 0 0 1 14,14 H2 A1,1 0 0 1 1,13 V3 A1,1 0 0 1 2,2 Z M2,3 V13 H14 V5 H7.19 L5.19,3 Z",
        // The folder outline stops short of the bottom-right corner, where the plus sits.
        ["FolderAdd"] = "F1 M2,2 H5.6 L7.6,4 H12 A1,1 0 0 1 13,5 V8 H12 V5 H7.19 L5.19,3 H2 V12 H8 V13 H2 A1,1 0 0 1 1,12 V3 A1,1 0 0 1 2,2 Z M12,9 H13 V12 H16 V13 H13 V16 H12 V13 H9 V12 H12 Z",
    };

    public static readonly DependencyProperty KindProperty = DependencyProperty.Register(
        nameof(Kind), typeof(string), typeof(AppIcon), new PropertyMetadata(null, (d, _) => ((AppIcon)d).Update()));

    /// <summary>"Folder" or "FolderAdd".</summary>
    public string? Kind
    {
        get => (string?)GetValue(KindProperty);
        set => SetValue(KindProperty, value);
    }

    private void Update() =>
        Data = Kind is not null && Paths.TryGetValue(Kind, out var path)
            ? (Geometry)XamlBindingHelper.ConvertValue(typeof(Geometry), path)
            : null;
}
