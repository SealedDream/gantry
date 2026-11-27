using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage.Streams;

namespace Bastion.Shell;

/// <summary>
/// The owner-approved connection icon set (D12, docs/design/ICON-SET.md), the Windows counterpart of apps/macos
/// ConnectionIcons.swift: a coloured tile per connection type, the monochrome glyph in the text colour under High
/// Contrast, and the folder and credential outlines in their tint. Drawn from the shared SVGs (ConnectionIconArt,
/// generated) with SvgImageSource; never from the symbol font or brand art. SSH turns on its 1 px edge in dark mode.
/// </summary>
public sealed partial class ConnectionIcon : Grid
{
    /// <summary>Core icon id → art name in docs/design/icons (the same map as the Mac).</summary>
    private static readonly Dictionary<string, string> ArtForId = new()
    {
        ["ssh"] = "ssh", ["services"] = "ssh", ["processes"] = "ssh", ["eventlog"] = "ssh",
        ["telnet"] = "telnet",
        ["local-terminal"] = "local", ["local"] = "local", ["powershell"] = "local", ["wsl"] = "local",
        ["rdp"] = "rdp", ["vnc"] = "vnc", ["serial"] = "serial",
        ["sftp"] = "files", ["scp"] = "files", ["ftp"] = "files", ["ftps"] = "files",
        ["web"] = "web",
        ["folder"] = "folder", ["credential"] = "credential",
    };

    /// <summary>Art drawn as an outline in a tint colour, not as a tile.</summary>
    private static bool IsOutline(string art) => art is "folder" or "credential";

    /// <summary>The art for a core icon id, or null when the id is not in the set (the caller keeps its font glyph).</summary>
    /// The tree binds IconId to the art name it already looked up (TreeItem.ArtId), so an art name is accepted as itself:
    /// "files" (SFTP, SCP, FTP, FTPS) is an art name but not a core id, and those rows drew no icon before (#984).
    /// A plugin connection type (<c>&lt;plugin id&gt;/&lt;type id&gt;</c>) of a known kind gets its own mark by type id,
    /// as on the Mac (Icons.pluginIcon); other plugin types keep the font glyph.
    public static string? Art(string? id) =>
        id is null ? null
        : ArtForId.TryGetValue(id, out var art) ? art
        : ArtForId.ContainsValue(id) || PluginArt.ContainsValue(id) || id == "docker" ? id // the tree binds the art name it already looked up
        : id.EndsWith(DockerHostSuffix, StringComparison.Ordinal) ? "docker"
        : id.LastIndexOf('/') is var slash and >= 0 && PluginArt.TryGetValue(id[(slash + 1)..], out var plugin) ? plugin
        : null;

    /// <summary>Plugin connection type id (after the slash) → art: own marks in each product's colours, not vendor logos.</summary>
    private static readonly Dictionary<string, string> PluginArt = new() { ["pve"] = "proxmox", ["vcenter"] = "vmware", ["esxi"] = "vmware" };

    /// <summary>Docker's type id (<c>host</c>) is too generic alone: matched as <c>&lt;…&gt;.docker/host</c> (official and test ids).</summary>
    private const string DockerHostSuffix = ".docker/host";

    public static readonly DependencyProperty IconIdProperty = DependencyProperty.Register(
        nameof(IconId), typeof(string), typeof(ConnectionIcon), new PropertyMetadata(null, (d, _) => ((ConnectionIcon)d).Update()));

    public static readonly DependencyProperty TintProperty = DependencyProperty.Register(
        nameof(Tint), typeof(Brush), typeof(ConnectionIcon), new PropertyMetadata(null, (d, _) => ((ConnectionIcon)d).Update()));

    /// <summary>A core icon id (ssh, rdp, folder, …).</summary>
    public string? IconId { get => (string?)GetValue(IconIdProperty); set => SetValue(IconIdProperty, value); }

    /// <summary>Folder and credential outline colour (identity colour); null uses the secondary text colour.</summary>
    public Brush? Tint { get => (Brush?)GetValue(TintProperty); set => SetValue(TintProperty, value); }

    private readonly Image _image = new() { Stretch = Stretch.Uniform };
    private string? _shownKey;

    public ConnectionIcon()
    {
        Children.Add(_image);
        ActualThemeChanged += (_, _) => Update();
        Loaded += (_, _) => Update();
        SizeChanged += (_, _) => Update();
    }

    private void Update()
    {
        if (XamlRoot is null || ActualWidth <= 0) return;
        var art = Art(IconId);
        if (art is null) { _image.Source = null; _shownKey = null; return; }
        var svg = Source(art, ActualTheme == ElementTheme.Dark, Ui.HighContrast, this, Tint);
        if (svg is null) return;
        var px = (int)Math.Ceiling(ActualWidth * XamlRoot.RasterizationScale);
        var key = svg + "|" + px;
        if (key == _shownKey) return;
        _shownKey = key;
        _image.Source = Image(key, svg, px);
    }

    /// <summary>The SVG text for a variant: tile (SSH edge on in dark), monochrome under High Contrast, outlines recoloured.</summary>
    internal static string? Source(string art, bool dark, bool highContrast, FrameworkElement scope, Brush? tint)
    {
        if (IsOutline(art))
            return Recolor(art, tint is SolidColorBrush s ? Hex(s.Color) : BrushHex(scope, highContrast ? "TextPrimaryBrush" : "TextSecondaryBrush"), scope);
        if (highContrast) return Recolor(art + "-mono", BrushHex(scope, "TextPrimaryBrush"), scope);
        if (!ConnectionIconArt.Svg.TryGetValue(art, out var svg)) return null;
        return dark && svg.Contains("class=\"dark-edge\"", StringComparison.Ordinal)
            ? svg.Replace("stroke-opacity=\"0\"", "stroke-opacity=\".22\"", StringComparison.Ordinal)
            : svg;
    }

    /// <summary>currentColor → <paramref name="hex"/>; the cut-out placeholder → the surface behind the icon.</summary>
    private static string? Recolor(string art, string hex, FrameworkElement scope) =>
        ConnectionIconArt.Svg.TryGetValue(art, out var svg)
            ? svg.Replace("currentColor", hex, StringComparison.Ordinal).Replace("BACKGROUND", BrushHex(scope, "ShellBackgroundBrush"), StringComparison.Ordinal)
            : null;

    /// <summary>A monochrome glyph (<c>&lt;art&gt;-mono</c>) in <paramref name="hex"/>, <paramref name="px"/> square; null for unknown art.</summary>
    internal static Image? Mono(string art, string hex, int px, FrameworkElement scope)
    {
        var svg = Recolor(art + "-mono", hex, scope);
        return svg is null ? null : new Image { Source = Image($"mono|{art}|{hex}|{px}", svg, px), Width = px, Height = px };
    }

    private static string BrushHex(FrameworkElement scope, string key)
    {
        try { return Ui.Brush(scope, key) is SolidColorBrush s ? Hex(s.Color) : "#808080"; }
        catch { return "#808080"; }
    }

    internal static string Hex(Windows.UI.Color c) => $"#{c.R:X2}{c.G:X2}{c.B:X2}";

    // A handful of variants in all (art × theme × size); each is parsed once and shared by every row.
    private static readonly Dictionary<string, SvgImageSource> Cache = new();

    private static SvgImageSource Image(string key, string svg, int px)
    {
        if (Cache.TryGetValue(key, out var hit)) return hit;
        var source = new SvgImageSource { RasterizePixelWidth = px, RasterizePixelHeight = px };
        Cache[key] = source;
        _ = Load(source, svg);
        return source;
    }

    private static async Task Load(SvgImageSource source, string svg)
    {
        try
        {
            using var stream = new InMemoryRandomAccessStream();
            using (var writer = new DataWriter(stream.GetOutputStreamAt(0)))
            {
                writer.WriteString(svg);
                await writer.StoreAsync();
                await writer.FlushAsync();
                writer.DetachStream();
            }
            stream.Seek(0);
            var status = await source.SetSourceAsync(stream);
            if (status != SvgImageSourceLoadStatus.Success) Fail(svg, status.ToString());
        }
        catch (Exception e) { Fail(svg, e.GetType().Name + ": " + e.Message); }
    }

    private static void Fail(string svg, string why)
    {
        Failed.Add(svg);
#if BASTION_TEST_HOOKS
        // Test builds: BASTION_ICON_FAILURES names a file that gets one line per SVG Direct2D refused.
        if (Environment.GetEnvironmentVariable("BASTION_ICON_FAILURES") is { Length: > 0 } log)
            try { File.AppendAllText(log, why + " " + svg + Environment.NewLine); } catch (IOException) { }
#endif
    }

    /// <summary>Variants that did not parse (a test reads this; empty when the art and Direct2D agree).</summary>
    internal static readonly List<string> Failed = new();

    /// <summary>Art the map needs that is missing from ConnectionIconArt. Empty when in sync with docs/design/icons.</summary>
    internal static IEnumerable<string> MissingArt() =>
        ArtForId.Values.Concat(PluginArt.Values).Distinct().SelectMany(a => IsOutline(a) ? new[] { a } : new[] { a, a + "-mono" })
            .Where(a => !ConnectionIconArt.Svg.ContainsKey(a)).Order();
}
