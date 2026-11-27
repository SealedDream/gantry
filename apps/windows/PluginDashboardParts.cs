using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;

namespace Bastion.Shell;

/// <summary>
/// Plugin API 1.6 display items, the Windows port of Native Mac's PluginDashboardParts.swift: the <c>stat</c> tile and
/// the <c>status</c> and <c>meter</c> table cells. Theme brushes only, so light and dark both follow the system.
/// </summary>
internal static class PluginDashboardParts
{
    /// <summary>A bar turns amber from 85 % and red from 90 % (owner, 2026-11-23).</summary>
    internal const double WarnAt = 0.85;
    internal const double CriticalAt = 0.90;
    private const double DotSize = 7;
    private const double MeterWidth = 60;

    internal static string BarBrushKey(double fraction) =>
        fraction >= CriticalAt ? "SystemFillColorCriticalBrush" : fraction >= WarnAt ? "SystemFillColorCautionBrush" : "AccentFillColorDefaultBrush";

    internal static string DotBrushKey(string? tone) => tone switch
    {
        "good" => "SystemFillColorSuccessBrush",
        "warning" => "SystemFillColorCautionBrush",
        "critical" => "SystemFillColorCriticalBrush",
        _ => "TextFillColorTertiaryBrush",
    };

    internal static ProgressBar Bar(FrameworkElement scope, double fraction)
    {
        var bar = new ProgressBar { Minimum = 0, Maximum = 1, Value = Math.Clamp(fraction, 0, 1), VerticalAlignment = VerticalAlignment.Center };
        bar.Foreground = Ui.Brush(scope, BarBrushKey(fraction));
        AutomationProperties.SetName(bar, $"{Math.Round(fraction * 100)} percent");
        return bar;
    }

    /// <summary>A summary tile: title, value, optional bar, detail. Tiles in a horizontal stack share its width.</summary>
    internal static FrameworkElement StatTile(FrameworkElement scope, JsonObject rec)
    {
        var panel = new StackPanel { Spacing = 3 };
        var title = Ui.Text(PluginViewModel.Str(rec, "title") ?? "", "CaptionTextStyle");
        title.Foreground = Ui.Brush(scope, "TextFillColorSecondaryBrush");
        panel.Children.Add(title);
        var value = Ui.Text(PluginViewModel.Str(rec, "value") ?? "", "SubtitleTextStyle");
        value.TextTrimming = TextTrimming.CharacterEllipsis;
        value.TextWrapping = TextWrapping.NoWrap;
        panel.Children.Add(value);
        if (rec["fraction"] is JsonValue f && f.TryGetValue<double>(out var d)) panel.Children.Add(Bar(scope, d));
        var detail = Ui.Text(PluginViewModel.Str(rec, "detail") ?? "", "CaptionTextStyle");
        detail.Foreground = Ui.Brush(scope, "TextFillColorSecondaryBrush");
        detail.TextTrimming = TextTrimming.CharacterEllipsis;
        detail.TextWrapping = TextWrapping.NoWrap;
        panel.Children.Add(detail);
        return new Border
        {
            Child = panel,
            Padding = new Thickness(10, 8, 10, 8),
            CornerRadius = new CornerRadius(6),
            Background = Ui.Brush(scope, "CardBackgroundFillColorDefaultBrush"),
            BorderBrush = Ui.Brush(scope, "CardStrokeColorDefaultBrush"),
            BorderThickness = new Thickness(1),
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
    }

    /// <summary>One table cell: text (whole numbers without ".0"), a status dot and text, or a meter and text.</summary>
    internal static FrameworkElement Cell(FrameworkElement scope, JsonNode? c)
    {
        var text = new TextBlock { Text = PluginViewModel.CellText(c), TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
        if (c is null) text.Foreground = Ui.Brush(scope, "TextFillColorSecondaryBrush");
        if (PluginViewModel.CellTone(c) is { } tone)
        {
            var dot = new Ellipse { Width = DotSize, Height = DotSize, Fill = Ui.Brush(scope, DotBrushKey(tone)), VerticalAlignment = VerticalAlignment.Center };
            return Row(dot, text);
        }
        if (PluginViewModel.CellFraction(c) is { } fraction)
        {
            var bar = Bar(scope, fraction);
            bar.Width = MeterWidth;
            return Row(bar, text);
        }
        return text;
    }

    private static Grid Row(FrameworkElement lead, TextBlock text)
    {
        var g = new Grid { ColumnSpacing = 6 };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(text, 1);
        g.Children.Add(lead);
        g.Children.Add(text);
        return g;
    }
}
