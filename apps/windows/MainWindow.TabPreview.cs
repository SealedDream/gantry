using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.System;

namespace Bastion.Shell;

// Tab hover previews and the tab overview (B11, docs/plans/B11-PREVIEWS.md); rules and cache in TabPreviewRules.cs.
// Previews live in memory only: never written to disk, the clipboard or a log. Nothing is captured while no preview
// and no overview is shown, so idle CPU is unchanged.
public sealed partial class MainWindow
{
    private const double PreviewCardWidth = 320;
    /// <summary>Overview tile: border plus padding on each side, and the two border widths.</summary>
    private const double TileInset = 9;
    private const double TileBorder = 1;
    private const double SelectedTileBorder = 2;
    private readonly PreviewCache<WorkspaceTab, WriteableBitmap> _previewCache = new();
    private readonly DispatcherTimer _previewHover = new() { Interval = TabPreviewRules.HoverDelay };
    private readonly DispatcherTimer _previewRefresh = new() { Interval = TabPreviewRules.RefreshInterval };
    private WorkspaceTab? _previewTab;
    private Popup? _previewPopup;
    private Grid? _overview;
    private readonly List<WorkspaceTab> _overviewTabs = new();
    private string _overviewFilter = "";
    private int _overviewIndex;
    private bool _previewInit;

    private void InitTabPreviews()
    {
        if (_previewInit) return;
        _previewInit = true;
        _previewHover.Tick += (_, _) => { _previewHover.Stop(); ShowTabPreview(); };
        _previewRefresh.Tick += (_, _) => RefreshPreviews();
    }

    /// <summary>Hook a new tab's header: a preview after the pointer rests on it.</summary>
    private void AttachTabPreview(WorkspaceTab tab)
    {
        InitTabPreviews();
        tab.Header.PointerEntered += (_, _) =>
        {
            _previewHover.Stop();
            HideTabPreview();
            if (ReferenceEquals(tab, _active) || SettingValue("tabs.previews") == "false") return;
            _previewTab = tab;
            _previewHover.Start();
        };
        tab.Header.PointerExited += (_, _) => { _previewHover.Stop(); HideTabPreview(); };
        tab.Header.PointerPressed += (_, _) => { _previewHover.Stop(); HideTabPreview(); };
    }

    private bool PreviewsLocked =>
        _credentials is null && (App.Personal is not null || File.Exists(CredentialStore.PathFor(_personal.Path)));

    private bool HidesPreview(WorkspaceTab tab)
    {
        if (tab.HostColorId is not { } id) return false;
        try { return _library.NoPreview(id); }
        catch (BastionException) { return true; } // unknown: keep the remote screen out
    }

    private bool MayShowImage(WorkspaceTab tab) =>
        TabPreviewRules.MayShowImage(SettingValue("tabs.previews") != "false", PreviewsLocked, HidesPreview(tab));

    /// <summary>Lock or previews turned off: drop every image at once and redraw what shows them.</summary>
    internal void ClearTabPreviews()
    {
        _previewCache.Clear();
        HideTabPreview();
        RefreshPreviews();
    }

    /// <summary>A tab closed: forget its picture.</summary>
    private void ForgetTabPreview(WorkspaceTab tab)
    {
        _previewCache.Remove(tab);
        if (ReferenceEquals(_previewTab, tab)) HideTabPreview();
        if (_overview is not null) BuildOverviewTiles();
    }

    private void ShowTabPreview()
    {
        if (_previewTab is not { } tab || Content.XamlRoot is null) return;
        var at = tab.Header.TransformToVisual(null).TransformPoint(new Windows.Foundation.Point(0, tab.Header.ActualHeight + 4));
        _previewPopup = new Popup
        {
            XamlRoot = Content.XamlRoot,
            Child = PreviewCard(tab),
            HorizontalOffset = at.X,
            VerticalOffset = at.Y,
            IsHitTestVisible = false,
            IsLightDismissEnabled = false,
        };
        _previewPopup.IsOpen = true;
        UpdatePreviewTimer();
    }

    private void HideTabPreview()
    {
        if (_previewPopup is { } p) p.IsOpen = false;
        _previewPopup = null;
        UpdatePreviewTimer();
    }

    private void UpdatePreviewTimer()
    {
        if (_previewPopup is not null || _overview is not null) { if (!_previewRefresh.IsEnabled) _previewRefresh.Start(); }
        else _previewRefresh.Stop();
    }

    private void RefreshPreviews()
    {
        if (_previewPopup is { } p && _previewTab is { } tab) p.Child = PreviewCard(tab);
        if (_overview is not null) BuildOverviewTiles();
    }

    private Border PreviewCard(WorkspaceTab tab)
    {
        var width = PreviewCardWidth - 16;
        var body = PreviewBody(tab);
        body.Width = width;
        body.Height = width * 10 / 16;
        var card = new Border
        {
            Width = PreviewCardWidth,
            Padding = new Thickness(8),
            CornerRadius = new CornerRadius(6),
            BorderThickness = new Thickness(1),
            BorderBrush = (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"],
            Background = (Brush)Application.Current.Resources["SolidBackgroundFillColorTertiaryBrush"],
            Child = new StackPanel { Spacing = 6, Children = { PreviewTitle(tab), body } },
        };
        // Decoration only: the tab's own accessible name is unchanged.
        AutomationProperties.SetAccessibilityView(card, Microsoft.UI.Xaml.Automation.Peers.AccessibilityView.Raw);
        return card;
    }

    private static TextBlock PreviewTitle(WorkspaceTab tab) =>
        new() { Text = tab.Title, TextTrimming = TextTrimming.CharacterEllipsis, MaxLines = 1 };

    /// <summary>The picture: a small copy of the remote desktop, the terminal's last lines, or nothing remote.</summary>
    private FrameworkElement PreviewBody(WorkspaceTab tab)
    {
        if (MayShowImage(tab))
        {
            if (tab.Rdp is { } rdp && PreviewBitmap(tab, rdp) is { } bitmap)
                return new Image { Source = bitmap, Stretch = Stretch.Uniform };
            if (tab.View is { } view)
            {
                var s = view.Session.Screen();
                return new Border
                {
                    Background = (Brush)Application.Current.Resources["SessionBackgroundBrush"],
                    Padding = new Thickness(4),
                    Child = new TextBlock
                    {
                        Text = TabPreviewRules.LastLines(s.CellText, s.Cols, TabPreviewRules.TextLines),
                        FontFamily = new FontFamily("Cascadia Mono, Consolas"),
                        FontSize = 7,
                        VerticalAlignment = VerticalAlignment.Bottom,
                    },
                };
            }
        }
        else
        {
            _previewCache.Remove(tab);
        }
        return new Border
        {
            Background = (Brush)Application.Current.Resources["CardBackgroundFillColorSecondaryBrush"],
            Child = new FontIcon { Glyph = "", FontSize = 32, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Opacity = 0.6 },
        };
    }

    private WriteableBitmap? PreviewBitmap(WorkspaceTab tab, RemoteDesktopView rdp)
    {
        var now = DateTime.UtcNow;
        if (_previewCache.NeedsRefresh(tab, now) && rdp.PreviewPixels() is { Width: > 0 } small)
        {
            var bitmap = new WriteableBitmap(small.Width, small.Height);
            using (var stream = bitmap.PixelBuffer.AsStream()) stream.Write(small.Pixels, 0, small.Pixels.Length);
            bitmap.Invalidate();
            _previewCache.Store(tab, bitmap, now);
        }
        return _previewCache.TryGet(tab, out var cached) ? cached : null;
    }

    // ---- Tab overview (Ctrl+Shift+\) ----

    private void ToggleTabOverview()
    {
        if (_overview is not null) { CloseTabOverview(); return; }
        InitTabPreviews();
        HideTabPreview();
        _overviewFilter = "";
        _overviewIndex = _active is { } current ? Math.Max(0, _tabs.ToList().IndexOf(current)) : 0;
        _overview = new Grid
        {
            Background = (Brush)Application.Current.Resources["SolidBackgroundFillColorBaseBrush"],
            Padding = new Thickness(16),
            RowSpacing = 12,
            IsTabStop = true,
            RowDefinitions = { new RowDefinition { Height = GridLength.Auto }, new RowDefinition { Height = new GridLength(1, GridUnitType.Star) } },
        };
        AutomationProperties.SetName(_overview, "Tab Overview");
        Canvas.SetZIndex(_overview, 100);
        _overview.KeyDown += OverviewKeyDown;
        _overview.CharacterReceived += (_, e) =>
        {
            if (char.IsControl(e.Character)) return;
            _overviewFilter += e.Character;
            _overviewIndex = 0;
            BuildOverviewTiles();
            e.Handled = true;
        };
        _overview.SizeChanged += (_, _) => BuildOverviewTiles();
        SessionHost.Visibility = Visibility.Visible;
        SessionHost.Children.Add(_overview);
        BuildOverviewTiles();
        _overview.Focus(FocusState.Programmatic);
        UpdatePreviewTimer();
    }

    private void CloseTabOverview(WorkspaceTab? open = null)
    {
        if (_overview is null) return;
        SessionHost.Children.Remove(_overview);
        _overview = null;
        UpdatePreviewTimer();
        if (open is not null) PickTab(open); // DASH-01: a chosen tab hides a folder dashboard
        else if (_active is { } tab) ActivateTab(tab);
        else ApplyHome();
    }

    private void BuildOverviewTiles()
    {
        if (_overview is null) return;
        _overviewTabs.Clear();
        _overviewTabs.AddRange(_tabs.Where(t => _overviewFilter.Length == 0 || t.Title.Contains(_overviewFilter, StringComparison.CurrentCultureIgnoreCase)));
        _overviewIndex = Math.Clamp(_overviewIndex, 0, Math.Max(0, _overviewTabs.Count - 1));
        var columns = TabPreviewRules.Columns(Math.Max(0, _overview.ActualWidth - 32));
        var title = new Grid { ColumnDefinitions = { new ColumnDefinition(), new ColumnDefinition { Width = GridLength.Auto } } };
        title.Children.Add(new TextBlock
        {
            Text = _overviewFilter.Length == 0 ? "Tab Overview" : $"Tab Overview: “{_overviewFilter}”",
            Style = (Style)Application.Current.Resources["SubtitleTextBlockStyle"],
            TextTrimming = TextTrimming.CharacterEllipsis,
            VerticalAlignment = VerticalAlignment.Center,
        });
        var done = new Button { Content = "Done" };
        done.Click += (_, _) => CloseTabOverview();
        Grid.SetColumn(done, 1);
        title.Children.Add(done);

        FrameworkElement body;
        if (_overviewTabs.Count == 0)
        {
            body = new TextBlock { Text = _tabs.Count == 0 ? "No open sessions" : "No tab matches", HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Opacity = 0.7 };
        }
        else
        {
            var grid = new Grid { ColumnSpacing = 12, RowSpacing = 12 };
            for (var c = 0; c < columns; c++) grid.ColumnDefinitions.Add(new ColumnDefinition());
            for (var i = 0; i < _overviewTabs.Count; i++)
            {
                if (i % columns == 0) grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var tile = OverviewTile(_overviewTabs[i], i == _overviewIndex);
                Grid.SetRow(tile, i / columns);
                Grid.SetColumn(tile, i % columns);
                grid.Children.Add(tile);
            }
            body = new ScrollViewer { Content = grid, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        }
        Grid.SetRow(body, 1);
        _overview.Children.Clear();
        _overview.Children.Add(title);
        _overview.Children.Add(body);
    }

    private Button OverviewTile(WorkspaceTab tab, bool selected)
    {
        var picture = PreviewBody(tab);
        picture.Height = (TabPreviewRules.TileWidth - 16) * 10 / 16;
        var tile = new Button
        {
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            // Border plus padding is the same on every tile, so the selected tile's thicker border does not make it 2 px
            // taller than its neighbours (WIN-EVEN-01, Tab overview row).
            Padding = new Thickness(TileInset - (selected ? SelectedTileBorder : TileBorder)),
            BorderThickness = new Thickness(selected ? SelectedTileBorder : TileBorder),
            BorderBrush = selected ? (Brush)Application.Current.Resources["AccentFillColorDefaultBrush"] : (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"],
            IsTabStop = false,
            Content = new StackPanel { Spacing = 6, Children = { PreviewTitle(tab), picture } },
        };
        AutomationProperties.SetName(tile, tab.Title);
        tile.Click += (_, _) => CloseTabOverview(tab);
        return tile;
    }

    private void OverviewKeyDown(object sender, KeyRoutedEventArgs e)
    {
        var columns = TabPreviewRules.Columns(Math.Max(0, (_overview?.ActualWidth ?? 0) - 32));
        var count = _overviewTabs.Count;
        switch (e.Key)
        {
            case VirtualKey.Left: _overviewIndex = TabPreviewRules.Move(_overviewIndex, -1, 0, count, columns); break;
            case VirtualKey.Right: _overviewIndex = TabPreviewRules.Move(_overviewIndex, 1, 0, count, columns); break;
            case VirtualKey.Up: _overviewIndex = TabPreviewRules.Move(_overviewIndex, 0, -1, count, columns); break;
            case VirtualKey.Down: _overviewIndex = TabPreviewRules.Move(_overviewIndex, 0, 1, count, columns); break;
            case VirtualKey.Enter when count > 0: e.Handled = true; CloseTabOverview(_overviewTabs[_overviewIndex]); return;
            case VirtualKey.Escape: e.Handled = true; CloseTabOverview(); return;
            case VirtualKey.Back when _overviewFilter.Length > 0: _overviewFilter = _overviewFilter[..^1]; _overviewIndex = 0; break;
            default: return;
        }
        e.Handled = true;
        BuildOverviewTiles();
    }
}
