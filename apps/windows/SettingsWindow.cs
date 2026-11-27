using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.Graphics;
using Windows.System;

namespace Bastion.Shell;

/// <summary>
/// Preview (owner, Mac look): Settings in a window of its own with a category sidebar, as the macOS Settings window
/// (apps/macos/Sources/Bastion/SettingsView.swift). One at a time: <see cref="MainWindow.OpenSettings"/> reuses it.
/// The main window builds the sidebar and the page (MainWindow.Settings.cs); this window only frames them. Dialogs
/// opened from a setting (themes, SSH config sources, type defaults) show over this window, as the Mac's sheets do.
/// </summary>
internal sealed partial class SettingsWindow : Window
{
    /// <summary>Opening size in DIPs: above the Mac window's minimum (680 x 420), with room for a page.</summary>
    private const double OpenWidth = 900;
    private const double OpenHeight = 640;
    /// <summary>Sidebar width (DIPs): the Mac sidebar's ideal width plus room for the search box.</summary>
    private const double SidebarWidth = 220;
    /// <summary>A readable page width (DIPs), the same cap the main-window page had.</summary>
    private const double PageMaxWidth = 760;

    private readonly ContentControl _sidebar;
    private readonly TextBlock _title;
    private readonly ContentControl _content;

    public Grid Root { get; }

    /// <summary>appearance.zoom as a factor (1 = 100%): Settings follows the main window's zoom (WIN-EVEN-01).</summary>
    private double _zoom = 1;

    public SettingsWindow(ElementTheme theme, KeyEventHandler modalKeys, Func<bool> escape)
    {
        Title = "Gantry Settings"; // the name the settings UI tests look for (SettingsWin)
        Root = new Grid { RequestedTheme = theme };
        Root.Background = Ui.Brush(Root, "ShellBackgroundBrush");
        Root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(SidebarWidth) });
        Root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        AutomationProperties.SetAutomationId(Root, "SettingsWindow");
        AutomationProperties.SetName(Root, "Settings");

        _sidebar = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch, VerticalContentAlignment = VerticalAlignment.Stretch, IsTabStop = false };
        Root.Children.Add(_sidebar);

        var page = new Grid
        {
            Background = Ui.Brush(Root, "LayerBackgroundBrush"),
            BorderBrush = Ui.Brush(Root, "DividerBrush"),
            BorderThickness = new Thickness(1, 0, 0, 0),
        };
        page.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        page.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(page, 1);

        var header = new Border
        {
            Padding = (Thickness)Application.Current.Resources["InspectorHeaderPadding"],
            BorderBrush = Ui.Brush(Root, "DividerBrush"),
            BorderThickness = (Thickness)Application.Current.Resources["BottomDividerThickness"],
        };
        _title = new TextBlock { Style = (Style)Application.Current.Resources["SubtitleTextStyle"], VerticalAlignment = VerticalAlignment.Center };
        AutomationProperties.SetHeadingLevel(_title, Microsoft.UI.Xaml.Automation.Peers.AutomationHeadingLevel.Level1);
        AutomationProperties.SetAutomationId(_title, "SettingsTitle");
        header.Child = _title;
        page.Children.Add(header);

        var columns = new Grid();
        columns.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star), MaxWidth = PageMaxWidth });
        columns.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _content = new ContentControl
        {
            Padding = (Thickness)Application.Current.Resources["InspectorBodyPadding"],
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            IsTabStop = false,
        };
        columns.Children.Add(_content);
        var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = columns };
        Grid.SetRow(scroll, 1);
        page.Children.Add(scroll);
        Root.Children.Add(page);

        // The dialog keys (Esc, Enter) as on the main window; then Esc closes the window when no dialog took it.
        Root.AddHandler(UIElement.KeyDownEvent, modalKeys, true);
        Root.KeyDown += (_, e) =>
        {
            if (e.Key != VirtualKey.Escape || e.Handled) return;
            e.Handled = escape();
        };

        Content = Root;
        SizeChanged += (_, _) => MainWindow.ScaleToZoom(Root, Bounds, _zoom);
        try { if (File.Exists(MainWindow.AppIconPath())) AppWindow.SetIcon(MainWindow.AppIconPath()); }
        catch (Exception e) when (e is System.Runtime.InteropServices.COMException or ArgumentException or IOException)
        {
            System.Diagnostics.Debug.WriteLine($"Gantry: settings window icon not set: {e.Message}");
        }
    }

    /// <summary>Size the window and centre it over the main window (screen pixels, at the main window's scale).</summary>
    public void PlaceOver(RectInt32 main, double scale)
    {
        scale *= _zoom; // the page keeps its logical size at any zoom
        // Never larger than the work area of the main window's screen (at 150% the open size ran past a 1024 px screen).
        var work = DisplayArea.GetFromRect(main, DisplayAreaFallback.Nearest).WorkArea;
        var w = Math.Min((int)(OpenWidth * scale), work.Width);
        var h = Math.Min((int)(OpenHeight * scale), work.Height);
        var x = Math.Clamp(main.X + (main.Width - w) / 2, work.X, work.X + work.Width - w);
        var y = Math.Clamp(main.Y + (main.Height - h) / 2, work.Y, work.Y + work.Height - h);
        AppWindow.MoveAndResize(new RectInt32(x, y, w, h));
        if (AppWindow.Presenter is OverlappedPresenter p) p.IsMinimizable = false;
    }

    /// <summary>Apply appearance.zoom (factor, 1 = 100%) to the whole Settings window.</summary>
    public void SetZoom(double zoom)
    {
        _zoom = zoom;
        MainWindow.ScaleToZoom(Root, Bounds, zoom);
    }

    public void Show(UIElement sidebar, string title, UIElement content)
    {
        _sidebar.Content = sidebar;
        _title.Text = title;
        _content.Content = content;
    }

    public ContentControl PageContent => _content;

    public void SetTheme(ElementTheme theme) => Root.RequestedTheme = theme;

    /// <summary>Put the main window's dialog surface over this window while a dialog opened from Settings is up.</summary>
    public void HostModal(FrameworkElement modal)
    {
        Grid.SetColumnSpan(modal, 2);
        Root.Children.Add(modal);
    }

    public void ReleaseModal(FrameworkElement modal)
    {
        Root.Children.Remove(modal);
        Grid.SetColumnSpan(modal, 1);
    }
}
