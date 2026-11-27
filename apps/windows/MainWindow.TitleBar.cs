using System.Runtime.InteropServices;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// Content in the title bar, as in Windows Terminal: the toolbar is the caption area, with the system's own
/// minimise / maximise / close buttons beside it. The toolbar's empty space drags the window, double-click
/// maximises and Win11 snap layouts come from the system caption buttons; each toolbar button is a passthrough
/// region so it still takes clicks. The window keeps its "Gantry" title for Alt+Tab and the taskbar.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>The app icon for the taskbar's theme: the light-on-dark glyph on a dark taskbar (docs/design/app-icon).</summary>
    internal static string AppIconPath() =>
        Path.Combine(AppContext.BaseDirectory, "Assets", TaskbarIsDark() ? "Bastion-dark.ico" : "Bastion.ico");

    /// <summary>Windows 10 and 11 keep the taskbar theme in SystemUsesLightTheme (0 = dark). Missing value: light.</summary>
    private static bool TaskbarIsDark()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("SystemUsesLightTheme") is int v && v == 0;
        }
        catch (System.Security.SecurityException) { return false; }
    }

    /// <summary>
    /// The window's own icon (title bar, Alt+Tab, taskbar, tray), set after the first frame on its own: not inside
    /// InitTitleBar, so a window that keeps the standard title bar still shows it (#863 runner). The .ico file next to
    /// the exe gives the theme variant; when it is missing or Windows refuses it, the icon built into Bastion.exe
    /// (ApplicationIcon) is used, so the taskbar never falls back to the generic one (Win11 runner, 2026-11-15).
    /// </summary>
    private void InitAppIcon() => Startup.AfterFirstFrame(this, () =>
    {
        if (_titleBarClosed) return;
        var path = AppIconPath();
        try
        {
            if (File.Exists(path)) { AppWindow.SetIcon(path); return; }
            System.Diagnostics.Debug.WriteLine($"Gantry: {path} missing; using the icon in Gantry.exe");
        }
        catch (Exception e) when (e is COMException or ArgumentException or IOException)
        {
            System.Diagnostics.Debug.WriteLine($"Gantry: app icon file not used: {e.Message}");
        }
        SetIconFromExe(Hwnd);
    });

    private const uint WmSetIcon = 0x0080, ImageIcon = 1, LrDefaultSize = 0x40, LrShared = 0x8000;
    private const int IconSmall = 0, IconBig = 1, AppIconResourceId = 32512; // the id the SDK gives ApplicationIcon

    /// <summary>Sets the window's big and small icons from the exe's own icon resource (shared handles: never freed).</summary>
    internal static void SetIconFromExe(IntPtr hwnd)
    {
        var module = GetModuleHandle(null);
        var big = LoadImage(module, AppIconResourceId, ImageIcon, 0, 0, LrDefaultSize | LrShared);
        var small = LoadImage(module, AppIconResourceId, ImageIcon, 16, 16, LrShared);
        if (big == IntPtr.Zero && small == IntPtr.Zero)
        {
            System.Diagnostics.Debug.WriteLine($"Gantry: no icon resource in Gantry.exe (error {Marshal.GetLastWin32Error()})");
            return;
        }
        if (big != IntPtr.Zero) SendMessage(hwnd, WmSetIcon, IconBig, big);
        if (small != IntPtr.Zero) SendMessage(hwnd, WmSetIcon, IconSmall, small);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandle(string? name);
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr LoadImage(IntPtr instance, nint name, uint type, int cx, int cy, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr SendMessage(IntPtr hwnd, uint msg, nint wParam, IntPtr lParam);

    private void InitTitleBar()
    {
        ExtendsContentIntoTitleBar = true;
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        SetTitleBar(Toolbar);
        Toolbar.SizeChanged += OnToolbarLayout;
        Toolbar.LayoutUpdated += OnToolbarLayout;
        // Layout keeps firing while the window closes, after AppWindow is gone; a throw there crashes the app.
        Closed += (_, _) => { _titleBarClosed = true; Toolbar.SizeChanged -= OnToolbarLayout; Toolbar.LayoutUpdated -= OnToolbarLayout; };
        // Runs after the first frame (#145): the toolbar is already laid out, so no layout pass may come to set the
        // passthrough regions; without them the caption area takes every click on the toolbar buttons.
        UpdateCaptionRegions();
    }

    private bool _titleBarClosed;
    private void OnToolbarLayout(object? sender, object e) { CheckTabBarRoom(); UpdateCaptionRegions(); }

    private Windows.Graphics.RectInt32[]? _passthrough;
    private double _captionInset = -1;

    /// <summary>Keep the toolbar clear of the caption buttons and its buttons clickable. Runs on layout, cheap when nothing moved.</summary>
    private void UpdateCaptionRegions()
    {
        if (_titleBarClosed || Toolbar.XamlRoot is not { } root || AppWindow is not { } window) return;
        var scale = root.RasterizationScale;
        // The caption buttons are not zoomed, but the toolbar is (RootGrid's ScaleTransform): its padding is in zoomed
        // units, so the inset is divided by the zoom too, or the toolbar runs under Minimize below 100 %.
        var zoom = ZoomPercent / (double)ActualSizePercent;
        var inset = window.TitleBar.RightInset / scale / zoom;
        if (Math.Abs(inset - _captionInset) > 0.5)
        {
            _captionInset = inset;
            var pad = Ui.Thickness("ToolbarPadding");
            Toolbar.Padding = new Thickness(pad.Left + window.TitleBar.LeftInset / scale / zoom, pad.Top, pad.Right + inset, pad.Bottom);
            // The inset is part of the toolbar's width: decide labels-or-icons again with it, or a zoom change keeps
            // labels that no longer fit and pushes More options under the caption buttons.
            UpdateToolbarLabels();
            UpdateCompactLibraryWidth(); // the switcher's width is measured from the toolbar's left padding
        }
        var rects = new List<Windows.Graphics.RectInt32>();
        // The tab bar sits in the title bar: its buttons and the scroller (sized to the tabs, never past TabArea) take
        // clicks; TabArea's space past the last tab still drags the window.
        var targets = Toolbar.Children.Where(c => c != TabBar).Concat(TabBar.Children.Where(c => c != TabArea)).Append(TabScroller);
        foreach (var child in targets)
        {
            if (child is not FrameworkElement { Visibility: Visibility.Visible, ActualWidth: > 0 } e) continue;
            var box = e.TransformToVisual(null).TransformBounds(new Windows.Foundation.Rect(0, 0, e.ActualWidth, e.ActualHeight));
            rects.Add(new((int)Math.Round(box.X * scale), (int)Math.Round(box.Y * scale), (int)Math.Round(box.Width * scale), (int)Math.Round(box.Height * scale)));
        }
        var next = rects.ToArray();
        if (_passthrough is not null && _passthrough.SequenceEqual(next)) return;
        _passthrough = next;
        InputNonClientPointerSource.GetForWindowId(window.Id).SetRegionRects(NonClientRegionKind.Passthrough, next);
    }

    /// <summary>Width of the title bar without the tab bar: toolbar actions, padding and the caption inset.</summary>
    private double ToolbarActionsWidth()
    {
        Toolbar.Measure(new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity));
        // The first row only: the tab bar is either in it (subtracted) or in the second row (not counted).
        var actions = Toolbar.Padding.Left + Toolbar.Padding.Right;
        var shown = Toolbar.Children.OfType<FrameworkElement>().Where(c => c != TabBar && c.Visibility == Visibility.Visible).ToList();
        actions += shown.Sum(c => c.DesiredSize.Width) + Math.Max(0, shown.Count) * Toolbar.ColumnSpacing;
        return actions;
    }

    /// <summary>The tab bar's own buttons and padding, without the tabs.</summary>
    private double TabBarFixedWidth()
    {
        TabBar.Measure(new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity));
        TabArea.Measure(new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity));
        return TabBar.DesiredSize.Width - TabArea.DesiredSize.Width;
    }

    /// <summary>
    /// Tabs live in the title bar. Only when the window is too narrow for the icon-only toolbar plus the tab bar's
    /// buttons and one tab (640 px at 150 %) does the tab bar drop to its own row above the session, so no control
    /// slides under the caption buttons; it moves back up once the window is wide enough again.
    /// </summary>
    private void PlaceTabBar(bool inTitleBar)
    {
        if (_tabBarInTitleRow == inTitleBar) return;
        _tabBarInTitleRow = inTitleBar;
        // The tab bar never changes parent: a second row of the toolbar holds it when the window is narrow. Moving it
        // out of the toolbar into the workspace and back dropped the session title bars from the UIA tree.
        if (Toolbar.RowDefinitions.Count < 2)
        {
            Toolbar.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Toolbar.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        }
        Grid.SetRow(TabBar, inTitleBar ? 0 : 1);
        Grid.SetColumn(TabBar, inTitleBar ? 4 : 0);
        Grid.SetColumnSpan(TabBar, inTitleBar ? 1 : Toolbar.ColumnDefinitions.Count);
        _passthrough = null; // the regions change with it
    }

    /// <summary>True while the tab bar sits in the first toolbar row, beside the actions.</summary>
    private bool _tabBarInTitleRow = true;
}
