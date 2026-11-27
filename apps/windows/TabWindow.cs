using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.Graphics;

namespace Bastion.Shell;

/// <summary>
/// B12-W2b: a window holding one torn-off tab. The tab stays in the main window's list (so link polling, saving,
/// quit, document lock and broadcast still see it); only its content (<see cref="WorkspaceTab.Body"/>) moves here,
/// and its strip header is hidden in the main window. Built in code, like the rest of the shell's dynamic UI.
/// Moving back: the bar's "Move to Main Window" button, or dragging the bar onto the main window's tab strip.
/// Closing asks as closing the tab does (<see cref="MainWindow.RequestCloseFromWindow"/>).
/// </summary>
internal sealed partial class TabWindow : Window
{
    /// <summary>Pointer travel (DIPs) before a press on the bar becomes a drag.</summary>
    private const double DragThreshold = 6;
    /// <summary>Height of the bar with the tab's title and buttons (DIPs).</summary>
    public const double BarHeight = 40;

    private readonly MainWindow _main;
    private readonly Border _host;
    private readonly Grid _cover;
    private readonly TextBlock _title;
    private readonly Grid _bar;
    private readonly long _titleToken;
    private bool _closingFromMain;

    public WorkspaceTab Tab { get; }
    /// <summary>B12-W2c: the window's id in the open-sessions set (core <c>SavedWindow.id</c>).</summary>
    public Guid Id { get; } = Guid.NewGuid();
    /// <summary>The window's frame in screen pixels, for the open-sessions set.</summary>
    public RectInt32 Frame => new(AppWindow.Position.X, AppWindow.Position.Y, AppWindow.Size.Width, AppWindow.Size.Height);

    /// <summary>UI-06: this window's own tones from its tab's terminal theme (null = stock). The bar takes the toolbar tone
    /// and the bar's light or dark look; the item status carries the tones for automation.</summary>
    internal void ApplyTones(Bastion.Shell.Interop.WindowTonesDto? t)
    {
        _bar.Background = t is null ? new SolidColorBrush(Microsoft.UI.Colors.Transparent) : new SolidColorBrush(MainWindow.ToneColor(t.Toolbar));
        _bar.RequestedTheme = t is null ? ElementTheme.Default : t.IsDark ? ElementTheme.Dark : ElementTheme.Light;
        if (t is null) _title.ClearValue(TextBlock.ForegroundProperty);
        else _title.Foreground = new SolidColorBrush(MainWindow.ToneColor(t.Text));
        AutomationProperties.SetItemStatus(_bar, t is null ? "off" : $"toolbar={t.Toolbar} text={t.Text} dark={t.IsDark}");
        AutomationProperties.SetName(_bar, "Torn-off bar");
    }

    public TabWindow(MainWindow main, WorkspaceTab tab, ElementTheme theme)
    {
        _main = main;
        Tab = tab;
        Title = tab.Label.Text;

        var root = new Grid { RequestedTheme = theme };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.Background = Ui.Brush(root, "ShellBackgroundBrush");

        _title = new TextBlock { Text = tab.Label.Text, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(12, 0, 8, 0) };
        AutomationProperties.SetAutomationId(_title, "TornOffTitle");
        var redock = new Button { Content = "Move to Main Window", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 4, 0) };
        AutomationProperties.SetAutomationId(redock, "TornOffRedock");
        ToolTipService.SetToolTip(redock, "Put this tab back in the main window's tab strip (or drag this bar onto it)");
        redock.Click += (_, _) => _main.RedockFromWindow(Tab);
        var close = new Button { Content = new FontIcon { Glyph = "", FontSize = 12 }, MinWidth = 32, MinHeight = 32, VerticalAlignment = VerticalAlignment.Center };
        AutomationProperties.SetName(close, "Close Tab");
        AutomationProperties.SetAutomationId(close, "TornOffClose");
        ToolTipService.SetToolTip(close, "Close Tab");
        close.Click += (_, _) => _main.RequestCloseFromWindow(Tab);

        // A transparent fill so the whole bar takes the pointer for dragging back.
        var bar = new Grid { Height = BarHeight, Padding = new Thickness(0, 0, 4, 0), Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Transparent) };
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _bar = bar;
        bar.Children.Add(_title);
        Grid.SetColumn(redock, 1);
        bar.Children.Add(redock);
        Grid.SetColumn(close, 2);
        bar.Children.Add(close);
        root.Children.Add(bar);

        _host = new Border { Child = tab.Body };
        Grid.SetRow(_host, 1);
        root.Children.Add(_host);

        // Document lock: the main window shows the Unlock screen; this window hides the session until it is unlocked.
        _cover = new Grid { Visibility = Visibility.Collapsed, Background = Ui.Brush(root, "ShellBackgroundBrush") };
        _cover.Children.Add(new TextBlock { Text = "Locked. Unlock in the main window.", HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center });
        AutomationProperties.SetAutomationId(_cover, "TornOffLocked");
        Grid.SetRow(_cover, 1);
        root.Children.Add(_cover);

        // B12-W2d: the main window's shortcuts (Ctrl+W, Ctrl+Tab, Ctrl+T, find, zoom) work here too, on this tab.
        root.PreviewKeyDown += (_, e) =>
        {
            if (Content is UIElement { XamlRoot: { } xr }) _main.TornOffKeyDown(Tab, e, Microsoft.UI.Xaml.Input.FocusManager.GetFocusedElement(xr) as DependencyObject);
        };
        Content = root;
        EnableDragBack(bar);
        _titleToken = tab.Label.RegisterPropertyChangedCallback(TextBlock.TextProperty, (_, _) => { _title.Text = Tab.Label.Text; Title = Tab.Label.Text; });
        // B12-W2c: a moved or resized window is saved (the main window skips the save when nothing changed).
        AppWindow.Changed += (_, a) => { if ((a.DidPositionChange || a.DidSizeChange) && !_closingFromMain) _main.SaveWindowFrames(); };
        // The window's close box asks like closing the tab; the main window closes this window once the tab is gone.
        AppWindow.Closing += (_, e) =>
        {
            if (_closingFromMain) return;
            e.Cancel = true;
            _main.RequestCloseFromWindow(Tab);
        };
    }

    /// <summary>Moves and sizes the window (physical pixels), kept on the work area of the display nearest <paramref name="at"/>.</summary>
    public void Place(RectInt32 frame) => Place(new PointInt32(frame.X, frame.Y), new SizeInt32(frame.Width, frame.Height));

    public void Place(PointInt32 at, SizeInt32 size)
    {
        var area = DisplayArea.GetFromPoint(at, DisplayAreaFallback.Nearest).WorkArea;
        var w = Math.Min(size.Width, area.Width);
        var h = Math.Min(size.Height, area.Height);
        var x = Math.Clamp(at.X, area.X, area.X + area.Width - w);
        var y = Math.Clamp(at.Y, area.Y, area.Y + area.Height - h);
        AppWindow.MoveAndResize(new RectInt32(x, y, w, h));
    }

    /// <summary>Takes the tab's content out of this window (before it moves back or is disposed).</summary>
    public void ReleaseBody()
    {
        _host.Child = null;
        Tab.Label.UnregisterPropertyChangedCallback(TextBlock.TextProperty, _titleToken);
    }

    /// <summary>Closes the window without asking: the main window already decided.</summary>
    public void CloseFromMain()
    {
        _closingFromMain = true;
        TerminalView.ForgetImeContexts(AppWindow.Id.Value); // its terminals' spare TSF contexts (WIN-SHELL-LEAK)
        // Hide now, close on a later dispatcher turn: closing inside the call that disposed the tab's views (after the
        // close prompt) crashed in Microsoft.UI.Xaml with E_POINTER (q958, 0xc000027b).
        Content = null;
        AppWindow.Hide();
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, Close);
    }

    /// <summary>Document lock: hide the session (and its focus) behind a cover, or show it again.</summary>
    public void SetCovered(bool covered)
    {
        _cover.Visibility = covered ? Visibility.Visible : Visibility.Collapsed;
        _host.Visibility = covered ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>A point in a window's content (DIPs) on the screen (physical pixels), for moving tabs between windows.</summary>
    public static PointInt32 ScreenOf(Window window, Point dip)
    {
        var scale = window.Content?.XamlRoot?.RasterizationScale ?? 1.0;
        var app = window.AppWindow;
        // The content starts inside the frame: half the width difference is the side border, the rest of the height
        // difference is the title bar (zero for a window whose content extends into its title bar, like the main one).
        var left = (app.Size.Width - app.ClientSize.Width) / 2;
        var top = app.Size.Height - app.ClientSize.Height - left;
        return new PointInt32(app.Position.X + left + (int)(dip.X * scale), app.Position.Y + top + (int)(dip.Y * scale));
    }

    private void EnableDragBack(Grid bar)
    {
        Point? pressed = null;
        var dragging = false;
        bar.PointerPressed += (_, e) =>
        {
            var pt = e.GetCurrentPoint(null);
            pressed = pt.Properties.IsLeftButtonPressed ? pt.Position : null;
            dragging = false;
        };
        bar.PointerMoved += (_, e) =>
        {
            if (pressed is not { } from || dragging) return;
            var pt = e.GetCurrentPoint(null);
            if (!pt.Properties.IsLeftButtonPressed) { pressed = null; return; }
            if (Math.Abs(pt.Position.X - from.X) < DragThreshold && Math.Abs(pt.Position.Y - from.Y) < DragThreshold) return;
            dragging = bar.CapturePointer(e.Pointer);
        };
        bar.PointerReleased += (_, e) =>
        {
            var wasDragging = dragging;
            pressed = null;
            dragging = false;
            bar.ReleasePointerCaptures();
            if (!wasDragging) return;
            // Dropped on the main window's tab strip: the tab goes back there.
            if (_main.IsOverStrip(ScreenOf(this, e.GetCurrentPoint(null).Position))) _main.RedockFromWindow(Tab);
        };
        bar.PointerCaptureLost += (_, _) => { pressed = null; dragging = false; };
    }
}
