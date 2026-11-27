using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

// Full screen (F11) with Royal TS-style auto-dock of the navigation pane: with "Auto-hide navigation in full screen"
// on, the pane leaves its column (one resize when full screen starts), and the pointer resting at the far left edge
// slides it in OVER the content, so sessions never resize while it comes and goes. Moving away slides it out again.
// It stays while a flyout, a text box in the pane (search, rename), a tree drag or a dialog is active. Ctrl+Alt+N pins
// it in or out. With Windows animations off it appears and goes at once.
public sealed partial class MainWindow
{
    /// <summary>Pointer distance from the left edge that counts as "at the edge", in view pixels.</summary>
    private const double DockEdgeWidth = 3;
    /// <summary>How long the pointer has to stay at the edge, so a fast pass to another monitor does not open it.</summary>
    private static readonly TimeSpan DockRevealDelay = TimeSpan.FromMilliseconds(150);
    /// <summary>How long the pointer has to stay away before the pane goes, so it never flickers.</summary>
    private static readonly TimeSpan DockHideDelay = TimeSpan.FromMilliseconds(400);
    private static readonly TimeSpan DockSlideDuration = TimeSpan.FromMilliseconds(300);
    /// <summary>Slack to the right of the pane before "away" counts.</summary>
    private const double DockHideMargin = 24;

    private bool _fullScreen;
    /// <summary>The pane is out of its column because full screen auto-dock is on (UpdatePanes keeps it collapsed).</summary>
    private bool _navDocked;
    private bool _dockPeek;
    private bool _dockPinned;
    private int _dockMotion;
    private DispatcherQueueTimer? _dockReveal;
    private DispatcherQueueTimer? _dockHide;
    private ToggleMenuFlyoutItem? _dockToggle;
    private ToggleMenuFlyoutItem? _fullScreenToggle;

    internal bool IsFullScreen => _fullScreen;
    internal bool IsDockPeekOpen => _dockPeek;

    /// <summary>Owner point W7: an unpinned pane is docked everywhere (edge reveal like the Mac), not only in full screen.</summary>
    private bool DockActive => _navDocked;

    private void InitFullScreen()
    {
        _dockReveal = DispatcherQueue.CreateTimer();
        _dockReveal.Interval = DockRevealDelay;
        _dockReveal.IsRepeating = false;
        _dockReveal.Tick += (_, _) => ShowDockPeek(pinned: false);
        _dockHide = DispatcherQueue.CreateTimer();
        _dockHide.Interval = DockHideDelay;
        _dockHide.IsRepeating = false;
        _dockHide.Tick += (_, _) => DockHideTick();

        // On the window's root: the body may sit a few pixels in from the screen edge.
        if (Content is UIElement root)
        {
            root.AddHandler(UIElement.PointerMovedEvent, new PointerEventHandler(Dock_PointerMoved), handledEventsToo: true);
            root.PointerExited += (_, e) => DockPointerLeft(e);
        }
        NavPane.PointerExited += (_, e) => DockPointerLeft(e);
        InitEdgeReveal();
    }

    /// <summary>The Full screen items in More options: nobody can open the menu before the first frame (start-up budget).</summary>
    private void BuildFullScreenMenu()
    {
        // View items next to the other pane switches in More options.
        _fullScreenToggle = new ToggleMenuFlyoutItem { Text = "Full screen", KeyboardAcceleratorTextOverride = "F11" };
        AutomationProperties.SetName(_fullScreenToggle, "Full screen");
        _fullScreenToggle.Click += (_, _) => ToggleFullScreen();
        _dockToggle = new ToggleMenuFlyoutItem { Text = "Auto-hide navigation in full screen" };
        AutomationProperties.SetName(_dockToggle, "Auto-hide navigation in full screen");
        AutomationProperties.SetHelpText(_dockToggle, "In full screen, the navigation pane slides in over the sessions when the pointer rests at the left edge");
        _dockToggle.Click += (_, _) => SetFullScreenAutoDock(_dockToggle.IsChecked);
        var at = MoreMenu.Items.IndexOf(NavAutoHideToggle) + 1;
        MoreMenu.Items.Insert(at, _dockToggle);
        MoreMenu.Items.Insert(at, _fullScreenToggle);
        MoreMenu.Opening += (_, _) =>
        {
            _fullScreenToggle.IsChecked = _fullScreen;
            _dockToggle.IsChecked = _appearance.FullScreenAutoDock;
        };
    }

    /// <summary>The window's frame just before F11, in screen pixels; restored on the way out.</summary>
    private Windows.Graphics.RectInt32? _frameBeforeFullScreen;

    /// <summary>W22: leaving full screen puts the window back where it was, inside the monitor's work area (a frame taller
    /// than the screen came back on a 1280x800 display with the taskbar).</summary>
    private void RestoreFrameInWorkArea()
    {
        if (_frameBeforeFullScreen is not { } f) return;
        var work = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        var (x, y, w, h) = WindowFrame.ClampToWorkArea((f.X, f.Y, f.Width, f.Height), (work.X, work.Y, work.Width, work.Height));
        AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(x, y, w, h));
    }

    /// <summary>F11 / More options › Full screen.</summary>
    internal void ToggleFullScreen()
    {
        _fullScreen = !_fullScreen;
        _inspectorOverlayDismissed = false;
        if (_fullScreen) _frameBeforeFullScreen = new(AppWindow.Position.X, AppWindow.Position.Y, AppWindow.Size.Width, AppWindow.Size.Height);
        try { AppWindow.SetPresenter(_fullScreen ? AppWindowPresenterKind.FullScreen : AppWindowPresenterKind.Overlapped); }
        catch (Exception e) when (e is InvalidOperationException or System.Runtime.InteropServices.COMException) { _fullScreen = !_fullScreen; return; }
        if (!_fullScreen) RestoreFrameInWorkArea();
        ApplyDock();
        ApplyInspectorLayout(InspectorVisible); // overlay in full screen, its column again outside
    }

    private void SetFullScreenAutoDock(bool on)
    {
        _appearance.SetFullScreenAutoDock(on, save: !_demo);
        ApplyDock();
    }

    /// <summary>Take the pane out of (or back into) its column for the current full screen and setting.</summary>
    private void ApplyDock()
    {
        HideDockPeek(animate: false);
        _dockPinned = false;
        _dockReveal?.Stop();
        _dockHide?.Stop();
        var docked = !_navWanted || (_fullScreen && _appearance.FullScreenAutoDock);
        if (docked == _navDocked) { UpdatePinButton(); return; }
        _navDocked = docked;
        UpdatePanes();
        UpdatePinButton();
    }

    /// <summary>Ctrl+Alt+N and the pane button while docked: pin the pane in, or send it away. False when not docked.</summary>
    private bool ToggleDockPeek()
    {
        if (!_navDocked || !_navWanted) return false;
        if (_dockPeek && _dockPinned) HideDockPeek(animate: true);
        else ShowDockPeek(pinned: true);
        return true;
    }

    private void Dock_PointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_navDocked || !DockActive || _dockReveal is null || _dockHide is null) return;
        var x = e.GetCurrentPoint(Content).Position.X;
        if (!_dockPeek)
        {
            if (x <= DockEdgeWidth) { if (!_dockReveal.IsRunning) _dockReveal.Start(); }
            else _dockReveal.Stop(); // a fast pass never opens it
            return;
        }
        if (_dockPinned) return;
        if (x > NavPane.ActualWidth + NavPane.TransformToVisual(Content).TransformPoint(default).X + DockHideMargin) { if (!_dockHide.IsRunning) _dockHide.Start(); }
        else _dockHide.Stop();
    }

    /// <summary>The pointer left the window (another monitor, or a native child such as an RDP view).</summary>
    // An exit raised while the pointer is still over the pane (the pane sliding in under a resting pointer, a layout
    // change, a tooltip) is not "away": hiding then would close the pane under a pointer that never moved.
    private void DockPointerLeft(PointerRoutedEventArgs e)
    {
        _dockReveal?.Stop();
        if (_dockPeek && Content is FrameworkElement body)
        {
            var p = e.GetCurrentPoint(body).Position;
            var right = NavPane.ActualWidth + NavPane.TransformToVisual(body).TransformPoint(default).X + DockHideMargin;
            if (p.X >= 0 && p.Y >= 0 && p.X <= right && p.Y <= body.ActualHeight) return;
        }
        if (_dockPeek && !_dockPinned && _dockHide is { IsRunning: false }) _dockHide.Start();
    }

    private void DockHideTick()
    {
        if (!_dockPeek || _dockPinned) return;
        if (DockBusy()) { _dockHide?.Start(); return; } // look again later
        if (CursorOverDockPane()) { _dockHide?.Start(); return; } // the pointer came back or never left
        HideDockPeek(animate: true);
    }

    /// <summary>Something in the pane is in use: a flyout or menu, a text box (search, rename), a tree drag, a dialog.</summary>
    private bool DockBusy()
    {
        if (_modal is not null) return true;
        // A drag needs the left button down: a cancelled drag (Esc) may never raise DropCompleted, which would leave
        // _dragId set and keep the pane open for good.
        if (_dragId is not null && LeftButtonDown()) return true;
        if (Content?.XamlRoot is { } root && VisualTreeHelper.GetOpenPopupsForXamlRoot(root).Any(p => p.Child is not ToolTip)) return true;
        return FocusedElement is TextBox box && Contains(NavPane, box);
    }

    private void ShowDockPeek(bool pinned)
    {
        _dockReveal?.Stop();
        _dockHide?.Stop();
        _dockPinned = pinned;
        if (_dockPeek || !_navDocked) return;
        _dockPeek = true;
        var motion = ++_dockMotion;
        // Over the content: span the body, keep the column at 0 so nothing else moves.
        Grid.SetColumnSpan(NavPane, 3);
        Canvas.SetZIndex(NavPane, 10);
        NavPane.HorizontalAlignment = HorizontalAlignment.Left;
        NavPane.Width = _navWidth;
        NavPane.Background = (Brush)Application.Current.Resources["LayerBackgroundBrush"];
        NavPane.BorderBrush = (Brush)Application.Current.Resources["DividerBrush"];
        NavPane.BorderThickness = new Thickness(0, 0, 1, 0);
        NavPane.Visibility = Visibility.Visible;
        NavPane.UpdateLayout();
        SlideDock(from: -(float)_navWidth, to: 0, motion, done: null);
        AutomationProperties.SetName(NavPane, "Navigation");
    }

    private void HideDockPeek(bool animate)
    {
        if (!_dockPeek) return;
        _dockPeek = false;
        _dockPinned = false;
        _dockHide?.Stop();
        var hadFocus = Contains(NavPane, FocusedElement);
        var motion = ++_dockMotion;
        if (animate) SlideDock(from: 0, to: -(float)NavPane.ActualWidth, motion, done: () => EndDockPeek(motion));
        else EndDockPeek(motion);
        if (hadFocus) FocusWorkspace();
    }

    /// <summary>Back into the (collapsed) column once the slide-out finished, unless a slide-in started meanwhile.</summary>
    private void EndDockPeek(int motion)
    {
        if (motion != _dockMotion || _dockPeek) return;
        var visual = ElementCompositionPreview.GetElementVisual(NavPane);
        visual.StopAnimation("Translation");
        visual.Properties.InsertVector3("Translation", Vector3.Zero);
        Grid.SetColumnSpan(NavPane, 1);
        NavPane.ClearValue(Canvas.ZIndexProperty);
        NavPane.ClearValue(FrameworkElement.HorizontalAlignmentProperty);
        NavPane.ClearValue(FrameworkElement.WidthProperty);
        NavPane.ClearValue(Panel.BackgroundProperty);
        NavPane.ClearValue(Grid.BorderBrushProperty);
        NavPane.ClearValue(Grid.BorderThicknessProperty);
        // Collapsed while docked; when undocking, UpdatePanes shows it in its column again.
        NavPane.Visibility = Visibility.Collapsed;
    }

    /// <summary>The 300 ms Native spring along x; nothing moves when Windows animations are off.</summary>
    private void SlideDock(float from, float to, int motion, Action? done)
    {
        var visual = ElementCompositionPreview.GetElementVisual(NavPane);
        ElementCompositionPreview.SetIsTranslationEnabled(NavPane, true);
        if (Motion.Reduced)
        {
            visual.Properties.InsertVector3("Translation", new Vector3(to, 0, 0));
            done?.Invoke();
            return;
        }
        var compositor = visual.Compositor;
        var slide = compositor.CreateVector3KeyFrameAnimation();
        slide.InsertKeyFrame(0f, new Vector3(from, 0, 0));
        slide.InsertKeyFrame(1f, new Vector3(to, 0, 0), compositor.CreateCubicBezierEasingFunction(new Vector2(0.32f, 0.72f), new Vector2(0f, 1f)));
        slide.Duration = DockSlideDuration;
        var batch = compositor.CreateScopedBatch(CompositionBatchTypes.Animation);
        visual.StartAnimation("Translation", slide);
        batch.End();
        if (done is null) return;
        var queue = DispatcherQueue;
        batch.Completed += (_, _) => queue.TryEnqueue(() => { if (motion == _dockMotion) done(); });
    }
}
