using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;
using Windows.Foundation;
using Windows.Graphics;

namespace Bastion.Shell;

/// <summary>
/// B12-W2b: tab tear-off (docs/plans/B12-TEAROFF.md). A torn-off tab keeps its place in this window's tab list and in
/// the store, so everything that walks the tabs (link polling, open-sessions saving, quit, broadcast, the session
/// tree) still covers it; <see cref="WorkspaceTab.Window"/> says where its content is shown. Its header leaves the
/// strip and its content moves into a <see cref="TabWindow"/>. No reconnect: the session and its views are the same
/// objects (decision 8). Saving and restoring torn-off windows is B12-W2c.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>A tab released this far (DIPs) above or below the strip tears off.</summary>
    private const double TearOffDistance = 40;
    /// <summary>A drop this close (DIPs) above or below the strip still lands on it.</summary>
    private const double DockSlack = 24;
    /// <summary>Smallest content size (DIPs) of a new torn-off window.</summary>
    private const double TornOffMinWidth = 640, TornOffMinHeight = 400;

    private static bool IsDocked(WorkspaceTab tab) => tab.Window is null;

    /// <summary>Was this drag released far enough off the strip to tear the tab off?</summary>
    private bool ReleasedOffStrip(PointerRoutedEventArgs e)
    {
        var p = e.GetCurrentPoint(TabStrip).Position;
        return p.Y < -TearOffDistance || p.Y > TabStrip.ActualHeight + TearOffDistance;
    }

    /// <summary>Moves <paramref name="tab"/> into a new window at <paramref name="at"/> (screen pixels), or near this
    /// window's corner when null (the tab menu's "Move Tab to New Window").</summary>
    private void TearOff(WorkspaceTab tab, PointInt32? at) => TearOff(tab, at, null);

    /// <param name="frame">B12-W2c: the saved frame to reopen at (screen pixels), instead of a place near the pointer.</param>
    private TabWindow? TearOff(WorkspaceTab tab, PointInt32? at, RectInt32? frame)
    {
        if (!IsDocked(tab) || _closed) return null;
        // A torn-off tab leaves its group: groups live in this window's strip.
        if (tab.Group is not null) tab.Group = null;
        var scale = RootGrid.XamlRoot?.RasterizationScale ?? 1.0;
        var size = new SizeInt32(
            (int)(Math.Max(SessionHost.ActualWidth, TornOffMinWidth) * scale),
            (int)((Math.Max(SessionHost.ActualHeight, TornOffMinHeight) + TabWindow.BarHeight) * scale));
        var corner = at is { } p
            ? new PointInt32(p.X - (int)(80 * scale), p.Y - (int)(TabWindow.BarHeight / 2 * scale))
            : new PointInt32(AppWindow.Position.X + (int)(48 * scale), AppWindow.Position.Y + (int)(48 * scale));

        TabStrip.Children.Remove(tab.Header);
        tab.Header.Visibility = Visibility.Collapsed;
        SessionHost.Children.Remove(tab.Body);
        tab.Body.Visibility = Visibility.Visible;
        var window = new TabWindow(this, tab, RootGrid.ActualTheme);
        tab.Window = window;
        if (frame is { } f) window.Place(f); else window.Place(corner, size);
        if (_gate is { Visibility: Visibility.Visible }) window.SetCovered(true);

        if (ReferenceEquals(_active, tab))
        {
            if (_tabs.FirstOrDefault(IsDocked) is { } next) ActivateTab(next, focus: false);
            else _active = null;
        }
        RenderStrip();
        UpdateWorkspace();
        SyncSessionSurface(); // UI-06: this window and the torn-off one each take their own tab's tones
        window.Activate();
        tab.FocusContent(FocusState.Programmatic);
        return window;
    }

    /// <summary>A torn-off window moved or was resized: save the set (skipped when nothing changed).</summary>
    internal void SaveWindowFrames() => SaveOpenSessions();

    /// <summary>B12-W2c (decision 4): after the restored tabs are open, each saved window comes back at its frame, kept on a
    /// visible display (<see cref="TabWindow.Place(RectInt32)"/>). A saved tab is matched to the first open, docked tab of
    /// the same connection, in order. A window whose tabs all failed to open is not created.</summary>
    private void ReopenTornOffWindows(LaunchPlanDto plan)
    {
        if (plan.Windows is not { Count: > 0 } windows || !plan.Restore) return;
        var used = new HashSet<WorkspaceTab>(ReferenceEqualityComparer.Instance);
        foreach (var saved in plan.Tabs.Where(t => t.Window is not null))
        {
            if (windows.FirstOrDefault(w => w.Id == saved.Window) is not { } w) continue;
            var tab = _tabs.FirstOrDefault(t => IsDocked(t) && !used.Contains(t) && (t.ConnectionId ?? t.HostColorId ?? t.Waiting?.Connection) == saved.Connection);
            if (tab is null) continue;
            used.Add(tab);
            var frame = new RectInt32((int)w.X, (int)w.Y, (int)Math.Max(w.Width, 1), (int)Math.Max(w.Height, 1));
            TearOff(tab, null, frame);
        }
        if (_tabs.FirstOrDefault(IsDocked) is { } front) ActivateTab(front, focus: false);
        Activate();
    }

    /// <summary>The torn-off windows for the open-sessions set: one per window, its front tab as an index into
    /// <paramref name="saved"/> (the tabs in the order they are saved).</summary>
    private List<SavedWindowDto> SavedWindows(IReadOnlyList<WorkspaceTab> saved)
    {
        var list = new List<SavedWindowDto>();
        for (var i = 0; i < saved.Count; i++)
        {
            if (saved[i].Window is not { } w) continue;
            var f = w.Frame;
            list.Add(new SavedWindowDto(w.Id.ToString(), f.X, f.Y, f.Width, f.Height, i));
        }
        return list;
    }

    /// <summary>Puts a torn-off tab back at the end of this window's strip and closes its window.</summary>
    internal void RedockFromWindow(WorkspaceTab tab)
    {
        if (tab.Window is not { } window) return;
        window.ReleaseBody();
        tab.Window = null;
        SessionHost.Children.Add(tab.Body);
        window.CloseFromMain();
        RenderStrip(); // the header joins the strip again
        ActivateTab(tab);
        Activate();
    }

    /// <summary>The torn-off window's Close button or close box: asks as closing the tab does, in this window.</summary>
    internal void RequestCloseFromWindow(WorkspaceTab tab)
    {
        Activate();
        _ = RequestCloseTab(tab, FocusState.Pointer);
    }

    /// <summary>B12-W2d: a key pressed in a torn-off window, set while it runs the main window's key handling.</summary>
    private DependencyObject? _keyFocus;

    /// <summary>
    /// B12-W2d: a key in a torn-off window runs the main window's shortcuts with that window's tab as the active one and
    /// its focused element as the focus, so Ctrl+W closes it, find and zoom act on it, Ctrl+T opens a tab here as usual.
    /// The main window's active tab is put back afterwards unless the shortcut changed it (Ctrl+Tab, a new tab).
    /// While the Unlock screen is up the torn-off window is covered and takes no shortcuts.
    /// </summary>
    internal void TornOffKeyDown(WorkspaceTab tab, KeyRoutedEventArgs e, DependencyObject? focused)
    {
        if (_closed || IsGated || _modal is not null || tab.Window is null) return;
        var previous = _active;
        _active = tab;
        _keyFocus = focused;
        try { Root_PreviewKeyDown(this, e); }
        finally
        {
            _keyFocus = null;
            if (ReferenceEquals(_active, tab)) _active = previous is not null && _tabs.Contains(previous) ? previous : _tabs.FirstOrDefault(IsDocked);
        }
    }

    /// <summary>Is the screen point over this window's tab strip (with a little slack above and below)?</summary>
    internal bool IsOverStrip(PointInt32 screen)
    {
        if (_closed || TabStrip.XamlRoot is null) return false;
        var origin = TabWindow.ScreenOf(this, new Point(0, 0));
        var scale = TabStrip.XamlRoot.RasterizationScale;
        var dip = new Point((screen.X - origin.X) / scale, (screen.Y - origin.Y) / scale);
        var strip = TabStrip.TransformToVisual(null).TransformBounds(new Rect(0, 0, TabStrip.ActualWidth, TabStrip.ActualHeight));
        return dip.X >= strip.Left && dip.X <= strip.Right && dip.Y >= strip.Top - DockSlack && dip.Y <= strip.Bottom + DockSlack;
    }

    /// <summary>Closing a tab: its torn-off window goes with it (the content is disposed by <see cref="CloseTab"/>).</summary>
    private void CloseWindowOf(WorkspaceTab tab)
    {
        if (tab.Window is not { } window) return;
        window.ReleaseBody();
        tab.Window = null;
        window.CloseFromMain();
    }

    /// <summary>Document lock: torn-off windows hide their sessions while the Unlock screen is up (decision 6).</summary>
    private void SetTornOffCovered(bool covered)
    {
        foreach (var tab in _tabs) tab.Window?.SetCovered(covered);
    }

    /// <summary>The main window is closing: torn-off windows close too; their tabs are disposed with the rest.</summary>
    private void CloseTornOffWindows()
    {
        foreach (var tab in _tabs.ToList()) CloseWindowOf(tab);
    }
}
