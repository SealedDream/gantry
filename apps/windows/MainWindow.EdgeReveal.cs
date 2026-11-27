using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

// W14: edge reveal that works on a real screen. XAML pointer events alone miss the edge in three common cases:
//  - a native child window (RDP, VNC, WebView2) fills the left of the window, so XAML never sees the pointer;
//  - a restored window's left edge is the invisible resize border, so the pointer at the visible edge is outside Content;
//  - a maximised window on a monitor with another monitor to its left: the pointer only touches the edge in passing.
// While the pane is docked and the window is in front, a light timer reads the cursor in screen pixels and compares it
// with the client area: a hot zone a few pixels either side of the left edge, within the window's height, opens the
// pane after the same dwell; while the pane is open the same timer starts the hide once the cursor is away from it.
// The XAML handlers stay for synthetic input (UI tests) and costs nothing extra.
public sealed partial class MainWindow
{
    private static readonly TimeSpan EdgePollInterval = TimeSpan.FromMilliseconds(50);
    /// <summary>Hot zone inside the client area, in view pixels (scaled by the window's DPI below).</summary>
    private const double EdgeInsideDip = 4;
    /// <summary>Hot zone outside the client area: the resize border of a restored window is about 7 px at 100 %.</summary>
    private const double EdgeOutsideDip = 8;

    private DispatcherQueueTimer? _edgePoll;
    private int _edgeDwellTicks;

    private void InitEdgeReveal()
    {
        _edgePoll = DispatcherQueue.CreateTimer();
        _edgePoll.Interval = EdgePollInterval;
        _edgePoll.IsRepeating = true;
        _edgePoll.Tick += (_, _) => EdgePollTick();
        _edgePoll.Start();
    }

    private void EdgePollTick()
    {
        if (_dockPeek) { _edgeDwellTicks = 0; HidePollTick(); return; }
        if (!_navDocked || _modal is not null) { _edgeDwellTicks = 0; return; }
        var hwnd = Hwnd;
        if (GetForegroundWindow() != hwnd || !GetCursorPos(out var p) || !GetClientRect(hwnd, out var rc)) { _edgeDwellTicks = 0; return; }
        var origin = new EdgePoint();
        if (!ClientToScreen(hwnd, ref origin)) return;
        var scale = GetDpiForWindow(hwnd) / 96.0;
        // A maximised window's client area can start off-screen (left of the monitor): the edge is the monitor's then.
        var left = origin.X;
        var info = new EdgeMonitorInfo { Size = Marshal.SizeOf<EdgeMonitorInfo>() };
        if (GetMonitorInfo(MonitorFromWindow(hwnd, 2), ref info)) left = Math.Max(left, info.Monitor.Left);
        var inZone = p.X >= left - EdgeOutsideDip * scale && p.X <= left + EdgeInsideDip * scale
                     && p.Y >= origin.Y && p.Y <= origin.Y + rc.Bottom;
        if (!inZone) { _edgeDwellTicks = 0; return; }
        // Same dwell as the XAML path, so a fast pass to another monitor never opens it.
        if (++_edgeDwellTicks * EdgePollInterval.TotalMilliseconds >= DockRevealDelay.TotalMilliseconds)
        {
            _edgeDwellTicks = 0;
            ShowDockPeek(pinned: false);
        }
    }

    /// <summary>Hide side of the same poll: XAML exit/move events do not arrive for some pointer input (injected input on
    /// Windows 10, a native child under the pointer), so the cursor read here starts the hide timer once it is away from
    /// the open pane. DockHideTick re-checks the cursor and the busy state before the pane slides out.</summary>
    private void HidePollTick()
    {
        if (_dockPinned || _dockHide is null || _dockHide.IsRunning || !GetCursorPos(out _)) return;
        if (!CursorOverDockPane()) _dockHide.Start();
    }

    /// <summary>The real cursor is over the open pane (or within its hide margin), read when the hide timer fires, so the
    /// order of XAML exit and move events (re-layout, slide, tooltip) can never close the pane under a resting pointer.</summary>
    private bool CursorOverDockPane()
    {
        if (Content is not FrameworkElement body) return false;
        var hwnd = Hwnd;
        if (!GetCursorPos(out var p) || !GetClientRect(hwnd, out var rc)) return false;
        var origin = new EdgePoint();
        if (!ClientToScreen(hwnd, ref origin)) return false;
        var scale = GetDpiForWindow(hwnd) / 96.0;
        if (scale <= 0) return false;
        double x = (p.X - origin.X) / scale, y = (p.Y - origin.Y) / scale;
        var right = NavPane.ActualWidth + NavPane.TransformToVisual(body).TransformPoint(default).X + DockHideMargin;
        return x >= 0 && y >= 0 && x <= right && y <= rc.Bottom / scale;
    }

    [StructLayout(LayoutKind.Sequential)] private struct EdgePoint { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct EdgeRect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] private struct EdgeMonitorInfo { public int Size; public EdgeRect Monitor, Work; public uint Flags; }
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] private static extern bool GetMonitorInfo(IntPtr monitor, ref EdgeMonitorInfo info);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out EdgePoint point);
    [DllImport("user32.dll")] private static extern short GetAsyncKeyState(int key);
    private const int VkLeftButton = 0x01;
    private static bool LeftButtonDown() => (GetAsyncKeyState(VkLeftButton) & 0x8000) != 0;
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr hwnd, out EdgeRect rect);
    [DllImport("user32.dll")] private static extern bool ClientToScreen(IntPtr hwnd, ref EdgePoint point);
}
