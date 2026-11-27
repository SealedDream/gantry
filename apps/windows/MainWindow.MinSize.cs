using System.Runtime.InteropServices;

namespace Bastion.Shell;

// The main window's minimum size (WindowMinWidth x WindowMinHeight logical pixels, scaled to the window's DPI and zoom).
// OverlappedPresenter.PreferredMinimumWidth/Height alone let a programmatic resize (SetWindowPos) shrink the window to
// 300x200 (library-ui-test, main 9a6e126f6 and #1245). Windows asks the window for its limits with WM_GETMINMAXINFO on
// every resize, by mouse or by code; answering it here holds the minimum for both.
public sealed partial class MainWindow
{
    private const uint WM_GETMINMAXINFO = 0x0024;
    private const nuint MinSizeSubclassId = 0x4241_4D4E; // "BAMN"
    /// <summary>MINMAXINFO.ptMinTrackSize: after ptReserved, ptMaxSize and ptMaxPosition (three POINTs of 8 bytes).</summary>
    private const int MinTrackSizeOffset = 24;

    /// <summary>Kept in a field so the delegate the native side calls is never collected.</summary>
    private SubclassProc? _minSizeProc;

    private void InitMinimumSize()
    {
        _minSizeProc = OnMinMaxMessage;
        var hwnd = Hwnd;
        try
        {
            if (!SetWindowSubclass(hwnd, _minSizeProc, MinSizeSubclassId, 0))
            {
                TraceLine($"min-size subclass failed error={Marshal.GetLastWin32Error()}");
                return;
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            TraceLine("min-size subclass unavailable");
            return;
        }
        Closed += (_, _) => RemoveWindowSubclass(hwnd, _minSizeProc, MinSizeSubclassId);
    }

    /// <summary>
    /// The minimum in screen pixels. appearance.zoom lays RootGrid out at the window size divided by the zoom
    /// (MainWindow.Zoom.cs), so the minimum scales with it too: the layout never gets less than WindowMinWidth x
    /// WindowMinHeight logical pixels, the size every surface is designed for (WIN-EVEN-01: at 150 % an 800 px window
    /// gave 533 and the Files panel ran past the edge).
    /// </summary>
    private (int Width, int Height) MinimumWindowSize(IntPtr hwnd)
    {
        var scale = Math.Max(96u, GetDpiForWindow(hwnd)) / 96.0 * _zoomFactor;
        return ((int)Math.Ceiling(Ui.Double("WindowMinWidth") * scale), (int)Math.Ceiling(Ui.Double("WindowMinHeight") * scale));
    }

    private IntPtr OnMinMaxMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam, nuint id, nuint refData)
    {
        var result = DefSubclassProc(hwnd, msg, wParam, lParam);
        if (msg != WM_GETMINMAXINFO || lParam == IntPtr.Zero) return result;
        var (minWidth, minHeight) = MinimumWindowSize(hwnd);
        // Raise only: a larger minimum set by the framework stays.
        Marshal.WriteInt32(lParam, MinTrackSizeOffset, Math.Max(Marshal.ReadInt32(lParam, MinTrackSizeOffset), minWidth));
        Marshal.WriteInt32(lParam, MinTrackSizeOffset + 4, Math.Max(Marshal.ReadInt32(lParam, MinTrackSizeOffset + 4), minHeight));
        return result;
    }
}
