using System.Runtime.InteropServices;
using Microsoft.UI.Windowing;

namespace Bastion.Shell;

// Dialogs never hide behind another window. Every dialog is the in-window modal (see MainWindow.xaml.cs), so one raised
// while the window is minimised, or while another app is in front (a connect that fails late, a host-key or password
// prompt, confirm-close from the tray), would wait unseen. Presenting one restores the window and asks for the
// foreground; when Windows refuses it (another app has the user's input), the taskbar button flashes until the
// window is activated, as Windows asks apps to do instead of stealing focus.
public sealed partial class MainWindow
{
    private const uint FLASHW_TRAY = 0x2, FLASHW_TIMERNOFG = 0xC;

    [StructLayout(LayoutKind.Sequential)]
    private struct FlashInfo { public uint Size; public IntPtr Hwnd; public uint Flags; public uint Count; public uint Timeout; }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hwnd);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("user32.dll")]
    private static extern bool FlashWindowEx(ref FlashInfo info);

    private const int SW_RESTORE = 9;

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr hwnd);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hwnd, int cmd);

    /// <summary>Show the window so a dialog on it can be seen: restore if minimised or hidden, then come forward or flash.</summary>
    private void BringForwardForDialog()
    {
        if (_demo) return; // snapshot and demo runs never take the shared desktop's foreground
        if (_modalOverSettings && _settingsWindow is { } settings) { settings.Activate(); return; } // the dialog is on Settings
        var hwnd = Hwnd;
        // The window's own state, not the presenter's: OverlappedPresenter.State is stale for a window minimised from
        // outside (taskbar, ShowWindow), and Restore() is ignored while AppWindow.Closing is being raised.
        if (IsIconic(hwnd)) ShowWindow(hwnd, SW_RESTORE);
        else if (AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Minimized } presenter) presenter.Restore();
        if (!AppWindow.IsVisible) AppWindow.Show();
        if (GetForegroundWindow() == hwnd || SetForegroundWindow(hwnd)) return;
        var flash = new FlashInfo { Size = (uint)Marshal.SizeOf<FlashInfo>(), Hwnd = hwnd, Flags = FLASHW_TRAY | FLASHW_TIMERNOFG };
        FlashWindowEx(ref flash);
    }
}
