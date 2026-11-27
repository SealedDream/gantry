using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;

namespace Bastion.Shell;

// Notification-area icon (TrayIcon.cs). Added after start-up work so it costs nothing before the first frame;
// never in demo or snapshot runs. Closing the window still quits, as in Bastion Tauri.
public sealed partial class MainWindow
{
    private TrayIcon? _tray;
    private bool _trayClosed;

    private void InitTray()
    {
        if (_demo) return;
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            if (_trayClosed || _tray is not null) return;
            // The window works without the icon (no notification area, e.g. some kiosk shells); the failure is not hidden from tests.
            try { _tray = new TrayIcon(Hwnd, AppIconPath(), ShowFromTray, () => Close()); }
            catch (InvalidOperationException ex) { System.Diagnostics.Debug.WriteLine($"Gantry: tray icon not added: {ex.Message}"); }
        });
    }

    private void ShowFromTray()
    {
        if (AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Minimized } presenter) presenter.Restore();
        AppWindow.Show();
        Activate();
    }

    private void DisposeTray()
    {
        _trayClosed = true;
        _tray?.Dispose();
        _tray = null;
    }
}
