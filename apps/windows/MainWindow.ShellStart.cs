using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

/// <summary>
/// WIN-STALL-USER: a new local shell (Ctrl+Shift+T, New > Local shell, PowerShell, WSL) starts its program off the UI
/// thread. Starting it creates a pseudoconsole (which starts conhost.exe) and then the shell process; both are process
/// starts that the antivirus scans, and inside the key's frame they cost 28 ms on a quiet run and 90-115 ms on others
/// (q-stall-ab, 'Ctrl+Shift+T new local shell'). The PTY starts at the grid the tab will have, so the new view resizes
/// nothing either. The tab appears once its program has started. Restore and snapshot runs keep the synchronous
/// <see cref="OpenTerminal"/>: they need the tab at once.
/// </summary>
public sealed partial class MainWindow
{
    /// <summary>The PTY size before the view has measured its area (restore, splits); the first layout resizes it.</summary>
    private const int DefaultShellCols = 80, DefaultShellRows = 24;

    /// <summary>Background starts run one after another, so the tabs open in the order they were asked for. UI thread only.</summary>
    private Task _shellStarts = Task.CompletedTask;

    /// <summary>What a local-shell kind starts (Settings > Terminal > New tab, open-local-shells.txt): its tab title and
    /// the start at a grid. The start calls only the core, so it may run on a worker thread.</summary>
    private static (string Title, Func<int, int, TerminalSession> Start) LocalShellStart(string kind) => kind switch
    {
        "powershell" => ("PowerShell", (c, r) => TerminalSession.Spawn("powershell.exe", ["-NoLogo"], c, r)),
        "cmd" => ("Command Prompt", (c, r) => TerminalSession.Spawn("cmd.exe", [], c, r)),
        "wsl" => ("WSL", (c, r) => TerminalSession.Spawn("wsl.exe", [], c, r)),
        _ when LocalShellDistro(kind) is { } distro => (distro, (c, r) => TerminalSession.Wsl(distro, c, r)),
        _ => ("Local shell", (c, r) => TerminalSession.LocalShell(c, r)),
    };

    /// <summary>The distribution of a "wsl:&lt;distro&gt;" kind; null for every other kind.</summary>
    private static string? LocalShellDistro(string kind) => kind.StartsWith("wsl:", StringComparison.Ordinal) ? kind[4..] : null;

    /// <summary>False for a saved WSL distribution that has been removed since. Listing WSL runs wsl.exe, so the new-tab
    /// path asks this on the worker, before the start.</summary>
    private static bool LocalShellInstalled(string kind) => LocalShellDistro(kind) is not { } distro || LocalShells.Distros().Any(d => d.Name == distro);

    private void StartTerminalInBackground((string Title, Func<int, int, TerminalSession> Start) shell) => StartTerminalInBackground(shell.Title, shell.Start, null);

    /// <summary>
    /// Start <paramref name="start"/> on a worker at the new tab's grid, then put it in a tab on the UI thread. A start that
    /// fails is reported as <see cref="OpenTerminal"/> reports it. <paramref name="available"/>, when given, runs first on
    /// the worker; false opens nothing.
    /// </summary>
    private void StartTerminalInBackground(string title, Func<int, int, TerminalSession> start, Func<bool>? available)
    {
        if (_modal is not null) return;
        var grid = NewTabGrid();
        var (cols, rows) = grid ?? (DefaultShellCols, DefaultShellRows);
        var queue = DispatcherQueue;
        _shellStarts = _shellStarts.ContinueWith(_ =>
        {
            TerminalSession? session = null;
            string? error = null;
            try
            {
                if (available?.Invoke() != false) session = start(cols, rows);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { error = ex.Message; } // reported on the UI thread, never lost here
            if (!queue.TryEnqueue(() => ShellStarted(title, session, error, start, grid))) session?.Dispose();
        }, TaskScheduler.Default);
    }

    /// <summary>UI thread: the worker's start finished.</summary>
    private void ShellStarted(string title, TerminalSession? session, string? error, Func<int, int, TerminalSession> start, (int Cols, int Rows)? grid)
    {
        if (_windowClosed) { session?.Dispose(); return; }
        if (session is null)
        {
            if (error is not null && _modal is null) _ = ShowModal("Could not start " + title, ErrorText(error), primary: "OK", cancel: null);
            return;
        }
        // A dialog that opened meanwhile keeps the focus: no tab opens behind it (OpenTerminal opens none while one is open).
        if (_modal is not null) { session.Dispose(); return; }
        AttachLocal(title, session, () => start(DefaultShellCols, DefaultShellRows), grid);
    }

    /// <summary>
    /// The grid of a new local shell tab's terminal: its body fills the session area (no session bar, no Files panel),
    /// which is the session host inside its padding, or the start page's place while no tab is open. Null when that area
    /// is not laid out; the view then sizes the PTY once it is laid out, as before.
    /// </summary>
    private (int Cols, int Rows)? NewTabGrid()
    {
        var host = SessionHost.Visibility == Visibility.Visible ? (FrameworkElement)SessionHost : StartPage;
        // A terminal tab's host has no padding (UI-03): the view pads itself, and GridFor accounts for it.
        var area = new Windows.Foundation.Size(host.ActualWidth, host.ActualHeight);
        if (area.Width <= 0 || area.Height <= 0) return null;
        return TerminalView.GridFor(area, TerminalFontSize, SettingValue("terminal.font-family"));
    }
}
