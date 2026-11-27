using System.Runtime.CompilerServices;
using System.Reflection;

namespace Bastion.Shell;

/// <summary>
/// WIN-SPEED-NIGHT5: the first filter keystroke after launch took 407-427 ms (later ones p95 47 ms) because the filter path
/// was compiled and first run on the UI thread at that keystroke. After the first tree row is painted, a background thread
/// compiles the UI-thread part of that path and runs its data part (match, count) once on the loaded library. Nothing here
/// touches XAML or runs on the UI thread. Under Native AOT the methods are already compiled and PrepareMethod costs nothing.
/// </summary>
public sealed partial class MainWindow
{
    private static readonly string[] FilterPathMethods =
    [
        nameof(ApplyFilter), nameof(ShowRows), nameof(SyncSessionRows), nameof(MarkExpanded), nameof(ExpandFolders),
        nameof(RefreshCredentialsPane), nameof(ApplicationSection), nameof(UpdateInspector), nameof(SearchBox_TextChanged),
    ];

    private bool _filterPrewarmed;

    /// <summary>Called once, when the first tree row is prepared (the window has painted).</summary>
    private void PrewarmFilterPath()
    {
        if (_filterPrewarmed) return;
        _filterPrewarmed = true;
        var roots = _roots; // the list is replaced, never changed in place, so this snapshot is safe to read off the UI thread
        _ = Task.Run(() =>
        {
            try
            {
                const BindingFlags Any = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
                foreach (var name in FilterPathMethods)
                    foreach (var m in typeof(MainWindow).GetMethods(Any))
                        if (m.Name == name && !m.ContainsGenericParameters) RuntimeHelpers.PrepareMethod(m.MethodHandle);
                // The data part: a query that matches nothing walks every item and copies none.
                _ = TreeItem.Filter(roots, "\u0001prewarm");
                _ = TreeItem.Filter(roots, "tag:\u0001prewarm");
                _ = TreeItem.CountConnections(roots);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // A warm-up only: the first keystroke is slower without it, nothing else changes.
                System.Diagnostics.Debug.WriteLine("Filter warm-up skipped: " + ex.Message);
            }
        });
    }

    /// <summary>After the first row is painted: the start-up has finished its own work by then (WIN-COLD gates).</summary>
    private static readonly TimeSpan TerminalWarmDelay = TimeSpan.FromSeconds(2);

    /// <summary>The bundled terminal font (TerminalView.BundledFont), relative to the app folder.</summary>
    private static readonly string TerminalFontFile = Path.Combine("Fonts", "JetBrainsMonoNerdFontMono-Regular.ttf");

    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _terminalWarmTimer;

    /// <summary>
    /// WIN-STALL-USER: the first new terminal loaded its font inside the key's frame (cell measure, q-stall-ab). Once, a
    /// little after the first row is painted, a worker reads the bundled font file (the file cache, as ColdPrefetch does;
    /// the bytes are discarded), then the UI thread measures the default terminal font at idle priority, which loads it
    /// and keeps its cell metrics (TerminalView.Cells.cs). Called once, with the filter warm-up.
    /// </summary>
    private void PrewarmTerminal()
    {
        if (_terminalWarmTimer is not null) return;
        var queue = DispatcherQueue;
        _terminalWarmTimer = queue.CreateTimer();
        _terminalWarmTimer.Interval = TerminalWarmDelay;
        _terminalWarmTimer.IsRepeating = false;
        _terminalWarmTimer.Tick += (_, _) =>
        {
            _terminalWarmTimer?.Stop();
            var dir = AppContext.BaseDirectory;
            _ = Task.Run(() => ColdPrefetch.ReadAll(dir, [TerminalFontFile]))
                .ContinueWith(_ => queue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, WarmTerminalFont), TaskScheduler.Default);
        };
        _terminalWarmTimer.Start();
    }

    private void WarmTerminalFont()
    {
        if (_windowClosed) return;
        try { TerminalView.Warm(TerminalFontSize, SettingValue("terminal.font-family")); }
        catch (Exception ex) when (ex is ArgumentException or System.Runtime.InteropServices.COMException)
        {
            // A warm-up only: the first terminal then measures its font itself, as before.
            System.Diagnostics.Debug.WriteLine("Terminal font warm-up skipped: " + ex.Message);
        }
    }
}
