using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        StartupProbe.Mark("app");
        // Bastion -> Gantry, once, before any data folder is read. Test libraries never use the real folders.
        if (TestHooks.LibraryOverride is null) AppRename.MigrateDataFolders();
        // No native prefetch here (WIN-COLD-START): loading bastion_cabi.dll on a worker during the XAML start-up held the
        // loader lock, and the UI thread waited behind it for 1.2-2.4 s on a first launch. Loaded where the library
        // opens, the DLL takes ~0.8 s and XAML ~0.16 s (q-cold-ab: median 1881 ms against 2128 ms with the prefetch).
#if BASTION_TEST_HOOKS
        // WIN-AOT diagnostics (test builds only): App.xaml parse errors happen before the handlers below exist, so
        // write them to stderr and rethrow.
        DebugSettings.XamlResourceReferenceFailed += (_, e) => Console.Error.WriteLine("XamlResourceReferenceFailed: " + e.Message);
        DebugSettings.BindingFailed += (_, e) => Console.Error.WriteLine("BindingFailed: " + e.Message);
        try { InitializeComponent(); }
        catch (Exception ex) { Console.Error.WriteLine("App.InitializeComponent failed: " + ex); Console.Error.Flush(); throw; }
        UnhandledException += (_, e) => { Console.Error.WriteLine("UnhandledException: " + e.Message + "\n" + e.Exception); Console.Error.Flush(); };
        // PLUG-OPEN-WIN crash hunt (test builds only): 0xC000027B leaves no crash.log, so write every exception to
        // bastion.log as it is thrown. AppLog appends and closes the file on each line, so the line survives the crash.
        UnhandledException += (_, e) => AppLog.Error($"XAML UnhandledException: {e.Message} | {e.Exception}");
        AppDomain.CurrentDomain.FirstChanceException += (_, e) =>
        {
            if (_inFirstChance) return;
            _inFirstChance = true;
            try { AppLog.Warn($"First-chance {e.Exception.GetType().FullName} 0x{e.Exception.HResult:X8}: {e.Exception.Message} | {e.Exception.StackTrace}"); }
            finally { _inFirstChance = false; }
        };
#else
        InitializeComponent();
#endif
        // Diagnostics: BASTION_LAYOUT_TRACE=1 writes WinUI's layout-cycle trace to the debug output (DBWIN listeners).
        if (TestHooks.LayoutTrace)
            DebugSettings.LayoutCycleTracingLevel = Microsoft.UI.Xaml.LayoutCycleTracingLevel.High;
        StartupProbe.Mark("app-resources");
        UnhandledException += (_, e) =>
        {
            StartupProbe.Fail(e.Exception);
            // In snapshot mode there is no one to read a dialog: record the failure and exit non-zero.
            if (SnapshotRunner.Active)
            {
                SnapshotRunner.Fail(e.Exception);
                e.Handled = true;
                return;
            }
            CrashLog.Write(e.Exception);
        };
        AppDomain.CurrentDomain.UnhandledException += (_, e) => CrashLog.Write(e.ExceptionObject as Exception);
    }

#if BASTION_TEST_HOOKS
    [ThreadStatic] private static bool _inFirstChance;
#endif

    /// <summary>The Personal document when this launch uses it; its vault replaces credentials.vault.</summary>
    internal static PersonalDocument? Personal { get; private set; }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        StartupProbe.Mark("launched");
        var snapshot = SnapshotRunner.FromEnvironment();
        // The window opens the library itself, after its base constructor and XAML (WIN-COLD-START round 4).
        Func<LibraryClient> open = () => OpenLibrary(snapshot);
        if (TestHooks.ColdLibraryFirst) open = OpenedFirst(open); // the old order, for a cold-start A/B in one build
        var main = new MainWindow(open, readOnlyDemo: snapshot is not null);
        if (main.OpenError is { } error)
        {
            if (snapshot is not null)
            {
                SnapshotRunner.Fail(error);
                return;
            }
            // Under the start-up probe nobody reads this window: record why and let the budget script fail fast.
            StartupProbe.Fail(error);
            if (StartupProbe.Active) { Exit(); return; }
            _window = main; // it shows why the library did not open
            main.Activate();
            return;
        }
        StartupProbe.Mark("window");
        _window = main;
        main.Activate();
        StartupProbe.Mark("activated");
        StartupProbe.Arm(main);
        if (snapshot is not null) _ = SnapshotRunner.RunAsync(main, snapshot);
    }

    /// <summary>Opens the library: the snapshot's demo file, the Personal document, or library.json. Throws on failure.</summary>
    private static LibraryClient OpenLibrary(SnapshotOptions? snapshot)
    {
        var path = snapshot?.LibraryPath ?? LibraryLocation.Resolve();
        // Owner points 7, 20: Personal is one encrypted .bastion document (the old files move in once).
        LibraryClient library;
        if (snapshot is null && PersonalDocument.Enabled)
        {
            Personal = PersonalDocument.Open(path);
            library = Personal.Library();
        }
        else library = LibraryClient.Open(path);
        if (snapshot is not null) SnapshotRunner.SeedDemoData(library);
        return library;
    }

    /// <summary>Test builds (BASTION_COLD_LIBRARY_FIRST=1): open now, before the window, and hand over the result.</summary>
    private static Func<LibraryClient> OpenedFirst(Func<LibraryClient> open)
    {
        try
        {
            var library = open();
            StartupProbe.Mark("library-first");
            return () => library;
        }
        catch (Exception e)
        {
            return () => throw e;
        }
    }
}

/// <summary>Where the library file lives.</summary>
public static class LibraryLocation
{
    /// <summary>%APPDATA%\Gantry\library.json, the real library.</summary>
    public static string Default => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Gantry", "library.json");

    /// <summary>The test library (TestHooks.LibraryOverride, test builds only), otherwise the default. The parent folder
    /// is created if missing.</summary>
    public static string Resolve()
    {
        var env = TestHooks.LibraryOverride;
        var path = string.IsNullOrWhiteSpace(env) ? Default : Path.GetFullPath(env);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        return path;
    }

    public static bool IsDefault(string path) =>
        string.Equals(Path.GetFullPath(path), Path.GetFullPath(Default), StringComparison.OrdinalIgnoreCase);
}

/// <summary>Appends unhandled exceptions to %LOCALAPPDATA%\Bastion\crash.log, so a crash at start-up (a XAML stowed exception
/// ends the process with no dialog) leaves a reason behind. Kept under 256 KB; never throws.</summary>
public static class CrashLog
{
    private const long MaxBytes = 256 * 1024;

    public static string Path => System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Gantry", "crash.log");

    public static void Write(Exception? e)
    {
        if (e is null) return;
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            if (File.Exists(Path) && new FileInfo(Path).Length > MaxBytes) File.Delete(Path);
            File.AppendAllText(Path, $"{DateTime.Now:O} pid {Environment.ProcessId} {Environment.ProcessPath}\r\n{e}\r\n\r\n");
        }
        catch
        {
            // Nothing sensible to do while the process is already failing.
        }
    }
}
