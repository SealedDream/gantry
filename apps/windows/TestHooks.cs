namespace Bastion.Shell;

/// <summary>
/// Test seams that UI tests drive through environment variables. They only exist in test builds
/// (dotnet build -p:BastionTestHooks=true defines BASTION_TEST_HOOKS). An owner build returns null for every seam
/// and does not even contain the variable names, so nothing in the environment can steer it.
/// </summary>
internal static class TestHooks
{
#if BASTION_TEST_HOOKS
    private static string? Env(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : null;

    /// <summary>BASTION_UITEST_EXPORT_PATH: SSH and library export write here without the save dialog.</summary>
    public static string? ExportPath => Env("BASTION_UITEST_EXPORT_PATH");
    /// <summary>BASTION_UITEST_IMPORT_PATH: File › Import Connections imports this file without the open dialog.</summary>
    public static string? ImportPath => Env("BASTION_UITEST_IMPORT_PATH");
    /// <summary>BASTION_PLUGIN_MIRROR: the Plugins page refreshes the catalogue from this folder, not the official one (PLUG-06b).</summary>
    public static string? PluginMirror => Env("BASTION_PLUGIN_MIRROR");
    /// <summary>BASTION_UITEST_PLUGIN_PATH: Install from File uses this file without the open dialog (PLUG-06b).</summary>
    public static string? PluginInstallPath => Env("BASTION_UITEST_PLUGIN_PATH");
    /// <summary>BASTION_UITEST_TRIGGERS_PATH: trigger import and export use this file without the file dialogs.</summary>
    public static string? TriggersPath => Env("BASTION_UITEST_TRIGGERS_PATH");
    /// <summary>BASTION_HOOK_TRACE=<file>: one line per task hook run, refusal and snippet send (B5; never a secret).</summary>
    public static string? HookTrace => Env("BASTION_HOOK_TRACE");
    /// <summary>PLUG-PG-REDO-WIN: log every key event at the plugin tab root and the SQL editor (test runs only).</summary>
    public static bool KeyTrace => Env("BASTION_KEY_TRACE") == "1";
    /// <summary>BASTION_DYN_TRACE=<file>: one line per dynamic-folder bind, trust, refresh and result (B15; never output).</summary>
    public static string? DynamicTrace => Env("BASTION_DYN_TRACE");
    /// <summary>BASTION_UITEST_KEEPASS_PATH: Import KeePass File opens this .kdbx without the open dialog (B8).</summary>
    public static string? KeePassPath => Env("BASTION_UITEST_KEEPASS_PATH");
    /// <summary>BASTION_UITEST_ANSIBLE_DIR: Ansible export and run inventories go here without the save dialog.</summary>
    public static string? AnsibleDir => Env("BASTION_UITEST_ANSIBLE_DIR");
    /// <summary>BASTION_TRACE_DRAG=1: credential drag decisions go to %TEMP%\bastion-drag.txt.</summary>
    public static bool TraceDrag => Env("BASTION_TRACE_DRAG") == "1";
    /// <summary>BASTION_LOCK_TRACE: file that records each lock outcome.</summary>
    public static string? LockTrace => Env("BASTION_LOCK_TRACE");
    /// <summary>BASTION_NET_TRACE: file that records network-change handling.</summary>
    public static string? NetTrace => Env("BASTION_NET_TRACE");
    /// <summary>BASTION_LAYOUT_TRACE=1: WinUI layout-cycle trace to the debug output.</summary>
    public static bool LayoutTrace => Env("BASTION_LAYOUT_TRACE") == "1";
    /// <summary>BASTION_COLD_LIBRARY_FIRST=1: open the library before the main window, the order before WIN-COLD-START round 4 (A/B).</summary>
    public static bool ColdLibraryFirst => Env("BASTION_COLD_LIBRARY_FIRST") == "1";
    /// <summary>BASTION_COLD_PRESCAN=0: no early image section for the core DLL (cold-start A/B in one build).</summary>
    public static bool ColdPrescanOff => Env("BASTION_COLD_PRESCAN") == "0";
    /// <summary>BASTION_COLD_PREFETCH=0: no early sequential read of the start-up files (cold-start A/B in one build).</summary>
    public static bool ColdPrefetchOff => Env("BASTION_COLD_PREFETCH") == "0";
    /// <summary>BASTION_COLD_EAGER=1: build the title bar, details pane, Credentials section and Recent sessions before the
    /// first frame, as before WIN-COLD-LIGHT, so the lighter first window is A/B-tested in one build.</summary>
    public static bool ColdEager => Env("BASTION_COLD_EAGER") == "1";
    /// <summary>UI-06: act as if Windows high contrast were on for the window tones only (the system setting stays).</summary>
    public static bool WindowTonesHighContrast => Env("BASTION_TEST_TONES_HIGH_CONTRAST") == "1";
    /// <summary>BASTION_TABBAR_TRACE=<file>: one line per tab-bar layout (widths, the cap, the scroll arrows).</summary>
    public static string? TabBarTrace => Env("BASTION_TABBAR_TRACE");
    /// <summary>BASTION_LIBRARY: a throwaway library file instead of %APPDATA%\Bastion\library.json. While it is set the
    /// launch skips the Personal document and the unlock gate unless the two switches below turn them back on.</summary>
    public static string? LibraryOverride => Env("BASTION_LIBRARY");
    /// <summary>BASTION_PERSONAL_DOCUMENT=1: use the Personal document under a test library.</summary>
    public static bool PersonalDocumentOptIn => Env("BASTION_PERSONAL_DOCUMENT") == "1";
    /// <summary>BASTION_PERSONAL_PATH: where Personal.bastion lives for a test.</summary>
    public static string? PersonalPathOverride => Env("BASTION_PERSONAL_PATH");
    /// <summary>BASTION_DOCUMENT_GATE=1: the unlock gate stays on under a test library.</summary>
    public static bool DocumentGateOptIn => Env("BASTION_DOCUMENT_GATE") == "1";
    /// <summary>BASTION_WEB_FIXTURE: a folder served at https://autofill.test/ inside web tabs (WebView2 virtual host), so the
    /// Fill sign-in proof needs no certificate in the machine's trust store. Test builds only.</summary>
    public static string? WebFixtureDir => Env("BASTION_WEB_FIXTURE");
    /// <summary>BASTION_UITEST_WEBFILL=1 (B13): seed the vault test login and the web connections "fill-on" (switch on) and
    /// "fill-off" at https://autofill.test/login.html, so the web sign-in fill suite needs no vault UI.</summary>
    public static bool WebFillSeed => Env("BASTION_UITEST_WEBFILL") == "1";
    /// <summary>BASTION_UITEST_PVE_SEED=port (PLUG-PVE-02): seed the Proxmox fixture, a synthetic vault token and a pinned
    /// entry for the mock Proxmox API on 127.0.0.1:port (MainWindow.PveSeedTestHook.cs).</summary>
    public static int? PveSeedPort => int.TryParse(Env("BASTION_UITEST_PVE_SEED"), out var p) && p is > 0 and < 65536 ? p : null;
    /// <summary>BASTION_UITEST_K8S_SEED=port (PLUG-K8S-01): seed the Kubernetes fixture, a synthetic bearer token and a
    /// pinned entry for the mock Kubernetes API on 127.0.0.1:port (MainWindow.K8sSeedTestHook.cs).</summary>
    public static int? K8sSeedPort => int.TryParse(Env("BASTION_UITEST_K8S_SEED"), out var p) && p is > 0 and < 65536 ? p : null;
    /// <summary>BASTION_UITEST_VMW_SEED=port (PLUG-VMW-01): seed the VMware fixture, a synthetic vault login and a pinned
    /// entry for the mock vCenter API on 127.0.0.1:port (MainWindow.VmwSeedTestHook.cs).</summary>
    public static int? VmwSeedPort => int.TryParse(Env("BASTION_UITEST_VMW_SEED"), out var p) && p is > 0 and < 65536 ? p : null;
    /// <summary>BASTION_UITEST_VMW_SEED_TYPE=esxi (VMW-ESXI): the VMware seed adds a standalone ESXi entry "esxi-mock"
    /// (type esxi, login user root) instead of the vCenter one.</summary>
    public static bool VmwSeedEsxi => Env("BASTION_UITEST_VMW_SEED_TYPE") == "esxi";
    /// <summary>BASTION_UITEST_PG_SEED=host:port:database:user (PG-LIVE): install the signed PostgreSQL pack
    /// (BASTION_UITEST_PLUGIN_PATH, signature required) and add the entry "pg-live" on system trust, its login's password read
    /// at run time from BASTION_UITEST_PG_PASSWORD_FILE (MainWindow.PgSeedTestHook.cs). The password is never logged.</summary>
    public static string? PgSeed => Env("BASTION_UITEST_PG_SEED");
    public static string? PgPasswordFile => Env("BASTION_UITEST_PG_PASSWORD_FILE");
    /// <summary>BASTION_UITEST_EXEC_SEED=host:port:user (PLUG-EXEC-01): install the exec fixture and add the entry
    /// "exec-lab" with the SSH key read from BASTION_UITEST_EXEC_KEY_FILE as its login (MainWindow.ExecSeedTestHook.cs).</summary>
    public static string? ExecSeed => Env("BASTION_UITEST_EXEC_SEED");
    public static string? ExecKeyFile => Env("BASTION_UITEST_EXEC_KEY_FILE");
    /// <summary>BASTION_WEBFILL_TRACE=<file>: one line per Fill sign-in click: the page origin and the notice, never a value.</summary>
    public static string? WebFillTrace => Env("BASTION_WEBFILL_TRACE");
    /// <summary>BASTION_SESSION_TREE_TRACE: file that records each session-tree update (rows touched, ms, full reloads; UI-05).</summary>
    public static string? SessionTreeTrace => Env("BASTION_SESSION_TREE_TRACE");
    /// <summary>BASTION_TREE_INPUT_LOG=<file>: library tree pointer, selection and menu events (WIN-FLAT-TREE).</summary>
    public static string? TreeInputLog => Env("BASTION_TREE_INPUT_LOG");
    /// <summary>BASTION_FILTER_REBIND=1: search swaps the tree's ItemsSource as before WIN-FILTER-INPLACE (speed A/B).</summary>
    public static bool FilterRebind => Env("BASTION_FILTER_REBIND") == "1";
    /// <summary>BASTION_RDP_OPTIONS_LOG: file that gets one JSON line per RDP connect with the options handed to rdp-ffi
    /// (host, port, redirection, colour depth; never a login or password).</summary>
    public static string? RdpOptionsLog => Env("BASTION_RDP_OPTIONS_LOG");
    /// <summary>BASTION_DESKTOP_FIT_LOG: file that gets one line per desktop size asked of a server (RDP connect, live
    /// resize; RDP-VNC-FIT). Sizes only.</summary>
    public static string? DesktopFitLog => Env("BASTION_DESKTOP_FIT_LOG");

    /// <summary>WIN-SINGLE-UNLOCK: a mocked Windows Hello answer (verified, canceled, unavailable, failed). Never real Hello.</summary>
    public static string? HelloMock => Env("BASTION_UITEST_HELLO");

    /// <summary>WIN-SINGLE-UNLOCK: one line "hello-prompt" per Windows Hello prompt, so a test can count them. No secrets.</summary>
    public static string? HelloTrace => Env("BASTION_HELLO_TRACE");
#else
    public static string? ExportPath => null;
    public static string? ImportPath => null;
    public static string? PluginMirror => null;
    public static string? PluginInstallPath => null;
    public static string? TriggersPath => null;
    public static string? HookTrace => null;
    public static bool KeyTrace => false;
    public static string? DynamicTrace => null;
    public static string? KeePassPath => null;
    public static string? AnsibleDir => null;
    public static bool TraceDrag => false;
    public static string? LockTrace => null;
    public static string? NetTrace => null;
    public static bool LayoutTrace => false;
    public static bool ColdLibraryFirst => false;
    public static bool ColdPrescanOff => false;
    public static bool ColdPrefetchOff => false;
    public static bool ColdEager => false;
    public static bool WindowTonesHighContrast => false;
    public static string? TabBarTrace => null;
    // LIBRARY-ENV-GATE: an owner build always opens the user's own library, the Personal document and the unlock gate.
    public static string? LibraryOverride => null;
    public static bool PersonalDocumentOptIn => false;
    public static string? PersonalPathOverride => null;
    public static bool DocumentGateOptIn => false;
    public static string? SessionTreeTrace => null;
    public static string? TreeInputLog => null;
    public static bool FilterRebind => false;
    public static string? RdpOptionsLog => null;
    public static string? DesktopFitLog => null;
    public static string? WebFixtureDir => null; // owner builds never map a host
    public static bool WebFillSeed => false;
    public static int? PveSeedPort => null;
    public static int? K8sSeedPort => null;
    public static int? VmwSeedPort => null;
    public static bool VmwSeedEsxi => false;
    public static string? WebFillTrace => null;
    public static string? HelloMock => null; // owner builds always ask the real Windows Hello
    public static string? HelloTrace => null;
#endif

    /// <summary>Test builds: count a Windows Hello prompt in <see cref="HelloTrace"/>.</summary>
    public static void TraceHelloPrompt() => TraceHello("hello-prompt");

    /// <summary>Test builds: one line "hello-<step> <result>" (a result code or exception type, never a secret).</summary>
    public static void TraceHello(string line)
    {
        if (HelloTrace is not { } path) return;
        try { File.AppendAllText(path, line + Environment.NewLine); }
        catch (IOException e) { System.Diagnostics.Debug.WriteLine($"hello trace: {e.Message}"); }
    }

    /// <summary>Test builds: one line "<what> <fit> <w>x<h>" to <see cref="DesktopFitLog"/>.</summary>
    public static void LogDesktopFit(DesktopFit fit, int width, int height, string what = "resize")
    {
        if (DesktopFitLog is not { } path) return;
        try { File.AppendAllText(path, $"{what} {fit.ToString().ToLowerInvariant()} {width}x{height}{Environment.NewLine}"); }
        catch (IOException e) { System.Diagnostics.Debug.WriteLine($"desktop fit log: {e.Message}"); }
    }
}
