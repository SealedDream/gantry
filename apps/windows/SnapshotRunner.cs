using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices.WindowsRuntime;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;

namespace Bastion.Shell;

/// <param name="Width">Window width in pixels (BASTION_SNAPSHOT_SIZE=WxH), or null for the default size.</param>
/// <param name="Scale">Render scale (BASTION_SNAPSHOT_SCALE). 1.5 renders the same layout into 1.5x the pixels with
/// RenderTargetBitmap: a pixel-scaled render, not a real 150% DPI test.</param>
internal sealed record SnapshotOptions(string Dir, string LibraryPath, int? Width, int? Height, double Scale);

#if BASTION_TEST_HOOKS
/// <summary>
/// BASTION_SNAPSHOT=&lt;dir&gt; mode: render the main window in light and dark (shell with a selection, the New folder
/// dialog, its validation message, the New connection dialog, a PowerShell tab, the empty library) with
/// RenderTargetBitmap, write timings.txt (theme switch, dialog open) and exit. It uses demo data in a throwaway
/// library and never saves; it refuses to run against the real library (%APPDATA%\Bastion\library.json).
/// </summary>
internal static class SnapshotRunner
{
    public const string EnvVar = "BASTION_SNAPSHOT";
    private static string? _dir;

    public static bool Active => _dir is not null;

    public static SnapshotOptions? FromEnvironment()
    {
        var dir = Environment.GetEnvironmentVariable(EnvVar);
        if (string.IsNullOrWhiteSpace(dir)) return null;
        _dir = Path.GetFullPath(dir);
        Directory.CreateDirectory(_dir);

        var lib = TestHooks.LibraryOverride;
        if (string.IsNullOrWhiteSpace(lib))
        {
            // No library given: use a fresh throwaway one, never the real one.
            var temp = Path.Combine(Path.GetTempPath(), "bastion-snapshot-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);
            lib = Path.Combine(temp, "library.json");
        }
        lib = Path.GetFullPath(lib);
        if (LibraryLocation.IsDefault(lib))
        {
            Fail(new InvalidOperationException($"{EnvVar} refuses to use the real library at {lib}. Point BASTION_LIBRARY at a throwaway file."), exitCode: 2);
        }

        int? width = null, height = null;
        var size = Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_SIZE")?.Split('x', 'X');
        if (size is { Length: 2 } && int.TryParse(size[0], out var w) && int.TryParse(size[1], out var h)) (width, height) = (w, h);
        var scale = double.TryParse(Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_SCALE"), NumberStyles.Float, CultureInfo.InvariantCulture, out var s) && s > 0 ? s : 1.0;
        return new SnapshotOptions(_dir, lib, width, height, scale);
    }

    /// <summary>Fill an empty throwaway library with in-memory demo data (it is never saved). No secrets.</summary>
    public static void SeedDemoData(LibraryClient lib)
    {
        if (lib.Tree() is { Folders.Count: > 0 } or { Connections.Count: > 0 }) return;

        var acme = lib.AddFolder(null, "Acme Corp");
        lib.AddConnection(acme, "web-1", "ssh", "web-1.acme.example", null, "ops");
        lib.AddConnection(acme, "web-2", "ssh", "web-2.acme.example", null, "ops");
        lib.AddConnection(acme, "db-1", "ssh", "db-1.acme.example", 2222, "dba");
        lib.AddConnection(acme, "backup-sftp", "sftp", "files.acme.example", null, "backup");

        var globex = lib.AddFolder(null, "Globex");
        lib.AddConnection(globex, "erp-desktop", "rdp", "erp.globex.example", null, "svc-erp");
        lib.AddConnection(globex, "legacy-ftp", "ftps", "10.0.0.5", 990, null);
        var staging = lib.AddFolder(globex, "Staging");
        lib.AddConnection(staging, "stage-web", "web", "stage.globex.example", null, null);

        lib.AddConnection(null, "home-nas", "sftp", "nas.home.example", null, "admin");
        lib.AddConnection(null, "lab-console", "vnc", "10.1.1.20", null, null);
    }

    public static async Task RunAsync(MainWindow window, SnapshotOptions options)
    {
        try
        {
            if (options.Width is { } w && options.Height is { } h) window.AppWindow.Resize(new Windows.Graphics.SizeInt32(w, h));
            await Task.Delay(1500); // first layout and render
            var root = window.RootElement;
            var timings = new List<string> { $"window {options.Width?.ToString() ?? "default"}x{options.Height?.ToString() ?? "default"}, render scale {options.Scale.ToString(CultureInfo.InvariantCulture)}" };
            var themes = new[] { (ElementTheme.Light, "light"), (ElementTheme.Dark, "dark") };

            if (!window.SelectByName("web-1")) throw new InvalidOperationException("demo data is missing web-1");
            await Task.Delay(600);

            // Theme switch: RequestedTheme on the root, then a synchronous layout pass, then the next frame.
            var layoutMs = new List<double>();
            var frameMs = new List<double>();
            for (var i = 0; i < 6; i++)
            {
                var sw = Stopwatch.StartNew();
                root.RequestedTheme = i % 2 == 0 ? ElementTheme.Light : ElementTheme.Dark;
                root.UpdateLayout();
                layoutMs.Add(sw.Elapsed.TotalMilliseconds);
                await NextFrame();
                frameMs.Add(sw.Elapsed.TotalMilliseconds);
                await Task.Delay(300);
            }
            timings.Add($"theme switch, populated shell (6 switches): layout median {Median(layoutMs):F1} ms (max {layoutMs.Max():F1}), next frame median {Median(frameMs):F1} ms (max {frameMs.Max():F1})");

            await CaptureBoth(root, themes, options, "");

            // BASTION_SNAPSHOT_NAV=1: the navigation pane collapsed from the status-bar button, then shown again.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_NAV") == "1")
            {
                var nav = new List<string> { "collapsed: " + window.ToggleNavForSnapshot() };
                await Task.Delay(300);
                await CaptureBoth(root, themes, options, "nav-collapsed-");
                nav.Add("shown: " + window.ToggleNavForSnapshot());
                await Task.Delay(300);
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "nav.txt"), nav);
            }

            // BASTION_SNAPSHOT_POLICY=1 (with BASTION_UI_SCRIPT and BASTION_UI_POLICY pointing at a test policy): Settings ›
            // Managed Policy, and the RDP/web gate the core answers for this policy.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_POLICY") == "1")
            {
                var policy = new List<string> { MainWindow.PolicyLinesForSnapshot() };
                foreach (var protocol in new[] { "rdp", "web", "ssh" })
                {
                    try { PolicyClient.CheckProtocol(protocol); policy.Add($"{protocol}: allowed"); }
                    catch (BastionException ex) { policy.Add($"{protocol}: refused ({ex.Message})"); }
                }
                window.OpenPolicyPageForSnapshot();
                await Task.Delay(400);
                await CaptureBoth(window.SettingsRootForSnapshot ?? root, themes, options, "policy-");
                window.CloseSettings();
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "policy.txt"), policy);
            }

            // The New folder dialog, opened over a folder so its destination caption shows.
            window.SelectByName("Acme Corp");
            await Task.Delay(400);
            var open = Stopwatch.StartNew();
            _ = window.NewFolderAsync();
            root.UpdateLayout();
            var openLayout = open.Elapsed.TotalMilliseconds;
            await NextFrame();
            timings.Add($"New folder dialog open: layout {openLayout:F1} ms, next frame {open.Elapsed.TotalMilliseconds:F1} ms");
            await CaptureBoth(root, themes, options, "folder-");
            window.PressModalPrimaryForSnapshot(); // empty name: shows the inline validation message
            await CaptureBoth(root, themes, options, "folder-error-");
            window.CancelModalForSnapshot();

            _ = window.NewConnectionAsync();
            await CaptureBoth(root, themes, options, "connection-");
            window.CancelModalForSnapshot();

            // B9 templates: Save as template, New from template (three token fields), Templates (list and fields).
            _ = window.SaveAsTemplateForSnapshot("web-1");
            await CaptureBoth(root, themes, options, "template-save-");
            window.CancelModalForSnapshot();
            window.SeedTemplateForSnapshot("web-1");
            _ = window.NewFromTemplateAsync();
            await CaptureBoth(root, themes, options, "template-new-");
            window.PressModalPrimaryForSnapshot(); // empty tokens: shows the inline message
            await CaptureBoth(root, themes, options, "template-new-error-");
            window.CancelModalForSnapshot();
            _ = window.ManageTemplatesAsync();
            await CaptureBoth(root, themes, options, "templates-");
            window.CancelModalForSnapshot();

            // BASTION_SNAPSHOT_TREE=1: the tree on the core registry: favourites, the core's icons, the context menus for a
            // connection, a folder and the root, the inspector's More actions, then rename, duplicate, sort, a move (the drop
            // that drag-and-drop performs), Add to Workspace › New Workspace and the persisted expansion. The menus' entries
            // go to tree.txt as the registry gave them.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_TREE") == "1")
            {
                var log = new List<string>();
                window.SetFavoritesForSnapshot("web-1", "erp-desktop");
                window.SelectByName("db-1");
                await Task.Delay(500);
                log.Add("== tree"); log.AddRange(window.TreeLinesForSnapshot());
                await CaptureBoth(root, themes, options, "tree-");
                foreach (var (row, prefix) in new[] { ("web-1", "tree-menu-connection-"), ("Acme Corp", "tree-menu-folder-"), ((string?)null, "tree-menu-root-") })
                {
                    await window.OpenTreeMenuForSnapshot(row);
                    await Task.Delay(500);
                    log.Add($"== menu {row ?? "(library root)"}"); log.AddRange(window.TreeMenuLabelsForSnapshot());
                    await CaptureBoth(root, themes, options, prefix);
                    window.CloseTreeMenuForSnapshot();
                    await Task.Delay(300);
                }
                window.SelectByName("web-1");
                await Task.Delay(400);
                window.OpenInspectorMoreForSnapshot();
                await CaptureBoth(root, themes, options, "inspector-more-");
                window.CloseInspectorMoreForSnapshot();
                window.SelectByName("Acme Corp");
                await CaptureBoth(root, themes, options, "inspector-folder-");
                _ = window.RunActionForSnapshot("properties", null);
                await Task.Delay(400);
                await CaptureBoth(root, themes, options, "tree-root-defaults-");
                window.CancelModalForSnapshot();

                _ = window.RunActionForSnapshot("rename", "db-1");
                await Task.Delay(300);
                window.SetModalFieldForSnapshot("Name", "db-primary");
                await CaptureBoth(root, themes, options, "tree-rename-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(300);
                await window.RunActionForSnapshot("duplicate", "web-2");
                await window.RunActionForSnapshot("sort", "Acme Corp");
                await window.MoveForSnapshot("home-nas", "Staging");
                await window.MoveForSnapshot("lab-console", "web-1");
                await Task.Delay(400);
                log.Add("== after rename db-1, duplicate web-2, sort Acme Corp, move home-nas into Staging, lab-console before web-1"); log.AddRange(window.TreeLinesForSnapshot());
                await CaptureBoth(root, themes, options, "tree-edited-");
                _ = window.RunActionForSnapshot("move", "erp-desktop");
                await Task.Delay(400);
                window.SelectMoveDestinationForSnapshot("Acme Corp");
                await CaptureBoth(root, themes, options, "tree-move-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(400);
                log.Add("== after Move to… erp-desktop into Acme Corp"); log.AddRange(window.TreeLinesForSnapshot());
                _ = window.RunActionForSnapshot("add-to-workspace", "web-1");
                await Task.Delay(300);
                window.SetModalFieldForSnapshot("Workspace name", "Acme web");
                await CaptureBoth(root, themes, options, "tree-new-workspace-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(300);
                var ws = window.WorkspacesForSnapshot();
                log.Add($"== workspaces: {string.Join(", ", ws.Select(w => $"{w.Name} ({w.Tabs.Count} tab)"))}");
                log.Add(window.ExpansionRoundTripForSnapshot(Path.GetDirectoryName(options.LibraryPath)!));
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "tree.txt"), log);
            }

            // BASTION_SNAPSHOT_SETTINGS=1: Settings from the core registry (categories, a search that finds a setting and a
            // shortcut), the Keyboard page with a recorded chord that another command holds (asked, then replaced) and one
            // Windows reserves (refused), the dispatcher running the new chord (and leaving Ctrl+letter to a terminal), and
            // the Credential Manager. Writes settings.txt.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_SETTINGS") == "1")
            {
                var log = new List<string>();
                foreach (var category in new[] { "general", "appearance", "security", "keyboard" })
                {
                    window.OpenSettings(category);
                    await Task.Delay(500);
                    await CaptureBoth(window.SettingsRootForSnapshot ?? root, themes, options, $"settings-{category}-");
                }
                _ = window.RecordShortcutForSnapshot("local-shell", "alt+shift+=");
                await Task.Delay(400);
                log.Add("== record Alt+Shift+= for New Local Shell: " + window.ModalTitleForSnapshot);
                await CaptureBoth(root, themes, options, "settings-keyboard-conflict-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(400);
                window.OpenSettings("keyboard");
                await Task.Delay(400);
                await CaptureBoth(window.SettingsRootForSnapshot ?? root, themes, options, "settings-keyboard-changed-");
                _ = window.RecordShortcutForSnapshot("add", "primary+c");
                await Task.Delay(400);
                log.Add("== record Ctrl+C for New Connection: " + window.ModalTitleForSnapshot);
                await CaptureBoth(root, themes, options, "settings-keyboard-reserved-");
                window.PressModalPrimaryForSnapshot();
                log.Add("== shortcuts"); log.AddRange(window.ShortcutLinesForSnapshot());
                window.CloseSettings();
                await Task.Delay(300);
                var before = window.TabCountForSnapshot;
                log.Add($"dispatch Alt+Shift+= outside a terminal: {window.DispatchForSnapshot((Windows.System.VirtualKey)187, false, true, true, inTerminal: false)}, tabs {before} -> {window.TabCountForSnapshot}");
                log.Add($"dispatch Ctrl+D in a terminal (stays with the program): {window.DispatchForSnapshot(Windows.System.VirtualKey.D, true, false, false, inTerminal: true)}");
                log.Add($"dispatch Ctrl+Alt+I (Show or Hide Inspector): {window.DispatchForSnapshot(Windows.System.VirtualKey.I, true, true, false, inTerminal: true)}");
                window.DispatchForSnapshot(Windows.System.VirtualKey.I, true, true, false, inTerminal: false);
                window.CloseAllTabsForSnapshot();
                window.SearchSettingsForSnapshot("lock");
                await Task.Delay(500);
                await CaptureBoth(window.SettingsRootForSnapshot ?? root, themes, options, "settings-search-");
                window.CloseSettings();
                window.SeedCredentialsForSnapshot();
                window.OpenCredentialManager();
                await Task.Delay(500);
                await CaptureBoth(root, themes, options, "credential-manager-");
                window.ClosePage();

                // Appearance on Windows: accent, density and terminal font size from settings.json, applied at once to the
                // shell and to an open terminal (its program is told the new grid size).
                var shell = window.OpenTerminal("PowerShell", () => TerminalSession.Spawn("powershell.exe", ["-NoLogo", "-NoProfile", "-NoExit", "-Command", "Write-Host 'Gantry terminal font size'; $Host.UI.RawUI.WindowSize"], 100, 30))
                            ?? throw new InvalidOperationException("could not start PowerShell");
                await Task.Delay(4000);
                shell.Poll();
                var gridBefore = $"{shell.Session.Screen().Cols}x{shell.Session.Screen().Rows}";
                window.SelectByName("web-1");
                window.SetAppearanceForSnapshot("appearance.accent", "violet");
                window.SetAppearanceForSnapshot("appearance.density", "compact");
                window.SetAppearanceForSnapshot("terminal.font-size", "17");
                window.SelectByName("web-1");
                await Task.Delay(1200);
                shell.Poll();
                log.Add($"appearance: violet, compact, terminal font 17 -> grid {gridBefore} became {shell.Session.Screen().Cols}x{shell.Session.Screen().Rows}");
                foreach (var (theme, _) in themes)
                {
                    root.RequestedTheme = theme;
                    await Task.Delay(500);
                    log.Add("accent probe: " + window.AccentProbeForSnapshot());
                }
                await CaptureBoth(root, themes, options, "appearance-violet-compact-", shell);
                window.SetAppearanceForSnapshot("appearance.accent", "amber");
                window.SetAppearanceForSnapshot("appearance.density", "spacious");
                window.SelectByName("web-1");
                await Task.Delay(800);
                await CaptureBoth(root, themes, options, "appearance-amber-spacious-", shell);
                window.OpenSettings("appearance");
                await Task.Delay(500);
                await CaptureBoth(window.SettingsRootForSnapshot ?? root, themes, options, "settings-appearance-changed-");
                window.CloseSettings();
                foreach (var (id, value) in new[] { ("appearance.accent", "electric"), ("appearance.density", "comfortable"), ("terminal.font-size", "13") })
                    window.SetAppearanceForSnapshot(id, value);
                window.CloseAllTabsForSnapshot();
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "settings.txt"), log);
            }

            // BASTION_SNAPSHOT_WORKSPACES=1: two SSH tabs (local stand-in shells tied to web-1 and db-1), web-1 split right at 62%
            // and its right pane split down; Save Current Layout; the Workspace Manager; the layout rebuilt on a fresh tab as
            // reopening does; Quick Connect (an address, its login dialog, a refused address); the command palette ranked by
            // the core; the toolbar at the default size and narrow; the empty state's configured keys. Writes workspaces.txt.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_WORKSPACES") == "1")
            {
                var log = new List<string>();
                window.CloseAllTabsForSnapshot();
                await CaptureBoth(root, themes, options, "empty-hints-");
                var key = Path.Combine(Path.GetDirectoryName(options.LibraryPath)!, "no-such-key");
                foreach (var name in new[] { "web-1", "db-1" })
                {
                    window.SelectByName(name);
                    await Task.Delay(300);
                    var stand = window.OpenTerminal($"ops@{name}", () => TerminalSession.Spawn("cmd.exe", ["/c", $"echo {name} & ping -n 120 127.0.0.1 >nul"], 100, 30))
                                ?? throw new InvalidOperationException("could not start the stand-in shell");
                    window.SuperviseForSnapshot(stand, key);
                    if (name == "web-1")
                    {
                        window.SplitWithShareForSnapshot(SplitAxis.Right, 0.62);
                        window.SplitWithShareForSnapshot(SplitAxis.Down, 0.5);
                    }
                }
                log.Add("== open tabs as saved"); log.AddRange(window.LayoutLinesForSnapshot());
                _ = window.SaveWorkspaceAsync();
                await Task.Delay(300);
                window.SetModalFieldForSnapshot("Workspace name", "Acme on-call");
                await CaptureBoth(root, themes, options, "workspaces-save-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(300);
                var saved = window.WorkspacesForSnapshot();
                log.Add("== saved: " + string.Join("; ", saved.Select(w => $"{w.Name}: " + string.Join(" | ", w.Tabs.Select(t => string.Join(",", t.Layout ?? []))))));
                window.OpenWorkspaceManager();
                await Task.Delay(400);
                await CaptureBoth(root, themes, options, "workspaces-manager-");
                window.ClosePage();
                window.CloseAllTabsForSnapshot();
                window.SelectByName("web-1");
                await Task.Delay(300); // the tree applies the selection on a later pass
                var again = window.OpenTerminal("ops@web-1", () => TerminalSession.Spawn("cmd.exe", ["/c", "echo web-1 & ping -n 120 127.0.0.1 >nul"], 100, 30))
                            ?? throw new InvalidOperationException("could not start the stand-in shell");
                window.SuperviseForSnapshot(again, key);
                var restored = window.ApplyLayoutForSnapshot(saved.First(w => w.Name == "Acme on-call").Tabs[0].Layout ?? []);
                await Task.Delay(600);
                log.Add($"== rebuilt from the saved layout (ok {restored})"); log.AddRange(window.LayoutLinesForSnapshot());
                await CaptureBoth(root, themes, options, "workspaces-restored-");
                window.CloseAllTabsForSnapshot();

                _ = window.QuickConnectAsync("ops@10.0.0.5:2222");
                await Task.Delay(300);
                await CaptureBoth(root, themes, options, "quick-connect-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(500);
                log.Add("quick connect opens: " + window.ModalTitleForSnapshot);
                await CaptureBoth(root, themes, options, "quick-connect-login-");
                window.CancelModalForSnapshot();
                await Task.Delay(300);
                _ = window.QuickConnectAsync("ssh://");
                await Task.Delay(300);
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(300);
                await CaptureBoth(root, themes, options, "quick-connect-error-");
                window.CancelModalForSnapshot();

                window.SelectByName("db-1");
                await Task.Delay(300);
                _ = window.PaletteAsync();
                await Task.Delay(400);
                foreach (var q in new[] { "qc", "web", "acme" })
                {
                    log.Add($"== palette “{q}”"); log.AddRange(window.PaletteTypeForSnapshot(q).Take(8));
                    if (q != "acme") await CaptureBoth(root, themes, options, $"palette-{q}-");
                }
                window.CancelModalForSnapshot();

                await CaptureBoth(root, themes, options, "toolbar-default-");
                log.Add($"toolbar at {root.ActualWidth:F0} px: labels {(window.ToolbarLabelsShownForSnapshot ? "shown" : "hidden")}");
                window.AppWindow.Resize(new Windows.Graphics.SizeInt32(900, 640));
                await Task.Delay(800);
                await CaptureBoth(root, themes, options, "toolbar-narrow-");
                log.Add($"toolbar at {root.ActualWidth:F0} px: labels {(window.ToolbarLabelsShownForSnapshot ? "shown" : "hidden")}");
                if (options.Width is { } w0 && options.Height is { } h0) window.AppWindow.Resize(new Windows.Graphics.SizeInt32(w0, h0));
                else window.ResetSizeForSnapshot();
                await Task.Delay(600);
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "workspaces.txt"), log);
            }

            // BASTION_SNAPSHOT_SSH_AUTH=1: the Connect dialog with the SSH agent and a jump host's own login, then the
            // one-time code prompt for a keyboard-interactive second factor.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_SSH_AUTH") == "1")
            {
                _ = window.ConnectFormForSnapshot();
                await CaptureBoth(root, themes, options, "ssh-auth-connect-");
                window.CancelModalForSnapshot();
                await Task.Delay(300);
                _ = window.OneTimeCodeForSnapshot();
                await CaptureBoth(root, themes, options, "ssh-auth-code-");
                window.CancelModalForSnapshot();
            }

            // BASTION_SNAPSHOT_HOST_CAS=1: a host CA on the Credential Manager page (the test fixture CA in a throwaway
            // known_hosts), the Add dialog, and its inline error for a pasted private key.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_HOST_CAS") == "1")
            {
                window.SeedHostCaForSnapshot();
                window.OpenCredentialManager();
                await Task.Delay(500);
                await CaptureBoth(root, themes, options, "host-cas-");
                _ = window.AddHostCaForSnapshot();
                await CaptureBoth(root, themes, options, "host-cas-add-");
                window.FillHostCaForSnapshot("*.lab", "-----BEGIN OPENSSH PRIVATE KEY-----");
                await Task.Delay(300); // TextChanged (which hides the message) is raised after the fill
                window.PressModalPrimaryForSnapshot();
                await CaptureBoth(root, themes, options, "host-cas-add-error-");
                window.CancelModalForSnapshot();
                window.ClosePage();
            }

            // BASTION_SNAPSHOT_GATEWAYS=1: the Gateway Manager with one gateway in use and one free, the Add dialog with the
            // core's refusal of a duplicate name, the Gateway picker in the property editor and the gateway sign-in dialog.
            // With BASTION_SNAPSHOT_GW=<jump host:port> plus BASTION_SNAPSHOT_GW_PASSWORD, BASTION_SNAPSHOT_GW_VNC=<host:port as the
            // jump host sees it> and BASTION_SNAPSHOT_GW_VNC_PASSWORD: a live VNC desktop through that gateway.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_GATEWAYS") == "1")
            {
                window.SeedGatewaysForSnapshot();
                window.OpenGatewayManager();
                await Task.Delay(500);
                await CaptureBoth(root, themes, options, "gateways-");
                _ = window.AddGatewayForSnapshot();
                window.FillGatewayForSnapshot("jump", "10.0.0.9", "22");
                await Task.Delay(300); // TextChanged (which hides the message) is raised after the fill
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(300);
                await CaptureBoth(root, themes, options, "gateways-add-error-");
                window.CancelModalForSnapshot();
                window.ClosePage();
                window.ShowGatewayLoginForSnapshot();
                await Task.Delay(400);
                await CaptureBoth(root, themes, options, "gateways-login-");
                window.CancelModalForSnapshot();
                if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_GW") is { } gw && gw.LastIndexOf(':') is var gc and > 0
                    && Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_GW_VNC") is { } vt && vt.LastIndexOf(':') is var vc and > 0)
                {
                    _ = await window.OpenVncThroughGatewayForSnapshot(gw[..gc], int.Parse(gw[(gc + 1)..]),
                        Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_GW_PASSWORD") ?? "", vt[..vc], int.Parse(vt[(vc + 1)..]),
                        Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_GW_VNC_PASSWORD") ?? "");
                    await Task.Delay(3000);
                    await CaptureBoth(root, themes, options, "gateways-vnc-");
                }
            }

            // BASTION_SNAPSHOT_TUNNELS=1: the Tunnel Manager with a local forward and a SOCKS tunnel, and the Add dialog's inline
            // validation. With BASTION_SNAPSHOT_TUN=<ssh host:port>, BASTION_SNAPSHOT_TUN_USER/_PASSWORD and
            // BASTION_SNAPSHOT_TUN_DEST=<host:port as the server sees it>: a live local forward started, read and stopped.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_TUNNELS") == "1")
            {
                var tlog = new List<string>();
                window.SeedTunnelsForSnapshot();
                window.OpenTunnelManager();
                await Task.Delay(500);
                await CaptureBoth(root, themes, options, "tunnels-");
                _ = window.AddTunnelForSnapshot();
                await Task.Delay(300);
                window.PressModalPrimaryForSnapshot(); // empty form: inline validation
                await Task.Delay(300);
                await CaptureBoth(root, themes, options, "tunnels-add-error-");
                window.CancelModalForSnapshot();
                if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_TUN") is { } tun && tun.LastIndexOf(':') is var tc and > 0
                    && Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_TUN_DEST") is { } td && td.LastIndexOf(':') is var dc and > 0)
                {
                    try
                    {
                        tlog.Add(await window.StartTunnelLiveForSnapshot(tun[..tc], int.Parse(tun[(tc + 1)..]),
                            Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_TUN_USER") ?? "", Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_TUN_PASSWORD") ?? "",
                            td[..dc], int.Parse(td[(dc + 1)..])));
                    }
                    catch (Exception ex) { tlog.Add("live tunnel FAILED: " + ex.Message); }
                    await CaptureBoth(root, themes, options, "tunnels-live-");
                }
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "tunnels.txt"), tlog);
                window.ClosePage();
            }

            // BASTION_SNAPSHOT_MULTIEXEC=1: the plan dialog's inline validation. With BASTION_SNAPSHOT_MX=<ssh host:port> and
            // BASTION_SNAPSHOT_MX_USER/_PASSWORD: a live run on that host (key pinned first) and on an unknown-key name for it.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_MULTIEXEC") == "1")
            {
                var mx = Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_MX");
                var mc = mx?.LastIndexOf(':') ?? -1;
                List<string> mlog;
                try
                {
                    mlog = await window.MultiExecForSnapshot(p => CaptureBoth(root, themes, options, p), mc > 0 ? mx![..mc] : null,
                        mc > 0 ? int.Parse(mx![(mc + 1)..]) : 22, Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_MX_USER") ?? "",
                        Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_MX_PASSWORD") ?? "");
                }
                catch (Exception ex) { mlog = ["multi-exec FAILED: " + ex.Message]; }
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "multiexec.txt"), mlog);
                window.ClosePage();
            }

            // BASTION_SNAPSHOT_CREDENTIALS=1: the credential vault (a throwaway one next to the demo library, DPAPI-keyed),
            // the manager, the Add password form, the assignment dialog and the inspector row.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_CREDENTIALS") == "1")
            {
                window.SelectByName("web-1");
                await Task.Delay(400);
                window.SeedCredentialsForSnapshot();
                await Task.Delay(400);
                await CaptureBoth(root, themes, options, "credentials-inspector-");
                _ = window.CredentialsAsync();
                await CaptureBoth(root, themes, options, "credentials-");
                window.CancelModalForSnapshot();
                _ = window.NewCredentialForSnapshot();
                await CaptureBoth(root, themes, options, "credentials-add-");
                window.PressModalPrimaryForSnapshot(); // empty form: inline validation
                await CaptureBoth(root, themes, options, "credentials-add-error-");
                window.CancelModalForSnapshot(); // back to the list, which it reopens
                await Task.Delay(300);
                window.CancelModalForSnapshot();
                _ = window.AssignCredentialAsync();
                await CaptureBoth(root, themes, options, "credentials-assign-");
                window.CancelModalForSnapshot();
            }

            // BASTION_SNAPSHOT_CREDENTIAL_EDIT=<encrypted key file>: the Edit dialog of the seeded SSH key importing that
            // file, then the core's inline error when it is saved without the passphrase. Nothing is stored.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_CREDENTIAL_EDIT") is { Length: > 0 } keyFile)
            {
                window.SeedCredentialsForSnapshot();
                window.OpenCredentialManager();
                await Task.Delay(500);
                await CaptureBoth(root, themes, options, "credentials-edit-page-");
                _ = window.EditKeyCredentialForSnapshot(keyFile);
                await CaptureBoth(root, themes, options, "credentials-edit-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(300);
                await CaptureBoth(root, themes, options, "credentials-edit-error-");
                window.CancelModalForSnapshot();
                window.ClosePage();
            }

            // BASTION_SNAPSHOT_VAULTWARDEN=url,email,password (a throwaway local Vaultwarden whose account has the login
            // "lab sshd", e.g. seeded by core's BASTION_VAULTWARDEN_SEED test): the unlock form, a wrong password, the
            // unlocked list. With BASTION_SNAPSHOT_VAULTWARDEN_SSH=host:port (the test sshd that login belongs to) an SSH
            // connection with that login assigned is connected through LOGIN_VAULTWARDEN and answers a command.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_VAULTWARDEN") is { Length: > 0 } vw)
            {
                var parts = vw.Split(',', 3);
                async Task WaitForModal(string title)
                {
                    var until = DateTime.UtcNow.AddSeconds(60);
                    while (DateTime.UtcNow < until && window.ModalTitleForSnapshot != title) await Task.Delay(200);
                    if (window.ModalTitleForSnapshot != title) throw new InvalidOperationException($"expected the \"{title}\" dialog, got \"{window.ModalTitleForSnapshot}\"");
                    await Task.Delay(300);
                }
                _ = window.VaultwardenAsync();
                await WaitForModal("Unlock Vaultwarden");
                window.SetModalFieldForSnapshot("Server", parts[0]);
                window.SetModalFieldForSnapshot("E-mail", parts[1]);
                await CaptureBoth(root, themes, options, "vaultwarden-unlock-");
                window.SetModalPasswordForSnapshot("Master password", "not-the-master-password");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(300); // the form closes while the attempt runs off the UI thread
                await WaitForModal("Unlock Vaultwarden"); // reopened with the refusal under the field
                await CaptureBoth(root, themes, options, "vaultwarden-refused-");
                window.SetModalPasswordForSnapshot("Master password", parts[2]);
                window.PressModalPrimaryForSnapshot();
                await WaitForModal("Vaultwarden");
                await CaptureBoth(root, themes, options, "vaultwarden-");
                window.CancelModalForSnapshot();
                timings.Add("vaultwarden: wrong password refused, unlocked");

                if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_VAULTWARDEN_SSH") is { Length: > 0 } sshTarget)
                {
                    window.CloseAllTabsForSnapshot();
                    var hp = sshTarget.LastIndexOf(':');
                    var connect = window.OpenVaultwardenConnectForSnapshot("lab sshd", sshTarget[..hp], int.Parse(sshTarget[(hp + 1)..], CultureInfo.InvariantCulture));
                    await Task.Delay(500);
                    if (connect.IsFaulted) await connect; // surface the connect flow's own exception
                    await WaitForModal("Connect to lab sshd");
                    await CaptureBoth(root, themes, options, "vaultwarden-connect-");
                    window.PressModalPrimaryForSnapshot();
                    // A fresh data directory does not know the test server's key yet: trust it (no user to verify it here).
                    var until = DateTime.UtcNow.AddSeconds(30);
                    while (DateTime.UtcNow < until && window.ActiveTerminalForSnapshot is null)
                    {
                        if (window.ModalTitleForSnapshot == "Trust this host key?") window.PressModalPrimaryForSnapshot();
                        await Task.Delay(300);
                    }
                    if (connect.IsFaulted) await connect;
                    var term = window.ActiveTerminalForSnapshot ?? throw new InvalidOperationException($"the Vaultwarden login did not open a session (dialog \"{window.ModalTitleForSnapshot}\")");
                    await Task.Delay(1500);
                    term.Session.Write(System.Text.Encoding.UTF8.GetBytes("echo vaultwarden-login-$((40+2)) as $(whoami)\r"));
                    await Task.Delay(1500);
                    term.Poll();
                    await CaptureBoth(root, themes, options, "vaultwarden-ssh-");
                    timings.Add("vaultwarden: SSH login through the assigned item");
                }
            }

            // BASTION_SNAPSHOT_PROPERTIES=1: the property editor for a connection (values from its folder, the SSH type
            // defaults and built-ins), a refused value, the folder's Default Settings and the SSH type defaults.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_PROPERTIES") == "1")
            {
                window.SeedPropertiesForSnapshot();
                window.SelectByName("web-2");
                await Task.Delay(400);
                _ = window.PropertiesAsync(window.SelectedForSnapshot!);
                await CaptureBoth(root, themes, options, "properties-");
                // The Security category (C ABI 16 options): Environment as a list, the two switches.
                timings.Add("properties security: " + window.ChooseModalOptionForSnapshot("Environment", "Production"));
                await Task.Delay(400);
                await CaptureBoth(root, themes, options, "properties-security-");
                window.CancelModalForSnapshot();
                await Task.Delay(300);
                _ = window.PropertiesAsync(window.SelectedForSnapshot!);
                await Task.Delay(300);
                window.SetModalFieldForSnapshot("Port", "0");
                await Task.Delay(300); // TextChanged is raised asynchronously; let it run before Save, as typing would
                window.PressModalPrimaryForSnapshot();
                await CaptureBoth(root, themes, options, "properties-error-");
                window.CancelModalForSnapshot();
                window.SelectByName("Acme Corp");
                await Task.Delay(400);
                _ = window.PropertiesAsync(window.SelectedForSnapshot!);
                await CaptureBoth(root, themes, options, "properties-folder-");
                window.CancelModalForSnapshot();
                _ = window.EditDefaultsAsync(new EditorTarget.Type("ssh", "SSH"));
                await CaptureBoth(root, themes, options, "properties-type-");
                window.CancelModalForSnapshot();
                window.SelectByName("web-1");
                await Task.Delay(400);
            }

            // A real PowerShell session (no profile, so the user's setup does not leak into the picture) with colour output.
            window.SelectByName("web-1");
            const string script =
                "Write-Host 'Gantry terminal' -ForegroundColor Cyan; " +
                "Write-Host ' OK ' -BackgroundColor DarkGreen -ForegroundColor White -NoNewline; Write-Host ' local PowerShell session' ; " +
                "Write-Host ' WARN ' -BackgroundColor DarkYellow -ForegroundColor Black -NoNewline; Write-Host ' colours, bold and background runs'; " +
                "Write-Host ('PowerShell ' + $PSVersionTable.PSVersion) -ForegroundColor Magenta; " +
                "Get-ChildItem $env:SystemRoot -Directory | Select-Object -First 6 Name, LastWriteTime | Format-Table -AutoSize";
            var view = window.OpenTerminal("PowerShell", () => TerminalSession.Spawn("powershell.exe", ["-NoLogo", "-NoProfile", "-NoExit", "-Command", script], 100, 30))
                       ?? throw new InvalidOperationException("could not start PowerShell");
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (DateTime.UtcNow < deadline)
            {
                await Task.Delay(250);
                view.Poll();
                var s = view.Session.Screen();
                if (s.CellText.Any(t => t == "W") && string.Concat(s.CellText).Contains("PowerShell ")) break;
            }
            await Task.Delay(1500); // let the table and prompt finish
            await CaptureBoth(root, themes, options, "terminal-", view);

            // BASTION_SNAPSHOT_TERMINAL_THEMES=1: the same session in every built-in terminal colour theme (dark shell),
            // then back to the default.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_TERMINAL_THEMES") == "1")
            {
                foreach (var (id, _) in TerminalThemes.All)
                {
                    window.SetTerminalTheme(id);
                    view.Poll();
                    await Task.Delay(400);
                    root.RequestedTheme = ElementTheme.Dark;
                    await CaptureAsync(root, Path.Combine(options.Dir, $"terminal-theme-{id}.png"), options.Scale);
                }
                window.SetTerminalTheme(AppearanceSettings.MatchAppTheme);
            }

            // BASTION_SNAPSHOT_THEME_EDITOR=1: Settings › Terminal › Edit themes: duplicate a bundled theme, change a colour,
            // a bad colour is refused, a low-contrast pair saves with a warning, then the copy is deleted. Written to theme-editor.txt.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_THEME_EDITOR") == "1")
            {
                var tlog = new List<string>();
                var editing = window.EditThemesForSnapshot();
                await Task.Delay(500);
                var form = window.ThemeEditorForSnapshot ?? throw new InvalidOperationException("theme editor did not open");
                async Task Step(string name, Action act)
                {
                    act();
                    await Task.Delay(300);
                    tlog.Add($"{name}: [{form.SelectedNameForSnapshot}] {form.StatusForSnapshot}");
                    tlog.Add($"  fit {window.ModalFitForSnapshot()}");
                    await CaptureBoth(root, themes, options, "theme-editor-" + name + "-");
                }
                await Step("open", () => { });
                await Step("duplicate", () => form.ClickForSnapshot("duplicate"));
                await Step("edit", () => { form.SetColorForSnapshot(2, "#ff5f5f"); form.ClickForSnapshot("save"); });
                await Step("bad-colour", () => { form.SetColorForSnapshot(0, "#12"); form.ClickForSnapshot("save"); });
                await Step("low-contrast", () => { form.SetColorForSnapshot(0, "#222222"); form.SetColorForSnapshot(1, "#202020"); form.ClickForSnapshot("save"); });
                await Step("delete", () => form.ClickForSnapshot("delete"));
                window.PressModalPrimaryForSnapshot();
                await editing;
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "theme-editor.txt"), tlog);
            }

            // BASTION_SNAPSHOT_CURSOR=1: the terminal with each cursor style (block, bar, underline), the scrollback size set to its
            // minimum, and the Settings › Terminal page showing both settings.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_CURSOR") == "1")
            {
                foreach (var style in new[] { "bar", "underline", "block" })
                {
                    window.SetSettingForSnapshot("terminal.cursor-style", style);
                    view.Poll();
                    await Task.Delay(400);
                    root.RequestedTheme = ElementTheme.Dark;
                    await CaptureAsync(root, Path.Combine(options.Dir, $"terminal-cursor-{style}.png"), options.Scale);
                }
                window.SetSettingForSnapshot("terminal.scrollback", "1000");
                window.OpenSettings("terminal");
                await Task.Delay(500);
                await CaptureBoth(window.SettingsRootForSnapshot ?? root, themes, options, "settings-terminal-");
                window.CloseSettings();
                window.SetSettingForSnapshot("terminal.scrollback", "10000");
            }

            // BASTION_SNAPSHOT_FONTS=1: a connection inherits its folder's terminal font; an app font change leaves it
            // alone and reaches other tabs. Written to fonts.txt.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_FONTS") == "1")
            {
                var flog = new List<string>();
                var plain = window.OpenTerminal("Plain", () => TerminalSession.Spawn("powershell.exe", ["-NoLogo", "-NoProfile", "-NoExit", "-Command", "'-> != => ==='"], 100, 30))
                            ?? throw new InvalidOperationException("could not start PowerShell");
                var boxed = window.OpenFolderFontTerminalForSnapshot();
                await Task.Delay(2000);
                plain.Poll(); boxed.Poll();
                flog.Add($"folder font: {boxed.FontForSnapshot} size {boxed.FontSizeForSnapshot}");
                flog.Add($"app font: {plain.FontForSnapshot} size {plain.FontSizeForSnapshot}");
                await CaptureBoth(root, themes, options, "fonts-folder-");
                window.SetSettingForSnapshot("terminal.font-family", "courier-new");
                window.SetSettingForSnapshot("terminal.ligatures", "false");
                flog.Add($"after app change, folder tab: {boxed.FontForSnapshot}");
                flog.Add($"after app change, plain tab: {plain.FontForSnapshot}");
                window.SetSettingForSnapshot("terminal.font-family", "bundled");
                window.SetSettingForSnapshot("terminal.ligatures", "true");
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "fonts.txt"), flog);
            }

            // BASTION_SNAPSHOT_ROYAL_LAYOUT=1: the Royal TS layout. The tree ends with the Application section (Credentials,
            // Tunnels, Workspaces, Triggers, Default Settings per type), its rows open their pages, and the bottom bar under the
            // tree fits the pane and follows the selection. Written to royal-layout.txt.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_ROYAL_LAYOUT") == "1")
            {
                var rlog = new List<string> { "tree:" };
                rlog.AddRange(window.TreeLinesForSnapshot().Select(l => "  " + l));
                rlog.Add("bottom bar fit " + window.BottomBarFitForSnapshot());
                rlog.Add("no selection: " + window.SelectForBottomBarSnapshot(null));
                await CaptureBoth(root, themes, options, "royal-layout-");
                var first = window.TreeLinesForSnapshot().Select(l => l.Trim()).FirstOrDefault(l => l.EndsWith("(SSH Terminal)"))?.Split("  (")[0].TrimEnd(' ', '★');
                if (first is not null)
                {
                    rlog.Add($"select {first}: " + window.SelectForBottomBarSnapshot(first));
                    rlog.Add(await window.ToggleFavoriteFromBarForSnapshot());
                    await Task.Delay(400);
                    rlog.Add($"favourite toggled: " + window.BottomBarStateForSnapshot() + "; Favorites section " + (window.TreeLinesForSnapshot().Contains("[Favorites]") ? "shown" : "missing") + "; " + window.ModalFitForSnapshot());
                    await CaptureBoth(root, themes, options, "royal-layout-selected-");
                    await window.ToggleFavoriteFromBarForSnapshot();
                    await Task.Delay(400);
                }
                foreach (var (id, what) in new[] { ("app:tasks", "Tasks"), ("app:triggers", "Triggers") })
                {
                    var opened = window.OpenAppRowForSnapshot(id);
                    await Task.Delay(700);
                    rlog.Add($"{what} row: {(opened ? "invoked" : "NOT FOUND")}, page {(window.PageOpenForSnapshot ? "open" : "modal " + window.ModalFitForSnapshot())}");
                    if (window.PageOpenForSnapshot) window.ClosePage(); else window.CancelModalForSnapshot();
                    await Task.Delay(300);
                }
                // Tasks: the core's built-ins plus one of the user's own, shown on the Tasks page.
                window.OpenAppRowForSnapshot("app:tasks");
                var taskId = window.AddTaskForSnapshot("Disk usage", "df");
                await Task.Delay(500);
                rlog.Add("tasks: " + string.Join("; ", window.TaskLinesForSnapshot()));
                await CaptureBoth(root, themes, options, "royal-layout-tasks-");
                window.RemoveTaskForSnapshot(taskId);
                window.ClosePage();
                // Settings opens in a window of its own; the main window keeps its tree. Fit at three sizes.
                window.OpenSettings("general");
                await Task.Delay(800);
                rlog.Add($"settings: own window {(window.SettingsOpenForSnapshot ? "open" : "MISSING")} (preview: Mac-style window)");
                foreach (var (sw, sh) in new[] { (1280, 800), (800, 600), (640, 480) })
                {
                    rlog.Add($"settings fit {sw}x{sh}: " + await window.SettingsFitForSnapshot(sw, sh));
                    await Task.Delay(300);
                }
                if (window.SettingsRootForSnapshot is { } settingsRoot) await CaptureBoth(settingsRoot, themes, options, "royal-layout-settings-");
                window.CloseSettings();
                await Task.Delay(300);
                rlog.Add($"settings closed: {(window.SettingsOpenForSnapshot ? "STILL OPEN" : "closed")}");
                _ = window.EditDefaultsAsync(new EditorTarget.Type("ssh", "SSH")); // Default Settings left the tree (as on the Mac)
                await Task.Delay(900);
                rlog.Add($"Default Settings › SSH: dialog {window.ModalFitForSnapshot()}");
                await CaptureBoth(root, themes, options, "royal-layout-defaults-");
                window.CancelModalForSnapshot();
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "royal-layout.txt"), rlog);
            }

            // BASTION_SNAPSHOT_SSH_SOURCES=1: Settings › SSH › SSH config sources with the user's OpenSSH config: files read,
            // placeholders and the change preview. Nothing is changed. Written to ssh-sources.txt.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_SSH_SOURCES") == "1")
            {
                var opening = window.EditSshSourcesForSnapshot();
                await Task.Delay(800);
                var form = window.SshSourcesForSnapshot ?? throw new InvalidOperationException("SSH sources dialog did not open");
                await CaptureBoth(root, themes, options, "ssh-sources-");
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "ssh-sources.txt"), form.LinesForSnapshot().Append("fit " + window.ModalFitForSnapshot()));
                window.PressModalPrimaryForSnapshot();
                await opening;
            }

            // BASTION_SNAPSHOT_SHORTCUTS=1: zoom is per tab and never saved, Select All takes the scrollback, Find Next opens the find
            // bar with nothing to repeat, and Send Break interrupts a running program. Written to shortcuts.txt.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_SHORTCUTS") == "1")
            {
                var slog = new List<string>();
                var other = window.OpenTerminal("Second", () => TerminalSession.Spawn("powershell.exe", ["-NoLogo", "-NoProfile", "-NoExit", "-Command", "1..50 | % { \"row$_\" }"], 100, 30))
                            ?? throw new InvalidOperationException("could not start PowerShell");
                await Task.Delay(2500);
                var setting = window.SettingValueForSnapshot("terminal.font-size");
                window.RunCommandForSnapshot("zoom-in");
                window.RunCommandForSnapshot("zoom-in");
                var sizes = window.TabFontSizesForSnapshot();
                slog.Add($"zoom: tabs {string.Join(", ", sizes)}; setting {setting} -> {window.SettingValueForSnapshot("terminal.font-size")}");
                window.RunCommandForSnapshot("zoom-reset");
                slog.Add($"zoom reset: tabs {string.Join(", ", window.TabFontSizesForSnapshot())}");
                // The reset resizes the terminal; ConPTY repaints, and a repaint over the selection clears it. Let it settle first.
                await Task.Delay(1500);
                window.RunCommandForSnapshot("select-all");
                var selected = other.Session.SelectionText() ?? "";
                slog.Add($"select all: {(selected.Contains("row1") && selected.Contains("row50") ? "scrollback and screen selected" : "WRONG: " + selected.Length + " chars")}");
                other.Session.ClearSelection();
                window.RunCommandForSnapshot("find-next");
                await Task.Delay(300);
                await CaptureBoth(root, themes, options, "shortcuts-find-", other);
                other.Session.Write("ping -t 127.0.0.1\r");
                await Task.Delay(2500);
                window.RunCommandForSnapshot("send-break");
                await Task.Delay(1500);
                var screen = string.Concat(other.Session.Screen().CellText);
                slog.Add($"send break: {(screen.Contains("Control-C") ? "ping stopped (Control-C)" : "PING STILL RUNNING")}");
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "shortcuts.txt"), slog);
            }

            // BASTION_SNAPSHOT_IMPORT=<folder>: import every .reg/.json/.rdg/.xml/.csv/.rdp file in it as File › Import Connections does,
            // and list what came in. (That no password is imported is checked by import_file_cabi_tests.) Written to import.txt.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_IMPORT") is { Length: > 0 } importDir)
            {
                var ilog = new List<string>();
                foreach (var f in Directory.GetFiles(importDir).OrderBy(f => f, StringComparer.Ordinal))
                {
                    var task = window.ImportConnectionsFromAsync(f);
                    await Task.Delay(400);
                    window.PressModalPrimaryForSnapshot(); // close the summary (or the error)
                    var r = await task;
                    ilog.Add(r is null ? $"{Path.GetFileName(f)}: refused" : $"{Path.GetFileName(f)}: {r.Connections} from {r.Format}; skipped {r.Skipped.Count}");
                }
                await Task.Delay(300);
                await CaptureBoth(root, themes, options, "import-");
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "import.txt"), ilog);
            }

            // BASTION_SNAPSHOT_IME_COMPOSE=1: a Japanese composition (に, にほ, にほん, 日本語) in a PowerShell tab: the overlay shows
            // each step at the cursor, the commit sends 日本語 once and the shell echoes it. Written to ime-compose.txt.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_IME_COMPOSE") == "1")
            {
                var ilog = new List<string>();
                var t = window.OpenTerminal("IME", () => TerminalSession.Spawn("powershell.exe", ["-NoLogo", "-NoProfile", "-NoExit"], 100, 30))
                        ?? throw new InvalidOperationException("could not start PowerShell");
                await Task.Delay(2500);
                t.Poll();
                var steps = t.ComposeForSnapshot(["に", "にほ", "にほん", "日本語"]);
                ilog.Add("composition overlay: " + string.Join(" > ", steps));
                await Task.Delay(1200);
                t.Poll();
                var text = string.Concat(t.Session.Screen().CellText);
                // Wide characters take two cells; the screen text may hold a spacer after each.
                var spaced = text.Replace("\0", "").Replace(" ", "");
                var hits = (spaced.Length - spaced.Replace("日本語", "").Length) / 3;
                ilog.Add($"commit reached the shell: {(hits >= 1 ? "yes" : "NO")} ({hits} time{(hits == 1 ? "" : "s")} on screen)");
                await CaptureBoth(root, themes, options, "ime-compose-", t);
                t.Session.Write("\r");
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "ime-compose.txt"), ilog);
            }

            // BASTION_SNAPSHOT_GLYPHS=1: Powerline, box drawing, Nerd Font icons and wide characters on their own cells
            // (the bar after each line must line up), then the find bar on a match. Also checks Ctrl+click URL detection.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_GLYPHS") == "1")
            {
                const string glyphs =
                    "Write-Host ('Powerline  ' + [char]0xE0B6 + ' main ' + [char]0xE0B0 + ' ' + [char]0xE0A0 + ' dev ' + [char]0xE0B1 + ' ok ' + [char]0xE0B2 + '|'); " +
                    "Write-Host ('Box        ' + [char]0x250C + [char]0x2500 + [char]0x252C + [char]0x2500 + [char]0x2510 + ' ' + [char]0x2588 + [char]0x2593 + [char]0x2592 + [char]0x2591 + '      |'); " +
                    "Write-Host ('           ' + [char]0x2514 + [char]0x2500 + [char]0x2534 + [char]0x2500 + [char]0x2518 + '           |'); " +
                    "Write-Host ('Nerd icons ' + [char]0xF07B + ' ' + [char]0xF113 + ' ' + [char]0xE718 + ' ' + [char]0xF489 + '           |'); " +
                    "Write-Host ('Wide       ' + [char]0x6F22 + [char]0x5B57 + [char]0x30C6 + [char]0x30B9 + [char]0x30C8 + ' |'); " +
                    "Write-Host 'ASCII      abcdefghij |'; Write-Host 'Link: https://example.com/docs?q=1.'";
                var g = window.OpenTerminal("Glyphs", () => TerminalSession.Spawn("powershell.exe", ["-NoLogo", "-NoProfile", "-NoExit", "-Command", glyphs], 100, 30))
                        ?? throw new InvalidOperationException("could not start PowerShell");
                var until = DateTime.UtcNow.AddSeconds(15);
                TerminalScreen? gs = null;
                while (DateTime.UtcNow < until)
                {
                    await Task.Delay(250);
                    g.Poll();
                    gs = g.Session.Screen();
                    if (string.Concat(gs.CellText).Contains("example.com")) break;
                }
                await Task.Delay(800);
                var glog = new List<string>();
                if (gs is not null)
                {
                    for (var r = 0; r < gs.Rows; r++)
                    {
                        var row = Enumerable.Range(r * gs.Cols, gs.Cols).Select(i => gs.CellText[i]).ToList();
                        if (row.IndexOf("|") is >= 0 and var bar) glog.Add($"row {r}: bar at column {bar}");
                        var link = row.FindIndex(t => t == "h");
                        if (string.Concat(row).Contains("Link:") && link >= 0)
                            glog.Add($"url at col {link + 3}: {TerminalView.UrlAt(gs.CellText, gs.Cols, r, link + 3) ?? "none"}; at col 0: {TerminalView.UrlAt(gs.CellText, gs.Cols, r, 0) ?? "none"}");
                    }
                }
                await CaptureBoth(root, themes, options, "terminal-glyphs-", g);
                g.ShowFindForSnapshot("dev");
                await Task.Delay(600);
                await CaptureBoth(root, themes, options, "terminal-find-", g);
                await File.WriteAllLinesAsync(Path.Combine(options.Dir, "glyphs.txt"), glog);
            }

            // BASTION_SNAPSHOT_WSL=1: the first (default) WSL distribution in its own tab, answering a command.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_WSL") == "1")
            {
                var distro = TerminalSession.WslDistros().FirstOrDefault() ?? throw new InvalidOperationException("no WSL distribution installed");
                var wsl = window.OpenWsl(distro) ?? throw new InvalidOperationException($"could not open WSL {distro}");
                await Task.Delay(1500);
                wsl.Session.Write(System.Text.Encoding.UTF8.GetBytes("echo wsl-$((40+2)) $(uname -sr); grep PRETTY /etc/os-release\r"));
                var until = DateTime.UtcNow.AddSeconds(20);
                while (DateTime.UtcNow < until)
                {
                    await Task.Delay(250);
                    wsl.Poll();
                    if (string.Concat(wsl.Session.Screen().CellText).Contains("wsl-42 Linux")) break;
                }
                await Task.Delay(500);
                await CaptureBoth(root, themes, options, "wsl-", wsl);
            }

            // BASTION_SNAPSHOT_SPLITS=1: one tab split right, then its right pane split down; each pane is its own shell
            // answering its own command. Then the focused pane closes and the tab carries on with two.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_SPLITS") == "1")
            {
                window.CloseAllTabsForSnapshot();
                window.SelectByName("web-1");
                var first = window.OpenTerminal("Local shell", () => TerminalSession.LocalShell(100, 30)) ?? throw new InvalidOperationException("could not start the shell");
                await Task.Delay(800);
                var right = window.SplitActive(SplitAxis.Right) ?? throw new InvalidOperationException("split right failed");
                await Task.Delay(800);
                var below = window.SplitActive(SplitAxis.Down) ?? throw new InvalidOperationException("split down failed");
                await Task.Delay(1200);
                var panes = new[] { (first, "left"), (right, "top-right"), (below, "bottom-right") };
                foreach (var (pane, name) in panes) pane.Session.Write($"echo pane-{name} %OS%\r");
                var until = DateTime.UtcNow.AddSeconds(15);
                while (DateTime.UtcNow < until && !panes.All(p => string.Concat(p.Item1.Session.Screen().CellText).Contains($"pane-{p.Item2} Windows_NT")))
                {
                    await Task.Delay(250);
                    foreach (var (pane, _) in panes) pane.Poll();
                }
                timings.Add($"splits: {panes.Count(p => string.Concat(p.Item1.Session.Screen().CellText).Contains($"pane-{p.Item2} Windows_NT"))}/3 panes answered");
                await CaptureBoth(root, themes, options, "splits-");
            }

            // BASTION_SNAPSHOT_WEB=1: a web connection to a page served on loopback by this process. The page sets a
            // cookie and shows the cookies it was sent; a second tab of the same connection must see none (each tab is
            // InPrivate in its own profile). Then the page tries a file: navigation, which must be refused.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_WEB") == "1")
            {
                window.CloseAllTabsForSnapshot();
                var port = 18000 + Environment.ProcessId % 1000;
                using var http = new System.Net.HttpListener();
                http.Prefixes.Add($"http://127.0.0.1:{port}/");
                http.Start();
                _ = Task.Run(async () =>
                {
                    while (http.IsListening)
                    {
                        System.Net.HttpListenerContext ctx;
                        try { ctx = await http.GetContextAsync(); } catch { return; }
                        var sent = ctx.Request.Headers["Cookie"] ?? "(none)";
                        var html = "<!doctype html><html><head><title>Ops intranet</title><style>body{font:15px 'Segoe UI';margin:32px;color:#222}h1{font-size:22px}code{background:#eee;padding:2px 6px}</style></head>"
                                 + $"<body><h1>Ops intranet</h1><p>Served on loopback for the Gantry web-tab snapshot.</p><p>Cookies sent with this request: <code>{System.Net.WebUtility.HtmlEncode(sent)}</code></p>"
                                 + "<script>document.cookie='bastion_tab=1; max-age=3600';</script></body></html>";
                        var bytes = System.Text.Encoding.UTF8.GetBytes(html);
                        ctx.Response.ContentType = "text/html; charset=utf-8";
                        await ctx.Response.OutputStream.WriteAsync(bytes);
                        ctx.Response.Close();
                    }
                });
                var url = $"http://127.0.0.1:{port}/";
                async Task<WebTabView> Open()
                {
                    var web = window.OpenWebForSnapshot("Ops intranet", url) ?? throw new InvalidOperationException("the web tab did not open");
                    var until = DateTime.UtcNow.AddSeconds(30);
                    while (DateTime.UtcNow < until && web.DocumentTitle != "Ops intranet") await Task.Delay(250);
                    await Task.Delay(800);
                    return web;
                }
                var one = await Open();
                await one.RunScriptForSnapshot("location.reload()"); // second request: this tab's cookie comes back
                await Task.Delay(1500);
                var firstText = await one.BodyTextForSnapshot();
                var two = await Open();
                var secondText = await two.BodyTextForSnapshot();
                await two.RunScriptForSnapshot("location.href='file:///C:/Windows/win.ini'");
                await Task.Delay(1500);
                var blocked = two.SourceForSnapshot == url;
                timings.Add($"web: tab 1 reload {(firstText.Contains("bastion_tab=1") ? "sent its cookie" : "sent NO cookie")}; tab 2 {(secondText.Contains("(none)") ? "saw no cookie" : "SAW A COOKIE")}; file: navigation {(blocked ? "refused" : "NOT REFUSED")}");
                // Address bar: shows the page, refuses javascript:/file:, and loads a typed http(s) address.
                var barShows = two.AddressForSnapshot == url;
                var jsRefused = !two.GoForSnapshot("javascript:alert(1)") && !two.GoForSnapshot("file:///C:/Windows/win.ini");
                var typed = url + "?page=2";
                var went = two.GoForSnapshot(typed);
                var until2 = DateTime.UtcNow.AddSeconds(15);
                while (DateTime.UtcNow < until2 && two.AddressForSnapshot != typed) await Task.Delay(200);
                timings.Add($"web address bar: {(barShows ? "shows the page" : "WRONG ADDRESS")}; javascript:/file: {(jsRefused ? "refused" : "NOT REFUSED")}; typed address {(went && two.AddressForSnapshot == typed ? "loaded" : "DID NOT LOAD")}");
                await two.FreezeForSnapshot();
                await CaptureBoth(root, themes, options, "web-");
                http.Stop();
            }

            // BASTION_SNAPSHOT_SFTP=user:password@host:port (a throwaway loopback test sshd, see
            // apps/windows/tests/ssh-test-setup.sh): an SSH tab with its Files panel; a folder is created, a local
            // file uploaded into it, and the upload is shown selected.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_SFTP") is { Length: > 0 } target)
            {
                window.CloseAllTabsForSnapshot();
                var at = target.LastIndexOf('@');
                var (cred, hostPort) = (target[..at], target[(at + 1)..]);
                var colon = cred.IndexOf(':');
                var hp = hostPort.LastIndexOf(':');
                var panel = await window.OpenSftpForSnapshot(hostPort[..hp], int.Parse(hostPort[(hp + 1)..], CultureInfo.InvariantCulture), cred[..colon], cred[(colon + 1)..]);
                var folder = $"bastion-snapshot-{Environment.ProcessId}";
                await panel.NewFolder(folder);
                await panel.Navigate(SftpSession.Join(panel.CurrentDirectory, folder));
                var local = Path.Combine(Path.GetTempPath(), "release-notes.txt");
                await File.WriteAllTextAsync(local, "Gantry SFTP upload from Windows\n");
                await panel.UploadFile(local);
                // The queue: the same file again waits as a conflict (rule Ask), Keep both writes "release-notes (1).txt";
                // a download into an empty local folder lands there.
                await panel.UploadFile(local);
                var conflictWaits = panel.JobsForSnapshot.Any(j => j.State == "conflict");
                await CaptureBoth(root, themes, options, "sftp-conflict-");
                await panel.AnswerConflict("rename");
                var keptBoth = panel.JobsForSnapshot.Any(j => j.State == "done" && j.Target.EndsWith("/release-notes (1).txt", StringComparison.Ordinal));
                var localDir = Path.Combine(Path.GetTempPath(), $"bastion-snapshot-local-{Environment.ProcessId}");
                Directory.CreateDirectory(localDir);
                await panel.NavigateLocal(localDir);
                await panel.QueueDownload(SftpSession.Join(panel.CurrentDirectory, "release-notes.txt"));
                var downloaded = File.Exists(Path.Combine(localDir, "release-notes.txt"));
                await CaptureBoth(root, themes, options, "sftp-queue-");
                Directory.Delete(localDir, true);
                timings.Add($"sftp queue: conflict {(conflictWaits ? "waits" : "DID NOT WAIT")}; keep both {(keptBoth ? "renamed" : "NOT RENAMED")}; download {(downloaded ? "landed" : "MISSING")}");
                File.Delete(local);
                await panel.Navigate(SftpSession.Parent(panel.CurrentDirectory));
                panel.Select(folder);
                await CaptureBoth(root, themes, options, "sftp-");
                await panel.Navigate(SftpSession.Join(panel.CurrentDirectory, folder));
                panel.Select("release-notes.txt");
                await CaptureBoth(root, themes, options, "sftp-upload-");
                // Several files at once (the Explorer drop path), then delete one file and the whole folder.
                var many = Enumerable.Range(1, 3).Select(i => Path.Combine(Path.GetTempPath(), $"drop-{i}.log")).ToList();
                foreach (var f in many) await File.WriteAllTextAsync(f, new string('x', 4096));
                await panel.UploadFiles(many);
                foreach (var f in many) File.Delete(f);
                await CaptureBoth(root, themes, options, "sftp-dropped-");
                var droppedText = panel.StatusForSnapshot;
                // Byte progress: a large upload shows partial byte counts on the bar while it runs.
                var big = Path.Combine(Path.GetTempPath(), $"bastion-big-{Environment.ProcessId}.bin");
                await using (var fs = File.Create(big)) { var block = new byte[1 << 20]; Random.Shared.NextBytes(block); for (var i = 0; i < 96; i++) await fs.WriteAsync(block); }
                panel.ProgressSamplesForSnapshot.Clear();
                await panel.UploadFiles([big]);
                File.Delete(big);
                var partial = panel.ProgressSamplesForSnapshot.Count(n => n > 0 && n < 96UL << 20);
                timings.Add($"sftp byte progress: {partial} partial samples of {panel.ProgressSamplesForSnapshot.Count} ({panel.StatusForSnapshot})");
                // A dropped folder: its subfolders are made on the server and every file inside is uploaded.
                var tree = Path.Combine(Path.GetTempPath(), $"bastion-drop-tree-{Environment.ProcessId}");
                Directory.CreateDirectory(Path.Combine(tree, "sub", "deep"));
                foreach (var f in new[] { "a.txt", Path.Combine("sub", "b.txt"), Path.Combine("sub", "deep", "c.txt") }) await File.WriteAllTextAsync(Path.Combine(tree, f), f);
                await panel.UploadItems([], [tree]);
                Directory.Delete(tree, true);
                var treeName = Path.GetFileName(tree);
                var treeDone = new[] { "/a.txt", "/sub/b.txt", "/sub/deep/c.txt" }.Count(t => panel.JobsForSnapshot.Any(j => j.State == "done" && j.Target.EndsWith("/" + treeName + t, StringComparison.Ordinal)));
                timings.Add($"sftp folder drop: {treeDone}/3 files under {treeName}/ ({panel.StatusForSnapshot})");
                panel.Select("drop-1.log");
                await panel.AskDelete();
                await CaptureBoth(root, themes, options, "sftp-delete-confirm-");
                await panel.ConfirmDelete();
                var fileGone = panel.StatusForSnapshot;
                await panel.Navigate(SftpSession.Parent(panel.CurrentDirectory));
                panel.Select(folder);
                await panel.AskDelete();
                await panel.ConfirmDelete();
                timings.Add($"sftp: folder {folder} with an uploaded file; drop: {droppedText}; delete: {fileGone}; folder: {panel.StatusForSnapshot}");
            }

            // BASTION_SNAPSHOT_RDP=user:password@host:port (a throwaway loopback xrdp, see apps/windows/tests/rdp-test-setup.sh):
            // the certificate prompt on first use, then the remote desktop in a tab once the certificate is pinned.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_RDP") is { Length: > 0 } rdpTarget)
            {
                window.CloseAllTabsForSnapshot();
                var at = rdpTarget.LastIndexOf('@');
                var (cred, hostPort) = (rdpTarget[..at], rdpTarget[(at + 1)..]);
                var colon = cred.IndexOf(':');
                var hp = hostPort.LastIndexOf(':');
                var rdpView = await window.OpenRdpForSnapshot(hostPort[..hp], int.Parse(hostPort[(hp + 1)..], CultureInfo.InvariantCulture), cred[..colon], cred[(colon + 1)..],
                    () => CaptureBoth(root, themes, options, "rdp-certificate-"));
                var until = DateTime.UtcNow.AddSeconds(20);
                while (DateTime.UtcNow < until && rdpView.DesktopSize.Width == 0) { rdpView.Poll(); await Task.Delay(250); }
                await Task.Delay(9000); // xrdp starts Xorg and the xterm after login (about 5 s)
                // Type "uname -a" and Enter as scancodes into the remote xterm: the keyboard path end to end.
                var rdpSession = ((RdpDesktop)rdpView.Desktop).Session;
                foreach (var code in new byte[] { 0x16, 0x31, 0x1E, 0x32, 0x12, 0x39, 0x0C, 0x1E, 0x1C }) { rdpSession.Key(code, false, true); rdpSession.Key(code, false, false); await Task.Delay(40); }
                await Task.Delay(1500);
                rdpView.Poll();
                await CaptureBoth(root, themes, options, "rdp-");
                timings.Add($"rdp: desktop {rdpView.DesktopSize.Width}x{rdpView.DesktopSize.Height}");
            }

            // BASTION_SNAPSHOT_VNC=password@host:port (a throwaway loopback x11vnc, see apps/windows/tests/vnc-test-setup.sh):
            // a wrong password must be refused, then the desktop opens in a tab and "uname -a" is typed as keysyms.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_VNC") is { Length: > 0 } vncTarget)
            {
                window.CloseAllTabsForSnapshot();
                var at = vncTarget.LastIndexOf('@');
                var hostPort = vncTarget[(at + 1)..];
                var hp = hostPort.LastIndexOf(':');
                var vncView = await window.OpenVncForSnapshot(hostPort[..hp], int.Parse(hostPort[(hp + 1)..], CultureInfo.InvariantCulture), vncTarget[..at]);
                var until = DateTime.UtcNow.AddSeconds(20);
                while (DateTime.UtcNow < until && vncView.DesktopSize.Width == 0) { vncView.Poll(); await Task.Delay(250); }
                vncView.Focus(FocusState.Programmatic);
                // No window manager on the test display: xterm takes keys only while the pointer is over it.
                vncView.Desktop.MouseMove(200, 120);
                vncView.Desktop.MouseButton(RemoteButton.Left, true);
                vncView.Desktop.MouseButton(RemoteButton.Left, false);
                await Task.Delay(300);
                foreach (var ch in "uname -a") vncView.Desktop.Character(ch);
                vncView.Desktop.Key(Windows.System.VirtualKey.Enter, 0, false, true);
                vncView.Desktop.Key(Windows.System.VirtualKey.Enter, 0, false, false);
                await Task.Delay(2000);
                vncView.Poll();
                await CaptureBoth(root, themes, options, "vnc-");
                timings.Add($"vnc: wrong password refused; desktop {vncView.DesktopSize.Width}x{vncView.DesktopSize.Height}");
            }

            // BASTION_SNAPSHOT_WORKSPACE=1: two SSH tabs (local stand-in shells tied to web-1 and db-1) saved as a workspace,
            // then reopened: each tab comes back through its own Connect dialog.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_WORKSPACE") == "1")
            {
                window.CloseAllTabsForSnapshot();
                var key = Path.Combine(Path.GetDirectoryName(options.LibraryPath)!, "no-such-key");
                foreach (var name in new[] { "web-1", "db-1" })
                {
                    window.SelectByName(name);
                    await Task.Delay(300);
                    var stand = window.OpenTerminal($"ops@{name}", () => TerminalSession.Spawn("cmd.exe", ["/c", $"echo {name} & ping -n 120 127.0.0.1 >nul"], 100, 30))
                                ?? throw new InvalidOperationException("could not start the stand-in shell");
                    window.SuperviseForSnapshot(stand, key);
                }
                _ = window.SaveWorkspaceAsync();
                await Task.Delay(300);
                window.SetModalFieldForSnapshot("Workspace name", "Acme on-call");
                await CaptureBoth(root, themes, options, "workspace-save-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(300);
                var saved = window.WorkspacesForSnapshot();
                if (saved.Count != 1 || saved[0].Tabs.Count != 2) throw new InvalidOperationException($"workspace not saved ({saved.Count})");
                timings.Add($"workspace: saved '{saved[0].Name}' with {saved[0].Tabs.Count} tabs");
                window.CloseAllTabsForSnapshot();
                _ = window.OpenWorkspaceAsync(saved[0]);
                await Task.Delay(800);
                await CaptureBoth(root, themes, options, "workspace-open-");
                window.CancelModalForSnapshot();
                await Task.Delay(500);
                window.CancelModalForSnapshot();
                await Task.Delay(300);
            }

            // BASTION_SNAPSHOT_IPC=1: what `bastion open web-1` does, sent over the real owner-only pipe the way the CLI
            // sends it: the app selects web-1 and shows its normal Connect dialog (nothing connects without it).
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_IPC") == "1")
            {
                window.CloseAllTabsForSnapshot();
                window.SelectByName("db-1");
                var endpoint = window.IpcEndpointForSnapshot ?? throw new InvalidOperationException("the window is not listening for IPC");
                string Ask(string line)
                {
                    using var pipe = new System.IO.Pipes.NamedPipeClientStream(".", endpoint.Replace(@"\.\pipe\", ""), System.IO.Pipes.PipeDirection.InOut);
                    pipe.Connect(5000);
                    var bytes = System.Text.Encoding.UTF8.GetBytes(line + "\n");
                    pipe.Write(bytes);
                    pipe.Flush();
                    using var reader = new StreamReader(pipe);
                    return reader.ReadLine() ?? "";
                }
                var pong = await Task.Run(() => Ask("{\"op\":\"ping\"}"));
                var unknown = await Task.Run(() => Ask("{\"op\":\"open\",\"name\":\"no-such-host\",\"files\":false}"));
                var opened = await Task.Run(() => Ask("{\"op\":\"open\",\"name\":\"web-1\",\"files\":false}"));
                timings.Add($"ipc: ping -> {pong}; open no-such-host -> {unknown}; open web-1 -> {opened}");
                var until = DateTime.UtcNow.AddSeconds(10);
                while ((!window.ModalOpenForSnapshot || window.SelectedForSnapshot?.Name != "web-1") && DateTime.UtcNow < until) await Task.Delay(100);
                if (!window.ModalOpenForSnapshot || window.SelectedForSnapshot?.Name != "web-1") throw new InvalidOperationException($"open web-1 did not show the Connect dialog (modal {window.ModalOpenForSnapshot}, selected {window.SelectedForSnapshot?.Name}; {timings[^1]})");
                await CaptureBoth(root, themes, options, "ipc-open-");
                window.CancelModalForSnapshot();
            }

            // BASTION_SNAPSHOT_RECONNECT=1: a supervised SSH tab whose link drops. A short-lived local program stands in
            // for the shell; the core supervisor then tries to log in again (a missing key file, so it cannot succeed) and
            // the tab name reads "…, reconnecting 1/5", then "…, disconnected" (dot amber, then red) once the attempts are used up.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_RECONNECT") == "1")
            {
                window.CloseAllTabsForSnapshot();
                window.SelectByName("web-1");
                var drop = window.OpenTerminal("ops@web-1.acme.example", () => TerminalSession.Spawn("cmd.exe", ["/c", "echo Connected to web-1 & ping -n 3 127.0.0.1 >nul"], 100, 30))
                           ?? throw new InvalidOperationException("could not start the stand-in shell");
                window.SuperviseForSnapshot(drop, Path.Combine(Path.GetDirectoryName(options.LibraryPath)!, "no-such-key"));
                var labels = new HashSet<string>();
                var until = DateTime.UtcNow.AddSeconds(120);
                while (DateTime.UtcNow < until)
                {
                    await Task.Delay(100);
                    var label = window.ActiveTabLabelForSnapshot();
                    if (label.Contains(", reconnecting") && labels.Add("reconnecting")) await CaptureBoth(root, themes, options, "reconnect-", drop);
                    if (label.EndsWith(", disconnected")) { await CaptureBoth(root, themes, options, "disconnected-", drop); break; }
                }
                if (!labels.Contains("reconnecting")) throw new InvalidOperationException("the tab never showed reconnecting");
                timings.Add($"reconnect proof: final tab label '{window.ActiveTabLabelForSnapshot()}'");
            }

            // BASTION_SNAPSHOT_SSH=1: the OpenSSH import dialog over a throwaway fixture (a user .ssh dir with config and
            // config.d, plus a separate system ssh_config; forward lines give the tunnel rows of SSH-IMPORT-FORWARDS: plain, warned,
            // blocked), then the result and the imported hosts in the tree.
            if (Environment.GetEnvironmentVariable("BASTION_SNAPSHOT_SSH") == "1")
            {
                window.CloseAllTabsForSnapshot();
                var fixture = Path.Combine(Path.GetDirectoryName(options.LibraryPath)!, "ssh-fixture");
                var userDir = Path.Combine(fixture, "user", ".ssh");
                var systemDir = Path.Combine(fixture, "ProgramData", "ssh");
                Directory.CreateDirectory(Path.Combine(userDir, "config.d"));
                Directory.CreateDirectory(systemDir);
                File.WriteAllText(Path.Combine(userDir, "config"), "Host web-1\n  HostName web-1.acme.example\n  User ops\n  LocalForward 5432 db:5432\n  LocalForward *:8080 web:80\n  LocalForward /tmp/a.sock /tmp/b.sock\n  RemoteForward 9000 localhost:3000\n\nHost lab-*\n  User root\n  DynamicForward 1080\n\nHost lab-router\n  HostName 10.20.0.1\n  Port 2222\n");
                File.WriteAllText(Path.Combine(userDir, "config.d", "initech"), "Host tps-db\n  HostName db.initech.example\n  User <your-user>\n  ProxyJump jump.initech.example\n");
                File.WriteAllText(Path.Combine(systemDir, "ssh_config"), "Host build-agent\n  HostName build.corp.example\n  User svc-build\n");
                _ = window.ImportSshAsync(userDir, Path.Combine(systemDir, "ssh_config"));
                await CaptureBoth(root, themes, options, "ssh-import-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(500);
                await CaptureBoth(root, themes, options, "ssh-import-done-");
                window.CancelModalForSnapshot();
                await Task.Delay(300);
                await CaptureBoth(root, themes, options, "ssh-import-tree-");

                // The inspector for an imported host: Network (jump host, the placeholder it needs, Personal Overrides…),
                // the overrides dialog, the host after its overrides, and Notes saved with the library.
                // Each step is written as it completes, so a failure shows where it stopped.
                var inspectorLog = Path.Combine(options.Dir, "inspector.txt");
                void Step(string line) => File.AppendAllText(inspectorLog, line + Environment.NewLine);
                Step("tps-db effective: " + window.EffectiveForSnapshot("tps-db"));
                Step("tps-db jump hosts: " + window.JumpHostsForSnapshot("tps-db"));
                window.SelectByName("tps-db");
                await Task.Delay(500);
                Step("selected tps-db");
                await CaptureBoth(root, themes, options, "inspector-network-");
                Step("captured the network section");
                window.OpenOverridesForSnapshot("tps-db");
                await Task.Delay(400);
                Step("overrides dialog open");
                window.SetOverrideFieldForSnapshot("Port", "2202");
                window.SetOverrideFieldForSnapshot("<your-user>", "mo");
                await CaptureBoth(root, themes, options, "inspector-overrides-");
                window.PressModalPrimaryForSnapshot();
                await Task.Delay(500);
                await CaptureBoth(root, themes, options, "inspector-overridden-");
                Step("tps-db after overrides: " + window.EffectiveForSnapshot("tps-db"));
                window.SelectByName("web-1");
                await Task.Delay(400);
                window.SetNotesForSnapshot("Patch window: Sunday 02:00 UTC\nOn call: platform team");
                window.SelectByName("tps-db");
                await Task.Delay(300);
                window.SelectByName("web-1");
                await Task.Delay(400);
                Step("web-1 notes after switching rows: " + window.NotesForSnapshot("web-1").Replace("\n", " / "));
                await CaptureBoth(root, themes, options, "inspector-notes-");
            }

            // First run: no tabs, empty library (the demo library is in memory only).
            window.CloseAllTabsForSnapshot();
            window.ClearDemoLibraryForSnapshot();
            await CaptureBoth(root, themes, options, "empty-");

            await File.WriteAllLinesAsync(Path.Combine(options.Dir, "timings.txt"), timings);
            await File.WriteAllLinesAsync(Path.Combine(options.Dir, "popups.txt"), Captured);
            File.WriteAllText(Path.Combine(options.Dir, "snapshot.log"), "ok");
            Environment.Exit(0);
        }
        catch (Exception e)
        {
            Fail(e);
        }
    }

    private static async Task CaptureBoth(FrameworkElement root, (ElementTheme Theme, string Name)[] themes, SnapshotOptions options, string prefix, TerminalView? terminal = null)
    {
        foreach (var (theme, name) in themes)
        {
            root.RequestedTheme = theme;
            await Task.Delay(700); // theme change, selection and tree realization
            terminal?.Poll();
            await CaptureAsync(root, Path.Combine(options.Dir, prefix + name + ".png"), options.Scale);
            if (LastPopupCount > 0) Captured.Add($"{prefix}{name}.png: {LastPopupCount} open popup(s) drawn over the window");
        }
    }

    /// <summary>Captures that composited popups (menus), written to popups.txt.</summary>
    private static readonly List<string> Captured = new();

    private static double Median(List<double> values)
    {
        var sorted = values.OrderBy(v => v).ToList();
        return sorted[(sorted.Count - 1) / 2];
    }

    /// <summary>Completes on the next composition frame. The handler is removed at once, so rendering can go idle again.</summary>
    private static Task NextFrame()
    {
        var done = new TaskCompletionSource();
        EventHandler<object>? handler = null;
        handler = (_, _) =>
        {
            CompositionTarget.Rendering -= handler;
            done.TrySetResult();
        };
        CompositionTarget.Rendering += handler;
        return done.Task;
    }

    private static async Task CaptureAsync(FrameworkElement element, string path, double scale)
    {
        var bitmap = new RenderTargetBitmap();
        if (Math.Abs(scale - 1) > 0.01) await bitmap.RenderAsync(element, (int)Math.Round(element.ActualWidth * scale), (int)Math.Round(element.ActualHeight * scale));
        else await bitmap.RenderAsync(element);
        if (bitmap.PixelWidth == 0 || bitmap.PixelHeight == 0) throw new InvalidOperationException("the window rendered at zero size");
        var pixels = (await bitmap.GetPixelsAsync()).ToArray();
        await DrawOpenPopups(element, pixels, bitmap.PixelWidth, bitmap.PixelHeight);

        // A blank render (all one colour) means the window was not drawn yet; do not save it as a screenshot.
        var distinct = new HashSet<uint>();
        for (var i = 0; i + 3 < pixels.Length && distinct.Count < 8; i += 4 * 17) distinct.Add(BitConverter.ToUInt32(pixels, i));
        if (distinct.Count < 4) throw new InvalidOperationException($"the render of {Path.GetFileName(path)} is blank");

        using var stream = new InMemoryRandomAccessStream();
        var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
        encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Ignore, (uint)bitmap.PixelWidth, (uint)bitmap.PixelHeight, 96, 96, pixels);
        await encoder.FlushAsync();

        var bytes = new byte[stream.Size];
        using var reader = new DataReader(stream.GetInputStreamAt(0));
        await reader.LoadAsync((uint)stream.Size);
        reader.ReadBytes(bytes);
        await File.WriteAllBytesAsync(path, bytes);
    }

    /// <summary>
    /// Menus and flyouts live in popups, outside the element RenderTargetBitmap draws. Render each open popup's content
    /// and copy it over the window's pixels at its place, so a screenshot shows an open menu as the user sees it.
    /// </summary>
    /// <summary>Open popups seen by the last capture, for the snapshot log.</summary>
    internal static int LastPopupCount { get; private set; }

    private static async Task DrawOpenPopups(FrameworkElement root, byte[] pixels, int width, int height)
    {
        LastPopupCount = 0;
        if (root.XamlRoot is null) return;
        var ratio = width / Math.Max(1, root.ActualWidth);
        foreach (var popup in Microsoft.UI.Xaml.Media.VisualTreeHelper.GetOpenPopupsForXamlRoot(root.XamlRoot))
        {
            if (popup.Child is not FrameworkElement child || child.ActualWidth < 1) continue;
            LastPopupCount++;
            var at = child.TransformToVisual(root).TransformPoint(new Windows.Foundation.Point(0, 0));
            var layer = new RenderTargetBitmap();
            await layer.RenderAsync(child, (int)Math.Round(child.ActualWidth * ratio), (int)Math.Round(child.ActualHeight * ratio));
            var top = (await layer.GetPixelsAsync()).ToArray();
            int x0 = (int)Math.Round(at.X * ratio), y0 = (int)Math.Round(at.Y * ratio);
            // RenderTargetBitmap cannot draw acrylic, so a menu's background comes out clear: lay its fallback colour first.
            // WinUI draws a menu's acrylic as a system backdrop on the popup, outside RenderTargetBitmap: use the app's
            // dialog surface colour for the theme instead (an approximation of the acrylic, documented in TESTING.md).
            if ((FindBackground(child) ?? (Ui.Brush(root, "DialogBackgroundBrush") as SolidColorBrush)?.Color) is { } fill)
            {
                for (var y = Math.Max(0, y0); y < Math.Min(height, y0 + layer.PixelHeight); y++)
                    for (var x = Math.Max(0, x0); x < Math.Min(width, x0 + layer.PixelWidth); x++)
                    {
                        var dst = (y * width + x) * 4;
                        (pixels[dst], pixels[dst + 1], pixels[dst + 2]) = (fill.B, fill.G, fill.R);
                    }
            }
            for (var y = 0; y < layer.PixelHeight; y++)
            {
                var ty = y0 + y;
                if (ty < 0 || ty >= height) continue;
                for (var x = 0; x < layer.PixelWidth; x++)
                {
                    var tx = x0 + x;
                    if (tx < 0 || tx >= width) continue;
                    int src = (y * layer.PixelWidth + x) * 4, dst = (ty * width + tx) * 4;
                    var a = top[src + 3];
                    if (a == 0) continue;
                    // Premultiplied BGRA over the opaque window.
                    for (var k = 0; k < 3; k++) pixels[dst + k] = (byte)Math.Min(255, top[src + k] + pixels[dst + k] * (255 - a) / 255);
                }
            }
        }
    }

    /// <summary>The solid colour behind a popup's content: a composition (acrylic) brush's fallback, or an opaque solid brush.</summary>
    private static Windows.UI.Color? FindBackground(DependencyObject element, int depth = 0)
    {
        var brush = element switch { Microsoft.UI.Xaml.Controls.Control c => c.Background, Microsoft.UI.Xaml.Controls.Border b => b.Background, Microsoft.UI.Xaml.Controls.Panel p => p.Background, _ => null };
        if (brush is XamlCompositionBrushBase composition) return composition.FallbackColor;
        if (brush is SolidColorBrush { Color.A: 255 } solid) return solid.Color;
        if (depth > 6) return null;
        for (var i = 0; i < Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChildrenCount(element); i++)
            if (FindBackground(Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChild(element, i), depth + 1) is { } found) return found;
        return null;
    }

    /// <summary>Record why the snapshot failed and exit non-zero. There is no console and no one to read a dialog.</summary>
    public static void Fail(Exception e, int exitCode = 1)
    {
        try
        {
            if (_dir is not null) File.WriteAllText(Path.Combine(_dir, "snapshot.log"), "FAILED: " + e);
        }
        catch
        {
            // Nothing else can be done about a log we cannot write.
        }
        Environment.Exit(exitCode);
    }
}
#else
/// <summary>
/// Owner and Release builds: the snapshot driver is not compiled in (WIN-UI-DRIVER-GATE). BASTION_SNAPSHOT and every
/// BASTION_SNAPSHOT_* variable are ignored, so nothing in the environment can script the UI. Test builds define
/// BASTION_TEST_HOOKS (dotnet build -p:BastionTestHooks=true) and get the full runner above.
/// </summary>
internal static class SnapshotRunner
{
    public static bool Active => false;
    public static SnapshotOptions? FromEnvironment() => null;
    public static void SeedDemoData(LibraryClient lib) { }
    public static Task RunAsync(MainWindow window, SnapshotOptions options) => Task.CompletedTask;
    public static void Fail(Exception e, int exitCode = 1) => CrashLog.Write(e);
}
#endif
