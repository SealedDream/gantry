using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// PLUG-06b (Native Windows): Application › Plugins, the same page as Native Mac (PLUG-06a part 1). Three views:
// Installed (id, version, badge, what the policy decides, Remove), Catalogue (Refresh, outcome in words) and Updates
// (the update plan). Install from File: a file has no signed record, so it is Unverified; refused at once when the
// policy forbids it, otherwise one confirm per install. All trust decisions are the core's (C ABI 120 and the PLUG-02c
// broker). Core calls run off the UI thread. Running plugins is PLUG-06b part 2.
public sealed partial class MainWindow
{
    public sealed class PluginRow(InstalledPluginDto p, string? block)
    {
        public InstalledPluginDto Plugin { get; } = p;
        public string Id { get; } = p.Id;
        public string Version { get; } = p.Version;
        public string Badge { get; } = PluginsText.Badge(p.Tier);
        public string Status { get; } = block ?? "Allowed";
        public string Name => $"{Id}, {Version}, {Badge}, {Status}";
    }

    public sealed class PluginUpdateRow(PluginUpdateDto u)
    {
        public string Id { get; } = u.Id;
        public string From { get; } = u.From;
        public string To { get; } = u.To;
        public string Note { get; } = PluginsText.UpdateNote(u);
        public string Name => $"{Id}, {From} to {To}{(Note.Length > 0 ? ", " + Note : "")}";
    }

    private static readonly string[] PluginViews = ["Installed", "Catalogue", "Updates"];
    private static readonly GridLength[] InstalledWidths = [new(2, GridUnitType.Star), new(90), new(100), new(1.5, GridUnitType.Star), GridLength.Auto];
    private static readonly GridLength[] UpdateWidths = [new(2, GridUnitType.Star), new(90), new(90), new(1.5, GridUnitType.Star)];

    private string _pluginView = "Installed";
    private readonly List<PluginRow> _pluginRows = [];
    private readonly List<PluginUpdateRow> _pluginUpdates = [];
    private PluginPolicyDto? _pluginPolicy;
    private string? _pluginRefresh, _pluginMessage;
    private bool _pluginBusy;

    internal void OpenPlugins()
    {
        _pageKind = "plugins";
        _pluginView = "Installed";
        _pluginMessage = null;
        ShowPluginsPage();
        _ = ReloadPluginsAsync();
    }

    private void ShowPluginsPage()
    {
        if (_pageKind != "plugins") return;
        var content = new Grid { RowSpacing = Ui.Double("Space8") };
        foreach (var h in new[] { GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto })
            content.RowDefinitions.Add(new RowDefinition { Height = h });

        content.Children.Add(PluginViewBar());

        if (_pluginPolicy is { } pol && PluginsText.PolicyBanner(pol) is { } banner)
        {
            var b = Ui.Text(banner, "BodyStrongTextStyle");
            b.TextTrimming = TextTrimming.CharacterEllipsis;
            ToolTipService.SetToolTip(b, banner);
            AutomationProperties.SetName(b, "Plugin policy");
            Grid.SetRow(b, 1);
            content.Children.Add(b);
        }

        FrameworkElement body = _pluginView switch
        {
            "Catalogue" => PluginCatalogueView(),
            "Updates" => PluginUpdatesView(),
            _ => PluginInstalledView(),
        };
        Grid.SetRow(body, 2);
        content.Children.Add(body);

        var footer = PluginFooter();
        Grid.SetRow(footer, 3);
        content.Children.Add(footer);
        ShowPage(null, "Plugins", content);
    }

    private SelectorBar PluginViewBar()
    {
        var bar = new SelectorBar();
        AutomationProperties.SetName(bar, "Plugin views");
        foreach (var v in PluginViews)
        {
            var item = new SelectorBarItem { Text = v, IsSelected = v == _pluginView };
            AutomationProperties.SetName(item, v);
            bar.Items.Add(item);
        }
        bar.SelectionChanged += (s, _) =>
        {
            if (s.SelectedItem?.Text is not { } v || v == _pluginView) return;
            _pluginView = v;
            ShowPluginsPage();
        };
        return bar;
    }

    private static Grid PluginColumns(GridLength[] widths)
    {
        var g = new Grid { ColumnSpacing = 8 };
        foreach (var w in widths) g.ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        return g;
    }

    private static void AddCell(Grid g, FrameworkElement e, int col)
    {
        Grid.SetColumn(e, col);
        g.Children.Add(e);
    }

    private static TextBlock Cell(string text)
    {
        var t = Ui.Text(text, "BodyTextStyle");
        t.VerticalAlignment = VerticalAlignment.Center;
        t.TextTrimming = TextTrimming.CharacterEllipsis;
        if (text.Length > 0) ToolTipService.SetToolTip(t, text);
        return t;
    }

    /// <summary>A header row and a scrolling list below it; <paramref name="empty"/> shows when there are no rows.</summary>
    private static Grid PluginTable(GridLength[] widths, string[] names, string listName, string empty, IEnumerable<Grid> rows)
    {
        var panel = new Grid { RowSpacing = 4 };
        panel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        panel.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        var header = PluginColumns(widths);
        for (var i = 0; i < names.Length; i++) AddCell(header, Ui.Text(names[i], "CaptionTextStyle"), i);
        panel.Children.Add(header);
        var list = new StackPanel { Spacing = 2 };
        foreach (var r in rows) list.Children.Add(r);
        if (list.Children.Count == 0) list.Children.Add(Ui.Text(empty, "BodyTextStyle"));
        var scroll = new ScrollViewer { Content = list };
        AutomationProperties.SetName(scroll, listName);
        Grid.SetRow(scroll, 1);
        panel.Children.Add(scroll);
        return panel;
    }

    private Grid PluginInstalledView() => PluginTable(InstalledWidths, ["Plugin", "Version", "Badge", "Status", ""], "Installed plugins", "No plugins installed",
        _pluginRows.Select(r =>
        {
            var g = PluginColumns(InstalledWidths);
            g.MinHeight = 32;
            AutomationProperties.SetName(g, r.Name);
            AddCell(g, Cell(r.Id), 0);
            AddCell(g, Cell(r.Version), 1);
            AddCell(g, Cell(r.Badge), 2);
            AddCell(g, Cell(r.Status), 3);
            var remove = new Button { Content = "Remove…", IsEnabled = !_pluginBusy }.Quiet("GlyphDelete", "Remove");
            AutomationProperties.SetName(remove, "Remove " + r.Id);
            var p = r.Plugin;
            remove.Click += (_, _) => _ = RemovePluginAsync(p);
            // PLUG-VIEW-WIN: Open runs the plugin's view in a normal tab (Native Mac #1351); refused by policy = disabled.
            var open = new Button { Content = "Open", IsEnabled = !_pluginBusy && r.Status == "Allowed" };
            AutomationProperties.SetName(open, "Open " + r.Id);
            ToolTipService.SetToolTip(open, r.Status == "Allowed" ? "Open in a tab" : r.Status);
            open.Click += (_, _) => _ = OpenPluginAsync(p);
            AddCell(g, new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { open, remove } }, 4);
            return g;
        }).ToList());

    private Grid PluginUpdatesView() => PluginTable(UpdateWidths, ["Plugin", "From", "To", "Note"], "Plugin updates", "No updates",
        _pluginUpdates.Select(u =>
        {
            var g = PluginColumns(UpdateWidths);
            g.MinHeight = 32;
            AutomationProperties.SetName(g, u.Name);
            AddCell(g, Cell(u.Id), 0);
            AddCell(g, Cell(u.From), 1);
            AddCell(g, Cell(u.To), 2);
            AddCell(g, Cell(u.Note), 3);
            return g;
        }).ToList());

    private StackPanel PluginCatalogueView()
    {
        var s = new StackPanel { Spacing = Ui.Double("Space8") };
        var state = Ui.Text(PluginsText.Catalogue(_pluginRefresh), "BodyStrongTextStyle");
        AutomationProperties.SetAutomationId(state, "plugins-catalogue-state");
        s.Children.Add(state);
        s.Children.Add(Ui.Text("Only signed catalogue entries are offered.", "CaptionSecondaryTextStyle"));
        return s;
    }

    private Grid PluginFooter()
    {
        var g = new Grid { ColumnSpacing = Ui.Double("Space8") };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var msg = Ui.Text(_pluginMessage ?? "", "CaptionSecondaryTextStyle");
        msg.VerticalAlignment = VerticalAlignment.Center;
        msg.TextTrimming = TextTrimming.CharacterEllipsis;
        AutomationProperties.SetAutomationId(msg, "plugins-message");
        if (_pluginMessage is { Length: > 0 } m) ToolTipService.SetToolTip(msg, m);
        g.Children.Add(msg);

        var off = _pluginBusy || _pluginPolicy is null || _pluginPolicy.PluginsDisabled;
        var refresh = new Button { Content = "Refresh Catalogue", IsEnabled = !off }.Quiet("GlyphRefresh", "Fetch the signed plugin catalogue");
        refresh.Click += (_, _) => _ = RefreshPluginsAsync();
        AddCell(g, refresh, 1);
        var install = new Button { Content = "Install from File…", IsEnabled = !off }.Quiet("GlyphImport", "Install a .gantryplugin file");
        install.Click += (_, _) => _ = PickPluginFileAsync();
        AddCell(g, install, 2);
        return g;
    }

    // ---- Actions ----

    private async Task ReloadPluginsAsync()
    {
        var dir = SessionDataDir;
        try
        {
            var (policy, rows, updates) = await Task.Run(() =>
            {
                var pol = PluginClient.Policy();
                // Running plugins is not wired yet, so the status shows what the policy decides; Safe mode is off.
                var r = PluginClient.Installed(dir).Select(p => new PluginRow(p, PluginClient.MayLoad(p.Id, p.Tier, p.Tier == "unverified", false))).ToList();
                var u = PluginClient.Updates(dir).Select(x => new PluginUpdateRow(x)).ToList();
                return (pol, r, u);
            });
            _pluginPolicy = policy;
            _pluginRows.Clear();
            _pluginRows.AddRange(rows);
            _pluginUpdates.Clear();
            _pluginUpdates.AddRange(updates);
        }
        catch (BastionException ex) { _pluginMessage = "Plugins unavailable: " + ex.Message; }
        ShowPluginsPage();
    }

    /// <summary>One core action off the UI thread; its result (or the error) becomes the footer message.</summary>
    private async Task RunPluginActionAsync(Func<string, string> action, string failPrefix)
    {
        var dir = SessionDataDir;
        _pluginBusy = true;
        ShowPluginsPage();
        try { _pluginMessage = await Task.Run(() => action(dir)); }
        catch (BastionException ex) { _pluginMessage = failPrefix + ex.Message; }
        finally { _pluginBusy = false; _pluginTypes = null; } // an install or removal changes the connection types
        await ReloadPluginsAsync();
    }

    private Task RefreshPluginsAsync()
    {
        var mirror = TestHooks.PluginMirror;
        return RunPluginActionAsync(dir =>
        {
            var outcome = PluginClient.Refresh(dir, mirror);
            _pluginRefresh = outcome;
            return PluginsText.Catalogue(outcome);
        }, "Refresh failed: ");
    }

    private async Task PickPluginFileAsync()
    {
        if (_modal is not null) return;
        if (_pluginPolicy is not { } policy)
        {
            _pluginMessage = "Policy forbids unverified plugins";
            ShowPluginsPage();
            return;
        }
        var path = TestHooks.PluginInstallPath;
        if (path is null)
        {
            var picker = new Windows.Storage.Pickers.FileOpenPicker();
            picker.FileTypeFilter.Add(".gantryplugin");
            picker.FileTypeFilter.Add(".bastionplugin"); // packs made before the rename
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            if (await picker.PickSingleFileAsync() is not { } file) return;
            path = file.Path;
        }
        var name = Path.GetFileName(path);
        // A signed record beside the file installs it at its tier with no question (PLUG-12).
        var unverified = false;
        await RunPluginActionAsync(dir =>
        {
            var kind = PluginClient.InstallSigned(dir, path);
            unverified = kind is null;
            return kind is null ? "" : PluginsText.Install(kind, name);
        }, "Not installed: ");
        if (!unverified) return;
        if (PluginsText.FileInstallForbidden(policy))
        {
            _pluginMessage = "Policy forbids unverified plugins";
            ShowPluginsPage();
            return;
        }
        var body = Ui.Text("No signed record: Gantry cannot check who made it.", "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        if (!await ShowModal("Install an unverified plugin?", body, primary: "Install", cancel: "Cancel", focusCancel: true)) return;
        await RunPluginActionAsync(dir => PluginsText.Install(PluginClient.InstallFile(dir, path, allowUnverified: true), name), "Not installed: ");
    }

    private async Task RemovePluginAsync(InstalledPluginDto p)
    {
        if (_modal is not null) return;
        var deleteData = new CheckBox { Content = "Also delete its data" };
        if (!await ShowModal($"Remove {p.Id}?", deleteData, primary: "Remove", cancel: "Cancel", focusCancel: true)) return;
        var withData = deleteData.IsChecked == true;
        var id = p.Id;
        await RunPluginActionAsync(dir =>
        {
            PluginClient.Remove(dir, id, withData);
            return withData ? $"Removed {id} and its data" : $"Removed {id}";
        }, "Not removed: ");
    }

    // ---- Plugin view tabs (PLUG-VIEW-WIN) ----

    /// <summary>The plugin's tab, selected if already open, else a new one whose helper starts now. Nothing starts at
    /// app launch; the helper stops when the tab closes (CloseTab → PluginTabView.Dispose).</summary>
    internal void OpenPluginTab(string pluginId, bool allowUnverified)
    {
        // The page covers the tabs (as the Mac's Plugins sheet dismisses on Open): close it so the plugin's tab shows.
        if (_pageKind.Length > 0) ClosePage();
        if (_tabs.FirstOrDefault(t => t.Plugin?.PluginId == pluginId) is { } open) { PickTab(open); return; }
        var view = new PluginTabView(pluginId);
        var tab = AddTab(pluginId, null, plugin: view, glyph: "GlyphList");
        tab.FocusContent(FocusState.Programmatic);
        _ = view.OpenAsync(SessionDataDir, "settings", allowUnverified);
    }

    /// <summary>As on Native Mac: an Unverified plugin asks first, each time (no stored "Allow unverified" setting yet).</summary>
    private async Task OpenPluginAsync(InstalledPluginDto p)
    {
        if (_modal is not null) return;
        var unverified = p.Tier == "unverified";
        if (unverified)
        {
            var body = Ui.Text("Unverified plugin: no known publisher signature. It runs in the plugin sandbox.", "BodyTextStyle");
            body.TextWrapping = TextWrapping.Wrap;
            if (!await ShowModal("Open an unverified plugin?", body, primary: "Open", cancel: "Cancel", focusCancel: true)) return;
        }
        OpenPluginTab(p.Id, unverified);
    }

    /// <summary>The open plugin view of <paramref name="pluginId"/> (UI tests).</summary>
    internal PluginViewModel? PluginViewFor(string pluginId) => _tabs.FirstOrDefault(t => t.Plugin?.PluginId == pluginId)?.Plugin?.Model;

    // ---- Snapshot hooks ----

    internal string PluginsStateForSnapshot() => $"installed={_pluginRows.Count} updates={_pluginUpdates.Count} catalogue={PluginsText.Catalogue(_pluginRefresh)}";
}
