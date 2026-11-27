using System.Text.Json.Nodes;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.System;
using Node = Bastion.Shell.PluginViewModel.Node;

namespace Bastion.Shell;

/// <summary>
/// PLUG-VIEW-WIN: a plugin's view in a normal tab, the Windows port of Native Mac's PluginTabView (#1351). The helper
/// starts when the tab opens and stops when it closes (<see cref="Dispose"/>); nothing starts at app launch. Draws the
/// node tree with app controls and theme resources; dialogs and confirmations show inside the tab, not in a window.
/// Stateful controls (fields, the SQL editor, tables, trees) are kept by node id across redraws, so an update never
/// loses what the user is typing.
/// </summary>
internal sealed partial class PluginTabView : UserControl, IDisposable
{
    private readonly PluginViewModel _model;
    private readonly DispatcherQueueSafe _ui;
    private readonly Grid _root = new();
    private readonly Grid _page = new() { RowSpacing = 0 };
    private readonly Grid _overlay = new() { Visibility = Visibility.Collapsed };
    private readonly Dictionary<string, FrameworkElement> _kept = [];
    private PluginViewSession? _session;
    private bool _disposed;

    public PluginTabView(string pluginId)
    {
        _ui = new DispatcherQueueSafe(Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread());
        _model = new PluginViewModel(pluginId, SendOffUi);
        _model.Changed += Redraw;
        AutomationProperties.SetAutomationId(this, "plugin-tab");
        AutomationProperties.SetName(this, pluginId);
        _overlay.Background = Ui.Brush(this, "SmokeFillColorDefaultBrush");
        _root.Children.Add(_page);
        _root.Children.Add(_overlay);
        Content = _root;
        KeyDown += OnKey;
        // Ctrl+Enter / F5 run the tab's SQL editor wherever focus is in the tab. Preview (tunnelling) so a focused button
        // or the editor never sees it first; marking it handled stops the editor's own handler, so it runs once
        // (q-pgredo-win3: focus was on a button after a click and nothing ran).
        AddHandler(PreviewKeyDownEvent, new KeyEventHandler(OnRunKey), handledEventsToo: true);
        TraceKeys(this, "tab");
        Redraw();
    }

    public string PluginId => _model.PluginId;
    internal PluginViewModel Model => _model;

    /// <summary>Opens the view off the UI thread (a cold open compiles first), then reads its updates.</summary>
    public Task OpenAsync(string dataDir, string viewName, bool allowUnverified)
    {
        var id = _model.PluginId;
        return OpenWithAsync(() => PluginViewSession.Open(dataDir, id, viewName, null, allowUnverified, safeMode: false));
    }

    /// <summary>The library entry this tab shows (PLUG-08-WIN), or null for a plugin's own view.</summary>
    public string? EntryId { get; init; }

    /// <summary>PVE-TLS: the banner's Trust Certificate… on the core's certificate refusal (set by the window).</summary>
    public Action<PluginTabView>? TrustCertificate { get; init; }

    /// <summary>The core's refusal when the server's certificate fails the entry's TLS mode (core broker/stream.rs).</summary>
    internal static bool IsCertificateRefusal(string text) => text.Contains("certificate did not pass the TLS mode", StringComparison.Ordinal);

    /// <summary>The gateway route the entry's streams use; the tab owns it and closes it with the view.</summary>
    public IDisposable? Route { get; set; }

    /// <summary>Opens with <paramref name="open"/> off the UI thread (a cold open compiles first), then reads updates.</summary>
    public async Task OpenWithAsync(Func<PluginViewSession> open)
    {
        var helper = Path.Combine(AppContext.BaseDirectory, "bastion-plugin-host.exe");
        try
        {
            var started = DateTime.UtcNow;
            // Diagnostic (PLUG-08-WIN q-plug08w4: the open never returned): say when it is still waiting.
            // The UI line shows whether the window's thread is still free (a lock held there would block it too).
            using var watchdog = new System.Threading.Timer(_ =>
            {
                AppLog.Warn($"Plugin view still opening after {(DateTime.UtcNow - started).TotalSeconds:0} s");
                _ui.Post(() => AppLog.Info("Plugin view: UI thread free"));
            }, null, 10000, 10000);
            var s = await Task.Run(() =>
            {
                AppLog.Info("Plugin view: helper path");
                PluginViewSession.EnsureHelper(helper);
                AppLog.Info("Plugin view: core open");
                var opened = open();
                AppLog.Info($"Plugin view: core open returned after {(DateTime.UtcNow - started).TotalMilliseconds:0} ms");
                return opened;
            });
            if (_disposed)
            {
                // The tab closed during a cold open: stop the helper that just started.
                AppLog.Warn("Plugin view: the tab closed while the view opened; helper stopped");
                _ = Task.Run(() => { s.Close(); s.Free(); });
                return;
            }
            _session = s;
            var seen = 0;
            s.StartReading(text =>
            {
                var ended = IsEnded(text);
                // Diagnostic (PLUG-08-WIN): the first updates' types and any end reason; never their contents.
                var type = UpdateType(text);
                if (seen++ < 20 || ended || type.StartsWith("open-", StringComparison.Ordinal)) AppLog.Info($"Plugin view: update {type}{(ended ? " (" + EndReason(text) + ")" : "")}{(type == "refuse" ? ": " + RefuseText(text) : "")}");
                _ui.Post(() =>
                {
                    if (_disposed) { AppLog.Warn("Plugin view: update after the tab closed"); return; }
                    try { _model.ApplyText(text); }
                    catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or FormatException or System.Text.Json.JsonException)
                    {
                        AppLog.Warn($"Plugin view: update not applied ({ex.GetType().Name}): {ex.Message}");
                    }
                });
                return ended;
            });
            AppLog.Info("Plugin view: reading updates");
        }
        catch (BastionException ex) { AppLog.Warn("Plugin view not opened: " + ex.Message); _model.OpenFailed(ex.Message); }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or InvalidOperationException or ArgumentException)
        {
            // Never a silent empty tab: an interop or argument failure shows in the tab and in the app log.
            AppLog.Warn($"Plugin view not opened ({ex.GetType().Name}): {ex.Message}");
            _model.OpenFailed(ex.Message);
        }
    }

    private static string UpdateType(string text)
    {
        try { return JsonNode.Parse(text) is JsonObject o ? PluginViewModel.Str(o, "type") ?? "?" : "?"; }
        catch (System.Text.Json.JsonException) { return "unreadable"; }
    }

    /// <summary>A refusal's ask and words (the plugin's or core's error text; never row data).</summary>
    private static string RefuseText(string text)
    {
        try { return JsonNode.Parse(text) is JsonObject o ? $"ask {o["ask"]?.ToJsonString() ?? "-"} '{PluginViewModel.Str(o, "message") ?? ""}'" : ""; }
        catch (System.Text.Json.JsonException) { return ""; }
    }

    private int _draws;

    private static string EndReason(string text)
    {
        try { return JsonNode.Parse(text) is JsonObject o ? PluginViewModel.Str(o, "reason") ?? "" : ""; }
        catch (System.Text.Json.JsonException) { return ""; }
    }

    private static bool IsEnded(string text)
    {
        try { return JsonNode.Parse(text) is JsonObject o && PluginViewModel.Str(o, "type") == "ended"; }
        catch (System.Text.Json.JsonException) { return false; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _model.Changed -= Redraw;
        if (_session is { } s) _ = Task.Run(s.Close);
        _session = null;
        Route?.Dispose();
        Route = null;
    }

    private void SendOffUi(string json)
    {
        if (_session is not { } s) return;
        _ = Task.Run(() =>
        {
            try { s.Send(json); }
            catch (BastionException ex) { _ui.Post(() => { _model.Message = ex.Message; Redraw(); }); }
        });
    }

    private void OnKey(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != VirtualKey.Escape || _overlay.Visibility != Visibility.Visible) return;
        e.Handled = true;
        if (_model.PendingOpen is { } o) _model.AnswerOpen(o, false, o.Route, false);
        else if (_model.PendingConfirm is { } c) _model.Answer(c, false);
        else _model.DismissTopDialog();
    }

    // ---- drawing ----

    /// <summary>PLUG-API-13: the session behind an entry's tree in the library. Nothing but its sheets (the core's open
    /// sheet) is drawn; the window shows this view over the library while one is up.</summary>
    public bool SheetsOnly { get; init; }

    /// <summary>With <see cref="SheetsOnly"/>: a sheet appeared (true) or went (false); also after every update.</summary>
    public event Action<bool>? SheetChanged;

    private void Redraw()
    {
        if (_disposed) return;
        if (SheetsOnly)
        {
            DrawOverlay();
            SheetChanged?.Invoke(_overlay.Visibility == Visibility.Visible);
            return;
        }
        var draw = ++_draws;
        if (draw <= 20) AppLog.Info($"Plugin view: draw {draw} start, nodes {_model.Nodes.Count}, message {(_model.Message is null ? "no" : "yes")}");
        foreach (var holder in _hosts.Values) holder.Child = null; // kept controls leave the old tree before it is cleared
        _page.Children.Clear();
        _page.RowDefinitions.Clear();
        foreach (var h in new[] { GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star) })
            _page.RowDefinitions.Add(new RowDefinition { Height = h });

        if (_model.Message is { } m)
        {
            var bar = new InfoBar { Message = m, Severity = InfoBarSeverity.Warning, IsOpen = true, IsClosable = true };
            AutomationProperties.SetAutomationId(bar, "plugin-message");
            bar.Closed += (_, _) => { _model.Message = null; Redraw(); };
            _page.Children.Add(bar);
        }
        if (_model.Ended is { } ended)
        {
            var t = Ui.Text(ended, "BodyTextStyle");
            t.Foreground = Ui.Brush(this, "TextFillColorSecondaryBrush");
            t.Margin = new Thickness(12, 8, 12, 8);
            AutomationProperties.SetAutomationId(t, "plugin-ended");
            Grid.SetRow(t, 1);
            _page.Children.Add(t);
        }
        FrameworkElement body;
        if (_model.Nodes.Count == 0 && _model.Ended is null)
        {
            var ring = new ProgressRing { IsActive = true, Width = 32, Height = 32, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            AutomationProperties.SetAutomationId(ring, "plugin-loading");
            AutomationProperties.SetName(ring, "Loading plugin");
            body = ring;
        }
        else
        {
            body = new ScrollViewer
            {
                Content = Children(null, _model.Nodes, vertical: true),
                Padding = new Thickness(12),
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            };
        }
        Grid.SetRow(body, 2);
        _page.Children.Add(body);
        DrawOverlay();
        if (draw <= 20) AppLog.Info($"Plugin view: draw {draw} end");
    }

    private int _shownOpen = -1;

    private void DrawOverlay()
    {
        _overlay.Children.Clear();
        FrameworkElement? card = null;
        if (_model.PendingOpen is { } o)
        {
            if (_shownOpen != o.Id) AppLog.Info($"Plugin view: open sheet build ({o.Protocol}, thread ui={DispatcherQueue.HasThreadAccess})");
            card = OpenCard(o);
            if (_shownOpen != o.Id) { _shownOpen = o.Id; AppLog.Info($"Plugin view: open sheet shown ({o.Protocol}, reported {o.Reported})"); }
        }
        else if (_model.PendingConfirm is { } c) card = ConfirmCard(c);
        else if (_model.Dialogs.Count > 0) card = DialogCard(_model.Dialogs[^1]);
        _overlay.Visibility = card is null ? Visibility.Collapsed : Visibility.Visible;
        if (card is null) return;
        if (card.Parent is not null) AppLog.Warn("Plugin view: overlay card already has a parent");
        _overlay.Children.Add(card);
        if (_model.PendingOpen is not null) AppLog.Info("Plugin view: open sheet added to overlay");
        // Focus the card's first control. TryMoveFocus(Next/Previous) with FindNextElementOptions throws ArgumentException
        // in Loaded, and WinUI turns that into a fail-fast 0xC000027B (q-pve02w5b).
        card.Loaded += (_, _) => { if (FocusManager.FindFirstFocusableElement(card) is Control first) first.Focus(FocusState.Programmatic); };
    }

    private Border Card(string title, string automationId, FrameworkElement content, StackPanel buttons)
    {
        buttons.Orientation = Orientation.Horizontal;
        buttons.Spacing = Ui.Double("Space8");
        buttons.HorizontalAlignment = HorizontalAlignment.Right;
        var stack = new StackPanel { Spacing = 12 };
        stack.Children.Add(Ui.Text(title, "SubtitleTextStyle"));
        stack.Children.Add(content);
        stack.Children.Add(buttons);
        var card = new Border
        {
            Child = stack,
            Padding = new Thickness(16),
            MinWidth = 360,
            MaxWidth = 640,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            CornerRadius = new CornerRadius(8),
            BorderThickness = new Thickness(1),
            Background = Ui.Brush(this, "SolidBackgroundFillColorBaseBrush"),
            BorderBrush = Ui.Brush(this, "SurfaceStrokeColorDefaultBrush"),
        };
        AutomationProperties.SetAutomationId(card, automationId);
        AutomationProperties.SetName(card, title);
        return card;
    }

    private Border ConfirmCard(PluginViewModel.Confirm c)
    {
        var text = new TextBlock { Text = string.Join("\n", new[] { c.Entry, c.Text }.OfType<string>()), TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
        var ok = new Button { Content = "Confirm" };
        ok.Click += (_, _) => _model.Answer(c, true);
        var cancel = new Button { Content = "Cancel", Style = Ui.Style("AccentButtonStyle") }; // the safe choice is the default
        cancel.Click += (_, _) => _model.Answer(c, false);
        return Card(c.Title, "plugin-confirm", text, new StackPanel { Children = { ok, cancel } });
    }

    /// <summary>PLUG-OPEN-WIN: the open sheet (Mac PluginOpenSheet.swift). The words are the app's; the plugin's label is
    /// shown after a fixed prefix. Not reported by the server: a warning, and Cancel is the default button.</summary>
    private Border OpenCard(PluginViewModel.OpenRequest r)
    {
        var proto = r.Protocol.ToUpperInvariant();
        var stack = new StackPanel { Spacing = Ui.Double("Space8") };
        stack.Children.Add(Ui.Text($"{r.Plugin} · {r.EntryName}", "BodyTextStyle"));
        var label = Ui.Text("From the plugin: " + r.Label, "BodyTextStyle");
        label.FontStyle = Windows.UI.Text.FontStyle.Italic;
        label.TextTrimming = TextTrimming.CharacterEllipsis;
        label.MaxLines = 1;
        ToolTipService.SetToolTip(label, r.Label);
        stack.Children.Add(label);
        var dest = new TextBox { Text = $"{r.Protocol}://{(r.Host.Contains(':') ? "[" + r.Host + "]" : r.Host)}:{r.Port}", IsReadOnly = true, FontFamily = new FontFamily("Consolas") };
        AutomationProperties.SetAutomationId(dest, "plugin-open-destination");
        AutomationProperties.SetName(dest, "Destination");
        stack.Children.Add(dest);
        ComboBox? routePick = null;
        if (r.EntryRoute == "direct")
            stack.Children.Add(Ui.Text("Route: direct", "CaptionTextStyle"));
        else
        {
            routePick = new ComboBox { Header = "Route", ItemsSource = new[] { "The entry's route", "Direct" }, SelectedIndex = r.Route == "direct" ? 1 : 0, MinWidth = 200 };
            AutomationProperties.SetAutomationId(routePick, "plugin-open-route");
            stack.Children.Add(routePick);
        }
        var reported = Ui.Text(r.Reported ? "Reported by the server." : "Not reported by the server. Check the address before you connect.", "CaptionTextStyle");
        reported.TextWrapping = TextWrapping.Wrap;
        if (!r.Reported) reported.Foreground = Ui.Brush(this, "SystemFillColorCautionBrush");
        AutomationProperties.SetAutomationId(reported, r.Reported ? "plugin-open-reported" : "plugin-open-warning");
        stack.Children.Add(reported);
        var save = new CheckBox { Content = "Save as a library entry", IsChecked = false };
        ToolTipService.SetToolTip(save, "Saved beside the plugin entry, with the route above. No password is copied.");
        AutomationProperties.SetAutomationId(save, "plugin-open-save");
        stack.Children.Add(save);
        string Route() => routePick is null ? r.Route : routePick.SelectedIndex == 1 ? "direct" : "entry";
        var open = new Button { Content = "Connect" };
        AutomationProperties.SetAutomationId(open, "plugin-open-connect");
        open.Click += (_, _) => _model.AnswerOpen(r, true, Route(), save.IsChecked == true);
        var cancel = new Button { Content = "Cancel" };
        AutomationProperties.SetAutomationId(cancel, "plugin-open-cancel");
        cancel.Click += (_, _) => _model.AnswerOpen(r, false, Route(), false);
        // The default (accent) button: Connect when the server reported the address, Cancel when it did not.
        (r.Reported ? open : cancel).Style = Ui.Style("AccentButtonStyle");
        return Card($"Open {proto} connection?", "plugin-open-sheet", stack, new StackPanel { Children = { cancel, open } });
    }

    private Border DialogCard(PluginViewModel.Dialog d)
    {
        var close = new Button { Content = "Close" };
        ToolTipService.SetToolTip(close, "Close (Esc)");
        close.Click += (_, _) => _model.DismissTopDialog();
        return Card(d.Title, "plugin-dialog", Children(null, d.Nodes, vertical: true), new StackPanel { Children = { close } });
    }

    private Panel Children(int? parent, IReadOnlyList<Node> list, bool vertical)
    {
        var kids = PluginViewModel.Kids(parent, list).ToList();
        // A row of stat tiles (API 1.6) shares the width evenly, like the Mac's HStack of tiles.
        if (!vertical && kids.Count > 0 && kids.All(k => k.Kind == "stat"))
        {
            var row = new Grid { ColumnSpacing = Ui.Double("Space8") };
            for (var i = 0; i < kids.Count; i++)
            {
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                var tile = Element(kids[i], list);
                Grid.SetColumn(tile, i);
                row.Children.Add(tile);
            }
            return row;
        }
        var p = new StackPanel { Orientation = vertical ? Orientation.Vertical : Orientation.Horizontal, Spacing = Ui.Double("Space8") };
        foreach (var n in PluginViewModel.Kids(parent, list)) p.Children.Add(Element(n, list));
        return p;
    }

    /// <summary>One node's control. A control without its own automation id gets <c>plugin-node-&lt;id&gt;</c>, so UI tests
    /// can read any node (status lines, the DDL) by the plugin's id.</summary>
    private FrameworkElement Element(Node n, IReadOnlyList<Node> list)
    {
        var e = ElementOf(n, list);
        // A kept control comes in a Border holder, which UI Automation does not show: the id goes on the control.
        var target = e is Border { Child: FrameworkElement kept } && _hosts.TryGetValue(kept, out var h) && h == e ? kept : e;
        if (string.IsNullOrEmpty(AutomationProperties.GetAutomationId(target))) AutomationProperties.SetAutomationId(target, $"plugin-node-{n.Id}");
        return e;
    }

    private FrameworkElement ElementOf(Node n, IReadOnlyList<Node> list)
    {
        var rec = n.Value as JsonObject ?? [];
        var str = (n.Value as JsonValue)?.TryGetValue<string>(out var s) == true ? s : null;
        switch (n.Kind)
        {
            case "stack": return Children(n.Id, list, vertical: str != "horizontal");
            case "tab": return Children(n.Id, list, vertical: true);
            case "split": return Split(n, list, str == "vertical");
            case "tabs": return Tabs(n, list);
            case "toolbar": return Toolbar(n.Id, list);
            case "label":
                var text = new TextBlock { Text = str ?? "", TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
                if (list.FirstOrDefault(p => p.Id == n.Parent)?.Kind == "toolbar")
                {
                    text.Foreground = Ui.Brush(this, "TextFillColorSecondaryBrush");
                    text.TextWrapping = TextWrapping.NoWrap;
                    text.TextTrimming = TextTrimming.CharacterEllipsis;
                    text.VerticalAlignment = VerticalAlignment.Center;
                }
                return text;
            case "banner":
                var bannerText = PluginViewModel.Str(rec, "text") ?? "";
                var banner = new InfoBar
                {
                    Message = bannerText,
                    IsOpen = true,
                    IsClosable = false,
                    Severity = PluginViewModel.Str(rec, "level") switch { "error" => InfoBarSeverity.Error, "warning" => InfoBarSeverity.Warning, _ => InfoBarSeverity.Informational },
                };
                if (EntryId is not null && TrustCertificate is { } trust && IsCertificateRefusal(bannerText))
                {
                    var button = new Button { Content = "Trust Certificate…" };
                    AutomationProperties.SetName(button, "Trust Certificate");
                    AutomationProperties.SetAutomationId(button, "plugin-banner-trust");
                    ToolTipService.SetToolTip(button, "Read the server's certificate, compare its SHA-256 fingerprint, then pin it");
                    button.Click += (_, _) => trust(this);
                    banner.ActionButton = button;
                }
                return banner;
            case "progress":
                var v = (n.Value as JsonValue)?.TryGetValue<double>(out var d) == true ? d : (double?)null;
                return v is { } pv ? new ProgressBar { Minimum = 0, Maximum = 1, Value = pv } : new ProgressBar { IsIndeterminate = true };
            case "stat": return PluginDashboardParts.StatTile(this, rec);
            case "empty-state":
                var es = new StackPanel { Spacing = 4, HorizontalAlignment = HorizontalAlignment.Center };
                es.Children.Add(Ui.Text(PluginViewModel.Str(rec, "title") ?? "", "BodyStrongTextStyle"));
                var et = Ui.Text(PluginViewModel.Str(rec, "text") ?? "", "BodyTextStyle");
                et.Foreground = Ui.Brush(this, "TextFillColorSecondaryBrush");
                es.Children.Add(et);
                return es;
            case "button":
                var b = new Button { Content = PluginViewModel.Str(rec, "label") ?? "", IsEnabled = PluginViewModel.Bool(rec, "enabled") ?? true };
                var bid = n.Id;
                b.Click += (_, _) => _model.Pressed(bid);
                return b;
            case "text-field": return Keep(n, () => TextField(n.Id, rec));
            case "number-field": return Keep(n, () => NumberField(n.Id, rec));
            case "choice": return Keep(n, () => Choice(n.Id, rec));
            case "toggle": return Keep(n, () => Toggle(n.Id, rec));
            case "code-editor": return Keep(n, () => CodeEditor(n.Id, rec));
            case "table": return Keep(n, () => Table(n.Id, rec), rowsOf: n.Id);
            case "tree": return Keep(n, () => Tree(n.Id, null));
            default:
                var u = Ui.Text("Unsupported element: " + n.Kind, "BodyTextStyle");
                u.Foreground = Ui.Brush(this, "TextFillColorSecondaryBrush");
                return u;
        }
    }

    /// <summary>The control already made for this node and value, or a new one. A table is remade when its rows change.</summary>
    private FrameworkElement Keep(Node n, Func<FrameworkElement> make, int? rowsOf = null)
    {
        var key = $"{n.Id}|{n.Kind}|{n.Value?.ToJsonString()}";
        if (rowsOf is { } r) key += $"|{_model.Rows.GetValueOrDefault(r)?.Count ?? -1}|{_model.Totals.GetValueOrDefault(r, -1)}|{_model.TableMessages.GetValueOrDefault(r)}";
        if (n.Kind == "tree") key += "|" + TreeVersion;
        foreach (var stale in _kept.Keys.Where(k => k.StartsWith($"{n.Id}|", StringComparison.Ordinal) && k != key).ToList())
        {
            if (_kept.Remove(stale, out var gone) && _hosts.Remove(gone, out var oldHost)) oldHost.Child = null;
        }
        if (!_kept.TryGetValue(key, out var el))
        {
            el = make();
            _kept[key] = el;
        }
        // Every draw gives a kept control a new holder and empties the old one first. Finding the old parent through
        // the tree missed a control left in the previous draw's split grid (q-plug08w8: 0x800F1000 "already the child
        // of another element" in Split on draw 4); the holder we made ourselves is always known.
        if (_hosts.TryGetValue(el, out var previous)) previous.Child = null;
        Detach(el);
        var host = new Border { Child = el };
        _hosts[el] = host;
        return host;
    }

    private readonly Dictionary<FrameworkElement, Border> _hosts = [];

    private static void Detach(FrameworkElement el)
    {
        switch (VisualTreeHelper.GetParent(el))
        {
            case Panel p: p.Children.Remove(el); break;
            case Border b when b.Child == el: b.Child = null; break;
            case ContentPresenter cp when cp.Content == el: cp.Content = null; break;
        }
        if (el.Parent is ContentControl cc && cc.Content == el) cc.Content = null;
        if (el.Parent is Border pb && pb.Child == el) pb.Child = null;
        if (el.Parent is Panel pp) pp.Children.Remove(el);
    }

    private Grid Split(Node n, IReadOnlyList<Node> list, bool vertical)
    {
        var g = new Grid { ColumnSpacing = 8, RowSpacing = 8 };
        var i = 0;
        foreach (var k in PluginViewModel.Kids(n.Id, list))
        {
            var el = Element(k, list);
            if (vertical) { g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); Grid.SetRow(el, i++); }
            else { g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); Grid.SetColumn(el, i++); }
            g.Children.Add(el);
        }
        return g;
    }

    private (int Id, SqlEditor Editor)? _runEditor;
    private readonly HashSet<SqlEditor> _traced = [];

    /// <summary>With BASTION_KEY_TRACE=1 (test runs only), logs each key event an element sees, handled or not.</summary>
    internal static void TraceKeys(UIElement el, string where)
    {
        if (!TestHooks.KeyTrace) return;
        static string Mods() => Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Control).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down) ? "ctrl" : "-";
        el.AddHandler(PreviewKeyDownEvent, new KeyEventHandler((_, e) => AppLog.Info($"Key trace: {where} preview {e.Key} {Mods()} handled {e.Handled}")), handledEventsToo: true);
        el.AddHandler(KeyDownEvent, new KeyEventHandler((_, e) => AppLog.Info($"Key trace: {where} down {e.Key} {Mods()} handled {e.Handled}")), handledEventsToo: true);
    }

    private void OnRunKey(object sender, KeyRoutedEventArgs e)
    {
        if (e.Handled && !(e.Key == VirtualKey.Enter || e.Key == VirtualKey.F5)) return;
        var ctrl = Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Control).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down);
        if (e.Key == VirtualKey.Enter) AppLog.Info($"Plugin view: Enter in tab, ctrl {ctrl}, editor {(_runEditor is null ? "none" : "yes")}");
        if (!(e.Key == VirtualKey.F5 || (e.Key == VirtualKey.Enter && ctrl))) return;
        if (_runEditor is not { } r || r.Editor.XamlRoot is null) { AppLog.Info("Plugin view: run key, no editor in the tree"); return; }
        AppLog.Info($"Plugin view: run key sends run to node {r.Id} ({r.Editor.Text.Length} chars)");
        e.Handled = true;
        _model.RunInput(r.Id, r.Editor.Text);
    }

    private readonly Dictionary<int, int> _tabPick = [];

    private StackPanel Tabs(Node n, IReadOnlyList<Node> list)
    {
        var tabs = PluginViewModel.Kids(n.Id, list).ToList();
        var bar = new SelectorBar();
        AutomationProperties.SetName(bar, "Plugin tabs");
        var pick = Math.Clamp(_tabPick.GetValueOrDefault(n.Id), 0, Math.Max(0, tabs.Count - 1));
        for (var i = 0; i < tabs.Count; i++)
        {
            var title = (tabs[i].Value as JsonValue)?.TryGetValue<string>(out var t) == true ? t : "";
            bar.Items.Add(new SelectorBarItem { Text = title, IsSelected = i == pick });
        }
        var host = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch };
        if (tabs.Count > 0) host.Content = Children(tabs[pick].Id, list, vertical: true);
        var id = n.Id;
        bar.SelectionChanged += (s, _) =>
        {
            var i = s.Items.IndexOf(s.SelectedItem);
            if (i < 0 || i == _tabPick.GetValueOrDefault(id)) return;
            _tabPick[id] = i;
            Redraw();
        };
        return new StackPanel { Spacing = 8, Children = { bar, host } };
    }

    private TextBox TextField(int id, JsonObject rec)
    {
        var multi = PluginViewModel.Bool(rec, "multi-line") ?? false;
        var tb = new TextBox
        {
            Header = PluginViewModel.Str(rec, "label"),
            Text = PluginViewModel.Str(rec, "value") ?? "",
            PlaceholderText = PluginViewModel.Str(rec, "placeholder") ?? "",
            AcceptsReturn = multi,
            TextWrapping = multi ? TextWrapping.Wrap : TextWrapping.NoWrap,
            MinHeight = multi ? 80 : 0,
        };
        // Enter sends (Ctrl+Enter in a multi-line field), as the Mac's onSubmit; leaving the field sends too.
        tb.KeyDown += (_, e) =>
        {
            if (e.Key != VirtualKey.Enter) return;
            if (multi && !Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Control).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down)) return;
            e.Handled = true;
            _model.TextInput(id, tb.Text);
        };
        var sent = tb.Text;
        tb.LostFocus += (_, _) => { if (tb.Text != sent) { sent = tb.Text; _model.TextInput(id, tb.Text); } };
        return tb;
    }

    private NumberBox NumberField(int id, JsonObject rec)
    {
        var nb = new NumberBox { Header = PluginViewModel.Str(rec, "label"), Value = PluginViewModel.Num(rec, "value") ?? 0, SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Compact };
        nb.ValueChanged += (_, e) => { if (!double.IsNaN(e.NewValue)) _model.NumberInput(id, e.NewValue); };
        return nb;
    }

    private ComboBox Choice(int id, JsonObject rec)
    {
        var cb = new ComboBox { Header = PluginViewModel.Str(rec, "label") };
        foreach (var o in rec["options"] as JsonArray ?? []) cb.Items.Add(o is JsonValue v && v.TryGetValue<string>(out var s) ? s : "");
        cb.SelectedIndex = PluginViewModel.Int(rec, "selected") ?? -1;
        cb.SelectionChanged += (_, _) => { if (cb.SelectedIndex >= 0) _model.ChoiceInput(id, cb.SelectedIndex); };
        return cb;
    }

    private ToggleSwitch Toggle(int id, JsonObject rec)
    {
        var ts = new ToggleSwitch { Header = PluginViewModel.Str(rec, "label"), IsOn = PluginViewModel.Bool(rec, "value") ?? false };
        ts.Toggled += (_, _) => _model.ToggleInput(id, ts.IsOn);
        return ts;
    }

    /// <summary>The stand-alone SQL editor (PLUG-06c-WIN) on a code-editor node: Ctrl+Enter / F5 sends <c>run</c>,
    /// completions come from the plugin (<c>completions</c> → <c>provide-completions</c>), ranked by the core.</summary>
    private Grid CodeEditor(int id, JsonObject rec)
    {
        var editor = new SqlEditor(PluginViewModel.Str(rec, "language") ?? "sql")
        {
            Text = PluginViewModel.Str(rec, "text") ?? "",
            IsReadOnly = PluginViewModel.Bool(rec, "read-only") ?? false,
            MinHeight = 160,
        };
        editor.RunRequested += text => _model.RunInput(id, text);
        editor.CompletionSource = (text, ctx) => _model.AskCompletions(id, text, ctx.CharOffset);
        var hint = Ui.Text("Ctrl+Space completions · Ctrl+/ comment · Ctrl+Enter run", "CaptionTextStyle");
        hint.Foreground = Ui.Brush(this, "TextFillColorSecondaryBrush");
        hint.TextTrimming = TextTrimming.CharacterEllipsis;
        var g = new Grid { RowSpacing = 4, MinHeight = 200 };
        g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        g.Children.Add(editor);
        Grid.SetRow(hint, 1);
        g.Children.Add(hint);
        // Ctrl+Enter runs the view's editable editor; a read-only one (PostgreSQL's DDL) never takes its place.
        if (!editor.IsReadOnly) _runEditor = (id, editor);
        if (!_traced.Contains(editor)) { _traced.Add(editor); TraceKeys(editor, "editor"); }
        return g;
    }

    private StackPanel Table(int id, JsonObject rec)
    {
        var columns = (rec["columns"] as JsonArray ?? []).OfType<JsonObject>().Select(c => PluginViewModel.Str(c, "title") ?? "").ToList();
        var rows = _model.Rows.GetValueOrDefault(id);
        var panel = new StackPanel { Spacing = 4 };
        var header = RowGrid(columns.Count);
        for (var i = 0; i < columns.Count; i++) AddCell(header, Ui.Text(columns[i], "BodyStrongTextStyle"), i);
        panel.Children.Add(header);
        // Rows are selectable (PLUG-PVE-02): the selection's row keys go to the plugin. Shift/Ctrl-click selects several
        // (Save as Connection on many guests, plugin API 1.6), as the Mac table does.
        var list = new ListView { SelectionMode = ListViewSelectionMode.Extended, MaxHeight = 480 };
        foreach (var r in rows ?? [])
        {
            var g = RowGrid(columns.Count);
            for (var i = 0; i < Math.Min(r.Count, Math.Max(columns.Count, 1)); i++)
                AddCell(g, PluginDashboardParts.Cell(this, r[i]), i);
            if (PluginViewModel.IsDimmed(r)) g.Opacity = 0.5;
            list.Items.Add(g);
        }
        list.SelectionChanged += (_, _) => _model.SelectRows(id, list.SelectedItems.Select(i => list.Items.IndexOf(i)).Where(i => i >= 0).ToList());
        AutomationProperties.SetName(list, "Plugin table");
        AutomationProperties.SetAutomationId(list, $"plugin-table-{id}");
        panel.Children.Add(list);
        if (_model.Totals.TryGetValue(id, out var total) && (rows?.Count ?? 0) < total)
        {
            var more = new Button { Content = "More Rows" };
            var have = rows?.Count ?? 0;
            more.Click += (_, _) => _model.AskRows(id, have);
            panel.Children.Add(more);
        }
        if (_model.TableMessages.TryGetValue(id, out var refused))
        {
            var msg = Ui.Text(refused, "BodyTextStyle");
            msg.TextWrapping = TextWrapping.Wrap;
            msg.Foreground = Ui.Brush(this, "TextFillColorSecondaryBrush");
            AutomationProperties.SetAutomationId(msg, "plugin-table-message");
            panel.Children.Add(msg);
        }
        else if (rows is null) _model.AskRows(id, 0);
        return panel;
    }

    private static Grid RowGrid(int columns)
    {
        var g = new Grid { ColumnSpacing = 8, MinHeight = 24 };
        for (var i = 0; i < Math.Max(columns, 1); i++) g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        return g;
    }

    private static void AddCell(Grid g, FrameworkElement e, int col)
    {
        Grid.SetColumn(e, col);
        g.Children.Add(e);
    }

    /// <summary>Bumped when any tree's children arrive, so kept trees redraw.</summary>
    private int TreeVersion => _model.ChildrenVersion;

    private StackPanel Tree(int id, string? parent)
    {
        var panel = new StackPanel { Spacing = 2, Margin = new Thickness(parent is null ? 0 : 16, 0, 0, 0) };
        var items = _model.Children(id, parent);
        if (items is null) { _model.AskChildren(id, parent); return panel; }
        foreach (var item in items)
        {
            var key = PluginViewModel.Str(item, "key") ?? "";
            var label = PluginViewModel.Str(item, "label") ?? key;
            if (PluginViewModel.Bool(item, "has-children") ?? false)
            {
                var open = _openTree.Contains(PluginViewModel.ChildKey(id, key));
                var b = new Button
                {
                    Content = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 4, Children = { Ui.Icon(open ? "GlyphChevronDown" : "GlyphChevronRight", "SmallIconSize"), new TextBlock { Text = label } } },
                    Style = Ui.Style("SubtleButtonStyle"),
                    MinHeight = 24,
                };
                AutomationProperties.SetName(b, label);
                var k = key;
                b.Click += (_, _) =>
                {
                    var ck = PluginViewModel.ChildKey(id, k);
                    if (!_openTree.Remove(ck)) _openTree.Add(ck);
                    _model.SelectTreeItem(id, k);   // a click also selects it (PostgreSQL's Object tab)
                    _model.TouchChildren();
                };
                AttachMenu(b, id, key, item);
                panel.Children.Add(b);
                if (open) panel.Children.Add(Tree(id, key));
            }
            else
            {
                // A leaf is a row the user can click to select (the plugin shows its details).
                var leaf = new Button
                {
                    Content = new TextBlock { Text = label },
                    Style = Ui.Style("SubtleButtonStyle"),
                    MinHeight = 24,
                    Margin = new Thickness(20, 0, 0, 0),
                };
                AutomationProperties.SetName(leaf, label);
                var lk = key;
                leaf.Click += (_, _) => { _model.SelectTreeItem(id, lk); _model.TouchChildren(); };
                AttachMenu(leaf, id, key, item);
                panel.Children.Add(leaf);
            }
        }
        return panel;
    }

    /// <summary>The tree item's menu from the plugin, as a right-click flyout (Mac: contextMenu, #1380).</summary>
    private void AttachMenu(FrameworkElement target, int id, string key, JsonObject item)
    {
        if (item["menu"] is not JsonArray menu || menu.Count == 0) return;
        var flyout = new MenuFlyout();
        foreach (var m in menu.OfType<JsonObject>())
        {
            var mid = PluginViewModel.Str(m, "id") ?? "";
            var mi = new MenuFlyoutItem { Text = PluginViewModel.Str(m, "title") ?? mid };
            mi.Click += (_, _) => _model.MenuInput(id, key, mid);
            flyout.Items.Add(mi);
        }
        target.ContextFlyout = flyout;
    }

    private readonly HashSet<string> _openTree = [];
}

/// <summary>Posts to the UI thread; a post after the window closed is dropped.</summary>
internal readonly struct DispatcherQueueSafe(Microsoft.UI.Dispatching.DispatcherQueue q)
{
    // An exception that leaves a DispatcherQueue callback is not routed to Application.UnhandledException: the process
    // fails fast (0xc000027b, PLUG-08-WIN q-plug08w6/w7, no crash.log). Log it with its stack instead; the tab stays.
    public void Post(Action a) => q.TryEnqueue(() =>
    {
        try { a(); }
        catch (Exception ex) { AppLog.Warn($"Plugin view: UI step failed ({ex.GetType().Name}): {ex}"); }
    });
}
