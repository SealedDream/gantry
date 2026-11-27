using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// More → Triggers: highlight and notify rules (core <c>triggers</c>, <c>triggers.json</c> beside the library, C ABI 69,
/// shared with the Mac and Tauri apps). The core matches, highlights and rate-limits; this applies the rules to every
/// terminal and polls once a second for notify events, only while a terminal is open.
/// </summary>
public sealed partial class MainWindow
{
    private static readonly TimeSpan TriggerPollInterval = TimeSpan.FromSeconds(1);
    private const int TriggerAlertsKept = 20;
    private const int TriggerAlertsShown = 5;

    private TriggerStore? _triggers;
    private readonly List<TerminalView> _triggerViews = new();
    private readonly List<string> _triggerAlerts = new();
    private DispatcherTimer? _triggerTimer;

    private TriggerStore Triggers => _triggers ??= new TriggerStore(Path.Combine(SessionDataDir, "triggers.json"));

    /// <summary>Called for every new terminal view.</summary>
    private void AttachTriggers(TerminalView view)
    {
        try { TriggerStore.Apply(view.Session, Triggers); }
        catch (BastionException) { return; } // an unreadable triggers.json leaves the terminal plain; the manager shows the error
        _triggerViews.Add(view);
        if (_triggerTimer is not null) return;
        _triggerTimer = new DispatcherTimer { Interval = TriggerPollInterval };
        _triggerTimer.Tick += (_, _) => PollTriggers();
        _triggerTimer.Start();
    }

    /// <summary>A reconnected link brings a new shell into the same view; give it the rules too.</summary>
    private void ReattachTriggers(TerminalView view)
    {
        try { TriggerStore.Apply(view.Session, Triggers); }
        catch (BastionException) { /* the old rules went with the old shell; the manager shows the error */ }
    }

    /// <summary>After an edit: recompile the rules on every open terminal. Returns the first error.</summary>
    private string? ReapplyTriggers()
    {
        _triggerViews.RemoveAll(v => v.Session.IsDisposed);
        string? first = null;
        foreach (var v in _triggerViews)
        {
            try { TriggerStore.Apply(v.Session, Triggers); v.Redraw(); }
            catch (BastionException ex) { first ??= ex.Message; }
        }
        return first;
    }

    private void PollTriggers()
    {
        _triggerViews.RemoveAll(v => v.Session.IsDisposed);
        if (_triggerViews.Count == 0) { _triggerTimer?.Stop(); _triggerTimer = null; return; }
        foreach (var v in _triggerViews)
        {
            IReadOnlyList<TriggerEventDto> events;
            try { events = TriggerStore.TakeEvents(v.Session); }
            catch (BastionException) { continue; }
            foreach (var ev in events) NotifyTrigger(v, ev);
        }
    }

    private void NotifyTrigger(TerminalView view, TriggerEventDto ev)
    {
        var line = ev.Line.Trim();
        _triggerAlerts.Insert(0, $"{DateTime.Now:HH:mm:ss} {ev.Name}: {line}");
        if (_triggerAlerts.Count > TriggerAlertsKept) _triggerAlerts.RemoveRange(TriggerAlertsKept, _triggerAlerts.Count - TriggerAlertsKept);
        MarkBell(view);
        _tray?.Balloon($"Trigger: {ev.Name}", line);
    }

    private void Triggers_Click(object sender, RoutedEventArgs e) => _ = TriggersAsync();

    internal async Task TriggersAsync()
    {
        if (_modal is not null) return;
        IReadOnlyList<TriggerDto> all;
        try { all = Triggers.List(); }
        catch (BastionException ex)
        {
            await ShowModal("Could not open triggers", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
            return;
        }

        var editor = new TriggerEditor();
        var list = new ListView { SelectionMode = ListViewSelectionMode.Single, MaxHeight = 200 };
        AutomationProperties.SetName(list, "Trigger list");
        var empty = new TextBlock { Text = "No triggers yet. Fill in the form to add one.", TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetName(empty, empty.Text);
        var status = new TextBlock { TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetAutomationId(status, "TriggerStatus");
        var alerts = new TextBlock { TextWrapping = TextWrapping.Wrap, Style = Ui.Style("CaptionTextBlockStyle") };
        AutomationProperties.SetAutomationId(alerts, "TriggerAlerts");

        void SetStatus(string text) { status.Text = text; AutomationProperties.SetName(status, text); }

        void ShowAlerts()
        {
            var text = _triggerAlerts.Count == 0 ? "No alerts yet." : "Recent alerts: " + string.Join(" · ", _triggerAlerts.Take(TriggerAlertsShown));
            alerts.Text = text;
            AutomationProperties.SetName(alerts, text);
        }

        void Refill(string? select)
        {
            try { all = Triggers.List(); }
            catch (BastionException ex) { SetStatus(Capitalised(ex.Message)); return; }
            list.ItemsSource = all.Select(TriggerLine).ToList();
            list.Visibility = all.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
            empty.Visibility = all.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            var i = select is null ? -1 : all.ToList().FindIndex(t => t.Id == select);
            list.SelectedIndex = i;
            if (i < 0) editor.Load(null);
            ShowAlerts();
        }

        list.SelectionChanged += (_, _) => { if (list.SelectedIndex >= 0 && list.SelectedIndex < all.Count) editor.Load(all[list.SelectedIndex]); };

        var add = new Button { Content = Ui.IconLabel(Ui.Icon("GlyphAdd"), "New trigger") };
        AutomationProperties.SetName(add, "New trigger");
        add.Click += (_, _) => { list.SelectedIndex = -1; editor.Load(null); SetStatus(""); };
        var save = new Button { Content = "Save trigger", Style = Ui.Style("AccentButtonStyle") };
        AutomationProperties.SetName(save, "Save trigger");
        save.Click += (_, _) =>
        {
            if (editor.Read() is not { } dto) { SetStatus(editor.Problem!); return; }
            string id;
            try { id = Triggers.Save(dto); }
            catch (BastionException ex) { SetStatus(Capitalised(ex.Message)); return; }
            Refill(id);
            SetStatus(ReapplyTriggers() is { } err ? Capitalised(err) : $"Saved {dto.Name}.");
        };
        var remove = new Button { Content = "Remove" }.Quiet("GlyphDelete", "Remove trigger");
        AutomationProperties.SetName(remove, "Remove trigger");
        remove.Click += (_, _) =>
        {
            if (editor.EditingId is not { } id) { SetStatus("Pick a trigger to remove."); return; }
            var name = editor.EditingName;
            try { Triggers.Remove(id); }
            catch (BastionException ex) { SetStatus(Capitalised(ex.Message)); return; }
            Refill(null);
            SetStatus(ReapplyTriggers() is { } err ? Capitalised(err) : $"Removed {name}.");
        };

        var import = new Button { Content = "Import…" }.Quiet("GlyphImport", "Import triggers");
        AutomationProperties.SetName(import, "Import triggers");
        import.Click += async (_, _) =>
        {
            if (await PickTriggersFile(save: false) is not { } file) return;
            try
            {
                var n = Triggers.Import(await File.ReadAllTextAsync(file));
                Refill(null);
                SetStatus(ReapplyTriggers() is { } err ? Capitalised(err) : $"Imported {n} trigger(s).");
            }
            catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException) { SetStatus(Capitalised(ex.Message)); }
        };
        var export = new Button { Content = "Export…" }.Quiet("GlyphUpload", "Export triggers");
        AutomationProperties.SetName(export, "Export triggers");
        export.Click += async (_, _) =>
        {
            if (all.Count == 0) { SetStatus("No triggers to export."); return; }
            if (await PickTriggersFile(save: true) is not { } file) return;
            try { await File.WriteAllTextAsync(file, Triggers.Export()); SetStatus($"Exported {all.Count} trigger(s)."); }
            catch (Exception ex) when (ex is BastionException or IOException or UnauthorizedAccessException) { SetStatus(Capitalised(ex.Message)); }
        };

        var intro = new TextBlock { Text = "Highlight terminal output or get notified when it matches a pattern (a regular expression). Rules apply to every terminal.", TextWrapping = TextWrapping.Wrap };
        var body = new StackPanel { Spacing = 10 };
        body.Children.Add(intro);
        body.Children.Add(add);
        body.Children.Add(empty);
        body.Children.Add(list);
        body.Children.Add(editor.Body);
        body.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { save, remove } });
        body.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { import, export } });
        body.Children.Add(status);
        body.Children.Add(alerts);
        Refill(null);

        // Alerts that arrive while the dialog is open show up without reopening it.
        var redraw = new DispatcherTimer { Interval = TriggerPollInterval };
        redraw.Tick += (_, _) => ShowAlerts();
        redraw.Start();
        try { await ShowModal("Triggers", body, primary: "Close", cancel: null, wide: true); }
        finally { redraw.Stop(); }
    }

    /// <summary>The triggers file to import from or export to; null when cancelled.</summary>
    private async Task<string?> PickTriggersFile(bool save)
    {
        if (TestHooks.TriggersPath is { } hooked) return hooked;
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        if (save)
        {
            var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = "bastion-triggers" };
            picker.FileTypeChoices.Add("Triggers (JSON)", new List<string> { ".json" });
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
            return (await picker.PickSaveFileAsync())?.Path;
        }
        var open = new Windows.Storage.Pickers.FileOpenPicker();
        open.FileTypeFilter.Add(".json");
        WinRT.Interop.InitializeWithWindow.Initialize(open, hwnd);
        return (await open.PickSingleFileAsync())?.Path;
    }

    internal static string TriggerLine(TriggerDto t)
    {
        var what = new List<string>();
        if (t.Highlight is { } h && (h.Fg is not null || h.Bg is not null || h.Bold == true)) what.Add("highlight");
        if (t.Notify) what.Add("notify");
        var off = t.Enabled ? "" : " (off)";
        var flags = t.CaseInsensitive ? "i" : "";
        return $"{t.Name}{off} · /{t.Pattern}/{flags} · {(what.Count == 0 ? "no action" : string.Join(" + ", what))}";
    }
}

/// <summary>The add/edit form of the Triggers dialog.</summary>
internal sealed class TriggerEditor
{
    private const double ColourFieldWidth = 150;
    private const double OptionWidth = 120;

    private readonly TextBox _name = new() { Header = "Name" };
    private readonly TextBox _pattern = new() { Header = "Pattern (regular expression)", FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Cascadia Mono, Consolas") };
    private readonly CheckBox _ignoreCase = new() { Content = "Ignore case" };
    private readonly CheckBox _enabled = new() { Content = "On", IsChecked = true };
    private readonly TextBox _fg = new() { Header = "Text colour", PlaceholderText = "#RRGGBB", Margin = new Thickness(0, 0, 8, 0) };
    private readonly TextBox _bg = new() { Header = "Background", PlaceholderText = "#RRGGBB", Margin = new Thickness(0, 0, 8, 0) };
    private readonly CheckBox _bold = new() { Content = "Bold" };
    private readonly CheckBox _notify = new() { Content = "Notify" };

    public string? EditingId { get; private set; }
    public string EditingName => _name.Text.Trim();
    public string? Problem { get; private set; }
    public StackPanel Body { get; }

    public TriggerEditor()
    {
        AutomationProperties.SetName(_name, "Trigger name");
        AutomationProperties.SetName(_pattern, "Trigger pattern");
        AutomationProperties.SetName(_ignoreCase, "Ignore case");
        AutomationProperties.SetName(_enabled, "Trigger on");
        AutomationProperties.SetName(_fg, "Highlight text colour");
        AutomationProperties.SetName(_bg, "Highlight background");
        AutomationProperties.SetName(_bold, "Bold");
        AutomationProperties.SetName(_notify, "Notify");
        // Wrap grids so the colour fields and options stack in a narrow window instead of running off the dialog.
        Body = new StackPanel
        {
            Spacing = 8,
            Children =
            {
                _name, _pattern,
                new VariableSizedWrapGrid { Orientation = Orientation.Horizontal, ItemWidth = ColourFieldWidth, Children = { _fg, _bg } },
                new VariableSizedWrapGrid { Orientation = Orientation.Horizontal, ItemWidth = OptionWidth, Children = { _bold, _notify, _ignoreCase, _enabled } },
            },
        };
    }

    public void Load(TriggerDto? t)
    {
        EditingId = t?.Id;
        _name.Text = t?.Name ?? "";
        _pattern.Text = t?.Pattern ?? "";
        _ignoreCase.IsChecked = t?.CaseInsensitive ?? false;
        _enabled.IsChecked = t?.Enabled ?? true;
        _fg.Text = Hex(t?.Highlight?.Fg);
        _bg.Text = Hex(t?.Highlight?.Bg);
        _bold.IsChecked = t?.Highlight?.Bold ?? false;
        _notify.IsChecked = t?.Notify ?? false;
    }

    /// <summary>The form as a trigger, or null with <see cref="Problem"/> set. The core checks the pattern.</summary>
    public TriggerDto? Read()
    {
        Problem = null;
        var name = _name.Text.Trim();
        if (name.Length == 0) { Problem = "Give the trigger a name."; return null; }
        if (_pattern.Text.Length == 0) { Problem = "Enter a pattern."; return null; }
        if (!TryColour(_fg.Text, out var fg)) { Problem = "Text colour must look like #RRGGBB."; return null; }
        if (!TryColour(_bg.Text, out var bg)) { Problem = "Background must look like #RRGGBB."; return null; }
        var bold = _bold.IsChecked == true;
        var highlight = fg is null && bg is null && !bold ? null : new TriggerHighlightDto(fg, bg, bold ? true : null);
        return new TriggerDto(EditingId, name, _pattern.Text, _ignoreCase.IsChecked == true, _enabled.IsChecked != false, highlight, _notify.IsChecked == true);
    }

    private static string Hex(uint? c) => c is { } v ? $"#{v:X6}" : "";

    /// <summary>Empty is "no colour"; otherwise #RRGGBB (the # is optional).</summary>
    internal static bool TryColour(string text, out uint? value)
    {
        value = null;
        var s = text.Trim();
        if (s.Length == 0) return true;
        if (s.StartsWith('#')) s = s[1..];
        if (s.Length != 6 || !uint.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v)) return false;
        value = v;
        return true;
    }
}
