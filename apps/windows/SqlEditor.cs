using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Bastion.Shell.Interop;
using Microsoft.UI.Input;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;
using Windows.UI.Core;

namespace Bastion.Shell;

/// <summary>
/// PLUG-06c (Native Windows): the SQL code editor. A RichEditBox coloured by the core's tokenizer (C ABI 136), line by
/// line from the edited line down (<see cref="SqlEditorModel"/>). Plain text only: paste drops formatting, the
/// built-in undo is replaced by <see cref="EditHistory"/> so colouring is never an undo step.
/// Keys: Ctrl+Enter or F5 runs, Ctrl+Space asks for completions, Ctrl+/ toggles "-- " comments, Tab and Shift+Tab
/// indent, Ctrl+Z / Ctrl+Y (Ctrl+Shift+Z) undo and redo. In the completion list: Up, Down, Enter or Tab, Escape.
/// Completions come from <see cref="CompletionSource"/> (the plugin, once the view host exists); without one, none.
/// </summary>
public sealed partial class SqlEditor : UserControl
{
    private const int PaintChunkLines = 400;
    private const int MaxListed = 12;

    private readonly RichEditBox _box = new()
    {
        AcceptsReturn = true,
        TextWrapping = TextWrapping.NoWrap,
        IsSpellCheckEnabled = false,
        IsTextPredictionEnabled = false,
        ClipboardCopyFormat = RichEditClipboardFormat.PlainText,
        DisabledFormattingAccelerators = DisabledFormattingAccelerators.All,
        FontFamily = new FontFamily("Cascadia Mono, Consolas"),
        FontSize = 13,
    };
    // Not light-dismiss: a light-dismiss popup takes keyboard focus when it opens, and the keys typed after the first
    // letter went to it instead of the editor (PLUG-VIEW-WIN q-plugview-win5). It closes when the editor loses focus.
    private readonly Popup _popup = new() { IsLightDismissEnabled = false };
    private readonly ListView _list = new() { MaxHeight = 260, MinWidth = 220, SelectionMode = ListViewSelectionMode.Single, IsTabStop = false, AllowFocusOnInteraction = false };
    private readonly SqlEditorModel _model;
    private EditHistory _history = new(new("", 0, 0));
    private string _text = "";
    private bool _applying;
    private bool _lastWasTyping;
    private int _paintGeneration;
    private CompletionContext? _completionAt;

    public SqlEditor(string language = "postgresql")
    {
        _model = new SqlEditorModel(language);
        AutomationProperties.SetName(_box, "SQL editor");
        AutomationProperties.SetAutomationId(_box, "sql-editor");
        AutomationProperties.SetName(_list, "Completions");
        AutomationProperties.SetAutomationId(_list, "sql-completions");
        ScrollViewer.SetHorizontalScrollBarVisibility(_box, ScrollBarVisibility.Auto);
        ScrollViewer.SetVerticalScrollBarVisibility(_box, ScrollBarVisibility.Auto);
        _box.Document.UndoLimit = 0;
        _box.TextChanged += (_, _) => OnTextChanged();
        _box.Paste += OnPaste;
        _box.PreviewKeyDown += OnKey;
        _box.LostFocus += (_, _) => _popup.IsOpen = false;
        _list.IsItemClickEnabled = true;
        _list.ItemClick += (_, e) => { if (e.ClickedItem is ListViewItem { Tag: CompletionItemDto item }) Accept(item); };
        _popup.Child = new Border { Child = _list, Padding = new Thickness(2), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(4) };
        _popup.Closed += (_, _) => _completionAt = null;
        Loaded += (_, _) => { PaintPopup(); RepaintAll(); };
        ActualThemeChanged += (_, _) => { PaintPopup(); RepaintAll(); };
        Content = new Grid { Children = { _box, _popup } };
    }

    /// <summary>Ctrl+Enter or F5, with the editor's text.</summary>
    public event Action<string>? RunRequested;

    /// <summary>Asked when the core says completions apply at the cursor: (text, context) → items (unranked; the
    /// core ranks them). Null: no completions. A plugin answers through the view host (PLUG-06c wiring).</summary>
    public Func<string, CompletionContext, Task<IReadOnlyList<CompletionItemDto>>>? CompletionSource { get; set; }

    public bool IsReadOnly { get => _box.IsReadOnly; set => _box.IsReadOnly = value; }

    /// <summary>The text, with '\n' line breaks.</summary>
    public string Text
    {
        get => _text.Replace('\r', '\n');
        set => SetState(new(string.Join('\r', SqlEditorModel.SplitLines(value ?? "")), 0, 0));
    }

    /// <summary>Whether the completion list is open (UI tests).</summary>
    internal bool CompletionsOpen => _popup.IsOpen;

    private string ReadBox()
    {
        _box.Document.GetText(TextGetOptions.None, out var t);
        // The document always ends in a paragraph mark that is not part of the user's text.
        return t.EndsWith('\r') ? t[..^1] : t;
    }

    private void SetState(EditResult s)
    {
        _applying = true;
        try
        {
            var ro = _box.IsReadOnly;
            _box.IsReadOnly = false;
            _box.Document.SetText(TextSetOptions.None, s.Text);
            _box.IsReadOnly = ro;
            _box.Document.Selection.SetRange(s.SelectionStart, s.SelectionStart + s.SelectionLength);
        }
        finally { _applying = false; }
        _text = s.Text;
        _history = new(s);
        _model.Update(_text);
        RepaintAll();
    }

    private void OnTextChanged()
    {
        if (_applying) return;
        var t = ReadBox();
        if (t == _text) return; // a formatting change, not an edit
        var sel = _box.Document.Selection;
        var typed = t.Length == _text.Length + 1 && sel.StartPosition > 0 && sel.StartPosition <= t.Length
            && (char.IsLetterOrDigit(t[sel.StartPosition - 1]) || t[sel.StartPosition - 1] == '_');
        _history.Record(new(t, sel.StartPosition, sel.EndPosition - sel.StartPosition), join: typed && _lastWasTyping);
        _lastWasTyping = typed;
        _text = t;
        Paint(_model.Update(_text));
        if (_popup.IsOpen || typed) _ = RefreshCompletions(explicitAsk: false);
    }

    private void Apply(EditResult r, bool record = true)
    {
        if (record) _history.Record(r, join: false);
        _lastWasTyping = false;
        _applying = true;
        try
        {
            _box.Document.SetText(TextSetOptions.None, r.Text);
            _box.Document.Selection.SetRange(r.SelectionStart, r.SelectionStart + r.SelectionLength);
        }
        finally { _applying = false; }
        _text = r.Text;
        // SetText drops every colour, so the whole document is painted again (in chunks for a large text).
        _model.Update(_text);
        RepaintAll();
    }

    private void RepaintAll()
    {
        var all = new List<int>(_model.LineCount);
        for (var i = 0; i < _model.LineCount; i++) all.Add(i);
        Paint(all);
    }

    /// <summary>Colours the given lines. A long list is painted in chunks on the dispatcher so typing never waits;
    /// a newer paint cancels the rest of an older one.</summary>
    private void Paint(IReadOnlyList<int> lines)
    {
        var generation = ++_paintGeneration;
        var dark = ActualTheme == ElementTheme.Dark;
        var plain = (Ui.Brush(this, "TextFillColorPrimaryBrush") as SolidColorBrush)?.Color ?? Microsoft.UI.Colors.Black;
        void Run(int from)
        {
            if (generation != _paintGeneration) return;
            var to = Math.Min(lines.Count, from + PaintChunkLines);
            _applying = true;
            // A read-only RichEditBox refuses formatting (UnauthorizedAccessException, which took the app down on
            // the PostgreSQL DDL tab): lift read-only for the paint, as SetState does for the text.
            var ro = _box.IsReadOnly;
            _box.IsReadOnly = false;
            _box.Document.BatchDisplayUpdates();
            try
            {
                for (var k = from; k < to; k++) PaintLine(lines[k], dark, plain);
            }
            catch (UnauthorizedAccessException ex)
            {
                AppLog.Warn($"SQL editor: a paint was refused ({ex.GetType().Name}); the text stays uncoloured");
            }
            finally
            {
                _box.Document.ApplyDisplayUpdates();
                _box.IsReadOnly = ro;
                _applying = false;
            }
            if (to < lines.Count) DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => Run(to));
        }
        if (lines.Count > 0) Run(0);
    }

    private void PaintLine(int i, bool dark, Windows.UI.Color plain)
    {
        if (i >= _model.LineCount) return;
        var start = _model.LineStart(i);
        var line = _model.LineText(i);
        var whole = _box.Document.GetRange(start, start + line.Length);
        whole.CharacterFormat.ForegroundColor = plain;
        whole.CharacterFormat.Italic = FormatEffect.Off;
        whole.CharacterFormat.Underline = UnderlineType.None;
        foreach (var t in _model.Tokens(i))
        {
            if (SqlEditorPalette.Colour(t.Kind, dark) is not { } argb && !SqlEditorPalette.Italic(t.Kind) && !SqlEditorPalette.Underline(t.Kind)) continue;
            var a = Math.Clamp(t.Start, 0, line.Length);
            var b = Math.Clamp(t.Start + t.Length, a, line.Length);
            if (b == a) continue;
            var r = _box.Document.GetRange(start + a, start + b);
            if (SqlEditorPalette.Colour(t.Kind, dark) is { } c)
                r.CharacterFormat.ForegroundColor = Windows.UI.Color.FromArgb((byte)(c >> 24), (byte)(c >> 16), (byte)(c >> 8), (byte)c);
            if (SqlEditorPalette.Italic(t.Kind)) r.CharacterFormat.Italic = FormatEffect.On;
            if (SqlEditorPalette.Underline(t.Kind)) r.CharacterFormat.Underline = UnderlineType.Wave;
        }
    }

    private void PaintPopup()
    {
        if (_popup.Child is Border b)
        {
            b.Background = Ui.Brush(this, "FlyoutPresenterBackground");
            b.BorderBrush = Ui.Brush(this, "SurfaceStrokeColorFlyoutBrush");
        }
    }

    private async void OnPaste(object sender, TextControlPasteEventArgs e)
    {
        // Plain text only: formatting from another program would fight the colouring.
        e.Handled = true;
        if (_box.IsReadOnly) return;
        var view = Clipboard.GetContent();
        if (!view.Contains(StandardDataFormats.Text)) return;
        string clip;
        try { clip = await view.GetTextAsync(); }
        catch (Exception) { return; } // another program holds the clipboard; nothing is pasted
        var sel = _box.Document.Selection;
        var insert = string.Join('\r', SqlEditorModel.SplitLines(clip));
        var start = Math.Clamp(sel.StartPosition, 0, _text.Length);
        var end = Math.Clamp(sel.EndPosition, start, _text.Length);
        Apply(new(_text.Remove(start, end - start).Insert(start, insert), start + insert.Length, 0));
    }

    private static bool Down(VirtualKey k) => InputKeyboardSource.GetKeyStateForCurrentThread(k).HasFlag(CoreVirtualKeyStates.Down);

    private void OnKey(object sender, KeyRoutedEventArgs e)
    {
        var ctrl = Down(VirtualKey.Control);
        var shift = Down(VirtualKey.Shift);
        if (_popup.IsOpen && ListKey(e.Key)) { e.Handled = true; return; }
        var sel = _box.Document.Selection;
        var (s, len) = (sel.StartPosition, sel.EndPosition - sel.StartPosition);
        switch (e.Key)
        {
            case VirtualKey.Enter when ctrl:
            case VirtualKey.F5:
                e.Handled = true;
                RunRequested?.Invoke(Text);
                return;
            case VirtualKey.Space when ctrl:
                e.Handled = true;
                _ = RefreshCompletions(explicitAsk: true);
                return;
            case (VirtualKey)191 when ctrl && !_box.IsReadOnly: // the / ? key
                e.Handled = true;
                Apply(SqlEditorModel.ToggleLineComment(_text, s, len));
                return;
            case VirtualKey.Tab when !ctrl && !_box.IsReadOnly:
                e.Handled = true;
                Apply(SqlEditorModel.Indent(_text, s, len, outdent: shift));
                return;
            case VirtualKey.Z when ctrl && !shift:
                e.Handled = true;
                if (!_box.IsReadOnly && _history.Undo() is { } u) Apply(u, record: false);
                return;
            case VirtualKey.Y when ctrl:
            case VirtualKey.Z when ctrl && shift:
                e.Handled = true;
                if (!_box.IsReadOnly && _history.Redo() is { } r) Apply(r, record: false);
                return;
        }
    }

    /// <summary>Keys the open completion list takes. Anything else goes to the editor (typing filters the list).</summary>
    private bool ListKey(VirtualKey key)
    {
        switch (key)
        {
            case VirtualKey.Escape:
                _popup.IsOpen = false;
                return true;
            case VirtualKey.Down:
                _list.SelectedIndex = Math.Min(_list.Items.Count - 1, _list.SelectedIndex + 1);
                _list.ScrollIntoView(_list.SelectedItem);
                return true;
            case VirtualKey.Up:
                _list.SelectedIndex = Math.Max(0, _list.SelectedIndex - 1);
                _list.ScrollIntoView(_list.SelectedItem);
                return true;
            case VirtualKey.Enter:
            case VirtualKey.Tab:
                if (_list.SelectedItem is ListViewItem { Tag: CompletionItemDto item }) Accept(item);
                else _popup.IsOpen = false;
                return true;
            default:
                return false;
        }
    }

    private async Task RefreshCompletions(bool explicitAsk)
    {
        if (CompletionSource is not { } source || _box.IsReadOnly) return;
        CompletionContext ctx;
        try { ctx = HighlightClient.Context(_model.Language, _text, _box.Document.Selection.StartPosition); }
        catch (BastionException) { _popup.IsOpen = false; return; }
        if (!ctx.Ask || (!explicitAsk && ctx.Prefix.Length == 0)) { _popup.IsOpen = false; return; }
        var asked = _text;
        IReadOnlyList<CompletionItemDto> items;
        try { items = HighlightClient.Rank(await source(asked, ctx), ctx.Prefix); }
        catch (Exception ex) when (ex is BastionException or InvalidOperationException or TaskCanceledException) { _popup.IsOpen = false; return; }
        if (asked != _text) return; // the user typed on; a newer ask follows
        ShowList(ctx, items);
    }

    private void ShowList(CompletionContext ctx, IReadOnlyList<CompletionItemDto> items)
    {
        if (items.Count == 0) { _popup.IsOpen = false; return; }
        _completionAt = ctx;
        _list.Items.Clear();
        foreach (var item in items)
        {
            var row = new Grid { ColumnSpacing = 12 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.Children.Add(new TextBlock { Text = item.Label, FontFamily = _box.FontFamily, TextTrimming = TextTrimming.CharacterEllipsis });
            if (item.Detail.Length > 0)
            {
                var detail = new TextBlock { Text = item.Detail, Foreground = Ui.Brush(this, "TextFillColorSecondaryBrush"), TextTrimming = TextTrimming.CharacterEllipsis, MaxWidth = 220 };
                ToolTipService.SetToolTip(detail, item.Detail);
                Grid.SetColumn(detail, 1);
                row.Children.Add(detail);
            }
            var lvi = new ListViewItem { Content = row, Tag = item, MinHeight = 28, Padding = new Thickness(8, 0, 8, 0) };
            AutomationProperties.SetName(lvi, item.Label);
            _list.Items.Add(lvi);
        }
        _list.SelectedIndex = 0;
        _list.MaxHeight = Math.Min(items.Count, MaxListed) * 28 + 6;
        _box.Document.Selection.GetRect(Microsoft.UI.Text.PointOptions.ClientCoordinates, out var caret, out _);
        var origin = _box.TransformToVisual(this).TransformPoint(new Windows.Foundation.Point(0, 0));
        _popup.HorizontalOffset = Math.Max(0, origin.X + caret.X);
        _popup.VerticalOffset = origin.Y + caret.Y + caret.Height + 2;
        _popup.IsOpen = true;
    }

    private void Accept(CompletionItemDto item)
    {
        var at = _completionAt;
        _popup.IsOpen = false;
        if (at is not { } ctx) return;
        Apply(SqlEditorModel.ApplyCompletion(_text, ctx, item));
        _box.Focus(FocusState.Programmatic);
    }
}
