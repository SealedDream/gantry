using Bastion.Shell.Interop;
using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;
using Windows.UI;
using Windows.UI.Core;

namespace Bastion.Shell;

/// <summary>
/// Draws a core terminal session and turns keyboard, mouse and clipboard actions into terminal input. The grid
/// state lives in the Rust core (alacritty_terminal); this control only renders snapshots and forwards input.
/// It redraws only when the core's generation counter moves.
/// </summary>
public sealed partial class TerminalView : UserControl, IDisposable
{
    /// <summary>The <c>terminal.font-size</c> default (core/src/settings.rs), in device-independent pixels.</summary>
    public const double DefaultFontSize = 13;
    /// <summary>The bundled Nerd Font (Fonts/, copied next to the app) as a XAML font URI.</summary>
    private const string BundledFont = "ms-appx:///Fonts/JetBrainsMonoNerdFontMono-Regular.ttf#JetBrainsMono Nerd Font Mono";
    /// <summary>After the chosen font: the bundled one for Powerline and icon glyphs, then Windows' symbol and emoji fonts.</summary>
    private const string Fallbacks = BundledFont + ", Cascadia Mono, Consolas, Segoe UI Symbol, Segoe UI Emoji";

    /// <summary>The XAML font family for a <c>terminal.font-family</c> id (core/src/settings.rs TERMINAL_FONTS).</summary>
    public static FontFamily FontFor(string? id) => new(id switch
    {
        "cascadia-mono" => "Cascadia Mono, " + Fallbacks,
        "consolas" => "Consolas, " + Fallbacks,
        "courier-new" => "Courier New, " + Fallbacks,
        _ => Fallbacks,
    });

    private FontFamily _mono;

    /// <summary>The connection's own font properties; null fields follow the app settings.</summary>
    public TerminalFontOverride FontOverride { get; init; } = TerminalFontOverride.None;

    private bool _ligatures = true;
    /// <summary><c>terminal.ligatures</c> (or the connection's <c>terminal_ligatures</c>): join pairs such as -&gt; where the font has them.</summary>
    public bool Ligatures
    {
        get => _ligatures;
        set
        {
            if (value == _ligatures) return;
            _ligatures = value;
            foreach (var row in _rows.Children.OfType<TextBlock>()) ApplyLigatures(row);
        }
    }

    private void ApplyLigatures(TextBlock tb)
    {
        Microsoft.UI.Xaml.Documents.Typography.SetStandardLigatures(tb, _ligatures);
        Microsoft.UI.Xaml.Documents.Typography.SetContextualLigatures(tb, _ligatures);
        Microsoft.UI.Xaml.Documents.Typography.SetContextualAlternates(tb, _ligatures);
    }

    private TerminalSession _session;
    private string? _themeId;
    private readonly Grid _root = new() { Background = new SolidColorBrush(Color.FromArgb(255, 0x1c, 0x1c, 0x1e)) };
    private readonly Canvas _backgrounds = new();
    /// <summary>Wide and symbol glyphs, each placed on its own cells so fallback fonts cannot shift the rest of the row.</summary>
    private readonly Canvas _glyphs = new() { IsHitTestVisible = false };
    private readonly StackPanel _rows = new();
    private readonly Rectangle _cursor = new() { Width = 2, IsHitTestVisible = false };
    private readonly Microsoft.UI.Dispatching.DispatcherQueueTimer _timer;

    /// <summary>
    /// Tells the GC what this view costs outside the managed heap: its rows, glyph runs and composition visuals are native
    /// XAML objects, freed only when their managed wrappers are collected. Without it the managed heap stays at a few MB,
    /// so closed tabs waited for a full GC that came only after ~200 tabs (q-mem-win on a75a4af03: 73 -> 220 MB, then
    /// flat). The pressure is released by the token's finalizer, when the view itself has been collected.
    /// </summary>
#pragma warning disable CS0414 // held, never read: its lifetime is the point
    private readonly NativeCost _nativeCost = new();
#pragma warning restore CS0414

    private sealed class NativeCost
    {
        /// <summary>About what one closed local shell tab kept before the timer fix (q-mem-win: ~0.95 MB per tab).</summary>
        private const long Bytes = 1L << 20;

        public NativeCost() => GC.AddMemoryPressure(Bytes);

        ~NativeCost() => GC.RemoveMemoryPressure(Bytes);
    }
    private readonly Dictionary<uint, SolidColorBrush> _brushes = new();
    private double _cellW, _cellH;
    private double _fontSize;
    private ulong _drawn = ulong.MaxValue;
    private bool _appCursor;
    private bool _selecting;
    private DateTime _lastPress;
    private int _clicks;
    private bool _exitReported;
    private uint _background = 0x1c1c1e;
    private bool _light;
    /// <summary>Link state of a supervised SSH session ("Reconnectingâ€¦", "Disconnected"), over the top-right corner.</summary>
    private readonly Border _banner = new()
    {
        HorizontalAlignment = HorizontalAlignment.Right,
        VerticalAlignment = VerticalAlignment.Top,
        Margin = new Thickness(8),
        Padding = new Thickness(10, 4, 10, 4),
        CornerRadius = new CornerRadius(4),
        Background = new SolidColorBrush(Color.FromArgb(0xee, 0x3a, 0x3a, 0x3c)),
        IsHitTestVisible = false,
        Visibility = Visibility.Collapsed,
    };
    private readonly TextBlock _bannerText = new() { Foreground = new SolidColorBrush(Colors.White), FontSize = 13, VerticalAlignment = VerticalAlignment.Center };
    /// <summary>Owner point W25: spins while the link is being retried, so a dropped session visibly keeps trying.</summary>
    private readonly ProgressRing _bannerRing = new()
    {
        Width = 14, Height = 14, MinWidth = 14, MinHeight = 14, IsActive = false, Visibility = Visibility.Collapsed,
        Foreground = new SolidColorBrush(Colors.White), VerticalAlignment = VerticalAlignment.Center,
    };

    /// <summary>Asks the user to confirm a multi-line paste (returns true to paste). Set by the window.</summary>
    public Func<string, Task<bool>>? ConfirmMultiLinePaste { get; set; }

    /// <summary>Raised once when the program exits.</summary>
    public event EventHandler? Exited;
    /// <summary>The program set or reset its window title (OSC 0/2); null after a reset. Raw text: the tab sanitizes it.</summary>
    public event Action<TerminalView, string?>? ProgramTitleChanged;
    private string? _programTitle;
    /// <summary>Keys the user typed, as sent to the program (for broadcast input).</summary>
    public event Action<TerminalView, string>? KeysSent;
    /// <summary>Text the user pasted, after the multi-line check (for broadcast input).</summary>
    public event Action<TerminalView, string>? Pasted;
    /// <summary>This pane's id for the core's broadcast review.</summary>
    public Guid PaneId { get; } = Guid.NewGuid();

    public TerminalSession Session => _session;

    public TerminalView(TerminalSession session, double fontSize = DefaultFontSize, string? fontId = null)
    {
        _session = session;
        _fontSize = fontSize;
        _mono = FontFor(fontId);
        IsTabStop = true;
        UseSystemFocusVisuals = false;
        AutomationProperties.SetName(this, "Terminal");
        LeakProbe.Track(this, "TerminalView");
        LeakProbe.TrackNative(_root, "nTermRoot");
        LeakProbe.TrackNative(_rows, "nTermRows");
        LeakProbe.TrackNative(_findBox, "nFindBox");
        MeasureCell();
        _cursor.Height = _cellH;
        _rows.IsHitTestVisible = false;
        _root.Children.Add(_backgrounds);
        _root.Children.Add(_rows);
        _root.Children.Add(_glyphs);
        _root.Children.Add(_flash);
        var overlay = new Canvas { IsHitTestVisible = false };
        overlay.Children.Add(_cursor);
        InitIme(overlay);
        _root.Children.Add(overlay);
        _banner.Child = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { _bannerRing, _bannerText } };
        AutomationProperties.SetAutomationId(_bannerText, "reconnect-badge"); // MAC-RECONNECT-BADGE parity
        AutomationProperties.SetLiveSetting(_bannerText, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);
        _root.Children.Add(_banner);
        _root.Children.Add(BuildFindBar());
        Content = _root;

        _timer = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread().CreateTimer();
        // Screen changes wake the view (TerminalWake); the slow timer only catches what moves no generation (a bell,
        // a clipboard request) and is a safety net.
        _timer.Interval = TimeSpan.FromMilliseconds(SafetyPollMs);
        LeakProbe.TrackNative(_timer, "nViewTimer");
        _timer.Tick += OnSafetyTick;
        Loaded += (_, _) => { FirstPhase(PhaseLoaded, "loaded"); _timer.Start(); StartWake(); Focus(FocusState.Programmatic); };
        Unloaded += (_, _) => { _timer.Stop(); StopWake(); };
        SizeChanged += (_, e) => { FirstPhase(PhaseSized, "size"); ResizeToFit(e.NewSize); };
        KeyDown += OnKeyDown;
        CharacterReceived += OnCharacter;
        PointerPressed += OnPointerPressed;
        PointerMoved += OnPointerMoved;
        PointerReleased += OnPointerReleased;
        PointerCaptureLost += (_, _) => EndPointerGesture();
        PointerCanceled += (_, e) => { EndPointerGesture(); ReleasePointerCaptures(); };
        PointerWheelChanged += OnWheel;
        Tapped += (_, _) => FocusFromPointer();
    }

    /// <summary>
    /// Take all the space offered. Sizing to content would make the first SizeChanged shrink the PTY to the
    /// rows drawn so far (one, at startup), and the program's early output would scroll away.
    /// </summary>
    protected override Windows.Foundation.Size MeasureOverride(Windows.Foundation.Size available)
    {
        FirstPhase(PhaseMeasured, "measure");
        base.MeasureOverride(available);
        var w = double.IsInfinity(available.Width) ? 80 * _cellW : available.Width;
        var h = double.IsInfinity(available.Height) ? 24 * _cellH : available.Height;
        return new Windows.Foundation.Size(w, h);
    }

    private void MeasureCell()
    {
        (_cellW, _cellH) = CellOf(_mono, _fontSize);
        var (x, y) = InsetFor(_fontSize);
        _root.Padding = new Thickness(x, y, x, y);
    }

    /// <summary>
    /// <c>terminal.font-size</c> changed: new cell metrics, rows rebuilt at the new size and the program told the new
    /// column and row count for the same space (as a window resize would).
    /// </summary>
    /// <summary>Snapshot mode: the current font size.</summary>
    internal double FontSizeForSnapshot => _fontSize;
    /// <summary>Snapshot mode: the current family list and ligature state.</summary>
    internal string FontForSnapshot => $"{_mono.Source}|ligatures={_ligatures}";

    public void SetFontSize(double size)
    {
        if (size == _fontSize) return;
        _fontSize = size;
        MeasureCell();
        _cursor.Height = _cellH;
        _sizedCols = 0; _sizedRows = 0; // new cell size: the next fit always resizes and redraws
        _drawn = ulong.MaxValue;
        _rows.Children.Clear();
        _glyphs.Children.Clear();
        if (ActualWidth > 0 && ActualHeight > 0) ResizeToFit(new Windows.Foundation.Size(ActualWidth, ActualHeight)); // else SizeChanged sizes it
        InvalidateMeasure();
    }

    /// <summary><c>terminal.font-family</c> changed: same as a size change, with the new typeface.</summary>
    public void SetFont(string id)
    {
        _mono = FontFor(id);
        var size = _fontSize;
        _fontSize = -1; // force SetFontSize to re-measure
        SetFontSize(size);
    }

    /// <summary>
    /// Size the PTY for <paramref name="area"/> before the view is first laid out (a new tab gets the same area as the
    /// terminal already shown), so its first layout finds the grid already right: no resize, and one first render.
    /// </summary>
    public void FitBeforeLayout(Windows.Foundation.Size area) => ResizeToFit(area);

    /// <summary>The grid the PTY was last sized to (0 = not yet, or the cell size changed).</summary>
    private int _sizedCols, _sizedRows;

    private void ResizeToFit(Windows.Foundation.Size size)
    {
        // A collapsed view (a tab in the background) reports no size: the program keeps its grid instead of being
        // squeezed to 2x1 and redrawn on every tab switch.
        if (Fit(size, _cellW, _cellH, _fontSize) is not { } grid) return;
        var (cols, rows) = grid;
        _visibleRows = rows;
        if (_session.IsDisposed) return;
        // Same grid as before (a tab shown again at the size it had): no PTY resize and no full redraw.
        if (cols == _sizedCols && rows == _sizedRows) return;
        TabSwitchProbe.Resized(_sizedCols, _sizedRows, cols, rows);
        try { _session.Resize(cols, rows); } catch (BastionException) { /* a closed session cannot resize */ }
        _sizedCols = cols; _sizedRows = rows;
        _drawn = ulong.MaxValue;
    }

    /// <summary>Redraw even if the screen did not change (new trigger highlights).</summary>
    public void Redraw()
    {
        _drawn = ulong.MaxValue;
        Poll();
    }

    /// <summary>Render if the core reports a change. Cheap when nothing changed (one native call).</summary>
    public void Poll()
    {
        if (_session.IsDisposed) return;
        var g = _session.Generation;
        if (g == _drawn) return;
        var t0 = PerfTrace.Enabled ? PerfTrace.Now() : 0;
        Render(_session.Screen());
        if (t0 != 0) TabSwitchProbe.Rendered(PerfTrace.Ms(t0));
        if (_session.TakeBell()) RingBell();
        if (!_clipboardBusy && _session.TakeClipboardRequest() is { } request) _ = HandleClipboardRequest(request);
    }

    /// <summary>Speed suite: when the oldest unanswered key was sent (0 = none), and whether a prompt was seen.</summary>
    private long _echoT0;
    private bool _promptSeen;

    private const int PhaseMeasured = 1, PhaseSized = 2, PhaseLoaded = 4, PhaseRendered = 8;
    /// <summary>Speed suite: the steps of this view's first showing already written (TabSwitchProbe.Phase).</summary>
    private int _phasesSeen;

    private void FirstPhase(int bit, string name)
    {
        if (!PerfTrace.Enabled || (_phasesSeen & bit) != 0) return;
        _phasesSeen |= bit;
        TabSwitchProbe.Phase(name);
    }

    private void Render(TerminalScreen s)
    {
        FirstPhase(PhaseRendered, "render");
        if (PerfTrace.Enabled) MarkRender(s);
        _drawn = s.Generation;
        _appCursor = s.AppCursor;
        if (!string.Equals(s.Title, _programTitle, StringComparison.Ordinal))
        {
            _programTitle = s.Title;
            ProgramTitleChanged?.Invoke(this, s.Title);
        }
        _screen = s;
        _backgrounds.Children.Clear();
        _glyphs.Children.Clear();
        while (_rows.Children.Count < s.Rows)
        {
            var row = new TextBlock { FontFamily = _mono, FontSize = _fontSize, Height = _cellH, TextWrapping = TextWrapping.NoWrap, IsTextScaleFactorEnabled = false };
            ApplyLigatures(row);
            _rows.Children.Add(row);
        }
        while (_rows.Children.Count > s.Rows) _rows.Children.RemoveAt(_rows.Children.Count - 1);

        for (var r = 0; r < s.Rows; r++)
        {
            var tb = (TextBlock)_rows.Children[r];
            tb.Inlines.Clear();
            var start = r * s.Cols;
            var run = new System.Text.StringBuilder();
            NativeCell? style = null;
            var bgStart = -1;
            uint bgColor = 0;
            for (var c = 0; c <= s.Cols; c++)
            {
                var end = c == s.Cols;
                var cell = end ? default : s.Cells[start + c];
                // Text runs: group cells sharing foreground and attributes.
                if (end || style is not { } st || st.Fg != cell.Fg || (st.Flags & 7) != (cell.Flags & 7))
                {
                    if (style is { } prev && run.Length > 0) tb.Inlines.Add(MakeRun(run.ToString(), prev));
                    run.Clear();
                    style = cell;
                }
                if (!end)
                {
                    var text = s.CellText[start + c];
                    var span = text.Length > 0 && c + 1 < s.Cols && s.CellText[start + c + 1].Length == 0 ? 2 : 1;
                    if (text.Length == 0) run.Append(' '); // trailing half of a wide glyph, drawn by the glyph layer
                    else if (span == 2 || IsSymbol(text)) { run.Append(' '); AddGlyph(r, c, span, text, cell); }
                    else run.Append(text);
                }
                // Background runs: only cells that differ from the default background (selection and search
                // matches are drawn as highlights).
                var bg = end ? 0u : EffectiveBg(cell);
                if (bgStart >= 0 && (end || bg != bgColor))
                {
                    AddBackground(r, bgStart, c, bgColor);
                    bgStart = -1;
                }
                if (!end && bg != 0 && bgStart < 0) { bgStart = c; bgColor = bg; }
            }
        }

        _cursor.Visibility = s.CursorVisible && s.Alive ? Visibility.Visible : Visibility.Collapsed;
        _cursor.Fill = Brush(_light ? 0x333333u : 0xd8d8d8u);
        PlaceCursor(s.CursorRow, s.CursorCol);

        if (!s.Alive && !_exitReported)
        {
            _exitReported = true;
            Exited?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>Selection fill (UI-03, as the Mac): the app accent at 40 % over the theme background, so selected
    /// text keeps its own colour and stays readable.</summary>
    private uint _selection = 0x264f78;
    private const double SelectionOpacity = 0.4;
    private uint SelectionOver(uint background)
    {
        if (Ui.Brush(this, "AccentFillColorDefaultBrush") is not SolidColorBrush { Color: var a }) return _light ? 0xb4d5feu : 0x264f78u;
        uint Mix(byte c, int shift) => (uint)Math.Round(c * SelectionOpacity + ((background >> shift) & 0xff) * (1 - SelectionOpacity)) << shift;
        return Mix(a.R, 16) | Mix(a.G, 8) | Mix(a.B, 0);
    }

    /// <summary>0 means "default background, draw nothing".</summary>
    private uint EffectiveBg(NativeCell c)
    {
        if ((c.Flags & NativeCell.Selected) != 0) return _selection;
        if ((c.Flags & NativeCell.Matched) != 0) return _light ? 0xf2e3a0u : 0x6b5b1eu;
        return c.Bg == _background ? 0 : c.Bg;
    }

    /// <summary>
    /// Switch to a built-in colour theme (core preset id). The core recolours the grid, including the default
    /// background; the view repaints its margins with that background and picks a cursor and highlight colours that
    /// stay visible on it.
    /// </summary>
    /// <summary>True when the connection sets its own <c>terminal_theme</c>; the app-wide colours then skip this tab.</summary>
    public bool OwnTheme { get; set; }

    /// <summary>The theme's background (0xRRGGBB); the session surface around the terminal takes it.</summary>
    public uint BackgroundColor => _background;

    /// <summary>The theme id last applied (UI-06 reads its foreground for the window tones).</summary>
    public string? ThemeId => _themeId;

    /// <summary>Raised after <see cref="ApplyTheme"/> repaints, so the host can match its padding to the new background.</summary>
    public event EventHandler? ThemeApplied;

    public void ApplyTheme(string id)
    {
        _themeId = id;
        if (_session.IsDisposed) return;
        _session.SetTheme(id);
        _background = _session.Background;
        var lum = 0.299 * ((_background >> 16) & 0xff) + 0.587 * ((_background >> 8) & 0xff) + 0.114 * (_background & 0xff);
        _light = lum > 128;
        _selection = SelectionOver(_background);
        _root.Background = Brush(_background);
        _drawn = ulong.MaxValue;
        Poll();
        ThemeApplied?.Invoke(this, EventArgs.Empty);
    }

    private void AddBackground(int row, int from, int to, uint color)
    {
        var rect = new Rectangle { Width = (to - from) * _cellW, Height = _cellH, Fill = Brush(color) };
        Canvas.SetLeft(rect, from * _cellW);
        Canvas.SetTop(rect, row * _cellH);
        _backgrounds.Children.Add(rect);
    }

    /// <summary>
    /// Box drawing, blocks, Powerline and other symbols (U+2500 and up, including the private-use area Nerd Fonts use):
    /// they come from whichever font has them, so each sits on its own cell instead of flowing with the row's text.
    /// </summary>
    internal static bool IsSymbol(string text) =>
        System.Text.Rune.DecodeFromUtf16(text, out var rune, out _) == System.Buffers.OperationStatus.Done
        && rune.Value >= 0x2500 && !(rune.Value >= 0xFF61 && rune.Value <= 0xFFDC); // halfwidth forms flow with text

    private void AddGlyph(int row, int col, int span, string text, NativeCell style)
    {
        var tb = new TextBlock
        {
            Text = text, FontFamily = _mono, FontSize = _fontSize, Foreground = Brush(style.Fg), IsTextScaleFactorEnabled = false,
            Width = span * _cellW, Height = _cellH, TextAlignment = span == 2 ? TextAlignment.Center : TextAlignment.Left,
            TextWrapping = TextWrapping.NoWrap, TextTrimming = TextTrimming.None,
        };
        if ((style.Flags & NativeCell.Bold) != 0) tb.FontWeight = FontWeights.Bold;
        Canvas.SetLeft(tb, col * _cellW);
        Canvas.SetTop(tb, row * _cellH);
        _glyphs.Children.Add(tb);
    }

    private Run MakeRun(string text, NativeCell style)
    {
        var run = new Run { Text = text, Foreground = Brush(style.Fg) };
        if ((style.Flags & NativeCell.Bold) != 0) run.FontWeight = FontWeights.Bold;
        if ((style.Flags & NativeCell.Italic) != 0) run.FontStyle = Windows.UI.Text.FontStyle.Italic;
        if ((style.Flags & NativeCell.Underline) != 0) run.TextDecorations = Windows.UI.Text.TextDecorations.Underline;
        return run;
    }

    private SolidColorBrush Brush(uint rgb)
    {
        if (!_brushes.TryGetValue(rgb, out var b))
        {
            b = new SolidColorBrush(Color.FromArgb(255, (byte)(rgb >> 16), (byte)(rgb >> 8), (byte)rgb));
            _brushes[rgb] = b;
        }
        return b;
    }

    // ---- keyboard ----

    private static bool Down(VirtualKey k) => InputKeyboardSource.GetKeyStateForCurrentThread(k).HasFlag(CoreVirtualKeyStates.Down);

    private void OnKeyDown(object sender, KeyRoutedEventArgs e)
    {
        var ctrl = Down(VirtualKey.Control);
        var shift = Down(VirtualKey.Shift);
        var alt = Down(VirtualKey.Menu);

        if (!ReferenceEquals(e.OriginalSource, this)) return; // typing in the find bar

        // Scrollback keys stay in the app (as in Windows Terminal and PuTTY); a full-screen program that wants
        // Shift+PageUp still gets plain PageUp.
        if (ScrollKeyLines(e.Key, ctrl, shift, alt, _visibleRows) is { } lines)
        {
            e.Handled = true;
            _session.Scroll(lines);
            Poll();
            return;
        }

        var seq = KeySequence(e.Key, ctrl, shift, alt, _appCursor);
        if (seq is null) return; // printable text arrives through CharacterReceived
        e.Handled = true;
        Send(seq);
    }

    /// <summary>Rows on screen, for paging through scrollback.</summary>
    private int _visibleRows = 24;

    /// <summary>Far enough to reach either end of any scrollback (the core clamps).</summary>
    private const int ScrollToEnd = 1_000_000;

    /// <summary>
    /// Lines to scroll the view for a scrollback key (positive is up, into history), or null when the key goes to the
    /// program: Shift+PageUp/PageDown and Ctrl+Shift+PageUp/PageDown a page, Ctrl+Shift+Up/Down a line,
    /// Ctrl+Shift+Home/End to the top or bottom.
    /// </summary>
    internal static int? ScrollKeyLines(VirtualKey key, bool ctrl, bool shift, bool alt, int pageRows)
    {
        if (!shift || alt) return null;
        var page = Math.Max(1, pageRows - 1);
        return key switch
        {
            VirtualKey.PageUp => page,
            VirtualKey.PageDown => -page,
            VirtualKey.Up when ctrl => 1,
            VirtualKey.Down when ctrl => -1,
            VirtualKey.Home when ctrl => ScrollToEnd,
            VirtualKey.End when ctrl => -ScrollToEnd,
            _ => null,
        };
    }

    /// <summary>xterm-style sequences for non-text keys; null for keys that produce text.</summary>
    private void MarkRender(TerminalScreen s)
    {
        if (!_promptSeen && s.CursorCol > 0)
        {
            _promptSeen = true;
            PerfTrace.End("ssh-open", "ssh-open-first-prompt");
        }
        if (_echoT0 == 0) return;
        PerfTrace.AfterLayout(DispatcherQueue, "keystroke-echo", _echoT0);
        _echoT0 = 0;
    }

    internal static string? KeySequence(VirtualKey key, bool ctrl, bool shift, bool alt, bool appCursor)
    {
        string Cursor(char c) => appCursor && !ctrl && !shift && !alt ? $"\x1bO{c}" : Mod(c);
        string Mod(char c)
        {
            var m = 1 + (shift ? 1 : 0) + (alt ? 2 : 0) + (ctrl ? 4 : 0);
            return m == 1 ? $"\x1b[{c}" : $"\x1b[1;{m}{c}";
        }
        string Tilde(int n)
        {
            var m = 1 + (shift ? 1 : 0) + (alt ? 2 : 0) + (ctrl ? 4 : 0);
            return m == 1 ? $"\x1b[{n}~" : $"\x1b[{n};{m}~";
        }
        switch (key)
        {
            case VirtualKey.Enter: return "\r";
            case VirtualKey.Back: return ctrl ? "\x08" : "\x7f";
            case VirtualKey.Tab: return shift ? "\x1b[Z" : "\t";
            case VirtualKey.Escape: return "\x1b";
            case VirtualKey.Up: return Cursor('A');
            case VirtualKey.Down: return Cursor('B');
            case VirtualKey.Right: return Cursor('C');
            case VirtualKey.Left: return Cursor('D');
            case VirtualKey.Home: return Cursor('H');
            case VirtualKey.End: return Cursor('F');
            case VirtualKey.Insert: return Tilde(2);
            case VirtualKey.Delete: return Tilde(3);
            case VirtualKey.PageUp: return Tilde(5);
            case VirtualKey.PageDown: return Tilde(6);
            case VirtualKey.F1: return "\x1bOP";
            case VirtualKey.F2: return "\x1bOQ";
            case VirtualKey.F3: return "\x1bOR";
            case VirtualKey.F4: return "\x1bOS";
            case VirtualKey.F5: return Tilde(15);
            case VirtualKey.F6: return Tilde(17);
            case VirtualKey.F7: return Tilde(18);
            case VirtualKey.F8: return Tilde(19);
            case VirtualKey.F9: return Tilde(20);
            case VirtualKey.F10: return Tilde(21);
            case VirtualKey.F11: return Tilde(23);
            case VirtualKey.F12: return Tilde(24);
        }
        // Ctrl+letter -> control character (Ctrl+C = 0x03). Ctrl+Shift+letter is left to window shortcuts.
        if (ctrl && !shift && !alt && key >= VirtualKey.A && key <= VirtualKey.Z) return ((char)(key - VirtualKey.A + 1)).ToString();
        if (ctrl && !shift && key == VirtualKey.Space) return "\0";
        return null;
    }

    private void OnCharacter(UIElement sender, CharacterReceivedRoutedEventArgs e)
    {
        if (!ReferenceEquals(e.OriginalSource, this)) return;
        var ch = e.Character;
        // Control characters are produced by OnKeyDown; only text goes through here (including IME output).
        if (ch < ' ' || ch == '\x7f') return;
        if (ImeActive && !Down(VirtualKey.Menu)) { e.Handled = true; return; } // the TSF context delivers this text
        e.Handled = true;
        Send(Down(VirtualKey.Menu) ? "\x1b" + ch : ch.ToString());
    }

    private void Send(string s)
    {
        if (_session.IsDisposed || !_session.IsAlive) return;
        if (PerfTrace.Enabled && _echoT0 == 0) _echoT0 = PerfTrace.Now();
        try { _session.Write(s); } catch (BastionException) { /* the program exited */ return; }
        KeysSent?.Invoke(this, s);
    }

    // ---- clipboard ----

    /// <summary>Copy the selection; false when nothing is selected.</summary>
    public bool CopySelection()
    {
        var text = _session.IsDisposed ? null : _session.SelectionText();
        if (string.IsNullOrEmpty(text)) return false;
        var data = new DataPackage();
        data.SetText(text);
        Clipboard.SetContent(data);
        return true;
    }

    private bool _clipboardBusy;
    private string _clipboardPolicy = "ask";

    /// <summary>Set this session's OSC 52 policy ("off", "ask", "allow").</summary>
    public void ApplyClipboardPolicy(string policy)
    {
        _clipboardPolicy = policy;
        if (_session.IsDisposed) return;
        try { _session.SetClipboardPolicy(policy); } catch (BastionException) { }
    }

    /// <summary>Asked before a program's OSC 52 copy lands on the clipboard (policy "ask"); null copies without asking.</summary>
    public Func<string, Task<bool>>? ConfirmClipboardWrite { get; set; }

    /// <summary>A program offered text for the clipboard (OSC 52); it can never read the clipboard back.</summary>
    private async Task HandleClipboardRequest(ClipboardRequest request)
    {
        _clipboardBusy = true;
        try
        {
            if (request.Ask && (ConfirmClipboardWrite is not { } confirm || !await confirm(request.Text))) return;
            var data = new DataPackage();
            data.SetText(request.Text);
            Clipboard.SetContent(data);
        }
        finally { _clipboardBusy = false; }
    }

    public async Task PasteFromClipboard()
    {
        var view = Clipboard.GetContent();
        if (!view.Contains(StandardDataFormats.Text)) return;
        var text = await view.GetTextAsync();
        await PasteText(text);
    }

    /// <summary>
    /// Paste, asking first when the text has more than one line and the program has not enabled bracketed paste:
    /// then every newline runs as Enter (Windows 10 ConPTY never forwards bracketed-paste mode).
    /// </summary>
    public async Task PasteText(string text)
    {
        if (string.IsNullOrEmpty(text) || _session.IsDisposed) return;
        var multiLine = text.TrimEnd('\r', '\n').IndexOfAny(['\r', '\n']) >= 0;
        if (multiLine && !_session.BracketedPaste && ConfirmMultiLinePaste is { } confirm && !await confirm(text)) return;
        try { _session.Paste(text); } catch (BastionException) { return; }
        Pasted?.Invoke(this, text);
        Focus(FocusState.Programmatic);
    }

    // ---- mouse ----

    private (int row, int col) CellAt(PointerRoutedEventArgs e)
    {
        var p = e.GetCurrentPoint(this).Position;
        var (x, y) = InsetFor(_fontSize);
        return ((int)Math.Max(0, (p.Y - y) / _cellH), (int)Math.Max(0, (p.X - x) / _cellW));
    }

    /// <summary>The button held since a press the program got, so drags report it and the release goes to it too.</summary>
    private TermMouseButton? _reportedButton;

    private static TermMouseMods MouseMods() =>
        (Down(VirtualKey.Shift) ? TermMouseMods.Shift : 0) | (Down(VirtualKey.Menu) ? TermMouseMods.Alt : 0) | (Down(VirtualKey.Control) ? TermMouseMods.Ctrl : 0);

    /// <summary>
    /// When the program turned on mouse reporting, a click, drag or wheel goes to it (core termmouse encoder) instead of
    /// selecting or scrolling. Shift keeps local selection, as in xterm and Windows Terminal.
    /// </summary>
    private bool ReportMouse(PointerRoutedEventArgs e, TermMouseAction action)
    {
        if (action != TermMouseAction.Release && (Down(VirtualKey.Shift) || !_session.MouseReporting)) return false;
        var props = e.GetCurrentPoint(this).Properties;
        var button = action switch
        {
            TermMouseAction.Press => props.IsLeftButtonPressed ? TermMouseButton.Left : props.IsRightButtonPressed ? TermMouseButton.Right : props.IsMiddleButtonPressed ? TermMouseButton.Middle : (TermMouseButton?)null,
            _ => _reportedButton ?? (action == TermMouseAction.Motion ? TermMouseButton.None : null),
        };
        if (button is not { } b) return false;
        var (r, c) = CellAt(e);
        try { _session.Mouse(b, action, Math.Max(0, r), Math.Max(0, c), MouseMods()); }
        catch (BastionException) { return false; }
        if (action == TermMouseAction.Press) { _reportedButton = b; CapturePointer(e.Pointer); }
        if (action == TermMouseAction.Release) { _reportedButton = null; ReleasePointerCapture(e.Pointer); }
        e.Handled = true;
        return true;
    }

    /// <summary>A press whose release never arrives (a menu opened mid-press, the capture was taken): drop the gesture state.</summary>
    private void EndPointerGesture()
    {
        _selecting = false;
        _reportedButton = null;
    }

    /// <summary>
    /// Take keyboard focus for a click. A pointer capture left over from an earlier press, or a flyout that just closed,
    /// can make the first Focus() fail and leave focus on the window's root site, so keys go nowhere (broadcast panes);
    /// release stale captures first and retry once the click has been dispatched.
    /// </summary>
    private void FocusFromPointer()
    {
        ReleasePointerCaptures();
        if (Focus(FocusState.Pointer)) return;
        DispatcherQueue.TryEnqueue(() => { if (!Focus(FocusState.Pointer)) Focus(FocusState.Programmatic); });
    }

    private void OnPointerPressed(object sender, PointerRoutedEventArgs e)
    {
        FocusFromPointer();
        // Handled, or the press bubbles to the session host's ScrollViewer, which takes focus for itself: a click in a
        // split pane then left the keyboard nowhere (typing went to no pane, or stayed in the other one).
        e.Handled = true;
        if (ReportMouse(e, TermMouseAction.Press)) return;
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) return;
        if (Down(VirtualKey.Control) && OpenLinkAt(CellAt(e))) { e.Handled = true; return; }
        var now = DateTime.UtcNow;
        _clicks = (now - _lastPress).TotalMilliseconds < 400 ? Math.Min(_clicks + 1, 3) : 1;
        _lastPress = now;
        var (r, c) = CellAt(e);
        if (_clicks == 1) _session.ClearSelection();
        _session.SelectStart(r, c, _clicks);
        _selecting = _clicks == 1;
        CapturePointer(e.Pointer);
        Poll();
    }

    private void OnPointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_selecting && ReportMouse(e, TermMouseAction.Motion)) return;
        if (!_selecting) return;
        var (r, c) = CellAt(e);
        _session.SelectExtend(r, c);
        Poll();
    }

    private void OnPointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (_reportedButton is not null && ReportMouse(e, TermMouseAction.Release)) return;
        var dragged = _selecting;
        _selecting = false;
        ReleasePointerCapture(e.Pointer);
        // A drag, double or triple click selects; with copy on select the selection goes to the clipboard at once.
        if (CopyOnSelect && (dragged || _clicks > 1)) CopySelection();
    }

    private void OnWheel(object sender, PointerRoutedEventArgs e)
    {
        var delta = e.GetCurrentPoint(this).Properties.MouseWheelDelta;
        if (!Down(VirtualKey.Shift) && _session.MouseReporting && delta != 0)
        {
            var (r, c) = CellAt(e);
            try { _session.Mouse(delta > 0 ? TermMouseButton.WheelUp : TermMouseButton.WheelDown, TermMouseAction.Press, Math.Max(0, r), Math.Max(0, c), MouseMods()); }
            catch (BastionException) { /* the session ended */ }
            e.Handled = true;
            return;
        }
        _session.Scroll(delta / 40); // 3 lines per notch
        e.Handled = true;
        Poll();
    }

    /// <summary>Show (or with null, hide) the link-state banner. <paramref name="warning"/> tints it for a lost link.</summary>
    /// <param name="detail">The core's status words (attempt n of m); tooltip and accessible name, the badge stays short.</param>
    public void SetBanner(string? text, bool warning = false, bool busy = false, string? detail = null)
    {
        _banner.Visibility = text is null ? Visibility.Collapsed : Visibility.Visible;
        var spin = busy && text is not null;
        if (_bannerRing.IsActive != spin)
        {
            _bannerRing.IsActive = spin;
            _bannerRing.Visibility = spin ? Visibility.Visible : Visibility.Collapsed;
        }
        if (text is null) return;
        var name = detail is null ? text : $"{text}. {detail}";
        if (_bannerText.Text == text && AutomationProperties.GetName(_bannerText) == name) return;
        _bannerText.Text = text;
        AutomationProperties.SetName(_bannerText, name);
        ToolTipService.SetToolTip(_banner, detail);
        _banner.Background = new SolidColorBrush(warning ? Color.FromArgb(0xee, 0x8a, 0x2b, 0x2b) : Color.FromArgb(0xee, 0x3a, 0x3a, 0x3c));
    }

    /// <summary>
    /// Show a new shell in this view (a reconnected SSH link). The old session is freed; the theme and size carry
    /// over, and <see cref="Exited"/> may fire again for the new shell.
    /// </summary>
    public void ReplaceSession(TerminalSession session)
    {
        var old = _session;
        StopWake();
        _session = session;
        _sizedCols = 0; _sizedRows = 0; // the new session has its own PTY: size it on the next fit
        old.Dispose();
        if (IsLoaded) StartWake();
        _exitReported = false;
        if (_themeId is { } id)
        {
            try { ApplyTheme(id); } catch (BastionException) { /* keep the default colours */ }
        }
        ApplyClipboardPolicy(_clipboardPolicy);
        // A hidden tab has no size yet; it resizes when it is shown.
        if (ActualWidth > 0 && ActualHeight > 0) ResizeToFit(new Windows.Foundation.Size(ActualWidth, ActualHeight));
        _drawn = ulong.MaxValue;
        Poll();
    }

    private void OnSafetyTick(Microsoft.UI.Dispatching.DispatcherQueueTimer sender, object args) => Poll();

    public void Dispose()
    {
        // The native timer holds its Tick handler, and the handler holds this view: a cycle through native code that
        // the GC cannot see, so a subscribed timer kept every closed tab alive (its view, rows, session wrapper, tab and
        // tab body) with one Timer, WaitCompletionPacket and Event handle each (q-leak-probe-run: 3 handles and
        // ~0.95 MB per closed local shell tab).
        _timer.Stop();
        _timer.Tick -= OnSafetyTick;
        StopWake();
        DetachIme(reusable: true);
        _session.Dispose();
        LeakProbe.MarkDisposed(this);
    }

    private const int SafetyPollMs = 250;
    private TerminalWake? _wake;

    private void StartWake()
    {
        if (_wake is not null || _session.IsDisposed) return;
        _wake = TerminalWake.Start(_session, DispatcherQueue, Poll);
    }

    private void StopWake()
    {
        _wake?.Stop();
        _wake = null;
    }
}
