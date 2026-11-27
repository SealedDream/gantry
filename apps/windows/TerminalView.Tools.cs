using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Bastion.Shell.Interop;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.System;

namespace Bastion.Shell;

/// <summary>The terminal's find bar, bell, Ctrl+click links and clear scrollback.</summary>
public sealed partial class TerminalView
{
    /// <summary>How long the visual bell shows, and the shortest time between two bells (a flood of BELs rings once).</summary>
    private static readonly TimeSpan BellFlash = TimeSpan.FromMilliseconds(120);
    private static readonly TimeSpan BellGap = TimeSpan.FromMilliseconds(250);

    private TerminalScreen? _screen;
    private DateTime _lastBell;
    private readonly Rectangle _flash = new() { IsHitTestVisible = false, Opacity = 0, Fill = new SolidColorBrush(Colors.White) };
    private readonly Border _findBar = new()
    {
        HorizontalAlignment = HorizontalAlignment.Right,
        VerticalAlignment = VerticalAlignment.Top,
        Margin = new Thickness(8),
        Padding = new Thickness(6),
        CornerRadius = new CornerRadius(4),
        Visibility = Visibility.Collapsed,
    };
    private readonly TextBox _findBox = new() { PlaceholderText = "Find", Width = 200 };
    private readonly TextBlock _findStatus = new() { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 4, 0), MinWidth = 64 };
    private readonly ToggleButton _findCase = FindToggle("Aa", "Match case (Alt+C)");
    private readonly ToggleButton _findRegex = FindToggle(".*", "Regular expression (Alt+R)");

    /// <summary><c>terminal.bell</c>: "off", "visual", "sound" or "both".</summary>
    public string BellMode { get; set; } = "visual";

    /// <summary><c>terminal.copy-on-select</c>.</summary>
    public bool CopyOnSelect { get; set; }

    /// <summary>Width of the bar cursor and height of the underline cursor, in pixels.</summary>
    private const double CursorStroke = 2;

    /// <summary>Opacity of the block cursor, so the character under it stays readable.</summary>
    private const double BlockCursorOpacity = 0.55;

    /// <summary><c>terminal.cursor-style</c>: "block", "bar" or "underline".</summary>
    public string CursorStyle
    {
        get => _cursorStyle;
        set
        {
            _cursorStyle = value;
            PlaceCursor(_cursorRow, _cursorCol); // the screen may not change again soon; show the new shape now
        }
    }

    private string _cursorStyle = "block";
    private int _cursorRow, _cursorCol;

    /// <summary><c>terminal.scrollback</c>: lines of history kept above the screen.</summary>
    public void SetScrollback(int lines) => _session.SetScrollback(lines);

    /// <summary>Size and place the cursor for <see cref="CursorStyle"/> at a cell.</summary>
    private void PlaceCursor(int row, int col)
    {
        (_cursorRow, _cursorCol) = (row, col);
        var (w, h, dy, opacity) = CursorStyle switch
        {
            "bar" => (CursorStroke, _cellH, 0.0, 1.0),
            "underline" => (_cellW, CursorStroke, _cellH - CursorStroke, 1.0),
            _ => (_cellW, _cellH, 0.0, BlockCursorOpacity),
        };
        (_cursor.Width, _cursor.Height, _cursor.Opacity) = (w, h, opacity);
        Canvas.SetLeft(_cursor, col * _cellW);
        Canvas.SetTop(_cursor, row * _cellH + dy);
    }

    /// <summary>Raised when the program rings the bell (after the flash or sound), so the window can mark a hidden tab.</summary>
    public event EventHandler? BellRang;

    // ---- find ----

    private Border BuildFindBar()
    {
        _findBar.Background = (Brush)Application.Current.Resources["SystemControlBackgroundChromeMediumBrush"];
        AutomationProperties.SetName(_findBox, "Find in terminal");
        AutomationProperties.SetLiveSetting(_findStatus, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);
        var previous = FindButton("", "Previous match (Enter)", () => FindNext(forward: false));
        var next = FindButton("", "Next match (Shift+Enter)", () => FindNext(forward: true));
        var close = FindButton("", "Close find (Esc)", CloseFind);
        _findBox.TextChanged += (_, _) => { _session.ClearSearch(); FindNext(forward: false); };
        _findCase.Click += (_, _) => Refind();
        _findRegex.Click += (_, _) => Refind();
        _findBox.KeyDown += (_, e) =>
        {
            if (e.Key == VirtualKey.Enter) { FindNext(forward: Down(VirtualKey.Shift)); e.Handled = true; }
            else if (e.Key == VirtualKey.Escape) { CloseFind(); e.Handled = true; }
        };
        _findBar.Child = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 2, Children = { _findBox, _findCase, _findRegex, _findStatus, previous, next, close } };
        return _findBar;
    }

    private static ToggleButton FindToggle(string label, string name)
    {
        // AllowFocusOnInteraction off: a click toggles without taking focus, so typing goes on in the find box (W11-ALTC).
        var t = new ToggleButton { Content = label, Padding = new Thickness(8, 4, 8, 4), MinWidth = 32, MinHeight = 24, FontFamily = new FontFamily("Consolas"), AllowFocusOnInteraction = false };
        AutomationProperties.SetName(t, name);
        ToolTipService.SetToolTip(t, name);
        return t;
    }

    /// <summary>
    /// Alt+C (Match case) or Alt+R (Regular expression) while this pane's find bar is open, wherever focus is in the pane
    /// (find box, an option button or the terminal itself), as on the Mac. False when the bar is closed, focus is in
    /// another pane, or for another key. Called from the window's PreviewKeyDown: neither the TextBox's KeyDown nor a
    /// KeyboardAccelerator on the bar received Alt+letter in the Win11 runs (#917). W11-ALTC: q940 had focus on the
    /// terminal after a click on Match case, and Alt+C did nothing.
    /// </summary>
    public bool ToggleFindOption(VirtualKey key, DependencyObject? focused)
    {
        if (_findBar.Visibility != Visibility.Visible || key is not (VirtualKey.C or VirtualKey.R)) return false;
        for (var o = focused; o is not null; o = VisualTreeHelper.GetParent(o))
        {
            if (!ReferenceEquals(o, this)) continue;
            var toggle = key == VirtualKey.C ? _findCase : _findRegex;
            toggle.IsChecked = toggle.IsChecked != true;
            Refind();
            return true;
        }
        return false;
    }

    /// <summary>An option changed: search again from the newest match.</summary>
    private void Refind()
    {
        _session.ClearSearch();
        FindNext(forward: false);
        _findBox.Focus(FocusState.Keyboard);
    }

    private static Button FindButton(string glyph, string name, Action click)
    {
        var b = new Button { Content = new FontIcon { Glyph = glyph, FontSize = 12 }, Padding = new Thickness(8, 6, 8, 6), MinWidth = 24, MinHeight = 24 };
        AutomationProperties.SetName(b, name);
        ToolTipService.SetToolTip(b, name);
        b.Click += (_, _) => click();
        return b;
    }

    /// <summary>Open the find bar (or focus it when open), starting from a one-line selection if there is one.</summary>
    /// <summary>Select All: the whole scrollback and screen; with copy on select it goes to the clipboard at once.</summary>
    public void SelectAll()
    {
        if (_session.IsDisposed) return;
        _session.SelectAll();
        if (CopyOnSelect) CopySelection();
        Poll();
    }

    /// <summary>Find Next / Find Previous (F3, Shift+F3): repeat the last search, or open the find bar when there is none.</summary>
    public void FindAgain(bool forward)
    {
        if (_findBox.Text.Length == 0) { ShowFind(); return; }
        FindNext(forward);
    }

    /// <summary>The interrupt character (Ctrl+C, ETX), as a terminal sends it for Break.</summary>
    private const string BreakSequence = "\u0003";

    /// <summary>Send Break: interrupt the running program.</summary>
    public void SendBreak()
    {
        if (!_session.IsDisposed) _session.Write(BreakSequence);
    }

    public void ShowFind()
    {
        if (!_session.IsDisposed && _session.SelectionText() is { Length: > 0 and < 200 } selected && !selected.Contains('\n')) _findBox.Text = selected;
        _findBar.Visibility = Visibility.Visible;
        _findBox.Focus(FocusState.Keyboard);
        _findBox.SelectAll();
    }

    internal void ShowFindForSnapshot(string text)
    {
        ShowFind();
        _findBox.Text = text;
    }

    private void FindNext(bool forward)
    {
        if (_session.IsDisposed) return;
        if (_findBox.Text.Length == 0) { _findStatus.Text = ""; Poll(); return; }
        try { _findStatus.Text = _session.Find(_findBox.Text, forward, _findCase.IsChecked == true, _findRegex.IsChecked == true).Status; }
        catch (BastionException ex) { _findStatus.Text = ex.Message; }
        Poll();
    }

    private void CloseFind()
    {
        _findBar.Visibility = Visibility.Collapsed;
        _findStatus.Text = "";
        _session.ClearSearch();
        _drawn = ulong.MaxValue;
        Poll();
        Focus(FocusState.Keyboard);
    }

    /// <summary>Drop the scrollback; the screen stays.</summary>
    public void ClearScrollback()
    {
        _session.ClearScrollback();
        Poll();
    }

    /// <summary>Scroll to the previous or next shell prompt (OSC 133 marks, C ABI 132); false when there is none in that
    /// direction (no shell marks, or already at the end).</summary>
    public bool JumpPrompt(bool forward)
    {
        // The outcome is the view's automation ItemStatus, for screen readers and the UI test.
        var moved = _session.JumpPrompt(forward);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetItemStatus(this, moved ? (forward ? "next prompt" : "previous prompt") : "no prompt");
        if (moved) Poll();
        return moved;
    }

    // ---- bell ----

    private void RingBell()
    {
        var now = DateTime.UtcNow;
        if (BellMode == "off" || now - _lastBell < BellGap) return;
        _lastBell = now;
        if (BellMode is "sound" or "both") MessageBeep(0); // MB_OK: the Windows "Default Beep" sound
        if (BellMode is "visual" or "both")
        {
            _flash.Fill = Brush(_light ? 0x000000u : 0xffffffu);
            _flash.Opacity = _light ? 0.18 : 0.12;
            var timer = DispatcherQueue.CreateTimer();
            timer.Interval = BellFlash;
            timer.IsRepeating = false;
            // Unsubscribed when it fires: a timer that keeps its handler keeps this view alive (see Dispose).
            Windows.Foundation.TypedEventHandler<Microsoft.UI.Dispatching.DispatcherQueueTimer, object>? endFlash = null;
            endFlash = (t, _) =>
            {
                t.Stop();
                t.Tick -= endFlash;
                _flash.Opacity = 0;
            };
            timer.Tick += endFlash;
            timer.Start();
        }
        BellRang?.Invoke(this, EventArgs.Empty);
    }

    [DllImport("user32.dll")]
    private static extern bool MessageBeep(uint type);

    // ---- links ----

    /// <summary>http and https URLs; punctuation that usually ends a sentence is trimmed off afterwards.</summary>
    private static readonly Regex UrlPattern = new(@"https?://[^\s<>""'`]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>The http(s) URL under a cell of the visible screen, or null.</summary>
    internal static string? UrlAt(IReadOnlyList<string> cellText, int cols, int row, int col)
    {
        if (cols <= 0 || row < 0 || col < 0 || col >= cols || (row + 1) * cols > cellText.Count) return null;
        // One character per cell (anything wider is not part of a URL) so string positions are columns.
        var line = string.Concat(Enumerable.Range(row * cols, cols).Select(i => cellText[i] is { Length: 1 } t ? t : " "));
        foreach (Match m in UrlPattern.Matches(line))
        {
            var url = m.Value.TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}');
            if (col < m.Index || col >= m.Index + url.Length) continue;
            return Uri.TryCreate(url, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps) ? uri.AbsoluteUri : null;
        }
        return null;
    }

    /// <summary>Ctrl+click: open the URL under the pointer in the default browser. False when there is none.</summary>
    private bool OpenLinkAt((int row, int col) cell)
    {
        if (_screen is not { } s || UrlAt(s.CellText, s.Cols, cell.row, cell.col) is not { } url) return false;
        _ = Launcher.LaunchUriAsync(new Uri(url));
        return true;
    }
}
