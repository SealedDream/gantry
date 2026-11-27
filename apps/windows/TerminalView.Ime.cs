using System;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Windows.UI.Text.Core;

namespace Bastion.Shell;

/// <summary>
/// IME input (Japanese, Chinese, Korean and other composing input methods) through a TSF edit context. The composition
/// is drawn inline at the terminal cursor, the candidate window is placed under it, and the committed text goes to the
/// program. Without a TSF context (the call can be refused) the view keeps the plain CharacterReceived path, which still
/// receives committed IME text from the system's floating composition window.
/// </summary>
public sealed partial class TerminalView
{
    private CoreTextEditContext? _ime;
    /// <summary>The window the current edit context was made for (0: unknown), where it goes back when this view closes.</summary>
    private ulong _imeWindow;
    private bool _imeTried;

    /// <summary>Spare edit contexts of closed terminals, per window (WIN-SHELL-LEAK; see <see cref="ImeContextPool{T}"/>).</summary>
    private static readonly ImeContextPool<CoreTextEditContext> SpareContexts = new();

    /// <summary>A torn-off window closed: drop the spare edit contexts made for it.</summary>
    internal static void ForgetImeContexts(ulong window) => SpareContexts.Forget(window);
    private ImeBuffer _imeBuffer = ImeBuffer.Empty;
    private bool _composing;
    private readonly TextBlock _composition = new()
    {
        IsHitTestVisible = false,
        TextDecorations = Windows.UI.Text.TextDecorations.Underline,
    };
    private readonly Border _compositionBack = new() { IsHitTestVisible = false, Visibility = Visibility.Collapsed };

    /// <summary>
    /// True once the TSF context has delivered text. Until then CharacterReceived stays the text path: on some hosts the
    /// context is created but never receives input, and suppressing CharacterReceived there would drop every key.
    /// </summary>
    private bool ImeActive { get; set; }

    private void InitIme(Canvas overlay)
    {
        _compositionBack.Child = _composition;
        AutomationProperties.SetName(_compositionBack, "IME composition");
        overlay.Children.Add(_compositionBack);
        GotFocus += (_, e) => { if (ReferenceEquals(e.OriginalSource, this)) ImeFocus(true); };
        LostFocus += (_, e) => { if (ReferenceEquals(e.OriginalSource, this)) ImeFocus(false); };
    }

    /// <summary>TSF took focus away from the edit context (a menu or flyout opened), or the pane is coming back after
    /// TSF had taken over its input: on Win11 the old context then does not deliver text again (FocusRemoved is not
    /// always raised), and with <see cref="ImeActive"/> set the pane dropped every key ("stuck pane"
    /// after the tab's Broadcast menu). The next focus starts from another context (a closed terminal's clean spare or a
    /// new one), as a new pane does; the suspect one is never handed on.</summary>
    private bool _imeLost;

    private void ImeFocus(bool entering)
    {
        if (entering && (_imeLost || ImeActive) && _ime is not null)
        {
            _imeLost = false;
            DetachIme(reusable: false);
            _imeTried = false;
            ImeActive = false;
        }
        if (entering && !_imeTried) _ime = CreateEditContext();
        if (_ime is null) return;
        try
        {
            if (entering)
            {
                _ime.NotifyFocusEnter();
                return;
            }
            _ime.NotifyFocusLeave();
        }
        catch (Exception ex) when (IsTsfFailure(ex))
        {
            // Native AOT: a TSF call the WinRT projection cannot marshal, or a spare context that went with its window.
            // Fall back to CharacterReceived, never crash; take the handlers off (TSF keeps the context, and they hold
            // this view), and never hand it on.
            System.Diagnostics.Debug.WriteLine($"TSF edit context dropped: {ex.Message}");
            var dropped = _ime;
            _ime = null;
            TryUnsubscribe(dropped);
        }
        ResetComposition();
    }

    private CoreTextEditContext? CreateEditContext()
    {
        _imeTried = true;
        if (LeakProbe.NoTsf) return null; // WIN-SHELL-LEAK A/B (test builds): CharacterReceived only
        var window = WindowKey();
        // A closed terminal's clean context first: TSF never frees the ones it made (WIN-SHELL-LEAK).
        while (SpareContexts.Take(window) is { } spare)
        {
            if (!TrySubscribe(spare)) continue; // went with its window: drop it
            _imeWindow = window;
            return spare;
        }
        try
        {
            var ctx = CoreTextServicesManager.GetForCurrentView().CreateEditContext();
            LeakProbe.TrackNative(ctx, "nTsfContext");
            ctx.InputScope = CoreTextInputScope.Default;
            ctx.InputPaneDisplayPolicy = CoreTextInputPaneDisplayPolicy.Manual;
            if (!TrySubscribe(ctx)) return null;
            _imeWindow = window;
            return ctx;
        }
        catch (Exception ex) when (IsTsfFailure(ex))
        {
            System.Diagnostics.Debug.WriteLine($"TSF edit context unavailable, using CharacterReceived: {ex.Message}");
            return null;
        }
    }

    /// <summary>The window this view is in, as the key for spare edit contexts; 0 when it cannot be told.</summary>
    private ulong WindowKey()
    {
        try { return XamlRoot?.ContentIslandEnvironment?.AppWindowId.Value ?? 0; }
        catch (Exception ex) when (ex is COMException or InvalidOperationException) { return 0; }
    }

    /// <summary>What a TSF call can throw when the projection cannot marshal it or the context is gone or refused.</summary>
    private static bool IsTsfFailure(Exception ex) =>
        ex is COMException or InvalidOperationException or NotSupportedException or UnauthorizedAccessException;

    /// <summary>Subscribe this view to <paramref name="ctx"/>; on failure take back what was added (a handler left on a
    /// context TSF keeps would keep this view alive) and report false.</summary>
    private bool TrySubscribe(CoreTextEditContext ctx)
    {
        try
        {
            Subscribe(ctx);
            return true;
        }
        catch (Exception ex) when (IsTsfFailure(ex))
        {
            System.Diagnostics.Debug.WriteLine($"TSF edit context unusable: {ex.Message}");
            TryUnsubscribe(ctx);
            return false;
        }
    }

    /// <summary>Take every handler off <paramref name="ctx"/>; returns false when the context refused (it is gone).</summary>
    private bool TryUnsubscribe(CoreTextEditContext? ctx)
    {
        if (ctx is null) return true;
        try
        {
            Unsubscribe(ctx);
            return true;
        }
        catch (Exception ex) when (IsTsfFailure(ex))
        {
            System.Diagnostics.Debug.WriteLine($"TSF edit context unsubscribe: {ex.Message}");
            return false;
        }
    }

    private void Subscribe(CoreTextEditContext ctx)
    {
        ctx.TextRequested += OnImeTextRequested;
        ctx.SelectionRequested += OnImeSelectionRequested;
        ctx.TextUpdating += OnImeTextUpdating;
        ctx.SelectionUpdating += OnImeSelectionUpdating;
        ctx.CompositionStarted += OnImeCompositionStarted;
        ctx.CompositionCompleted += OnImeCompositionCompleted;
        ctx.LayoutRequested += OnImeLayoutRequested;
        ctx.FocusRemoved += OnImeFocusRemoved;
    }

    private void Unsubscribe(CoreTextEditContext ctx)
    {
        ctx.TextRequested -= OnImeTextRequested;
        ctx.SelectionRequested -= OnImeSelectionRequested;
        ctx.TextUpdating -= OnImeTextUpdating;
        ctx.SelectionUpdating -= OnImeSelectionUpdating;
        ctx.CompositionStarted -= OnImeCompositionStarted;
        ctx.CompositionCompleted -= OnImeCompositionCompleted;
        ctx.LayoutRequested -= OnImeLayoutRequested;
        ctx.FocusRemoved -= OnImeFocusRemoved;
    }

    /// <summary>
    /// Let go of the edit context: leave focus and remove every handler (each handler holds this view, and TSF keeps the
    /// context, so a subscribed context kept a closed tab's terminal alive: q-mem-win, ~0.95 MB and 3 handles per closed
    /// tab). TSF keeps the context itself for the life of the app whatever we do (WIN-SHELL-LEAK), so when this view
    /// closes a clean context goes to <see cref="SpareContexts"/> for the next terminal in its window.
    /// <paramref name="reusable"/> is false when a lost or used context is being replaced: it is never handed on.
    /// </summary>
    private void DetachIme(bool reusable)
    {
        if (_ime is not { } ctx) return;
        _ime = null;
        var left = true;
        try { ctx.NotifyFocusLeave(); }
        catch (Exception ex) when (IsTsfFailure(ex))
        {
            // The context is gone with its window: still take the handlers off, but hand nothing on.
            System.Diagnostics.Debug.WriteLine($"TSF edit context detach: {ex.Message}");
            left = false;
        }
        var unsubscribed = TryUnsubscribe(ctx);
        if (reusable && left && unsubscribed) SpareContexts.Return(_imeWindow, ctx, clean: !ImeActive && !_imeLost && !_composing);
    }

    private void OnImeTextRequested(CoreTextEditContext sender, CoreTextTextRequestedEventArgs a) =>
        a.Request.Text = _imeBuffer.Slice(a.Request.Range.StartCaretPosition, a.Request.Range.EndCaretPosition);

    private void OnImeSelectionRequested(CoreTextEditContext sender, CoreTextSelectionRequestedEventArgs a) =>
        a.Request.Selection = new CoreTextRange { StartCaretPosition = _imeBuffer.Caret, EndCaretPosition = _imeBuffer.Caret };

    private void OnImeSelectionUpdating(CoreTextEditContext sender, CoreTextSelectionUpdatingEventArgs a) =>
        _imeBuffer = _imeBuffer.WithCaret(a.Selection.EndCaretPosition);

    private void OnImeCompositionStarted(CoreTextEditContext sender, CoreTextCompositionStartedEventArgs a) => _composing = true;

    private void OnImeCompositionCompleted(CoreTextEditContext sender, CoreTextCompositionCompletedEventArgs a)
    {
        _composing = false;
        CommitIme();
    }

    private void OnImeFocusRemoved(CoreTextEditContext sender, object a)
    {
        ResetComposition();
        _imeLost = true;
    }

    private void OnImeTextUpdating(CoreTextEditContext sender, CoreTextTextUpdatingEventArgs a)
    {
        ImeActive = true;
        _imeBuffer = _imeBuffer.Replace(a.Range.StartCaretPosition, a.Range.EndCaretPosition, a.Text, a.NewSelection.EndCaretPosition);
        a.Result = CoreTextTextUpdatingResult.Succeeded;
        if (_composing) ShowComposition();
        else CommitIme(); // plain typing with no composition, or a direct commit
    }

    /// <summary>Send the buffer to the program and tell TSF the buffer is empty again.</summary>
    private void CommitIme()
    {
        var text = _imeBuffer.Text;
        _imeBuffer = ImeBuffer.Empty;
        HideComposition();
        if (text.Length == 0) return;
        Send(ImeText.ForTerminal(text));
        _ime?.NotifyTextChanged(new CoreTextRange { StartCaretPosition = 0, EndCaretPosition = text.Length }, 0,
            new CoreTextRange { StartCaretPosition = 0, EndCaretPosition = 0 });
    }

    private void ResetComposition()
    {
        _composing = false;
        _imeBuffer = ImeBuffer.Empty;
        HideComposition();
    }

    private void ShowComposition()
    {
        _composition.Text = _imeBuffer.Text;
        _composition.FontFamily = _mono;
        _composition.FontSize = _fontSize;
        _composition.Foreground = Brush(_light ? 0x111111u : 0xf0f0f0u);
        _compositionBack.Background = Brush(_background);
        Canvas.SetLeft(_compositionBack, _cursorCol * _cellW);
        Canvas.SetTop(_compositionBack, _cursorRow * _cellH);
        _compositionBack.Visibility = _imeBuffer.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void HideComposition() => _compositionBack.Visibility = Visibility.Collapsed;

    /// <summary>
    /// Snapshot only: an input-method composition through the same steps TSF drives (CompositionStarted, TextUpdating
    /// per candidate, CompositionCompleted). Returns what the composition overlay showed at each step.
    /// </summary>
    internal IReadOnlyList<string> ComposeForSnapshot(IReadOnlyList<string> steps)
    {
        var shown = new List<string>();
        _composing = true;
        foreach (var step in steps)
        {
            _imeBuffer = ImeBuffer.Empty.Replace(0, 0, step, step.Length);
            ShowComposition();
            shown.Add(_compositionBack.Visibility == Visibility.Visible ? _composition.Text : "(hidden)");
        }
        _composing = false;
        CommitIme();
        shown.Add(_compositionBack.Visibility == Visibility.Visible ? "overlay still shown" : "overlay hidden after commit");
        return shown;
    }

    /// <summary>Tell TSF where the cursor cell is on screen (physical pixels) so the candidate window opens under it.</summary>
    private void OnImeLayoutRequested(CoreTextEditContext sender, CoreTextLayoutRequestedEventArgs a)
    {
        if (XamlRoot is null) return;
        var scale = XamlRoot.RasterizationScale;
        var origin = ClientOrigin();
        var toRoot = TransformToVisual(null);
        var cell = toRoot.TransformBounds(new Windows.Foundation.Rect(_cursorCol * _cellW, _cursorRow * _cellH, _cellW, _cellH));
        var view = toRoot.TransformBounds(new Windows.Foundation.Rect(0, 0, ActualWidth, ActualHeight));
        a.Request.LayoutBounds.TextBounds = ImeText.ToScreen(cell, origin.X, origin.Y, scale);
        a.Request.LayoutBounds.ControlBounds = ImeText.ToScreen(view, origin.X, origin.Y, scale);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint { public int X; public int Y; }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ClientToScreen(IntPtr hwnd, ref NativePoint point);

    /// <summary>Screen position of the window's client area, in physical pixels.</summary>
    private NativePoint ClientOrigin()
    {
        var pt = new NativePoint();
        try
        {
            var hwnd = Microsoft.UI.Win32Interop.GetWindowFromWindowId(XamlRoot!.ContentIslandEnvironment.AppWindowId);
            if (hwnd != IntPtr.Zero && !ClientToScreen(hwnd, ref pt)) pt = new NativePoint();
        }
        catch (Exception ex) when (ex is COMException or InvalidOperationException)
        {
            System.Diagnostics.Debug.WriteLine($"IME layout: no window origin: {ex.Message}");
        }
        return pt;
    }
}

/// <summary>The TSF-visible text of the composition in progress. Immutable; every edit returns a new buffer.</summary>
public sealed record ImeBuffer(string Text, int Caret)
{
    public static readonly ImeBuffer Empty = new(string.Empty, 0);

    public string Slice(int start, int end)
    {
        var s = Math.Clamp(start, 0, Text.Length);
        var e = Math.Clamp(end, s, Text.Length);
        return Text[s..e];
    }

    public ImeBuffer WithCaret(int caret) => this with { Caret = Math.Clamp(caret, 0, Text.Length) };

    /// <summary>Replace [start, end) with <paramref name="text"/>; ranges outside the buffer are clamped.</summary>
    public ImeBuffer Replace(int start, int end, string? text, int caret)
    {
        var s = Math.Clamp(start, 0, Text.Length);
        var e = Math.Clamp(end, s, Text.Length);
        var next = Text[..s] + (text ?? string.Empty) + Text[e..];
        return new ImeBuffer(next, Math.Clamp(caret, 0, next.Length));
    }
}

/// <summary>Pure helpers for the IME path, kept free of XAML so they can be checked on their own.</summary>
public static class ImeText
{
    /// <summary>Committed text as the terminal should get it: line breaks become CR, other control characters are dropped.</summary>
    public static string ForTerminal(string text)
    {
        var sb = new System.Text.StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') continue;
            if (c is '\r' or '\n') sb.Append('\r');
            else if (c >= ' ' && c != '\x7f') sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>A rectangle in XAML root DIPs to screen physical pixels.</summary>
    public static Windows.Foundation.Rect ToScreen(Windows.Foundation.Rect dips, int originX, int originY, double scale) =>
        new(originX + dips.X * scale, originY + dips.Y * scale, dips.Width * scale, dips.Height * scale);
}
