using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace Bastion.Shell;

/// <summary>
/// A tooltip that is created only when it is first needed: on the first pointer hover or keyboard focus.
/// <see cref="ToolTipService.SetToolTip"/> costs 11-39 ms per UI stall while the library rows and tabs are built
/// (WIN-SPEED-ROOTCAUSE), and most rows are never hovered. Until then the element holds only the text.
/// Use <c>local:LazyToolTip.Text="{x:Bind …}"</c> in XAML or <see cref="Set"/> in code.
/// </summary>
public static class LazyToolTip
{
    /// <summary>How long the pointer rests before the first tooltip opens, close to the framework's own hover delay.</summary>
    private static readonly TimeSpan FirstShowDelay = TimeSpan.FromMilliseconds(400);

    public static readonly DependencyProperty TextProperty = DependencyProperty.RegisterAttached(
        "Text", typeof(string), typeof(LazyToolTip), new PropertyMetadata(null, OnTextChanged));

    private static readonly DependencyProperty HookedProperty = DependencyProperty.RegisterAttached(
        "Hooked", typeof(bool), typeof(LazyToolTip), new PropertyMetadata(false));

    public static string? GetText(DependencyObject element) => (string?)element.GetValue(TextProperty);

    public static void SetText(DependencyObject element, string? value) => element.SetValue(TextProperty, value);

    /// <summary>Code-behind form of the attached property.</summary>
    public static void Set(UIElement element, string? text) => SetText(element, text);

    private static void OnTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not UIElement element) return;
        var text = e.NewValue as string;
        // Already shown once: keep the live tooltip in step with the text (a renamed tab, a session that ended).
        if (ToolTipService.GetToolTip(element) is ToolTip live)
        {
            live.Content = text;
            live.IsEnabled = !string.IsNullOrEmpty(text);
            return;
        }
        if (string.IsNullOrEmpty(text) || (bool)element.GetValue(HookedProperty)) return;
        element.SetValue(HookedProperty, true);
        element.PointerEntered += OnPointerEntered;
        element.GotFocus += OnGotFocus;
    }

    private static void OnPointerEntered(object sender, PointerRoutedEventArgs e) => Materialize((UIElement)sender, openOnRest: true);

    private static void OnGotFocus(object sender, RoutedEventArgs e) => Materialize((UIElement)sender, openOnRest: false);

    /// <summary>
    /// Create the real tooltip. The tooltip service starts listening only now, after this hover began,
    /// so the first hover opens it here once the pointer has rested; later hovers are the service's own.
    /// </summary>
    private static void Materialize(UIElement element, bool openOnRest)
    {
        element.PointerEntered -= OnPointerEntered;
        element.GotFocus -= OnGotFocus;
        element.SetValue(HookedProperty, false);
        if (GetText(element) is not { Length: > 0 } text || ToolTipService.GetToolTip(element) is not null) return;
        // Never hit-testable: a tooltip must not take a click meant for the button under it.
        var tip = new ToolTip { Content = text, IsHitTestVisible = false };
        ToolTipService.SetToolTip(element, tip);
        if (openOnRest && element.DispatcherQueue is { } queue) OpenAfterRest(element, tip, queue);
    }

    /// <summary>The one first-hover open still waiting. Entering a row and its icon at once opens only the innermost tooltip.</summary>
    private static Microsoft.UI.Dispatching.DispatcherQueueTimer? _pending;

    private static void OpenAfterRest(UIElement element, ToolTip tip, Microsoft.UI.Dispatching.DispatcherQueue queue)
    {
        _pending?.Stop();
        var left = false;
        void Exited(object s, PointerRoutedEventArgs a) => left = true;
        element.PointerExited += Exited;
        var timer = queue.CreateTimer();
        timer.Interval = FirstShowDelay;
        timer.IsRepeating = false;
        timer.Tick += (t, _) =>
        {
            t.Stop();
            if (ReferenceEquals(_pending, t)) _pending = null;
            element.PointerExited -= Exited;
            if (!left && element.XamlRoot is not null && tip.IsEnabled) OpenUntilLeft(element, tip);
        };
        _pending = timer;
        timer.Start();
    }

    /// <summary>
    /// Open the first-hover tooltip and close it on the first exit, press, wheel or key, as the tooltip service does for
    /// the ones it opens. A tooltip opened with IsOpen stayed open over the tab strip after the pointer left
    /// (q-recents-r2: the test's click on the tab's close button then had no effect).
    /// </summary>
    private static void OpenUntilLeft(UIElement element, ToolTip tip)
    {
        PointerEventHandler? onPointer = null;
        KeyEventHandler? onKey = null;
        void Close()
        {
            tip.IsOpen = false;
            element.PointerExited -= onPointer;
            element.RemoveHandler(UIElement.PointerPressedEvent, onPointer);
            element.PointerCanceled -= onPointer;
            element.PointerCaptureLost -= onPointer;
            element.PointerWheelChanged -= onPointer;
            element.KeyDown -= onKey;
        }
        onPointer = (_, _) => Close();
        onKey = (_, _) => Close();
        // handledEventsToo: a Button marks PointerPressed handled, and the close must still happen.
        element.AddHandler(UIElement.PointerPressedEvent, onPointer, true);
        element.PointerExited += onPointer;
        element.PointerCanceled += onPointer;
        element.PointerCaptureLost += onPointer;
        element.PointerWheelChanged += onPointer;
        element.KeyDown += onKey;
        tip.IsOpen = true;
    }
}
