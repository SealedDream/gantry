using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.System;
using Windows.UI.Core;

namespace Bastion.Shell;

/// <summary>
/// A vertical splitter that sets the width of one grid column. Drag it with mouse, pen or touch, or focus it and use
/// Left/Right (Shift for larger steps), Home/End for the limits and Enter (or a double-click) for the default width.
/// WinUI 3 has no GridSplitter; this avoids a toolkit dependency. Its only feedback is a plain colour change on
/// hover and while dragging: no animation (docs/TESTING.md, "WinUI CPU spin").
/// </summary>
public sealed partial class PaneSplitter : ContentControl
{
    private const double KeyStep = 8, LargeKeyStep = 48;
    private readonly Rectangle _line = new() { HorizontalAlignment = HorizontalAlignment.Center, IsHitTestVisible = false };
    private bool _dragging, _hover;
    private double _startX, _startWidth;

    /// <summary>The column this splitter resizes.</summary>
    public ColumnDefinition? Column { get; set; }

    /// <summary>True when the column lies to the right of the splitter, so dragging left widens it.</summary>
    public bool ColumnIsAfter { get; set; }

    public double MinValue { get; set; } = 160;
    public double MaxValue { get; set; } = 600;
    public double DefaultValue { get; set; } = 260;

    /// <summary>Raised when a drag ends or a key changed the width.</summary>
    public event EventHandler? WidthCommitted;

    public PaneSplitter()
    {
        IsTabStop = true;
        UseSystemFocusVisuals = true;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Stretch;
        _line.Width = Ui.Double("SplitterLineWidth");
        // A transparent (not null) background makes the whole width hit-testable.
        Content = new Grid { Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent), Children = { _line } };
        ProtectedCursor = InputSystemCursor.Create(InputSystemCursorShape.SizeWestEast);

        PointerEntered += (_, _) => { _hover = true; UpdateLine(); };
        PointerExited += (_, _) => { _hover = false; UpdateLine(); };
        PointerPressed += OnPressed;
        PointerMoved += OnMoved;
        PointerReleased += (_, e) => EndDrag(e.Pointer);
        PointerCaptureLost += (_, _) => EndDrag(null);
        DoubleTapped += (_, e) => { Commit(DefaultValue); e.Handled = true; };
        KeyDown += OnKey;
        ActualThemeChanged += (_, _) => UpdateLine();
    }

    private void UpdateLine() =>
        _line.Fill = _hover || _dragging ? Ui.Brush(this, "SplitterHoverBrush") : null;

    private void OnPressed(object sender, PointerRoutedEventArgs e)
    {
        if (Column is null) return;
        var point = e.GetCurrentPoint(null);
        if (point.PointerDeviceType == Microsoft.UI.Input.PointerDeviceType.Mouse && !point.Properties.IsLeftButtonPressed) return;
        _dragging = CapturePointer(e.Pointer);
        _startX = point.Position.X;
        _startWidth = Column.ActualWidth;
        Focus(FocusState.Pointer);
        UpdateLine();
        e.Handled = true;
    }

    private void OnMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_dragging || Column is null) return;
        var dx = e.GetCurrentPoint(null).Position.X - _startX;
        Apply(_startWidth + (ColumnIsAfter ? -dx : dx));
        e.Handled = true;
    }

    private void EndDrag(Pointer? pointer)
    {
        if (!_dragging) return;
        _dragging = false;
        if (pointer is not null) ReleasePointerCapture(pointer);
        UpdateLine();
        WidthCommitted?.Invoke(this, EventArgs.Empty);
    }

    private void OnKey(object sender, KeyRoutedEventArgs e)
    {
        if (Column is null) return;
        var shift = InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Shift).HasFlag(CoreVirtualKeyStates.Down);
        var step = shift ? LargeKeyStep : KeyStep;
        var wider = ColumnIsAfter ? VirtualKey.Left : VirtualKey.Right;
        var narrower = ColumnIsAfter ? VirtualKey.Right : VirtualKey.Left;
        var width = Column.ActualWidth;
        if (e.Key == wider) Commit(width + step);
        else if (e.Key == narrower) Commit(width - step);
        else if (e.Key == VirtualKey.Home) Commit(MinValue);
        else if (e.Key == VirtualKey.End) Commit(MaxValue);
        else if (e.Key == VirtualKey.Enter) Commit(DefaultValue);
        else return;
        e.Handled = true;
    }

    private void Commit(double width)
    {
        Apply(width);
        WidthCommitted?.Invoke(this, EventArgs.Empty);
    }

    private void Apply(double width)
    {
        if (Column is null) return;
        Column.Width = new GridLength(Math.Round(Math.Clamp(width, MinValue, Math.Max(MinValue, MaxValue))));
    }
}
