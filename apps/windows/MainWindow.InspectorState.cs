using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// The details pane (inspector) as the owner decided: hidden for a new profile; one remembered global toggle (toolbar
// button, Ctrl+Alt+I, More options › Details pane) kept in appearance.json; Properties… and Test Connection open it for
// as long as their dialog is up without touching the remembered choice; in full screen it lies over the sessions.
public sealed partial class MainWindow
{
    /// <summary>Open for a Properties… or Test Connection dialog only; the remembered choice is unchanged.</summary>
    private bool _inspectorTransient;

    /// <summary>Full screen only: a click outside the overlaid pane or a dialog sent it away until it is toggled again or
    /// another item is selected. The remembered choice is unchanged.</summary>
    private bool _inspectorOverlayDismissed;

    private bool InspectorShown => _inspectorTransient || (_inspectorWanted && !(_fullScreen && _inspectorOverlayDismissed));

    /// <summary>Full screen: a press outside the overlaid pane (or a dialog opening) closes it so it never covers what the
    /// user went to.</summary>
    private void DismissInspectorOverlay(DependencyObject? pressed)
    {
        if (!_fullScreen || _inspectorTransient || _inspectorOverlayDismissed || !InspectorVisible) return;
        if (pressed is not null && Contains(Inspector!, pressed)) return; // its own toggle decides
        // The title-bar toggle decides too: dismissing on its press made its Click show the pane again (WIN-EVEN-01).
        if (pressed is not null && _titleBar is { } bar && Contains(bar.InspectorToggleButton, pressed)) return;
        _inspectorOverlayDismissed = true;
        UpdatePanes();
    }

    private void InitInspectorState()
    {
        _inspectorWanted = _appearance.InspectorShown;
        if (Content is UIElement root)
            root.AddHandler(UIElement.PointerPressedEvent, new Microsoft.UI.Xaml.Input.PointerEventHandler((_, e) => DismissInspectorOverlay(e.OriginalSource as DependencyObject)), handledEventsToo: true);
        TestConnectionPanel.PinDecision = PinModal;
        TestConnectionPanel.UnpinDecision = e => UnpinModal(e);
    }

    private void InspectorButton_Click(object sender, RoutedEventArgs e) => ToggleInspector();

    /// <summary>Button and Ctrl+Alt+I: flip what is on screen; with nothing to show (Welcome, a page) flip the remembered choice.</summary>
    private void ToggleInspector() => ShowInspector(InspectorHasSubject ? !InspectorVisible : !_inspectorWanted);

    /// <summary>The remembered toggle: button, shortcut, menu or the pane's own Hide button.</summary>
    private void RememberInspector(bool show)
    {
        _inspectorTransient = false;
        _inspectorOverlayDismissed = false;
        _appearance.SetInspector(show, save: !_demo);
    }

    internal void BeginInspectorTransient()
    {
        if (_inspectorTransient || _inspectorWanted) return;
        _inspectorTransient = true;
        _inspectorForced = _inspectorNarrow;
        UpdatePanes();
    }

    /// <summary>The dialog that opened it closed: back to the remembered choice.</summary>
    private void EndInspectorTransient()
    {
        if (!_inspectorTransient) return;
        _inspectorTransient = false;
        _inspectorForced = _inspectorWanted && _inspectorNarrow;
        UpdatePanes();
    }

    /// <summary>In full screen the pane lies over the right of the workspace; its column stays at 0 so nothing resizes.</summary>
    private bool ApplyInspectorOverlay(bool visible)
    {
        var pane = BuiltInspector; // called once the pane is built (ApplyInspectorLayout)
        var overlay = _fullScreen && visible;
        if (overlay)
        {
            pane.Visibility = Visibility.Visible;
            InspectorSplitter.Visibility = Visibility.Collapsed;
            InspectorColumn.MinWidth = 0;
            InspectorColumn.Width = new GridLength(0);
            Grid.SetColumn(pane, 0);
            Grid.SetColumnSpan(pane, 3);
            Canvas.SetZIndex(pane, 10);
            pane.HorizontalAlignment = HorizontalAlignment.Right;
            pane.Width = _inspectorWidth;
            pane.Background = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["LayerBackgroundBrush"];
            return true;
        }
        Grid.SetColumn(pane, 2);
        Grid.SetColumnSpan(pane, 1);
        pane.ClearValue(Canvas.ZIndexProperty);
        pane.ClearValue(FrameworkElement.HorizontalAlignmentProperty);
        pane.ClearValue(FrameworkElement.WidthProperty);
        pane.ClearValue(Panel.BackgroundProperty);
        return false;
    }

    internal string InspectorStateForSnapshot() =>
        $"wanted={_inspectorWanted} transient={_inspectorTransient} visible={InspectorVisible} saved={_appearance.InspectorShown}";
}
