using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// WIN-FLAT-TREE: one row of <see cref="LibraryTree"/>: indent, chevron, the row content from the item template, and the
/// selection and hover fill with the accent bar the TreeView drew. To UI Automation it is a TreeItem with the
/// SelectionItem, ExpandCollapse and ScrollItem patterns, as a TreeViewItem was.
/// </summary>
public sealed partial class LibraryRow : ContentControl
{
    /// <summary>The chevron column (WinUI TreeView's glyph cell).</summary>
    private const double ChevronWidth = 24;

    private static ControlTemplate? s_template;

    private LibraryTree? _tree;
    private UIElement? _hoverFill;
    private UIElement? _selectedFill;
    private FrameworkElement? _bar;
    /// <summary>The template's accent fill for the selection bar, put back when the UI-06 override goes.</summary>
    private Microsoft.UI.Xaml.Media.Brush? _accentFill;
    private FontIcon? _chevron;
    private ContentPresenter? _presenter;
    private bool _hover;
    /// <summary>Where a left press started, until it is released or becomes a drag.</summary>
    private Windows.Foundation.Point? _pressAt;
    /// <summary>Pointer travel that turns a press into a drag (Windows' default drag rectangle is 4 px).</summary>
    private const double DragThreshold = 4;

    public LibraryRow()
    {
        Template = s_template ??= (ControlTemplate)XamlReader.Load(TemplateXaml);
        IsTabStop = true;
        UseSystemFocusVisuals = true;
        HorizontalAlignment = HorizontalAlignment.Stretch;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Center;
        PointerEntered += (_, _) => { _hover = true; UpdateState(); };
        PointerExited += (_, _) => { _hover = false; UpdateState(); };
        PointerCanceled += (_, _) => { _hover = false; UpdateState(); };
        // The row starts its own drag (StartDragAsync) instead of setting CanDrag: with CanDrag, WinUI's drag recognizer
        // took the press, so taps, double taps and right taps on rows never arrived (no invoke, no menu, no connect).
        AddHandler(PointerPressedEvent, new PointerEventHandler(Row_PointerPressed), handledEventsToo: true);
        AddHandler(PointerMovedEvent, new PointerEventHandler(Row_PointerMoved), handledEventsToo: true);
        AddHandler(PointerReleasedEvent, new PointerEventHandler((_, _) => _pressAt = null), handledEventsToo: true);
        PointerCaptureLost += (_, _) => _pressAt = null;
        // Keyboard focus selects its row, as in the TreeView: focus moved by arrow keys or XY navigation must not leave
        // the selection behind (Enter acted on the old selection and connected a session row's connection again).
        GotFocus += (_, _) => { if (FocusState == FocusState.Keyboard) _tree?.RowFocused(this); };
        Tapped += Row_Tapped;
        DoubleTapped += Row_DoubleTapped;
    }

    /// <summary>The row's item (the repeater sets it as the data context).</summary>
    /// <summary>
    /// The row's item, given by the tree when the repeater prepares the row. Not read from DataContext: the x:Bind
    /// template does not need one and the repeater left it null, so presses found no item (no selection, root menu).
    /// It is set as the DataContext too, for the handlers that read that.
    /// </summary>
    internal TreeItem? Item { get; private set; }

    internal void Attach(LibraryTree tree, TreeItem? item)
    {
        _tree = tree;
        Item = item;
        DataContext = item; // the drag and drop handlers in MainWindow.Tree.cs read the row's DataContext
    }

    /// <summary>The row went back to the recycle pool: forget its item. DataContext stays until the row is reused, so
    /// no binding runs on a row that is being torn down with its window.</summary>
    internal void Detach() => Item = null;

    protected override void OnApplyTemplate()
    {
        base.OnApplyTemplate();
        _hoverFill = GetTemplateChild("HoverFill") as UIElement;
        _selectedFill = GetTemplateChild("SelectedFill") as UIElement;
        _bar = GetTemplateChild("Bar") as FrameworkElement;
        _chevron = GetTemplateChild("Chevron") as FontIcon;
        _presenter = GetTemplateChild("Presenter") as ContentPresenter;
        if (_chevron is not null) _chevron.Tapped += Chevron_Tapped;
        UpdateState();
    }

    /// <summary>Indent, chevron and fill for the current item, depth, expansion and selection.</summary>
    internal void UpdateState()
    {
        if (_tree is null || Item is not { } item || _chevron is null || _presenter is null || _hoverFill is null || _selectedFill is null || _bar is null) return;
        var indent = _tree.DepthOf(item) * LibraryTree.IndentPerLevel;
        _chevron.Margin = new Thickness(indent, 0, 0, 0);
        _chevron.Visibility = item.Children.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        _chevron.Glyph = item.Expanded ? "" : "";
        _presenter.Margin = new Thickness(indent + ChevronWidth, 0, 0, 0);
        var selected = _tree.IsSelected(item);
        _bar.Visibility = selected ? Visibility.Visible : Visibility.Collapsed;
        if (_bar is Microsoft.UI.Xaml.Shapes.Shape shape)
        {
            _accentFill ??= shape.Fill;
            var fill = _tree.SelectionBarOverride ?? _accentFill;
            if (!ReferenceEquals(shape.Fill, fill)) shape.Fill = fill;
        }
        _selectedFill.Opacity = selected ? 1 : 0;
        _hoverFill.Opacity = _hover ? 1 : 0;
    }

    private void Row_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        var point = e.GetCurrentPoint(this).Properties;
        if (!point.IsLeftButtonPressed && !point.IsRightButtonPressed) return;
        _pressAt = point.IsLeftButtonPressed ? e.GetCurrentPoint(this).Position : null;
        _tree?.RowPressed(this, FocusState.Pointer, right: point.IsRightButtonPressed);
    }

    private void Row_PointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (_pressAt is not { } start) return;
        var now = e.GetCurrentPoint(this);
        if (!now.Properties.IsLeftButtonPressed) { _pressAt = null; return; }
        if (Math.Abs(now.Position.X - start.X) < DragThreshold && Math.Abs(now.Position.Y - start.Y) < DragThreshold) return;
        _pressAt = null;
        _ = StartDragAsync(now); // raises DragStarting (MainWindow decides what may move) and DropCompleted
    }

    private void Row_Tapped(object sender, TappedRoutedEventArgs e)
    {
        if (e.Handled) return;
        _tree?.RowInvoked(this);
    }

    /// <summary>A double click opens or closes a folder (the TreeView's own double click); MainWindow handles connections first.</summary>
    private void Row_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (e.Handled || Item is not { Children.Count: > 0 } item || IsInside(e.OriginalSource as DependencyObject, _chevron)) return;
        // PLUG-API-13: a plugin item with an "open" action connects on double-click (as on the Mac); the arrow expands it.
        if (item.PluginMenu.Any(m => m.Id == "open")) return;
        _tree?.Toggle(item);
    }

    private static bool IsInside(DependencyObject? d, DependencyObject? ancestor)
    {
        for (; d is not null && ancestor is not null; d = VisualTreeHelper.GetParent(d))
            if (ReferenceEquals(d, ancestor)) return true;
        return false;
    }

    private void Chevron_Tapped(object sender, TappedRoutedEventArgs e)
    {
        e.Handled = true;
        if (Item is { } item) _tree?.Toggle(item);
    }

    internal void RaiseSelected()
    {
        if (FrameworkElementAutomationPeer.FromElement(this) is { } peer)
            peer.RaiseAutomationEvent(AutomationEvents.SelectionItemPatternOnElementSelected);
    }

    internal void RaiseExpandState(bool on)
    {
        if (FrameworkElementAutomationPeer.FromElement(this) is { } peer)
            peer.RaisePropertyChangedEvent(ExpandCollapsePatternIdentifiers.ExpandCollapseStateProperty,
                on ? ExpandCollapseState.Collapsed : ExpandCollapseState.Expanded,
                on ? ExpandCollapseState.Expanded : ExpandCollapseState.Collapsed);
    }

    protected override AutomationPeer OnCreateAutomationPeer() => new LibraryRowPeer(this);

    private const string TemplateXaml = """
        <ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                         xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" TargetType="ContentControl">
            <Grid Margin="4,1,4,1" CornerRadius="4" Background="Transparent">
                <Border x:Name="SelectedFill" Background="{ThemeResource SubtleFillColorSecondaryBrush}" Opacity="0" />
                <Border x:Name="HoverFill" Background="{ThemeResource SubtleFillColorSecondaryBrush}" Opacity="0" />
                <Rectangle x:Name="Bar" Width="3" Height="16" RadiusX="1.5" RadiusY="1.5" HorizontalAlignment="Left" VerticalAlignment="Center"
                           Fill="{ThemeResource AccentFillColorDefaultBrush}" Visibility="Collapsed" />
                <FontIcon x:Name="Chevron" Width="24" Height="24" FontSize="12" HorizontalAlignment="Left" VerticalAlignment="Center"
                          FontFamily="{ThemeResource SymbolThemeFontFamily}" Foreground="{ThemeResource TextFillColorSecondaryBrush}"
                          Glyph="&#xE76C;" AutomationProperties.AccessibilityView="Raw" />
                <ContentPresenter x:Name="Presenter" Content="{TemplateBinding Content}" ContentTemplate="{TemplateBinding ContentTemplate}"
                                  HorizontalContentAlignment="Stretch" VerticalAlignment="Center" />
            </Grid>
        </ControlTemplate>
        """;

    private sealed partial class LibraryRowPeer(LibraryRow owner) : FrameworkElementAutomationPeer(owner),
        IExpandCollapseProvider, ISelectionItemProvider, IScrollItemProvider
    {
        protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.TreeItem;
        protected override string GetClassNameCore() => "TreeViewItem";
        protected override int GetLevelCore() => owner.Item is { } item && owner._tree is { } tree ? tree.DepthOf(item) + 1 : base.GetLevelCore();
        protected override int GetPositionInSetCore() => owner.Item is { } item && owner._tree is { } tree ? tree.SetOf(item).Position : base.GetPositionInSetCore();
        protected override int GetSizeOfSetCore() => owner.Item is { } item && owner._tree is { } tree ? tree.SetOf(item).Size : base.GetSizeOfSetCore();

        protected override object GetPatternCore(PatternInterface patternInterface) => patternInterface switch
        {
            PatternInterface.ExpandCollapse or PatternInterface.SelectionItem or PatternInterface.ScrollItem => this,
            _ => base.GetPatternCore(patternInterface),
        };

        public ExpandCollapseState ExpandCollapseState => owner.Item switch
        {
            null or { Children.Count: 0 } => ExpandCollapseState.LeafNode,
            { Expanded: true } => ExpandCollapseState.Expanded,
            _ => ExpandCollapseState.Collapsed,
        };

        public void Expand() { if (owner.Item is { } item) owner._tree?.SetExpanded(item, true); }
        public void Collapse() { if (owner.Item is { } item) owner._tree?.SetExpanded(item, false); }

        public bool IsSelected => owner.Item is { } item && owner._tree?.IsSelected(item) == true;

        public IRawElementProviderSimple? SelectionContainer =>
            owner._tree is { } tree && FromElement(tree) is { } peer ? ProviderFromPeer(peer) : null;

        public void Select() { if (owner._tree is { } tree && owner.Item is { } item) tree.SelectedItem = item; }
        public void AddToSelection() { if (owner._tree is { } tree && owner.Item is { } item) tree.AddToSelection(item); }
        public void RemoveFromSelection() { if (IsSelected && owner._tree is { } tree && owner.Item is { } item) tree.RemoveFromSelection(item); }

        public void ScrollIntoView() => owner.StartBringIntoView(new BringIntoViewOptions { AnimationDesired = false });
    }
}
