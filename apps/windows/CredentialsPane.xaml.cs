using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;

namespace Bastion.Shell;

/// <summary>
/// The Credentials section pinned under the connection tree, as on Native Mac. It only shows rows and reports what the
/// user did; MainWindow (MainWindow.CredentialsPane.cs) owns the vault, the menus and the drag-and-drop rules.
/// </summary>
public sealed partial class CredentialsPane : UserControl
{
    /// <summary>The most of the navigation pane the section may take; the rest stays for the library.</summary>
    private const double MaxShareOfParent = 0.4;

    private TreeItem? _menuTarget;
    private FrameworkElement? _sizedBy;

    /// <summary>The menu for a row (null: empty space, the vault root).</summary>
    public Func<TreeItem?, IReadOnlyList<MenuFlyoutItemBase>>? MenuFor { get; set; }

    /// <summary>A row was dragged; return false to cancel the drag.</summary>
    public Func<TreeItem, DragStartingEventArgs, bool>? DragStart { get; set; }

    /// <summary>A row was opened (true) or closed (false), so a rebuild keeps it that way.</summary>
    public Action<string, bool>? ExpandedChanged { get; set; }

    public Action? DragEnded { get; set; }
    public Action<TreeItem?, DragEventArgs>? DragOverRow { get; set; }
    public Action<TreeItem?, DragEventArgs>? DropOnRow { get; set; }

    public CredentialsPane()
    {
        InitializeComponent();
        Rows.AddHandler(PointerPressedEvent, new PointerEventHandler(SelectOnRightPress), true);
        Loaded += (_, _) => FollowParentHeight();
        Unloaded += (_, _) => { if (_sizedBy is not null) _sizedBy.SizeChanged -= OnParentSizeChanged; _sizedBy = null; };
    }

    /// <summary>Show the section heading and its rows (the heading's children), or nothing while a search matches none.</summary>
    public void Show(TreeItem? section)
    {
        // Hidden, the rows stay bound: clearing a search brings back the same section, and a rebind recreated every
        // TreeView container and their layout inside the Escape that cleared it (WIN-STALL-USER).
        if (section is null) { Visibility = Visibility.Collapsed; return; }
        Visibility = Visibility.Visible;
        // Compared with the bound rows as they are now: the user may have opened or closed a folder since they were bound.
        if (Rows.ItemsSource is List<TreeItem> { Count: 1 } bound && RowsKey(bound[0]) == RowsKey(section)) return;
        Rows.ItemsSource = new List<TreeItem> { section };
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => ApplyExpansion(section, MaxExpandPasses));
    }

    /// <summary>Everything a row shows or acts on (ids, names, icons and their colour, tooltips, parents, open state), in
    /// tree order. A theme change gives other icon colours, so the rows are bound again then.</summary>
    internal static string RowsKey(TreeItem section)
    {
        var key = new System.Text.StringBuilder();
        void Add(TreeItem item, int depth)
        {
            var tint = item.IconBrush is Microsoft.UI.Xaml.Media.SolidColorBrush solid ? solid.Color.ToString() : item.IconBrush?.GetType().Name;
            key.Append(depth).Append('\u001f').Append(item.Id).Append('\u001f').Append(item.Name).Append('\u001f').Append(item.Description)
               .Append('\u001f').Append(item.Glyph).Append('\u001f').Append(item.ArtId).Append('\u001f').Append(item.IconLabel)
               .Append('\u001f').Append(tint).Append('\u001f').Append(item.ParentId).Append('\u001f').Append(item.Expanded ? '1' : '0').Append('\u001e');
            foreach (var child in item.Children) Add(child, depth + 1);
        }
        Add(section, 0);
        return key.ToString();
    }

    /// <summary>Deepest folder level re-opened after a redraw; each pass realises one more level of rows.</summary>
    private const int MaxExpandPasses = 8;

    /// <summary>
    /// After a redraw, open each realised row the model marks open (a new credential's folder, the heading). Rows inside a
    /// row opened here are only realised on the next layout, so it runs again until nothing changes.
    /// </summary>
    private void ApplyExpansion(TreeItem root, int passesLeft)
    {
        if (passesLeft <= 0 || Rows.ItemsSource is not List<TreeItem> { Count: 1 } shown || !ReferenceEquals(shown[0], root)) return;
        if (Open(root)) DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => ApplyExpansion(root, passesLeft - 1));
    }

    /// <summary>Open this row and its open descendants that have containers; true when one was changed.</summary>
    private bool Open(TreeItem item)
    {
        if (!item.Expanded || item.Children.Count == 0) return false;
        var changed = false;
        if (Rows.ContainerFromItem(item) is TreeViewItem { IsExpanded: false } container) { container.IsExpanded = true; changed = true; }
        foreach (var child in item.Children) changed |= Open(child);
        return changed;
    }

    private void FollowParentHeight()
    {
        if (Parent is not FrameworkElement parent || ReferenceEquals(parent, _sizedBy)) return;
        _sizedBy = parent;
        parent.SizeChanged += OnParentSizeChanged;
        Rows.MaxHeight = parent.ActualHeight * MaxShareOfParent;
    }

    private void OnParentSizeChanged(object sender, SizeChangedEventArgs e) => Rows.MaxHeight = e.NewSize.Height * MaxShareOfParent;

    private void Rows_Expanding(TreeView sender, TreeViewExpandingEventArgs args)
    {
        if (args.Item is not TreeItem item) return;
        item.Expanded = true; // the binding is one-time, so the row keeps the user's choice when its container is reused
        ExpandedChanged?.Invoke(item.Id, true);
    }

    private void Rows_Collapsed(TreeView sender, TreeViewCollapsedEventArgs args)
    {
        if (args.Item is not TreeItem item) return;
        item.Expanded = false;
        ExpandedChanged?.Invoke(item.Id, false);
    }

    /// <summary>
    /// A click on a row: the Locked row unlocks; a folder (or the heading) opens or closes on a click anywhere on its row,
    /// not only on its arrow, as in the library tree (owner round 4, CRED-FOLDERS).
    /// </summary>
    private void Rows_ItemInvoked(TreeView sender, TreeViewItemInvokedEventArgs args)
    {
        if (args.InvokedItem is TreeItem { Open: { } open })
        {
            args.Handled = true;
            open();
            return;
        }
        if (args.InvokedItem is not TreeItem item || !IsFolderRow(item)) return;
        if (Rows.ContainerFromItem(item) is not TreeViewItem container) return;
        args.Handled = true;
        container.IsExpanded = !container.IsExpanded;
    }

    /// <summary>A row that holds others: a vault folder or the section heading.</summary>
    internal static bool IsFolderRow(TreeItem item) => item is { Credential.IsFolder: true } or { Id: TreeItem.CredentialsGroupId };

    /// <summary>Opens or closes the named folder row, as a click on it does (UI tests); false when it has no row.</summary>
    internal bool ToggleRowForTest(string name)
    {
        if (Rows.ItemsSource is not List<TreeItem> { Count: 1 } shown || Find(shown[0], name) is not { } item || !IsFolderRow(item)) return false;
        if (Rows.ContainerFromItem(item) is not TreeViewItem container) return false;
        container.IsExpanded = !container.IsExpanded;
        return true;
    }

    /// <summary>Whether the named row is open (UI tests).</summary>
    internal bool? IsRowOpenForTest(string name) =>
        Rows.ItemsSource is List<TreeItem> { Count: 1 } shown && Find(shown[0], name) is { } item && Rows.ContainerFromItem(item) is TreeViewItem c
            ? c.IsExpanded : null;

    private static TreeItem? Find(TreeItem item, string name)
    {
        if (item.Name == name) return item;
        foreach (var child in item.Children) if (Find(child, name) is { } hit) return hit;
        return null;
    }

    /// <summary>A drop on the empty space under the rows lands at the top level, as on the heading.</summary>
    private void Rows_DragOver(object sender, DragEventArgs e) { if (!e.Handled) DragOverRow?.Invoke(Heading, e); }

    private void Rows_Drop(object sender, DragEventArgs e) { if (!e.Handled) DropOnRow?.Invoke(Heading, e); }

    private TreeItem? Heading => Rows.ItemsSource is List<TreeItem> { Count: 1 } shown ? shown[0] : null;

    private void Rows_ContextRequested(UIElement sender, ContextRequestedEventArgs args)
    {
        args.Handled = true;
        _menuTarget = RowOf(args.OriginalSource as DependencyObject);
        var options = new FlyoutShowOptions();
        if (args.TryGetPosition(Rows, out var at)) options.Position = at;
        RowMenu.ShowAt(Rows, options);
    }

    /// <summary>
    /// A right press selects its row before the menu is asked for, as the library tree does (MainWindow.InitTreeRightPress):
    /// selected while the menu opens, the TreeView's selection work closes the menu again at once.
    /// Registered for handled presses too, since the row handles its own.
    /// </summary>
    private void SelectOnRightPress(object sender, PointerRoutedEventArgs e)
    {
        if (!e.GetCurrentPoint(Rows).Properties.IsRightButtonPressed) return;
        if (RowOf(e.OriginalSource as DependencyObject) is not { } item || ReferenceEquals(Rows.SelectedItem, item)) return;
        try { Rows.SelectedItem = item; }
        catch { /* selection is a convenience; the menu still works from _menuTarget */ }
    }

    private void RowMenu_Opening(object sender, object e)
    {
        RowMenu.Items.Clear();
        foreach (var entry in MenuFor?.Invoke(_menuTarget) ?? []) RowMenu.Items.Add(entry);
    }

    /// <summary>The row an element belongs to: the nearest TreeViewItem's item.</summary>
    private static TreeItem? RowOf(DependencyObject? d)
    {
        for (; d is not null; d = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(d))
            if (d is TreeViewItem { DataContext: TreeItem item }) return item;
        return null;
    }

    /// <summary>
    /// The TreeView drops IsExpanded bound before a row's children exist, so the heading came up collapsed and hid the
    /// Locked row. Re-apply the row's state once its container is realised, as the library tree does (SyncExpansion).
    /// </summary>
    private void Row_DataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)
    {
        if (sender is not TreeViewItem container || args.NewValue is not TreeItem { Children.Count: > 0 } item) return;
        DispatcherQueue.TryEnqueue(() =>
        {
            if (!ReferenceEquals(container.DataContext, item)) return; // recycled meanwhile
            if (Rows.NodeFromContainer(container) is { } node && node.IsExpanded != item.Expanded) node.IsExpanded = item.Expanded;
        });
    }

    private void Row_DragStarting(UIElement sender, DragStartingEventArgs args)
    {
        if ((sender as FrameworkElement)?.DataContext is not TreeItem item || DragStart?.Invoke(item, args) != true) args.Cancel = true;
    }

    private void Row_DropCompleted(UIElement sender, DropCompletedEventArgs args) => DragEnded?.Invoke();

    private void Row_DragOver(object sender, DragEventArgs e) => DragOverRow?.Invoke((sender as FrameworkElement)?.DataContext as TreeItem, e);

    private void Row_Drop(object sender, DragEventArgs e) => DropOnRow?.Invoke((sender as FrameworkElement)?.DataContext as TreeItem, e);
}
