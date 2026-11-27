using Microsoft.UI.Xaml;
using Windows.System;

namespace Bastion.Shell;

/// <summary>
/// Multi-select (owner 2026-11-16, to match Native Mac LibraryOutline): Ctrl+click adds or removes a row, Shift+click
/// selects the range from the anchor, Ctrl+A selects every shown row. <see cref="LibraryTree.SelectedItem"/> stays the
/// anchor (the single selection every existing caller uses); the others are kept apart, so a plain click, the arrow
/// keys and single-click behaviour work as before and clear the extra rows.
/// </summary>
public sealed partial class LibraryTree
{
    private readonly HashSet<TreeItem> _more = new(ReferenceEqualityComparer.Instance);
    /// <summary>The press had Ctrl or Shift: the Tapped that follows must not open the row.</summary>
    private bool _suppressInvoke;

    /// <summary>Raised when the set of selected rows changes beyond the anchor (Ctrl, Shift, Ctrl+A, or cleared).</summary>
    public event Action? MultiSelectionChanged;

    /// <summary>Every selected shown row, in tree order (the anchor included).</summary>
    public IReadOnlyList<TreeItem> SelectedItems => _more.Count == 0
        ? _selected is { } one && _index.ContainsKey(one) ? [one] : []
        : _rows.Where(IsSelected).ToList();

    private void ClearMore()
    {
        if (_more.Count == 0) return;
        var gone = _more.ToList();
        _more.Clear();
        foreach (var item in gone) ContainerFromItem(item)?.UpdateState();
        MultiSelectionChanged?.Invoke();
    }

    private void SetMore(IEnumerable<TreeItem> items)
    {
        var old = _more.ToList();
        _more.Clear();
        foreach (var item in items) if (!ReferenceEquals(item, _selected)) _more.Add(item);
        foreach (var item in old.Concat(_more)) ContainerFromItem(item)?.UpdateState();
        MultiSelectionChanged?.Invoke();
    }

    /// <summary>Ctrl or Shift on a press, or a right press inside a multi-selection; true when handled here.</summary>
    private bool PressWithModifiers(LibraryRow row, TreeItem item, bool right, FocusState how)
    {
        if (right)
        {
            // The context menu acts on the selection: a right press inside it keeps it.
            if (_more.Count == 0 || !IsSelected(item)) return false;
            row.Focus(how);
            return true;
        }
        var ctrl = IsDown(VirtualKey.Control);
        var shift = IsDown(VirtualKey.Shift);
        if (!ctrl && !shift) return false;
        _suppressInvoke = true;
        if (_selected is null) { Select(item); row.Focus(how); return true; }
        if (shift && _index.TryGetValue(_selected, out var from) && _index.TryGetValue(item, out var to))
        {
            var (lo, hi) = from <= to ? (from, to) : (to, from);
            SetMore(_rows.Skip(lo).Take(hi - lo + 1).ToList());
            row.Focus(how);
            return true;
        }
        if (IsSelected(item)) RemoveFromSelection(item);
        else { AddToSelection(item); row.Focus(how); }
        return true;
    }

    /// <summary>Add a shown row to the selection (Ctrl+click, UIA AddToSelection).</summary>
    internal void AddToSelection(TreeItem item)
    {
        if (!_index.ContainsKey(item) || IsSelected(item)) return;
        if (_selected is null) { Select(item); return; }
        SetMore(_more.Append(item).ToList());
    }

    /// <summary>Take a row out of the selection; when it is the anchor, the next selected row becomes the anchor.</summary>
    internal void RemoveFromSelection(TreeItem item)
    {
        if (!IsSelected(item)) return;
        if (!ReferenceEquals(item, _selected)) { SetMore(_more.Where(m => !ReferenceEquals(m, item)).ToList()); return; }
        var rest = _rows.Where(r => _more.Contains(r)).ToList();
        if (rest.Count == 0) { Select(null); return; }
        Select(rest[0]); // clears the others, so put them back after
        SetMore(rest.Skip(1).ToList());
    }

    /// <summary>Ctrl+A: every shown row.</summary>
    private void SelectAll()
    {
        if (_selected is null || !_index.ContainsKey(_selected)) Select(_rows[0]);
        SetMore(_rows.ToList());
    }
}
