using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// WIN-TREE-REBUILD: a library rebuild (a save, a session's typed password saved, a favourite, a vault change) keeps
/// the row objects of everything that did not change, so the flat tree (<see cref="LibraryTree"/>) swaps only the
/// changed rows (<see cref="RowEdits"/>) instead of making every row in view again. A row is kept when everything it
/// shows or acts on is equal (<see cref="TreeItem.SameRow"/>); a folder only when all its children were kept, in the
/// same order. A connection's session and plugin rows belong to the window (SyncSessionRows), so a kept connection
/// keeps them and a new one gets them added.
/// </summary>
internal sealed class TreeReuse
{
    private readonly Dictionary<string, TreeItem> _old = new(StringComparer.Ordinal);

    /// <summary>Rows kept from the earlier tree, and rows made new (test trace only).</summary>
    public int Kept { get; private set; }
    public int Made { get; private set; }

    private TreeReuse() { }

    /// <summary>
    /// A reuse over <paramref name="previous"/>, or null when nothing may be kept: no earlier tree, or it was built for
    /// another theme, contrast mode or set of plugin types (rows read those when they are drawn, not when built).
    /// </summary>
    public static TreeReuse? Over(IEnumerable<TreeItem>? previous, string? previousContext, string context)
    {
        if (previous is null || previousContext != context) return null;
        var reuse = new TreeReuse();
        reuse.Index(previous);
        return reuse._old.Count == 0 ? null : reuse;
    }

    /// <summary>What a row's look depends on besides its own fields: compared before any row is kept.</summary>
    public static string Context() => string.Join('|',
        TreeItem.DarkNames, Ui.HighContrast,
        string.Join(',', TreeItem.OpenablePluginTypes.Order(StringComparer.Ordinal)),
        string.Join(',', TreeItem.SidebarTreeTypes.Order(StringComparer.Ordinal)),
        string.Join(',', TreeItem.PluginTypeNames.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => p.Key + "=" + p.Value)));

    private void Index(IEnumerable<TreeItem> level)
    {
        foreach (var item in level)
        {
            if (item.IsSession || item.IsPluginRow || item.IsMirror) continue;
            _old.TryAdd(item.Id, item);
            if (item.IsFolder) Index(item.Children);
        }
    }

    /// <summary>The earlier row for <paramref name="made"/> when it is the same; otherwise <paramref name="made"/>.</summary>
    public TreeItem Keep(TreeItem made)
    {
        if (_old.TryGetValue(made.Id, out var old) && TreeItem.SameRow(old, made)) { Kept++; return old; }
        Made++;
        return made;
    }
}
