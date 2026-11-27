namespace Bastion.Shell;

/// <summary>What one edit does to the shown list: put a new row at an index, take the row there out, or swap it.</summary>
public enum RowEditKind { Insert, Remove, Replace }

/// <summary>One edit, at <see cref="Index"/> of the list as it is when the edit is applied (edits run in order).</summary>
public readonly record struct RowEdit<T>(RowEditKind Kind, int Index, T? Row) where T : class;

/// <summary>
/// WIN-TREE-REBUILD: the edits that turn the shown rows into the new rows, compared by object identity, so the flat
/// tree (LibraryTree) rebinds only the rows that changed. After a library rebuild that kept the unchanged rows
/// (<see cref="TreeReuse"/>), the changes are a few rows spread over the list: a folder header near the top, the changed
/// connection further down, the Application section at the end. A head-and-tail comparison saw one long changed run
/// there and replaced the whole list, so every row in view was made again.
/// </summary>
public static class RowEdits
{
    /// <summary>
    /// The edits, in order, or null when more than <paramref name="limit"/> are needed, a row moved (it is in both lists
    /// but out of order) or a list holds the same row twice: then the caller replaces the whole list.
    /// </summary>
    public static List<RowEdit<T>>? Plan<T>(IReadOnlyList<T> old, IReadOnlyList<T> rows, int limit) where T : class
    {
        if (Math.Abs(old.Count - rows.Count) > limit) return null;
        var inOld = new HashSet<T>(old, ReferenceEqualityComparer.Instance);
        var inNew = new HashSet<T>(rows, ReferenceEqualityComparer.Instance);
        if (inOld.Count != old.Count || inNew.Count != rows.Count) return null;
        var edits = new List<RowEdit<T>>();
        // Invariant: the list being edited holds rows[0..j) followed by old[i..].
        var i = 0;
        var j = 0;
        while (i < old.Count || j < rows.Count)
        {
            if (i < old.Count && j < rows.Count && ReferenceEquals(old[i], rows[j])) { i++; j++; continue; }
            var gone = i < old.Count && !inNew.Contains(old[i]);
            var came = j < rows.Count && !inOld.Contains(rows[j]);
            if (gone && came) { edits.Add(new(RowEditKind.Replace, j, rows[j])); i++; j++; }
            else if (came) { edits.Add(new(RowEditKind.Insert, j, rows[j])); j++; }
            else if (gone) { edits.Add(new(RowEditKind.Remove, j, null)); i++; }
            else return null; // both rows are in both lists, in another order: a move
            if (edits.Count > limit) return null;
        }
        return edits;
    }

    /// <summary>Apply <paramref name="edits"/> (from <see cref="Plan"/>) to <paramref name="list"/>.</summary>
    public static void Apply<T>(IList<T> list, IEnumerable<RowEdit<T>> edits) where T : class
    {
        foreach (var e in edits)
        {
            switch (e.Kind)
            {
                case RowEditKind.Insert: list.Insert(e.Index, e.Row!); break;
                case RowEditKind.Remove: list.RemoveAt(e.Index); break;
                default: list[e.Index] = e.Row!; break;
            }
        }
    }
}
