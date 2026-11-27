namespace Bastion.Shell;

/// <summary>One custom property row as the editor shows it.</summary>
public sealed record CustomPropertyRow(string Name, string Value);

/// <summary>
/// The rules behind the Icon and Custom properties page (PARITY-01 rows 8 and 9), kept free of WinUI so the unit
/// test compiles them on their own. The core validates names, values and icon ids; this only works out which calls
/// to make and refuses what the core cannot tell apart (two rows with one name).
/// </summary>
public static class ItemExtrasEdits
{
    /// <summary>The label shown for a core icon name ("database" → "Database").</summary>
    public static string IconLabel(string name) => name.Length == 0 ? name : char.ToUpperInvariant(name[0]) + name[1..];

    /// <summary>
    /// The core calls that turn <paramref name="saved"/> into <paramref name="edited"/>: removes first (value null),
    /// then sets, each name once. Rows with a blank name are ignored when their value is blank too. Returns an error
    /// text instead when a name is blank but has a value, or when two rows share a name (case-insensitive).
    /// </summary>
    public static (IReadOnlyList<(string Name, string? Value)> Calls, string? Error) Changes(IReadOnlyList<CustomPropertyRow> saved, IReadOnlyList<CustomPropertyRow> edited)
    {
        var rows = new List<CustomPropertyRow>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in edited)
        {
            var name = row.Name.Trim();
            if (name.Length == 0)
            {
                if (row.Value.Trim().Length == 0) continue;
                return ([], "Enter a name for every custom property.");
            }
            if (!seen.Add(name)) return ([], $"\"{name}\" is used twice.");
            rows.Add(new CustomPropertyRow(name, row.Value));
        }

        var calls = new List<(string, string?)>();
        var kept = new HashSet<string>(rows.Select(r => r.Name), StringComparer.Ordinal);
        foreach (var old in saved)
        {
            if (!kept.Contains(old.Name)) calls.Add((old.Name, null));
        }
        var before = saved.ToDictionary(r => r.Name, r => r.Value, StringComparer.Ordinal);
        foreach (var row in rows)
        {
            if (!before.TryGetValue(row.Name, out var old) || old != row.Value) calls.Add((row.Name, row.Value));
        }
        return (calls, null);
    }
}
