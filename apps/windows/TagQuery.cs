namespace Bastion.Shell;

/// <summary>
/// Connection tags (owner 2026-11-16): stored lower case without duplicates (core <c>properties::normalize_tags</c>).
/// A filter's <c>tag:name</c> terms must all be tags of the connection; the rest is free text.
/// </summary>
internal sealed record TagQuery(IReadOnlyList<string> Tags, string Text)
{
    private const string Prefix = "tag:";

    /// <summary>Lower case, trimmed, no blanks, no duplicates; first order kept.</summary>
    public static List<string> Normalize(IEnumerable<string> tags)
    {
        var result = new List<string>();
        foreach (var t in tags)
        {
            var v = t.Trim().ToLowerInvariant();
            if (v.Length > 0 && !result.Contains(v)) result.Add(v);
        }
        return result;
    }

    public static TagQuery Parse(string filter)
    {
        if (!filter.Contains(Prefix, StringComparison.OrdinalIgnoreCase)) return new([], filter);
        var tags = new List<string>();
        var words = new List<string>();
        foreach (var w in filter.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (w.Length > Prefix.Length && w.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) tags.Add(w[Prefix.Length..]);
            else words.Add(w);
        }
        return tags.Count == 0 ? new([], filter) : new(Normalize(tags), string.Join(' ', words));
    }

    /// <summary>Whether <paramref name="tags"/> holds every tag the query names.</summary>
    public bool Admits(IReadOnlyList<string>? tags) => Tags.All(t => tags?.Contains(t) == true);
}
