namespace Bastion.Shell;

/// <summary>
/// B12-W1: the app's open tabs, owned by the app rather than by one window, so that a torn-off window (B12-W2) can
/// share them. Each window has its own ordered list; a tab is in exactly one window. Windows read their list through
/// <see cref="TabsOf"/> (the live list, no copy) and change it only through this store.
/// Plain C# with no WinUI types, so it runs in <c>tests/session-store</c>.
/// </summary>
internal sealed class SessionStore<TTab> where TTab : class
{
    private readonly Dictionary<object, List<TTab>> _byWindow = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<TTab, object> _windowOf = new(ReferenceEqualityComparer.Instance);
    private static readonly IReadOnlyList<TTab> None = Array.Empty<TTab>();

    /// <summary>The window's tabs in strip order; empty for a window with none.</summary>
    public IReadOnlyList<TTab> TabsOf(object window) =>
        _byWindow.TryGetValue(window, out var list) ? list : None;

    /// <summary>Where <paramref name="tab"/> sits in <paramref name="window"/>'s strip, or -1.</summary>
    public int IndexOf(object window, TTab tab) =>
        _byWindow.TryGetValue(window, out var list) ? list.IndexOf(tab) : -1;

    /// <summary>Every open tab, window by window.</summary>
    public IEnumerable<TTab> All => _byWindow.Values.SelectMany(l => l);

    /// <summary>The window that shows <paramref name="tab"/>, or null when it is not open.</summary>
    public object? WindowOf(TTab tab) => _windowOf.GetValueOrDefault(tab);

    /// <summary>Puts <paramref name="tab"/> at the end of <paramref name="window"/>'s strip.</summary>
    public void Add(object window, TTab tab)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(tab);
        if (_windowOf.ContainsKey(tab)) throw new InvalidOperationException("The tab is already open in a window.");
        if (!_byWindow.TryGetValue(window, out var list)) _byWindow[window] = list = new List<TTab>();
        list.Add(tab);
        _windowOf[tab] = window;
    }

    /// <summary>Takes <paramref name="tab"/> out of its window. False when it was not open.</summary>
    public bool Remove(TTab tab)
    {
        if (!_windowOf.Remove(tab, out var window)) return false;
        _byWindow[window].Remove(tab);
        return true;
    }

    /// <summary>
    /// Sets <paramref name="window"/>'s strip order. <paramref name="order"/> must hold exactly that window's tabs;
    /// anything else is refused, so a reorder can never drop, duplicate or steal a tab.
    /// </summary>
    public void Reorder(object window, IReadOnlyList<TTab> order)
    {
        var current = TabsOf(window);
        var set = new HashSet<TTab>(order, ReferenceEqualityComparer.Instance);
        if (order.Count != current.Count || set.Count != order.Count || !current.All(set.Contains))
            throw new ArgumentException("The order must list each of the window's tabs once.", nameof(order));
        if (current.Count == 0) return;
        var list = _byWindow[window];
        list.Clear();
        list.AddRange(order);
    }

    /// <summary>Forgets a closed window's (now empty) list. Refused while it still holds tabs.</summary>
    public void ForgetWindow(object window)
    {
        if (TabsOf(window).Count > 0) throw new InvalidOperationException("The window still has tabs.");
        _byWindow.Remove(window);
    }
}
