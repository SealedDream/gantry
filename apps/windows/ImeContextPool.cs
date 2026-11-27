namespace Bastion.Shell;

/// <summary>
/// Spare TSF edit contexts, per window (WIN-SHELL-LEAK). The text services keep every CoreTextEditContext they make
/// alive for the life of the app, after the terminal that asked for it has let go (q-shell-leak-ab: 210 of 210 still
/// alive natively after 21 cycles of 10 closed local shell tabs, while the tabs' XAML objects were all freed), so each
/// new terminal's context was native heap that never came back. A closing terminal hands its context back here and the
/// next terminal in the same window takes it instead of asking for a new one: the number of contexts stops at the most
/// terminals open at once. Only a clean context comes back, one that never delivered text and never had its focus
/// taken by TSF: such a context may no longer deliver text (the Win11 "stuck pane", WIN-FORGOTTEN-01), so it is
/// dropped as before. Generic so it can be unit tested without WinRT. UI thread only.
/// </summary>
internal sealed class ImeContextPool<T> where T : class
{
    private readonly Dictionary<ulong, Stack<T>> _spare = new();
    /// <summary>Windows that closed: a context made for one comes back from a tab that moved to another window, and is
    /// not kept (nothing would take it).</summary>
    private readonly HashSet<ulong> _closed = new();

    /// <summary>
    /// A spare context made for <paramref name="window"/>, or null when there is none. A terminal asking for a context in
    /// <paramref name="window"/> shows the window is open (window ids can be reused after a window closes).
    /// </summary>
    public T? Take(ulong window)
    {
        _closed.Remove(window);
        return _spare.TryGetValue(window, out var s) && s.Count > 0 ? s.Pop() : null;
    }

    /// <summary>
    /// Hand back a context a terminal in <paramref name="window"/> no longer uses. Kept only when it is
    /// <paramref name="clean"/> and its window is known; returns whether it was kept.
    /// </summary>
    public bool Return(ulong window, T context, bool clean)
    {
        if (window == 0 || !clean || _closed.Contains(window)) return false;
        if (!_spare.TryGetValue(window, out var s)) _spare[window] = s = new Stack<T>();
        if (!s.Any(c => ReferenceEquals(c, context))) s.Push(context);
        return true;
    }

    /// <summary>The window closed: its spare contexts go with it, and none made for it is kept from now on.</summary>
    public void Forget(ulong window)
    {
        _spare.Remove(window);
        _closed.Add(window);
    }

    public int SpareCount(ulong window) => _spare.TryGetValue(window, out var s) ? s.Count : 0;
}
