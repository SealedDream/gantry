using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.System;

namespace Bastion.Shell;

/// <summary>
/// Chords as the core writes them (<c>primary+shift+p</c>, core/src/shortcuts.rs) and as Windows shows and types them.
/// On Windows the primary modifier is Ctrl; the core resolves <c>primary</c> to <c>ctrl</c> when it lists chords for the
/// <c>windows</c> platform, and a recorded Ctrl is written as <c>primary</c> so the file means the same on both systems.
/// </summary>
internal static class Chords
{
    private static readonly Dictionary<string, string> Names = new()
    {
        ["return"] = "Enter", ["tab"] = "Tab", ["escape"] = "Esc", ["space"] = "Space", ["delete"] = "Delete",
        ["up"] = "Up", ["down"] = "Down", ["left"] = "Left", ["right"] = "Right", ["home"] = "Home", ["end"] = "End",
        ["pageup"] = "Page Up", ["pagedown"] = "Page Down",
    };

    private static readonly Dictionary<VirtualKey, string> Keys = new()
    {
        [VirtualKey.Enter] = "return", [VirtualKey.Tab] = "tab", [VirtualKey.Escape] = "escape", [VirtualKey.Space] = "space",
        [VirtualKey.Delete] = "delete", [VirtualKey.Up] = "up", [VirtualKey.Down] = "down", [VirtualKey.Left] = "left",
        [VirtualKey.Right] = "right", [VirtualKey.Home] = "home", [VirtualKey.End] = "end", [VirtualKey.PageUp] = "pageup",
        [VirtualKey.PageDown] = "pagedown",
        // US-layout OEM keys; the core accepts these punctuation keys.
        [(VirtualKey)186] = ";", [(VirtualKey)187] = "=", [(VirtualKey)188] = ",", [(VirtualKey)189] = "-", [(VirtualKey)190] = ".",
        [(VirtualKey)191] = "/", [(VirtualKey)192] = "`", [(VirtualKey)219] = "[", [(VirtualKey)220] = "\\", [(VirtualKey)221] = "]",
        [(VirtualKey)222] = "'",
    };

    /// <summary>"ctrl+shift+p" → "Ctrl+Shift+P"; null → "".</summary>
    public static string Display(string? chord)
    {
        if (string.IsNullOrEmpty(chord)) return "";
        var parts = chord.Split('+');
        var key = parts[^1];
        var mods = parts[..^1].Select(m => m switch { "primary" or "ctrl" => "Ctrl", "alt" => "Alt", "shift" => "Shift", _ => m });
        return string.Join("+", mods.Distinct().Append(Names.TryGetValue(key, out var n) ? n : key.ToUpperInvariant()));
    }

    /// <summary>The key's name in a chord, or null for a key a shortcut cannot use (a modifier alone, Windows keys).</summary>
    public static string? KeyName(VirtualKey key) => key switch
    {
        >= VirtualKey.A and <= VirtualKey.Z => ((char)('a' + (key - VirtualKey.A))).ToString(),
        >= VirtualKey.Number0 and <= VirtualKey.Number9 => ((char)('0' + (key - VirtualKey.Number0))).ToString(),
        >= VirtualKey.F1 and <= VirtualKey.F12 => "f" + (key - VirtualKey.F1 + 1),
        _ => Keys.GetValueOrDefault(key),
    };

    /// <summary>The neutral chord for a key press (Ctrl recorded as <c>primary</c>), or null when the key cannot be bound.</summary>
    public static string? FromPress(VirtualKey key, bool ctrl, bool alt, bool shift) =>
        KeyName(key) is { } name ? string.Join("+", new[] { ctrl ? "primary" : null, alt ? "alt" : null, shift ? "shift" : null, name }.Where(p => p is not null)) : null;

    /// <summary>Whether a Windows-resolved chord (<c>ctrl+shift+p</c>) is this key press.</summary>
    public static bool Matches(string chord, VirtualKey key, bool ctrl, bool alt, bool shift)
    {
        var parts = chord.Split('+');
        return KeyName(key) == parts[^1]
               && ctrl == (parts.Contains("ctrl") || parts.Contains("primary"))
               && alt == parts.Contains("alt")
               && shift == parts.Contains("shift");
    }
}

/// <summary>
/// Settings › Keyboard: every command with its shortcut, filtered by name (core search) or by keys. Click a shortcut
/// to record a new one; a chord another command holds asks before it moves, a chord Windows reserves is refused,
/// Backspace removes the shortcut and Esc cancels. Same rules and file (<c>shortcuts.json</c>) as the macOS page.
/// </summary>
internal sealed class KeyboardPage
{
    private readonly ShortcutsClient _shortcuts;
    private readonly IReadOnlySet<string> _commands;
    private readonly Func<string, string, Task<bool>> _confirm;
    private readonly Action<string> _refuse;
    private readonly Action _changed;
    private readonly StackPanel _list = new() { Spacing = Ui.Double("Space4") };
    private readonly TextBox _filter;
    private Button? _recording;

    public StackPanel Body { get; }

    /// <param name="commands">The commands this app runs; only they are listed.</param>
    /// <param name="confirm">Asks (title, text) whether to take a chord from another command.</param>
    /// <param name="refuse">Shows why a chord cannot be used.</param>
    /// <param name="changed">Called after any change, so menus and tooltips pick up the new keys.</param>
    public KeyboardPage(ShortcutsClient shortcuts, IReadOnlySet<string> commands, Func<string, string, Task<bool>> confirm, Action<string> refuse, Action changed)
    {
        _shortcuts = shortcuts;
        _commands = commands;
        _confirm = confirm;
        _refuse = refuse;
        _changed = changed;
        _filter = new TextBox { PlaceholderText = "Filter by command or keys", IsSpellCheckEnabled = false, MaxWidth = 360, HorizontalAlignment = HorizontalAlignment.Left, MinWidth = 280 };
        AutomationProperties.SetName(_filter, "Filter shortcuts");
        _filter.TextChanged += (_, _) => Fill();
        var restoreAll = new Button { Content = "Restore All Defaults", Style = Ui.Style("SubtleButtonStyle") };
        restoreAll.Click += (_, _) => Change(() => _shortcuts.Reset(null));
        var note = Ui.Text("Click a shortcut to change it. Backspace removes it, Esc cancels. In a terminal, Ctrl plus a letter goes to the program; shortcuts with Ctrl+Shift, Alt or a function key work everywhere.", "CaptionSecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        var head = new Grid { ColumnSpacing = Ui.Double("Space8"), ColumnDefinitions = { new ColumnDefinition(), new ColumnDefinition { Width = GridLength.Auto } } };
        head.Children.Add(_filter);
        Grid.SetColumn(restoreAll, 1);
        head.Children.Add(restoreAll);
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { head, note, _list } };
        Fill();
    }

    /// <summary>Show only <paramref name="query"/>'s matches (the Settings search, the snapshot).</summary>
    public void Filter(string query)
    {
        _filter.Text = query;
        Fill(); // TextChanged does not run for a box that is not in the window yet
    }

    /// <summary>Snapshot only: record <paramref name="chord"/> for a command as if its keys were pressed.</summary>
    internal Task RecordForSnapshot(string id, string chord) => TryAssign(_shortcuts.List().First(s => s.Id == id), chord);

    private void Fill()
    {
        _list.Children.Clear();
        List<ShortcutDto> all;
        HashSet<string> shadowed;
        try { (all, shadowed) = (_shortcuts.List().Where(s => _commands.Contains(s.Id)).ToList(), _shortcuts.Shadowed().ToHashSet()); }
        catch (BastionException ex) { _list.Children.Add(Ui.Text(ex.Message, "BodySecondaryTextStyle")); return; }
        var query = _filter.Text.Trim();
        HashSet<string>? byName = null;
        if (query.Length > 0)
        {
            try { byName = ShortcutsClient.Search(query).ToHashSet(); }
            catch (BastionException) { byName = new(); }
        }
        var shown = all.Where(s => byName is null || byName.Contains(s.Id) || Chords.Display(s.Chord).Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
        if (shown.Count == 0)
        {
            _list.Children.Add(Ui.Text($"No commands or keys match “{query}”.", "BodySecondaryTextStyle"));
            return;
        }
        foreach (var group in shown.GroupBy(s => s.GroupLabel))
        {
            var header = Ui.Text(group.Key, "SectionHeaderTextStyle");
            header.Margin = Ui.Thickness("InspectorSectionMargin");
            AutomationProperties.SetHeadingLevel(header, AutomationHeadingLevel.Level3);
            _list.Children.Add(header);
            foreach (var s in group) _list.Children.Add(Row(s, shadowed.Contains(s.Id)));
        }
    }

    private Grid Row(ShortcutDto s, bool shadowed)
    {
        var row = new Grid { ColumnSpacing = Ui.Double("Space8"), MinHeight = Ui.Double("ControlHeight") };
        row.ColumnDefinitions.Add(new ColumnDefinition());
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(160) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(88) });
        var label = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Children = { Ui.Text(s.Label, "BodyTextStyle") } };
        if (shadowed) label.Children.Add(Ui.Text("Does nothing: an earlier command has the same keys.", "CaptionSecondaryTextStyle"));
        row.Children.Add(label);
        var keys = new Button { Content = s.Chord is null ? "None" : Chords.Display(s.Chord), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Left };
        AutomationProperties.SetName(keys, $"{s.Label} shortcut: {(s.Chord is null ? "none" : Chords.Display(s.Chord))}. Press to change.");
        keys.Click += (_, _) => StartRecording(keys, s);
        keys.PreviewKeyDown += (_, e) => Recorded(keys, s, e);
        keys.LostFocus += (_, _) => { if (ReferenceEquals(_recording, keys)) StopRecording(); };
        Grid.SetColumn(keys, 1);
        row.Children.Add(keys);
        if (!s.IsDefault)
        {
            var restore = new Button { Content = "Restore", Style = Ui.Style("SubtleButtonStyle") };
            ToolTipService.SetToolTip(restore, s.DefaultChord is null ? "Restore: no shortcut" : "Restore " + Chords.Display(s.DefaultChord));
            AutomationProperties.SetName(restore, "Restore the default shortcut of " + s.Label);
            restore.Click += (_, _) => Change(() => _shortcuts.Reset(s.Id));
            Grid.SetColumn(restore, 2);
            row.Children.Add(restore);
        }
        return row;
    }

    private void StartRecording(Button keys, ShortcutDto s)
    {
        StopRecording();
        _recording = keys;
        keys.Content = "Press keys…";
        AutomationProperties.SetName(keys, $"Recording a shortcut for {s.Label}. Press the keys, Backspace to remove, Esc to cancel.");
    }

    private void StopRecording()
    {
        if (_recording is null) return;
        _recording = null;
        Fill();
    }

    private void Recorded(Button keys, ShortcutDto s, KeyRoutedEventArgs e)
    {
        if (!ReferenceEquals(_recording, keys)) return;
        e.Handled = true;
        static bool Down(VirtualKey k) => Microsoft.UI.Input.InputKeyboardSource.GetKeyStateForCurrentThread(k).HasFlag(Windows.UI.Core.CoreVirtualKeyStates.Down);
        var (ctrl, alt, shift) = (Down(VirtualKey.Control), Down(VirtualKey.Menu), Down(VirtualKey.Shift));
        switch (e.Key)
        {
            case VirtualKey.Control or VirtualKey.Menu or VirtualKey.Shift or VirtualKey.LeftWindows or VirtualKey.RightWindows:
                return; // wait for the key itself
            case VirtualKey.Escape when !ctrl && !alt && !shift:
                StopRecording();
                return;
            case VirtualKey.Back when !ctrl && !alt && !shift:
                Change(() => _shortcuts.Set(s.Id, null, replace: false));
                return;
        }
        if (Chords.FromPress(e.Key, ctrl, alt, shift) is not { } chord)
        {
            _refuse("This key cannot be part of a shortcut.");
            StopRecording();
            return;
        }
        _ = TryAssign(s, chord);
    }

    private async Task TryAssign(ShortcutDto s, string chord)
    {
        _recording = null;
        try
        {
            var shown = Chords.Display(chord);
            switch (_shortcuts.Conflict(s.Id, chord))
            {
                case null:
                    Change(() => _shortcuts.Set(s.Id, chord, replace: false));
                    return;
                case { CommandId: null } reserved:
                    _refuse($"Windows uses {shown} for {reserved.Label}, so it cannot be a shortcut.");
                    break;
                case { CommandId: { } other } taken when other != s.Id:
                    if (await _confirm($"{shown} is assigned to {taken.Label}", $"Use {shown} for {s.Label} and remove it from {taken.Label}?"))
                    {
                        Change(() => _shortcuts.Set(s.Id, chord, replace: true));
                        return;
                    }
                    break;
            }
        }
        catch (BastionException ex)
        {
            // The core says why (for example a chord without Ctrl or Alt, which would swallow typing).
            _refuse(ex.Message.StartsWith("invalid input: ", StringComparison.Ordinal) ? ex.Message["invalid input: ".Length..] : ex.Message);
        }
        Fill();
    }

    private void Change(Action change)
    {
        try { change(); }
        catch (BastionException ex) { _refuse(ex.Message); }
        _recording = null;
        Fill();
        _changed();
    }
}
