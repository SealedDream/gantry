using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace Bastion.Shell;

/// <summary>
/// Tags as removable tokens (property editor, kind <c>tags</c>). Enter or a comma in the box adds a tag; a token's
/// click (or Delete/Backspace while it has focus) removes it; Backspace in an empty box removes the last one. The value
/// goes to the core as the comma-separated list it parses; no tags reads as null, so the field inherits like an empty
/// text box.
/// </summary>
internal sealed partial class TagTokens : UserControl
{
    private const double TokenGlyphSize = 10;
    private readonly List<string> _tags = [];
    private readonly StackPanel _tokens = new() { Orientation = Orientation.Horizontal, Spacing = 4 };
    private readonly TextBox _entry = new() { PlaceholderText = "Add a tag", MinWidth = 120 };

    private readonly StackPanel _suggest = new() { Orientation = Orientation.Horizontal, Spacing = 8 };

    /// <summary>Every tag in the open library, offered while typing. Set by the main window.</summary>
    public static Func<IReadOnlyList<string>>? LibraryTags { get; set; }

    private const int MaxSuggestions = 6;

    public event EventHandler? Changed;

    public TagTokens(string header, string? value, string? placeholder)
    {
        foreach (var t in Split(value)) Add(t, raise: false);
        _suggest.Visibility = Visibility.Visible;
        if (_tags.Count == 0 && !string.IsNullOrEmpty(placeholder)) _entry.PlaceholderText = placeholder;
        AutomationProperties.SetName(_entry, "Add tag");
        _entry.KeyDown += OnEntryKey;
        _entry.TextChanged += (_, _) =>
        {
            ShowSuggestions();
            if (!_entry.Text.Contains(',')) return;
            var parts = _entry.Text.Split(',');
            foreach (var p in parts[..^1]) Add(p);
            _entry.Text = parts[^1].TrimStart();
            _entry.SelectionStart = _entry.Text.Length;
        };
        _entry.LostFocus += (_, _) => Commit();
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 4, Children = { _tokens, _entry } };
        Content = new StackPanel
        {
            Spacing = 4,
            Children =
            {
                Ui.Text(header, "BodyTextStyle"),
                new ScrollViewer { Content = row, HorizontalScrollMode = ScrollMode.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollMode = ScrollMode.Disabled },
                _suggest,
            },
        };
    }

    /// <summary>The tags as the core stores them, or null for none. Text still in the box counts as a tag.</summary>
    public string? Value
    {
        get
        {
            Commit();
            return _tags.Count == 0 ? null : string.Join(", ", _tags);
        }
    }

    public void Clear()
    {
        _tags.Clear();
        _tokens.Children.Clear();
        _entry.Text = "";
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Focus goes to the entry box (used when Apply reports a problem).</summary>
    public void FocusEntry() => _entry.Focus(FocusState.Programmatic);

    private static IEnumerable<string> Split(string? value) =>
        (value ?? "").Split(',').Select(t => t.Trim()).Where(t => t.Length > 0);

    private void Commit()
    {
        if (_entry.Text.Trim().Length == 0) return;
        Add(_entry.Text);
        _entry.Text = "";
    }

    /// <summary>Library tags that start with what is typed, as links; a click adds one.</summary>
    private void ShowSuggestions()
    {
        _suggest.Children.Clear();
        var typed = _entry.Text.Trim().ToLowerInvariant();
        if (typed.Length == 0 || typed.Contains(',') || LibraryTags is null) return;
        foreach (var s in LibraryTags().Where(t => t.StartsWith(typed, StringComparison.Ordinal) && t != typed && !_tags.Contains(t)).Take(MaxSuggestions))
        {
            var link = new HyperlinkButton { Content = s, Padding = new Thickness(4, 2, 4, 2), MinHeight = 24 };
            AutomationProperties.SetName(link, $"Add tag {s}");
            link.Click += (_, _) => { Add(s); _entry.Text = ""; _entry.Focus(FocusState.Keyboard); };
            _suggest.Children.Add(link);
        }
    }

    private void Add(string raw, bool raise = true)
    {
        var tag = raw.Trim().ToLowerInvariant();
        if (tag.Length == 0 || _tags.Contains(tag)) return;
        _tags.Add(tag);
        _tokens.Children.Add(Token(tag));
        if (raise) Changed?.Invoke(this, EventArgs.Empty);
    }

    private void Remove(string tag, Button token)
    {
        var index = _tokens.Children.IndexOf(token);
        _tags.Remove(tag);
        _tokens.Children.Remove(token);
        Changed?.Invoke(this, EventArgs.Empty);
        // Keep the keyboard on a neighbour so a run of removals needs no mouse.
        if (_tokens.Children.Count > 0) ((Control)_tokens.Children[Math.Clamp(index, 0, _tokens.Children.Count - 1)]).Focus(FocusState.Keyboard);
        else _entry.Focus(FocusState.Keyboard);
    }

    private Button Token(string tag)
    {
        var glyph = new FontIcon { Glyph = Ui.String("GlyphClose"), FontSize = TokenGlyphSize };
        var token = new Button
        {
            Content = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, Children = { new TextBlock { Text = tag }, glyph } },
            Padding = new Thickness(8, 2, 6, 2),
        };
        AutomationProperties.SetName(token, $"Remove tag {tag}");
        token.Click += (_, _) => Remove(tag, token);
        token.KeyDown += (_, e) =>
        {
            if (e.Key is not (Windows.System.VirtualKey.Delete or Windows.System.VirtualKey.Back)) return;
            e.Handled = true;
            Remove(tag, token);
        };
        return token;
    }

    private void OnEntryKey(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter && _entry.Text.Trim().Length > 0)
        {
            e.Handled = true; // Enter adds a tag here; it does not apply the dialog
            Commit();
        }
        else if (e.Key == Windows.System.VirtualKey.Back && _entry.Text.Length == 0 && _tags.Count > 0)
        {
            e.Handled = true;
            Remove(_tags[^1], (Button)_tokens.Children[^1]);
            _entry.Focus(FocusState.Keyboard);
        }
    }
}
