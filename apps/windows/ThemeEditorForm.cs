using Bastion.Shell.Interop;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// Settings › Terminal › Edit themes. Pick a theme, duplicate a bundled one, edit a custom one's 18 colours
/// (foreground, background, 16 ANSI) with a live preview and the core's contrast warning, or delete it. Bundled
/// themes are read-only; every rule (bad colour, duplicate name, contrast) comes from the core store.
/// </summary>
internal sealed class ThemeEditorForm
{
    private static readonly string[] AnsiNames =
        ["Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White",
         "Bright black", "Bright red", "Bright green", "Bright yellow", "Bright blue", "Bright magenta", "Bright cyan", "Bright white"];

    private readonly Action _changed;
    private readonly ComboBox _picker = new() { HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly TextBox _name = new() { Header = "Name" };
    private readonly List<TextBox> _hex = [];
    private readonly List<Border> _swatches = [];
    private readonly Border _preview = new() { Padding = new Thickness(12), CornerRadius = new CornerRadius(4) };
    private readonly TextBlock _previewText = new() { FontFamily = new FontFamily("Cascadia Mono, Consolas"), Text = "user@host:~$ ls --color\nREADME.md  src/  Cargo.toml" };
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap };
    private readonly Button _duplicate = new() { Content = "Duplicate" };
    private readonly Button _save = new() { Content = "Save" };
    private readonly Button _delete = new() { Content = "Delete" };
    private List<TermThemeDto> _themes = [];
    private bool _loading;

    public StackPanel Body { get; } = new() { Spacing = Ui.Double("Space12") };
    public Control Field => _picker;

    public ThemeEditorForm(Action changed, string? select = null)
    {
        _changed = changed;
        AutomationProperties.SetName(_picker, "Theme");
        AutomationProperties.SetAutomationId(_picker, "theme-picker");
        AutomationProperties.SetAutomationId(_name, "theme-name");
        AutomationProperties.SetAutomationId(_duplicate, "theme-duplicate");
        AutomationProperties.SetAutomationId(_save, "theme-save");
        AutomationProperties.SetAutomationId(_delete, "theme-delete");
        AutomationProperties.SetAutomationId(_status, "theme-status");
        AutomationProperties.SetLiveSetting(_status, AutomationLiveSetting.Assertive);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { _duplicate, _save, _delete } };
        Body.Children.Add(_picker);
        Body.Children.Add(buttons);
        Body.Children.Add(_name);

        var grid = new Grid { ColumnSpacing = Ui.Double("Space12"), RowSpacing = Ui.Double("Space4") };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });
        for (var i = 0; i < 18; i++)
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var label = i == 0 ? "Foreground" : i == 1 ? "Background" : AnsiNames[i - 2];
            var swatch = new Border { Width = 20, Height = 20, CornerRadius = new CornerRadius(3), BorderThickness = new Thickness(1), BorderBrush = new SolidColorBrush(Colors.Gray) };
            var box = new TextBox { MaxLength = 7, PlaceholderText = "#rrggbb", Width = 120 };
            AutomationProperties.SetName(box, label + " colour");
            AutomationProperties.SetAutomationId(box, "theme-color-" + i);
            box.TextChanged += (_, _) => { if (!_loading) Refresh(); };
            var text = Ui.Text(label, "BodyTextStyle");
            text.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetRow(swatch, i); Grid.SetColumn(swatch, 0);
            Grid.SetRow(text, i); Grid.SetColumn(text, 1);
            Grid.SetRow(box, i); Grid.SetColumn(box, 2);
            grid.Children.Add(swatch); grid.Children.Add(text); grid.Children.Add(box);
            _swatches.Add(swatch); _hex.Add(box);
        }
        Body.Children.Add(grid);
        _preview.Child = _previewText;
        Body.Children.Add(_preview);
        Body.Children.Add(_status);

        _picker.SelectionChanged += (_, _) => { if (!_loading) LoadSelected(); };
        _duplicate.Click += (_, _) => Run(Duplicate);
        _save.Click += (_, _) => Run(Save);
        _delete.Click += (_, _) => Run(Delete);
        Reload(select);
    }

    /// <summary>Snapshot runs only: press a button or type a colour the way a user would.</summary>
    internal void ClickForSnapshot(string which) => Run(which switch { "duplicate" => Duplicate, "save" => Save, "delete" => Delete, _ => throw new ArgumentException(which) });
    internal void SetColorForSnapshot(int index, string hex) => _hex[index].Text = hex;
    internal string StatusForSnapshot => _status.Text;
    internal string SelectedNameForSnapshot => Selected.Name;

    private TermThemeDto Selected => _themes[Math.Max(0, _picker.SelectedIndex)];

    private void Reload(string? select)
    {
        _loading = true;
        try
        {
            _themes = TermThemes.List();
            _picker.ItemsSource = _themes.Select(t => t.Bundled ? t.Name : t.Name + " (custom)").ToList();
            var i = select is null ? 0 : _themes.FindIndex(t => t.Id == select);
            _picker.SelectedIndex = Math.Max(0, i);
        }
        finally { _loading = false; }
        LoadSelected();
    }

    private void LoadSelected()
    {
        var t = Selected;
        _loading = true;
        _name.Text = t.Name;
        _hex[0].Text = t.Foreground;
        _hex[1].Text = t.Background;
        for (var i = 0; i < 16; i++) _hex[i + 2].Text = i < t.Ansi.Count ? t.Ansi[i] : "";
        _loading = false;
        foreach (var b in _hex) b.IsReadOnly = t.Bundled;
        _name.IsReadOnly = t.Bundled;
        _save.IsEnabled = !t.Bundled;
        _delete.IsEnabled = !t.Bundled;
        Refresh();
        Say(t.Bundled ? "Bundled theme: duplicate it to change the colours." : "");
    }

    private void Refresh()
    {
        for (var i = 0; i < _hex.Count; i++)
        {
            _swatches[i].Background = TryColor(_hex[i].Text) is { } c ? new SolidColorBrush(c) : null;
        }
        if (TryColor(_hex[0].Text) is { } fg) _previewText.Foreground = new SolidColorBrush(fg);
        if (TryColor(_hex[1].Text) is { } bg) _preview.Background = new SolidColorBrush(bg);
    }

    private void Duplicate()
    {
        var copy = TermThemes.Duplicate(Selected.Id);
        _changed();
        Reload(copy.Id);
        Say("Duplicated as " + copy.Name + ".");
    }

    private void Delete()
    {
        var name = Selected.Name;
        TermThemes.Remove(Selected.Id);
        _changed();
        Reload(null);
        Say("Deleted " + name + ".");
    }

    private void Save()
    {
        var t = Selected;
        var edited = t with { Name = _name.Text.Trim(), Foreground = _hex[0].Text.Trim(), Background = _hex[1].Text.Trim(), Ansi = _hex.Skip(2).Select(b => b.Text.Trim()).ToList() };
        var warning = TermThemes.Put(edited);
        _changed();
        Reload(t.Id);
        Say(warning is null ? "Saved." : "Saved. " + warning);
    }

    private void Run(Action action)
    {
        try { action(); }
        catch (BastionException ex) { Say(ex.Message); }
    }

    private void Say(string text)
    {
        _status.Text = text;
        AutomationProperties.SetName(_status, text);
    }

    private static Windows.UI.Color? TryColor(string text)
    {
        var s = text.Trim();
        if (s.Length != 7 || s[0] != '#' || !int.TryParse(s.AsSpan(1), System.Globalization.NumberStyles.HexNumber, null, out var v)) return null;
        return Windows.UI.Color.FromArgb(255, (byte)(v >> 16), (byte)(v >> 8), (byte)v);
    }
}
