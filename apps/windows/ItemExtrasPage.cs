using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Bastion.Shell;

/// <summary>
/// The "Icon and properties" page of a connection's property editor (PARITY-01 rows 8 and 9; the Mac has the same
/// two parts): the item's own icon, picked from the core's icon names or left on the type icon, and free name/value
/// custom properties. Changes go through the core on Save or Apply; the core refuses unknown icons, bad names and
/// names that look like secrets, so these never hold a password.
/// </summary>
internal sealed class ItemExtrasPage
{
    public const string PageName = "Icon and properties";

    private readonly LibraryClient _library;
    private readonly string _id;
    private readonly ComboBox _icon;
    private readonly StackPanel _rows = new() { Spacing = 4 };
    private readonly FieldMessage _error = new();
    private string? _savedIcon;
    private IReadOnlyList<CustomPropertyRow> _saved;

    public FrameworkElement Body { get; }

    public ItemExtrasPage(LibraryClient library, string id, string? ownIcon)
    {
        _library = library;
        _id = id;
        _savedIcon = ownIcon;
        _saved = library.CustomProperties(id);

        _icon = new ComboBox { Header = "Icon", MinWidth = 200 };
        AutomationProperties.SetName(_icon, "Icon");
        AutomationProperties.SetHelpText(_icon, "Shown in the library tree instead of the type icon");
        _icon.Items.Add(new ComboBoxItem { Content = "Type icon", Tag = null });
        foreach (var name in LibraryClient.ConnectionIconNames())
        {
            var item = new ComboBoxItem { Content = IconRow(name), Tag = name };
            AutomationProperties.SetName(item, ItemExtrasEdits.IconLabel(name));
            _icon.Items.Add(item);
        }
        SelectIcon(ownIcon);

        var header = Ui.Text("Custom properties", "BodyStrongTextStyle");
        var add = new Button { Content = Ui.IconLabel(Ui.Icon("GlyphAdd"), "Add property") };
        AutomationProperties.SetName(add, "Add property");
        add.Click += (_, _) => AddRow(new CustomPropertyRow("", ""), focus: true);
        foreach (var row in _saved) AddRow(row, focus: false);

        Body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { _icon, header, _rows, add, _error.Element } };
    }

    private static FrameworkElement IconRow(string name) => new StackPanel
    {
        Orientation = Orientation.Horizontal,
        Spacing = 8,
        Children =
        {
            new FontIcon { Glyph = FluentIcons.Object(name), FontFamily = (FontFamily)Application.Current.Resources["SymbolFontFamily"], FontSize = Ui.Double("IconSize") },
            new TextBlock { Text = ItemExtrasEdits.IconLabel(name), VerticalAlignment = VerticalAlignment.Center },
        },
    };

    private void SelectIcon(string? name)
    {
        _icon.SelectedIndex = 0;
        for (var i = 1; i < _icon.Items.Count; i++)
        {
            if ((string?)((ComboBoxItem)_icon.Items[i]).Tag == name) _icon.SelectedIndex = i;
        }
    }

    private void AddRow(CustomPropertyRow row, bool focus)
    {
        var name = new TextBox { PlaceholderText = "Name", Text = row.Name, Width = 160 };
        var value = new TextBox { PlaceholderText = "Value", Text = row.Value, MinWidth = 160 };
        AutomationProperties.SetName(name, "Property name");
        AutomationProperties.SetName(value, "Property value");
        var remove = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphDelete", "IconSize") };
        AutomationProperties.SetName(remove, "Remove property");
        ToolTipService.SetToolTip(remove, "Remove property");
        var line = new Grid { ColumnSpacing = 8 };
        line.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        line.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        line.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetColumn(value, 1);
        Grid.SetColumn(remove, 2);
        line.Children.Add(name);
        line.Children.Add(value);
        line.Children.Add(remove);
        line.Tag = (name, value);
        remove.Click += (_, _) => _rows.Children.Remove(line);
        name.TextChanged += (_, _) => _error.Hide();
        _rows.Children.Add(line);
        if (focus) name.Focus(FocusState.Programmatic);
    }

    private List<CustomPropertyRow> Edited() =>
        _rows.Children.OfType<Grid>().Select(g => ((TextBox Name, TextBox Value))g.Tag).Select(t => new CustomPropertyRow(t.Name.Text, t.Value.Text)).ToList();

    /// <summary>Hand the changes to the core. False (with the message shown) when one is refused; nothing after it is applied.</summary>
    public bool Apply()
    {
        var icon = (string?)((ComboBoxItem?)_icon.SelectedItem)?.Tag;
        var (calls, error) = ItemExtrasEdits.Changes(_saved, Edited());
        if (error is not null)
        {
            _error.Show(error);
            return false;
        }
        try
        {
            if (icon != _savedIcon)
            {
                _library.SetIcon(_id, icon);
                _savedIcon = icon;
            }
            foreach (var (name, value) in calls) _library.SetCustomProperty(_id, name, value);
        }
        catch (BastionException ex)
        {
            _error.Show(ex.Message.StartsWith("invalid input: ", StringComparison.Ordinal) ? ex.Message["invalid input: ".Length..] : ex.Message);
            _saved = _library.CustomProperties(_id);
            return false;
        }
        _saved = _library.CustomProperties(_id);
        return true;
    }
}
