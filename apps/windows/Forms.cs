using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// An inline validation message under a field: an error glyph and a caption in the critical colour (styles from
/// Themes/Tokens.xaml, so it follows the element's theme). Screen readers hear it as an assertive live region.
/// </summary>
internal sealed class FieldMessage
{
    private readonly TextBlock _text;

    public FrameworkElement Element { get; }

    public FieldMessage()
    {
        _text = new TextBlock { Style = Ui.Style("FieldErrorTextStyle"), TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetLiveSetting(_text, AutomationLiveSetting.Assertive);
        var icon = new FontIcon { Style = Ui.Style("FieldErrorIconStyle"), Glyph = (string)Application.Current.Resources["GlyphError"] };
        AutomationProperties.SetAccessibilityView(icon, AccessibilityView.Raw);
        // A Grid, not a horizontal StackPanel: a stack gives its children unbounded width, so a long message
        // would run past the dialog instead of wrapping under itself.
        var grid = new Grid
        {
            ColumnSpacing = Ui.Double("Space4"),
            Margin = Ui.Thickness("FieldMessageMargin"),
            Visibility = Visibility.Collapsed,
        };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        icon.VerticalAlignment = VerticalAlignment.Top;
        Grid.SetColumn(_text, 1);
        grid.Children.Add(icon);
        grid.Children.Add(_text);
        Element = grid;
    }

    public string Text => _text.Text;

    public void Show(string message)
    {
        _text.Text = message;
        Element.Visibility = Visibility.Visible;
        (FrameworkElementAutomationPeer.FromElement(_text) ?? FrameworkElementAutomationPeer.CreatePeerForElement(_text))
            ?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
    }

    /// <summary>An error from a failed call: the message with its support code (LOG-ERRCODES), also logged.</summary>
    public void ShowCoded(string area, string message)
    {
        var code = ErrorCodes.Code(area, message);
        AppLog.Failure(code, message);
        Show(message + "\n" + code);
    }

    public void Hide() => Element.Visibility = Visibility.Collapsed;
}

/// <summary>The "New folder" dialog body: one field, validated for an empty name and for a duplicate in the same parent.</summary>
internal sealed class NewFolderForm
{
    private readonly TextBox _name = new() { Header = "Folder name", PlaceholderText = "Customer, site or environment", IsSpellCheckEnabled = false };
    private readonly FieldMessage _error = new();
    private readonly List<string> _siblings;
    private readonly string? _parentName;

    public StackPanel Body { get; }
    public Control Field => _name;
    public string FolderName => _name.Text.Trim();

    /// <param name="siblingFolderNames">Folders already in the destination.</param>
    /// <param name="parentName">The destination folder, or null for the library root.</param>
    public NewFolderForm(IEnumerable<string> siblingFolderNames, string? parentName)
    {
        _siblings = siblingFolderNames.ToList();
        _parentName = parentName;
        Body = new StackPanel { Children = { _name, _error.Element } };
        _name.TextChanged += (_, _) => _error.Hide();
    }

    public string? Error => _error.Element.Visibility == Visibility.Visible ? _error.Text : null;

    /// <summary>True when the name can be used; otherwise shows the problem under the field and selects the text.</summary>
    public bool Validate()
    {
        var name = FolderName;
        string? problem = null;
        if (name.Length == 0) problem = "Enter a folder name.";
        else if (_siblings.Any(s => string.Equals(s.Trim(), name, StringComparison.OrdinalIgnoreCase)))
            problem = $"A folder named “{name}” already exists {(_parentName is null ? "at the top level" : "in " + _parentName)}.";
        if (problem is null)
        {
            _error.Hide();
            return true;
        }
        _error.Show(problem);
        _name.Focus(FocusState.Programmatic);
        _name.SelectAll();
        return false;
    }
}
