using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Bulk edit (packet B3-BULK-EDIT, Native Mac #1130 BulkEdit.swift): set one property on several selected connections.
/// The core lists the properties they all share (C ABI 126 <c>properties_for_selection</c>) and applies the change to all
/// of them or to none (<c>apply_to_selection</c>), with the same checks as the single editor.
/// </summary>
internal sealed class BulkEditForm
{
    /// <summary>Choice label for "inherit from the folder or type" (Mac: "Inherit").</summary>
    private const string InheritLabel = "Inherit";

    private readonly LibraryClient _library;
    private readonly IReadOnlyList<string> _ids;
    private readonly IReadOnlyList<SelectionPropertyDto> _props;
    private readonly ComboBox? _picker;
    private readonly TextBlock _now = Ui.Text("", "BodySecondaryTextStyle");
    private readonly TextBlock _help = Ui.Text("", "CaptionSecondaryTextStyle");
    private readonly ContentControl _editorHost = new() { HorizontalContentAlignment = HorizontalAlignment.Stretch, HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly FieldMessage _error = new();
    private Func<string?> _read = () => null;
    /// <summary>Set while Tags is chosen: tags are added and removed, never replaced, so other tags stay.</summary>
    private (TagTokens Add, TagTokens Remove)? _tags;

    public FrameworkElement Body { get; }
    public Control? FirstField => _picker;
    public bool HasProperties => _props.Count > 0;
    public string Title => $"Edit {_ids.Count} Connections";
    public string ApplyLabel => $"Apply to {_ids.Count}";

    public BulkEditForm(LibraryClient library, IReadOnlyList<string> ids)
    {
        _library = library;
        _ids = ids;
        _props = library.PropertiesForSelection(ids);
        _help.TextWrapping = TextWrapping.Wrap;

        var panel = new StackPanel { Spacing = Ui.Double("Space12"), MinWidth = 400 };
        if (_props.Count == 0)
        {
            var none = Ui.Text("These connections share no property that can be edited together.", "BodySecondaryTextStyle");
            none.TextWrapping = TextWrapping.Wrap;
            panel.Children.Add(none);
            Body = panel;
            return;
        }

        _picker = new ComboBox { Header = "Property", ItemsSource = _props.Select(p => p.Def.Label).ToList(), HorizontalAlignment = HorizontalAlignment.Stretch };
        AutomationProperties.SetName(_picker, "Property");
        _picker.SelectionChanged += (_, _) => ShowSelected();
        var nowRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { Ui.Text("Now", "BodyTextStyle"), _now } };
        AutomationProperties.SetAutomationId(_now, "bulk-edit-now"); // its Name stays the shown text
        panel.Children.Add(_picker);
        panel.Children.Add(nowRow);
        panel.Children.Add(_editorHost);
        panel.Children.Add(_help);
        panel.Children.Add(_error.Element);
        Body = panel;
        _picker.SelectedIndex = 0;
    }

    private SelectionPropertyDto? Selected => _picker is { SelectedIndex: >= 0 and var i } && i < _props.Count ? _props[i] : null;

    private void ShowSelected()
    {
        _error.Hide();
        if (Selected is not { } p) return;
        _now.Text = p.Mixed ? "Mixed" : p.Value ?? "Inherited";
        _help.Text = p.Def.Help;
        _help.Visibility = string.IsNullOrEmpty(p.Def.Help) ? Visibility.Collapsed : Visibility.Visible;
        var start = p.Mixed ? null : p.Value;
        _tags = null;
        if (p.Def.Key == "tags")
        {
            var add = new TagTokens("Add", null, null);
            var remove = new TagTokens("Remove", null, null);
            add.Changed += (_, _) => _error.Hide();
            remove.Changed += (_, _) => _error.Hide();
            AutomationProperties.SetName(add, "Add tags");
            AutomationProperties.SetName(remove, "Remove tags");
            _tags = (add, remove);
            _editorHost.Content = new StackPanel { Spacing = Ui.Double("Space8"), Children = { add, remove } };
        }
        else if (p.Def.Kind is "choice" or "toggle")
        {
            var options = new List<(string? Id, string Label)> { (null, InheritLabel) };
            if (p.Def.Kind == "toggle") { options.Add(("true", "On")); options.Add(("false", "Off")); }
            else options.AddRange((p.Def.Options ?? []).Select(o => ((string?)o.Id, o.Label)));
            var combo = new ComboBox { Header = "New value", ItemsSource = options.Select(o => o.Label).ToList(), HorizontalAlignment = HorizontalAlignment.Stretch };
            combo.SelectedIndex = Math.Max(0, options.FindIndex(o => o.Id == start));
            AutomationProperties.SetName(combo, "New value");
            _read = () => combo.SelectedIndex > 0 ? options[combo.SelectedIndex].Id : null;
            _editorHost.Content = combo;
        }
        else
        {
            var box = new TextBox { Header = "New value", PlaceholderText = "Empty: inherit", Text = start ?? "" };
            AutomationProperties.SetName(box, "New value");
            _read = () => string.IsNullOrWhiteSpace(box.Text) ? null : box.Text;
            _editorHost.Content = box;
        }
    }

    /// <summary>Apply the value to every selected connection, or to none; on a refusal the message shows and the dialog stays.</summary>
    public bool Apply()
    {
        if (Selected is not { } p) return false;
        try
        {
            if (_tags is var (add, remove))
            {
                var adds = TagQuery.Normalize((add.Value ?? "").Split(','));
                var removes = TagQuery.Normalize((remove.Value ?? "").Split(','));
                if (adds.Count > 0 || removes.Count > 0) _library.EditTagsOnSelection(_ids, adds, removes);
                return true;
            }
            _library.ApplyToSelection(_ids, p.Def.Key, _read());
            return true;
        }
        catch (BastionException ex)
        {
            _error.ShowCoded("APP", ex.Message);
            return false;
        }
    }
}
