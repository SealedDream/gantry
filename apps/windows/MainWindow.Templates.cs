using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Connection templates (B9, docs/plans/B9-TEMPLATES.md): Save as Template (tree context menu), New from Template
// (palette and the compact New menu) and Templates (palette: edit and delete). Templates live outside the tree in
// the core, so none of these can connect. Labels are one line; explanations are tooltips.
public sealed partial class MainWindow
{
    internal async Task SaveAsTemplateAsync(TreeItem item)
    {
        if (_modal is not null) return;
        var form = new RenameForm(item.Name);
        ToolTipService.SetToolTip(form.Field, "Use $Token$ in the template's fields; New from Template asks for each one.");
        if (!await ShowModal("Save as template", form.Body, primary: "Save", cancel: "Cancel", validate: form.Validate, focus: form.Field)) return;
        await Mutate(() => { _library.SaveAsTemplate(item.Id, form.NewName); return item.Id; }, "Could not save the template");
        Announce("Template saved");
    }

    internal async Task NewFromTemplateAsync()
    {
        if (_modal is not null) return;
        var templates = _library.Templates();
        if (templates.Count == 0)
        {
            await ShowModal("New from template", ErrorText("No templates. Right-click a connection, then Save as template."), primary: "OK", cancel: null);
            return;
        }
        var parent = CurrentParent();
        var form = new NewFromTemplateForm(templates);
        string? created = null;
        bool Create()
        {
            if (!form.Validate()) return false;
            try
            {
                created = _library.NewFromTemplate(form.Template.Id, form.Values, parent?.Id);
                return true;
            }
            catch (BastionException ex)
            {
                form.ShowError(ex.Message);
                return false;
            }
        }
        if (!await ShowModal("New from template", form.Body, primary: "Create connection", cancel: "Cancel",
                caption: DestinationCaption(parent), validate: Create, focus: form.FirstField)) return;
        if (parent is not null) SaveExpanded(parent.Id, true);
        await Mutate(() => created, "Could not create the connection");
    }

    /// <summary>Snapshot runs: the Save as template dialog for a connection by name (the template is not saved).</summary>
    internal Task? SaveAsTemplateForSnapshot(string name)
    {
        static TreeItem? Find(IEnumerable<TreeItem> items, string name) =>
            items.Select(i => i.Name == name && !i.IsFolder ? i : Find(i.Children, name)).FirstOrDefault(i => i is not null);
        return Find(_roots, name) is { } item ? SaveAsTemplateAsync(item) : null;
    }

    /// <summary>Snapshot runs: one template with three tokens (Host, Port, Customer), so New from template and Templates have
    /// content. The source is an SSH connection, so the host is a plain name: core refuses a URL on any type but web.</summary>
    internal void SeedTemplateForSnapshot(string connectionName)
    {
        static TreeItem? Find(IEnumerable<TreeItem> items, string name) =>
            items.Select(i => i.Name == name && !i.IsFolder ? i : Find(i.Children, name)).FirstOrDefault(i => i is not null);
        if (Find(_roots, connectionName) is not { } item || _library.Templates().Count > 0) return;
        var id = _library.SaveAsTemplate(item.Id, "Web console");
        var t = _library.Templates().First(x => x.Id == id);
        _library.UpdateTemplate(id, "$Host$ console", "$Host$", "$Port$", t.Username, "Customer $Customer$");
    }

    internal async Task ManageTemplatesAsync()
    {
        if (_modal is not null) return;
        var form = new TemplatesForm(_library);
        await ShowModal("Templates", form.Body, primary: "Done", cancel: null, validate: form.SaveIfChanged, focus: form.List, wide: true);
        if (form.Changed) SaveLibrary();
    }
}

/// <summary>New from Template body: the template, then one field per token.</summary>
internal sealed class NewFromTemplateForm
{
    private readonly List<TemplateDto> _templates;
    private readonly ComboBox _picker;
    private readonly TextBlock _summary;
    private readonly StackPanel _fields = new() { Spacing = Ui.Double("Space8") };
    private readonly FieldMessage _error = new();
    private readonly Dictionary<string, TextBox> _boxes = new();

    public StackPanel Body { get; }
    public Control FirstField => _boxes.Values.FirstOrDefault() as Control ?? _picker;
    public TemplateDto Template => _templates[Math.Max(0, _picker.SelectedIndex)];
    public IReadOnlyDictionary<string, string> Values => _boxes.ToDictionary(kv => kv.Key, kv => kv.Value.Text.Trim());

    public NewFromTemplateForm(List<TemplateDto> templates)
    {
        _templates = templates;
        _picker = new ComboBox { Header = "Template", ItemsSource = templates.Select(t => t.Name).ToList(), SelectedIndex = 0, HorizontalAlignment = HorizontalAlignment.Stretch };
        _summary = new TextBlock { Style = Ui.Style("CaptionTextBlockStyle"), TextTrimming = TextTrimming.CharacterEllipsis };
        _picker.SelectionChanged += (_, _) => Build();
        Body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { _picker, _summary, _fields, _error.Element } };
        Build();
    }

    private void Build()
    {
        _error.Hide();
        _fields.Children.Clear();
        _boxes.Clear();
        var t = Template;
        _summary.Text = $"{t.Protocol.ToUpperInvariant()} · {t.Host}";
        ToolTipService.SetToolTip(_summary, t.Host);
        foreach (var token in t.Tokens)
        {
            var box = new TextBox { Header = token, IsSpellCheckEnabled = false };
            AutomationProperties.SetName(box, token);
            box.TextChanged += (_, _) => _error.Hide();
            _boxes[token] = box;
            _fields.Children.Add(box);
        }
    }

    public bool Validate()
    {
        var empty = _boxes.FirstOrDefault(kv => kv.Value.Text.Trim().Length == 0);
        if (empty.Value is null) return true;
        _error.Show($"Enter {empty.Key}.");
        empty.Value.Focus(FocusState.Programmatic);
        return false;
    }

    public void ShowError(string message) => _error.Show(message);
}

/// <summary>Templates body: the list, the selected template's token fields, Save and Delete.</summary>
internal sealed class TemplatesForm
{
    private readonly LibraryClient _library;
    private List<TemplateDto> _templates = [];
    private readonly TextBox _name = new() { Header = "Name", IsSpellCheckEnabled = false };
    private readonly TextBox _host = new() { Header = "Host", IsSpellCheckEnabled = false };
    private readonly TextBox _port = new() { Header = "Port", IsSpellCheckEnabled = false };
    private readonly TextBox _user = new() { Header = "User name", IsSpellCheckEnabled = false };
    private readonly TextBox _notes = new() { Header = "Notes" };
    private readonly FieldMessage _error = new();
    private readonly Button _save = new() { Content = "Save" };
    private readonly Button _delete = new() { Content = "Delete" };

    public ListView List { get; } = new() { SelectionMode = ListViewSelectionMode.Single, Height = 220 };
    public Grid Body { get; }
    public bool Changed { get; private set; }

    public TemplatesForm(LibraryClient library)
    {
        _library = library;
        ToolTipService.SetToolTip(_host, "Computer name or URL. $Token$ allowed.");
        ToolTipService.SetToolTip(_port, "Number or $Token$. Empty: protocol default.");
        AutomationProperties.SetName(List, "Templates");
        var fields = new StackPanel { Spacing = Ui.Double("Space8"), Children = { _name, _host, _port, _user, _notes, _error.Element,
            new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { _save, _delete } } } };
        Body = new Grid { ColumnSpacing = Ui.Double("Space16") };
        Body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
        Grid.SetColumn(fields, 1);
        Body.Children.Add(List);
        Body.Children.Add(fields);
        List.SelectionChanged += (_, _) => Load();
        _save.Click += (_, _) => Save();
        _delete.Click += (_, _) => Delete();
        Reload(null);
    }

    private TemplateDto? Selected => List.SelectedIndex >= 0 && List.SelectedIndex < _templates.Count ? _templates[List.SelectedIndex] : null;

    private void Reload(string? select)
    {
        _templates = _library.Templates();
        List.ItemsSource = _templates.Select(t => t.Name).ToList();
        var at = _templates.FindIndex(t => t.Id == select);
        List.SelectedIndex = _templates.Count == 0 ? -1 : Math.Max(0, at);
        Load();
    }

    private void Load()
    {
        _error.Hide();
        var t = Selected;
        foreach (var c in new Control[] { _name, _host, _port, _user, _notes, _save, _delete }) c.IsEnabled = t is not null;
        _name.Text = t?.Name ?? "";
        _host.Text = t?.Host ?? "";
        _port.Text = t?.Port ?? "";
        _user.Text = t?.Username ?? "";
        _notes.Text = t?.Notes ?? "";
    }

    private bool Dirty(TemplateDto t) =>
        _name.Text != t.Name || _host.Text != t.Host || _port.Text != (t.Port ?? "") || _user.Text != (t.Username ?? "") || _notes.Text != t.Notes;

    private bool Save()
    {
        if (Selected is not { } t) return true;
        try
        {
            _library.UpdateTemplate(t.Id, _name.Text.Trim(), _host.Text.Trim(), _port.Text.Trim(), _user.Text.Trim(), _notes.Text);
            Changed = true;
            Reload(t.Id);
            return true;
        }
        catch (BastionException ex)
        {
            _error.ShowCoded("APP", ex.Message);
            return false;
        }
    }

    private void Delete()
    {
        if (Selected is not { } t) return;
        try
        {
            _library.DeleteTemplate(t.Id);
            Changed = true;
            Reload(null);
        }
        catch (BastionException ex)
        {
            _error.ShowCoded("APP", ex.Message);
        }
    }

    /// <summary>Done: keep unsaved edits of the selected template, or stay open on an error.</summary>
    public bool SaveIfChanged() => Selected is not { } t || !Dirty(t) || Save();
}
