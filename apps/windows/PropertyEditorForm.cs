using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>What the property editor edits: one connection, a folder's Default Settings, or a type's.</summary>
internal abstract record EditorTarget
{
    public sealed record Connection(string Id, string Name, string Protocol, string? OwnIcon = null) : EditorTarget;
    public sealed record Folder(string Id, string Name) : EditorTarget;
    public sealed record Type(string Protocol, string Label) : EditorTarget;
}

/// <summary>
/// Schema-driven property editor, the Windows counterpart of apps/macos PropertyEditor.swift. The fields come from the
/// core, so only settings the core honours appear. Each field shows its own value; when it is empty the placeholder
/// shows the value that applies instead and the caption says where it comes from (folder, type default, built-in).
/// For defaults the caption lists the connections a value would reach. Save applies every change through the core,
/// which validates it; on the first refusal the earlier changes are rolled back and the message shows under the field.
/// </summary>
internal sealed class PropertyEditorForm
{
    private readonly LibraryClient _library;
    private readonly EditorTarget _target;
    private readonly List<Field> _fields = new();
    private readonly ListView _pages;
    private readonly TextBox _search;
    private readonly TextBlock _noMatch;
    /// <summary>Icon and custom properties (connections only).</summary>
    private readonly ItemExtrasPage? _extras;
    private readonly PluginEntryPage? _plugin;

    /// <summary>
    /// One editor row: a text box, or for <c>choice</c> a combo box and for <c>toggle</c> a switch (core kinds). <c>Row</c> is
    /// what the page list and search show or hide; <c>Overridden</c> holds the badge and Reset link, shown while the row has its own value.
    /// </summary>
    private sealed record Field(PropertyDefDto Def, Control Control, Func<string?> Read, FieldMessage Error, string? Own,
        FrameworkElement Row, FrameworkElement Overridden, InheritFlag Inherit);

    /// <summary>Set by Reset on a combo box or switch (which cannot show "empty"); cleared when the user changes the control again.</summary>
    private sealed class InheritFlag { public bool On; }

    public FrameworkElement Body { get; }
    public Control? FirstField => _search;

    /// <summary>Called after Apply saved the changes without closing, so the caller can save the library and refresh the tree.</summary>
    public Action? Applied { get; init; }

    /// <summary>W8 (Mac points 5, 16): a connection's Credentials page also takes the password. Called on Save/Apply with
    /// the user name and the typed password; it saves the password to the vault and assigns it, so connecting asks nothing.</summary>
    public Action<string, string>? SavePassword { get; init; }

    private PasswordBox? _password;
    private Func<string?>? _readUser;

    /// <param name="plugin">PVE-TLS: the installed type and data folder when the target is a plugin entry.</param>
    public PropertyEditorForm(LibraryClient library, EditorTarget target, IReadOnlyList<CredentialDto>? credentials = null,
        (PluginTypeDto Type, string DataDir)? plugin = null, Action? pluginRuleChanged = null,
        Func<string, int, Func<ProbeStepDto>?>? pluginLoginTest = null)
    {
        _library = library;
        _credentials = credentials ?? [];
        _target = target;
        var (defs, values) = target switch
        {
            EditorTarget.Connection c => (LibraryClient.PropertySchema(c.Protocol, false), library.PropertyValues(c.Id)),
            EditorTarget.Folder f => (LibraryClient.PropertySchema(null, true), library.PropertyValues(f.Id)),
            EditorTarget.Type t => (LibraryClient.PropertySchema(t.Protocol, true), library.TypeDefaultValues(t.Protocol)),
            _ => throw new ArgumentOutOfRangeException(nameof(target)),
        };
        var byKey = values.ToDictionary(v => v.Key);

        var intro = target switch
        {
            EditorTarget.Folder => "Connections and sub-folders inside inherit these unless they set their own.",
            EditorTarget.Type t => $"Applies to every {t.Label} connection unless a folder or the connection sets its own.",
            _ => "Leave a field empty to inherit it.",
        };
        var introText = Ui.Text(intro, "BodySecondaryTextStyle");
        introText.TextWrapping = TextWrapping.Wrap;

        _search = new TextBox { PlaceholderText = "Search settings" };
        AutomationProperties.SetName(_search, "Search settings");
        _search.TextChanged += (_, _) => Filter();

        var list = new StackPanel { Spacing = Ui.Double("Space12") };
        var categories = new List<string>();
        foreach (var group in defs.GroupBy(PageOf))
        {
            categories.Add(group.Key);
            foreach (var def in group)
            {
                byKey.TryGetValue(def.Key, out var v);
                var error = new FieldMessage();
                var inherit = new InheritFlag { On = v?.Own is null && def.Kind is "choice" or "toggle" };
                var (control, read) = def.Kind switch
                {
                    "choice" => ChoiceField(def, v, error, inherit),
                    "toggle" => ToggleField(def, v, error, inherit),
                    "gateway" => GatewayField(def, v, error),
                    "credential" => CredentialField(def, v, error),
                    "terminaltheme" => ThemeField(def, v, error),
                    "tags" => TagsField(def, v, error),
                    _ => TextField(def, v, error),
                };
                AutomationProperties.SetName(control, def.Label);
                AutomationProperties.SetHelpText(control, def.Help);
                var caption = Ui.Text(Caption(def, v), "CaptionSecondaryTextStyle");
                caption.TextWrapping = TextWrapping.Wrap;
                var overridden = OverriddenRow(def, control, inherit);
                overridden.Visibility = v?.Own is null ? Visibility.Collapsed : Visibility.Visible;
                var row = new StackPanel { Spacing = 2, Children = { control, overridden, caption, error.Element } };
                if (def.Key == AlgorithmsKey && control is TextBox algorithms) row.Children.Insert(1, AlgorithmsPreview(algorithms, v));
                if (def.Key == "username" && target is EditorTarget.Connection)
                {
                    // Same row as the user name, so the page filter keeps them together and nothing typed is lost
                    // when switching pages (a hidden row keeps its value).
                    _password = new PasswordBox { Header = "Password", PlaceholderText = "Unchanged" };
                    AutomationProperties.SetName(_password, "Password");
                    AutomationProperties.SetHelpText(_password, "Saved encrypted in this library and used when connecting, so no password is asked.");
                    row.Children.Add(_password);
                    var note = Ui.Text("Saved encrypted in this library; connecting will not ask again.", "CaptionSecondaryTextStyle");
                    note.TextWrapping = TextWrapping.Wrap; // was clipped at the field width
                    row.Children.Add(note);
                    _readUser = read;
                }
                list.Children.Add(row);
                _fields.Add(new Field(def, control, () => inherit.On ? null : read(), error, v?.Own, row, overridden, inherit));
            }
        }

        if (target is EditorTarget.Connection pc && plugin is { } p)
        {
            _plugin = new PluginEntryPage(library, p.DataDir, pc.Id, p.Type)
            {
                Target = () => (FieldText("host") ?? "", int.TryParse(FieldText("port"), out var port) ? port : null),
                RuleChanged = pluginRuleChanged,
                LoginTest = pluginLoginTest,
            };
            categories.Insert(0, _plugin.PageName);
            list.Children.Insert(0, _plugin.Body);
        }

        if (target is EditorTarget.Connection conn)
        {
            _extras = new ItemExtrasPage(library, conn.Id, conn.OwnIcon);
            categories.Add(ItemExtrasPage.PageName);
            list.Children.Add(_extras.Body);
        }

        _pages = new ListView { ItemsSource = categories, SelectionMode = ListViewSelectionMode.Single, Width = 168 };
        AutomationProperties.SetName(_pages, "Setting pages");
        _pages.SelectionChanged += (_, _) => Filter();
        _noMatch = Ui.Text("No setting matches.", "BodySecondaryTextStyle");
        _noMatch.Visibility = Visibility.Collapsed;

        var fields = new ScrollViewer { Content = new StackPanel { Spacing = Ui.Double("Space12"), Children = { list, _noMatch } },
            MaxHeight = 420, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(0, 0, 12, 0) };
        var columns = new Grid { ColumnSpacing = Ui.Double("Space12") };
        columns.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        columns.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(fields, 1);
        columns.Children.Add(_pages);
        columns.Children.Add(fields);

        var apply = new Button { Content = "Apply" };
        AutomationProperties.SetHelpText(apply, "Save the changes and keep the dialog open");
        apply.Click += (_, _) =>
        {
            if (!Apply()) return;
            Applied?.Invoke();
            Refresh();
        };

        Body = new StackPanel { Spacing = Ui.Double("Space8"), Children = { introText, _search, columns, apply } };
        _pages.SelectedIndex = categories.Count > 0 ? 0 : -1;
    }

    /// <summary>Page title for the Fonts page (E2, same as Native Mac #1129).</summary>
    internal const string FontsPage = "Fonts";

    /// <summary>The page a setting is shown on: its core category, except the terminal font settings, which get their own
    /// Fonts page beside Terminal (Mac <c>EditorPage.pageId</c>). Only types that have them (SSH, Telnet, Local) show it.</summary>
    internal static string PageOf(PropertyDefDto def) => def.Key switch
    {
        "terminal_font_family" or "terminal_font_size" or "terminal_ligatures" => FontsPage,
        _ => def.Category,
    };

    /// <summary>"Overridden" and a Reset link that empties the field, so Save or Apply hands the key back to inheritance.</summary>
    private static FrameworkElement OverriddenRow(PropertyDefDto def, Control control, InheritFlag inherit)
    {
        var badge = Ui.Text("Overridden", "CaptionTextStyle");
        var reset = new HyperlinkButton { Content = "Reset", Padding = new Thickness(4, 0, 4, 0) };
        AutomationProperties.SetName(reset, $"Reset {def.Label}");
        var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 4, Children = { badge, reset } };
        reset.Click += (_, _) =>
        {
            if (control is TextBox box) box.Text = "";
            else if (control is TagTokens tags) tags.Clear();
            else if (control is ComboBox combo && def.Kind is "gateway" or "terminaltheme" or "credential") combo.SelectedIndex = 0;
            else if (control is ComboBox { IsEditable: true } free) { free.SelectedIndex = -1; free.Text = ""; }
            inherit.On = control is not (TextBox or TagTokens) && def.Kind is not ("gateway" or "terminaltheme" or "credential");
            panel.Visibility = Visibility.Collapsed;
        };
        return panel;
    }

    /// <summary>The text field <paramref name="key"/> holds now (saved or typed), or null.</summary>
    private string? FieldText(string key) =>
        _fields.FirstOrDefault(f => f.Def.Key == key) is { } f && f.Read() is { Length: > 0 } t ? t.Trim() : null;

    /// <summary>With search text, every matching setting from all pages; otherwise the selected page.</summary>
    private void Filter()
    {
        var query = _search.Text.Trim();
        var page = _pages.SelectedItem as string;
        var shown = 0;
        foreach (var f in _fields)
        {
            var visible = query.Length > 0
                ? f.Def.Label.Contains(query, StringComparison.OrdinalIgnoreCase) || f.Def.Help.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || f.Def.Key.Contains(query, StringComparison.OrdinalIgnoreCase)
                : PageOf(f.Def) == page;
            f.Row.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            if (visible) shown++;
        }
        if (_plugin is not null)
        {
            var visible = query.Length > 0
                ? "certificate tls test".Contains(query, StringComparison.OrdinalIgnoreCase)
                : page == _plugin.PageName;
            _plugin.Body.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            if (visible) shown++;
        }
        if (_extras is not null)
        {
            var visible = query.Length > 0
                ? "icon custom properties".Contains(query, StringComparison.OrdinalIgnoreCase)
                : page == ItemExtrasPage.PageName;
            _extras.Body.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            if (visible) shown++;
        }
        _pages.Opacity = query.Length > 0 ? 0.5 : 1;
        _noMatch.Visibility = shown == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>After Apply: the saved values become each field's own value, so Unchanged and the badges start from them.</summary>
    private void Refresh()
    {
        for (var i = 0; i < _fields.Count; i++)
        {
            var f = _fields[i];
            var own = f.Read();
            f.Inherit.On = false;
            f.Overridden.Visibility = own is null ? Visibility.Collapsed : Visibility.Visible;
            _fields[i] = f with { Own = own };
        }
    }

    private static (Control, Func<string?>) TextField(PropertyDefDto def, PropertyValueDto? v, FieldMessage error)
    {
        var multi = def.Kind == "multiline";
        var box = new TextBox
        {
            Header = def.Label,
            Text = v?.Own ?? "",
            PlaceholderText = v?.Own is null && v?.Effective is { } eff ? eff : "",
            IsSpellCheckEnabled = multi,
            AcceptsReturn = multi,
            TextWrapping = multi ? TextWrapping.Wrap : TextWrapping.NoWrap,
            Height = multi ? 96 : double.NaN,
            InputScope = def.Kind is "port" or "seconds" ? NumberScope() : null,
        };
        box.TextChanged += (_, _) => error.Hide();
        return (box, () => Normal(box.Text));
    }

    private const string AlgorithmsKey = "ssh_algorithms";

    /// <summary>Advanced › Algorithms: what the connection would offer (C ABI 33 preview), updated as the user types.</summary>
    private static TextBlock AlgorithmsPreview(TextBox box, PropertyValueDto? v)
    {
        var preview = Ui.Text("", "CaptionSecondaryTextStyle");
        preview.TextWrapping = TextWrapping.Wrap;
        preview.IsTextSelectionEnabled = true;
        AutomationProperties.SetName(preview, "Algorithms preview");
        void Update()
        {
            preview.Text = AlgorithmPreviewText(Normal(box.Text) ?? v?.Effective);
            AutomationProperties.SetHelpText(preview, preview.Text); // the name is fixed, so screen readers and tests read the lists here
        }
        box.TextChanged += (_, _) => Update();
        Update();
        return preview;
    }

    internal static string AlgorithmPreviewText(string? settingsJson)
    {
        AlgorithmPreviewDto p;
        try { p = LibraryClient.AlgorithmPreview(settingsJson); }
        catch (BastionException ex) { return "Preview unavailable: " + ex.Message; }
        if (p.Error is { } err) return "Not usable: " + err;
        var lines = new List<string>
        {
            "Key exchange: " + string.Join(", ", p.Kex),
            "Ciphers: " + string.Join(", ", p.Ciphers),
            "MACs: " + string.Join(", ", p.Macs),
            "Host keys: " + string.Join(", ", p.HostKeys),
        };
        if (p.WeakEnabled.Count > 0) lines.Add("Weak, allowed for this host: " + string.Join(", ", p.WeakEnabled));
        if (p.ForbidWeak) lines.Add("Policy forbids weak algorithms.");
        lines.AddRange(p.Warnings);
        return string.Join("\n", lines);
    }

    /// <summary>Tags as tokens; the inherited tags show as the placeholder while the connection has none of its own.</summary>
    private static (Control, Func<string?>) TagsField(PropertyDefDto def, PropertyValueDto? v, FieldMessage error)
    {
        var placeholder = v?.Own is null && v?.Effective is { } eff ? eff : null;
        var tags = new TagTokens(def.Label, v?.Own, placeholder);
        tags.Changed += (_, _) => error.Hide();
        return (tags, () => tags.Value);
    }

    /// <summary>A fixed list from the core (Environment); the stored id goes back unchanged.</summary>
    private static (Control, Func<string?>) ChoiceField(PropertyDefDto def, PropertyValueDto? v, FieldMessage error, InheritFlag inherit)
    {
        var options = def.Key == LocalShells.ShellKey
            ? LocalShells.Options(LocalShells.Distros(), includeHidden: false, v?.Own ?? v?.Effective).Select(o => new PropertyOptionDto(o.Id, o.Label)).ToList()
            : def.Options ?? [];
        var combo = new ComboBox { Header = def.Label, ItemsSource = options.Select(o => o.Label).ToList(), HorizontalAlignment = HorizontalAlignment.Stretch };
        combo.SelectedIndex = options.FindIndex(o => o.Id == (v?.Own ?? v?.Effective));
        combo.SelectionChanged += (_, _) => { error.Hide(); inherit.On = false; };
        if (def.Key == HostColorKey) return FreeChoice(combo, options, v, error, inherit);
        return (combo, () => combo.SelectedIndex >= 0 ? options[combo.SelectedIndex].Id : v?.Own);
    }

    private const string HostColorKey = "host_color";

    /// <summary>
    /// Host colour: the presets plus a free <c>#rrggbb</c> typed in the box; the core validates and normalises it. The box
    /// decides inheritance itself (UI Automation can type without raising a selection event): left showing the inherited
    /// colour, or emptied (Reset), it stores nothing.
    /// </summary>
    private static (Control, Func<string?>) FreeChoice(ComboBox combo, IReadOnlyList<PropertyOptionDto> options, PropertyValueDto? v, FieldMessage error, InheritFlag inherit)
    {
        combo.IsEditable = true;
        inherit.On = false;
        if (combo.SelectedIndex < 0 && (v?.Own ?? v?.Effective) is { } shown) combo.Text = shown;
        string Id(string typed) => options.FirstOrDefault(o => o.Label.Equals(typed, StringComparison.OrdinalIgnoreCase) || o.Id.Equals(typed, StringComparison.OrdinalIgnoreCase))?.Id ?? typed;
        combo.TextSubmitted += (_, _) => error.Hide();
        return (combo, () =>
        {
            var typed = combo.Text?.Trim() ?? "";
            if (typed.Length == 0) return null;
            var id = Id(typed);
            return v?.Own is null && string.Equals(id, v?.Effective, StringComparison.OrdinalIgnoreCase) ? null : id;
        });
    }

    /// <summary>
    /// The library's gateways by name, first "None": empty inherits (or means direct), as for any text field. The stored id goes
    /// back unchanged; a reference to a gateway that no longer exists is shown as such and left for the user to change.
    /// </summary>
    private readonly IReadOnlyList<CredentialDto> _credentials;

    /// <summary>
    /// Vault credentials by name, first "Inherit (name)" or "None": empty means the nearest folder's credential, as in
    /// Royal TS. With the vault locked the names are unknown; a stored id is kept and shown as "Locked credential".
    /// </summary>
    private (Control, Func<string?>) CredentialField(PropertyDefDto def, PropertyValueDto? v, FieldMessage error)
    {
        string Name(string id) => _credentials.FirstOrDefault(c => c.Id == id)?.Name ?? "locked";
        var ids = new List<string?> { null };
        var labels = new List<string> { v?.Own is null && v?.Effective is { Length: > 0 } eff ? $"Inherit ({Name(eff)})" : "None" };
        foreach (var c in _credentials)
        {
            ids.Add(c.Id);
            labels.Add(c.Name);
        }
        if (v?.Own is { } own && !ids.Contains(own))
        {
            ids.Add(own);
            labels.Add(_credentials.Count == 0 ? "Locked credential" : "Missing credential");
        }
        var combo = new ComboBox { Header = def.Label, ItemsSource = labels, HorizontalAlignment = HorizontalAlignment.Stretch, SelectedIndex = Math.Max(0, ids.IndexOf(v?.Own)) };
        combo.SelectionChanged += (_, _) => error.Hide();
        return (combo, () => combo.SelectedIndex > 0 ? ids[combo.SelectedIndex] : null);
    }

    private (Control, Func<string?>) GatewayField(PropertyDefDto def, PropertyValueDto? v, FieldMessage error)
    {
        IReadOnlyList<GatewayDto> gateways;
        try { gateways = _library.Gateways(); }
        catch (BastionException) { gateways = []; }
        var ids = new List<string?> { null };
        var labels = new List<string> { v?.Own is null && v?.Effective is { } eff ? $"Inherit ({GatewayLabel(gateways, eff)})" : "None" };
        foreach (var g in gateways)
        {
            ids.Add(g.Id);
            labels.Add($"{g.Name} ({g.Host}:{g.Port ?? 22})");
        }
        if (v?.Own is { } own && !ids.Contains(own))
        {
            ids.Add(own);
            labels.Add("Missing gateway");
        }
        var combo = new ComboBox { Header = def.Label, ItemsSource = labels, HorizontalAlignment = HorizontalAlignment.Stretch, SelectedIndex = Math.Max(0, ids.IndexOf(v?.Own)) };
        combo.SelectionChanged += (_, _) => error.Hide();
        return (combo, () => combo.SelectedIndex > 0 ? ids[combo.SelectedIndex] : null);
    }

    /// <summary>
    /// Terminal theme: the bundled and custom themes by name, first "App theme" (or "Inherited (name)" when a folder sets
    /// one), which stores nothing. An id whose theme was deleted is shown as such and kept until the user picks another.
    /// </summary>
    private static (Control, Func<string?>) ThemeField(PropertyDefDto def, PropertyValueDto? v, FieldMessage error)
    {
        List<(string Id, string Name)> themes;
        try { themes = TermThemes.List().Select(t => (t.Id, t.Name)).ToList(); }
        catch (BastionException) { themes = TerminalThemes.All.ToList(); }
        string Name(string id) => themes.FirstOrDefault(t => t.Id == id).Name ?? id;
        var ids = new List<string?> { null };
        var labels = new List<string> { v?.Own is null && v?.Effective is { Length: > 0 } eff ? $"Inherited ({Name(eff)})" : "App theme" };
        foreach (var (id, name) in themes) { ids.Add(id); labels.Add(name); }
        if (v?.Own is { Length: > 0 } own && !ids.Contains(own)) { ids.Add(own); labels.Add("Missing theme"); }
        var combo = new ComboBox { Header = def.Label, ItemsSource = labels, HorizontalAlignment = HorizontalAlignment.Stretch, SelectedIndex = Math.Max(0, ids.IndexOf(v?.Own)) };
        combo.SelectionChanged += (_, _) => error.Hide();
        return (combo, () => combo.SelectedIndex > 0 ? ids[combo.SelectedIndex] : null);
    }

    private static string GatewayLabel(IReadOnlyList<GatewayDto> gateways, string id) =>
        gateways.FirstOrDefault(g => g.Id == id)?.Name ?? "missing gateway";

    /// <summary>On or off, stored as <c>true</c> / <c>false</c> as the core parses it.</summary>
    private static (Control, Func<string?>) ToggleField(PropertyDefDto def, PropertyValueDto? v, FieldMessage error, InheritFlag inherit)
    {
        var toggle = new ToggleSwitch { Header = def.Label, IsOn = (v?.Own ?? v?.Effective) == "true" };
        toggle.Toggled += (_, _) => { error.Hide(); inherit.On = false; };
        return (toggle, () => toggle.IsOn ? "true" : "false");
    }

    private static Microsoft.UI.Xaml.Input.InputScope NumberScope() =>
        new() { Names = { new Microsoft.UI.Xaml.Input.InputScopeName(Microsoft.UI.Xaml.Input.InputScopeNameValue.Number) } };

    private string Caption(PropertyDefDto def, PropertyValueDto? v)
    {
        var parts = new List<string> { def.Help };
        if (v is not null && v.Own is null)
        {
            var from = v.Source switch
            {
                "inherited" => $"Inherited from {v.From}.",
                "typedefault" => $"From the {v.From?.ToUpperInvariant()} type defaults.",
                "builtin" => "Built-in value.",
                _ => null,
            };
            if (from is not null) parts.Add(from);
        }
        if (_target is EditorTarget.Folder or EditorTarget.Type)
        {
            try
            {
                var affected = _target is EditorTarget.Folder f ? _library.AffectedByDefault(f.Id, null, def.Key) : _library.AffectedByDefault(null, ((EditorTarget.Type)_target).Protocol, def.Key);
                parts.Add(affected.Count == 0 ? "No connection takes this value from here."
                    : $"Applies to {affected.Count}: {string.Join(", ", affected.Take(4))}{(affected.Count > 4 ? ", …" : "")}.");
            }
            catch (BastionException) { }
        }
        return string.Join(" ", parts);
    }

    /// <summary>A refused field may sit on another page or be hidden by search: clear the search and open its page.</summary>
    private void ShowRow(FrameworkElement row, PropertyDefDto def)
    {
        if (row.Visibility == Visibility.Visible) return;
        _search.Text = "";
        _pages.SelectedItem = PageOf(def);
        Filter();
    }

    private static string? Normal(string text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();

    private void Set(string key, string? value)
    {
        switch (_target)
        {
            case EditorTarget.Connection c: _library.SetProperty(c.Id, key, value); break;
            case EditorTarget.Folder f: _library.SetProperty(f.Id, key, value); break;
            case EditorTarget.Type t: _library.SetTypeDefault(t.Protocol, key, value); break;
        }
    }

    /// <summary>True when there is nothing to change.</summary>
    public bool Unchanged => _fields.All(f => f.Read() == Normal(f.Own ?? ""));

    /// <summary>
    /// Apply every changed field in memory. On the first refusal, undo the ones already applied, show the message
    /// under that field, focus it and return false (the dialog stays open). The caller saves the library.
    /// </summary>
    public bool Apply()
    {
        var done = new List<(string Key, string? Old)>();
        foreach (var (def, control, read, error, own, row, _, _) in _fields)
        {
            var value = read();
            if (value == Normal(own ?? "")) continue;
            try
            {
                Set(def.Key, value);
                done.Add((def.Key, own));
            }
            catch (BastionException ex)
            {
                foreach (var (key, old) in Enumerable.Reverse(done))
                {
                    try { Set(key, old); } catch (BastionException) { /* the old value was accepted before */ }
                }
                ShowRow(row, def);
                error.Show(ex.Message.StartsWith("invalid input: ", StringComparison.Ordinal) ? ex.Message["invalid input: ".Length..] : ex.Message);
                control.Focus(FocusState.Programmatic);
                if (control is TextBox box) box.SelectAll();
                else if (control is TagTokens tags) tags.FocusEntry();
                return false;
            }
        }
        if (_plugin is not null && !_plugin.Apply())
        {
            _pages.SelectedItem = _plugin.PageName;
            return false;
        }
        if (_extras is not null && !_extras.Apply())
        {
            _pages.SelectedItem = ItemExtrasPage.PageName;
            return false;
        }
        if (_password is { Password.Length: > 0 } typed && SavePassword is { } save)
        {
            var user = _readUser?.Invoke() ?? "";
            save(user, typed.Password);
            typed.Password = "";
        }
        return true;
    }
}
