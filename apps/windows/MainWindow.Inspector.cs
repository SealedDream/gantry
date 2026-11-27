using Bastion.Shell.Interop;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Inspector sections at parity with apps/macos InspectorView: Network for SSH (jump hosts in connect order, the identity
// file and the placeholders an imported host still needs, Personal Overrides… for hosts imported from an OpenSSH config)
// and Notes, saved with the library as you type. Everything shown comes from the core (C ABI 17); nothing is a secret.
public sealed partial class MainWindow
{
    private static readonly TimeSpan NotesSaveDelay = TimeSpan.FromMilliseconds(600);

    private TextBox? _notesBox;
    private string? _notesFor;
    private string _notesSaved = "";
    private DispatcherQueueTimer? _notesTimer;

    /// <summary>Effective values of an imported host, or null (not imported, or the store could not be read).</summary>
    private SshEffectiveDto? ImportedEffective(ConnectionDto c)
    {
        try { return SshOverrides.Effective(SessionDataDir, _library, c.Id); }
        catch (BastionException) { return null; }
    }

    /// <summary>The value Connect uses, marked when the user's overrides or placeholder answers changed the config's.</summary>
    private static string Overridden(string? effective, string source) =>
        effective is null || effective == source ? source : $"{effective} (your override)";

    /// <summary>Network: where the connection really goes, and the personal overrides of an imported host.</summary>
    private void AddNetworkSection(ConnectionDto c, SshEffectiveDto? effective)
    {
        string hops;
        if (effective is { Unresolved.Count: > 0 }) hops = "Known once the placeholders are answered";
        else
        {
            try
            {
                var list = Sessions.JumpHosts(_library, c.Id);
                hops = list.Count == 0 ? "None" : string.Join(" → ", list.Select(h => $"{h.Username}@{h.Key}"));
            }
            catch (BastionException ex) { hops = "Cannot resolve: " + ex.Message; }
        }
        var rows = new List<(string, string)> { ("Jump hosts", hops) };
        if (effective?.IdentityFile is { Length: > 0 } key) rows.Add(("Identity", key));
        AddSection("Network", rows.ToArray());
        if (c.SourceStatus == "removed-from-source") InspectorBody.Children.Add(Notice("No longer in the SSH config"));
        if (effective is { Unresolved.Count: > 0 } e) InspectorBody.Children.Add(Notice("Needs " + string.Join(", ", e.Unresolved.Select(p => $"<{p}>"))));
        if (effective is null) return;
        var overrides = new Button { Content = "Personal Overrides…", Margin = Ui.Thickness("InspectorButtonMargin") };
        AutomationProperties.SetName(overrides, "Personal Overrides");
        ToolTipService.SetToolTip(overrides, "Your own values for this imported host, kept apart from the SSH config");
        overrides.Click += (_, _) => _ = OverridesAsync(c, effective);
        InspectorBody.Children.Add(overrides);
    }

    private static TextBlock Notice(string text)
    {
        var t = Ui.Text(text, "CaptionTextStyle");
        t.TextWrapping = TextWrapping.Wrap;
        t.Margin = Ui.Thickness("InspectorButtonMargin");
        return t;
    }

    /// <summary>Notes: free text saved with the connection a moment after typing stops, and when the inspector changes.</summary>
    private void AddNotesSection(ConnectionDto c)
    {
        string text;
        try { text = _library.Notes(c.Id); }
        catch (BastionException) { text = ""; }
        var header = Ui.Text("Notes", "SectionHeaderTextStyle");
        header.Margin = Ui.Thickness("InspectorSectionMargin");
        AutomationProperties.SetHeadingLevel(header, AutomationHeadingLevel.Level3);
        InspectorBody.Children.Add(header);
        // AcceptsReturn before Text: a TextBox that is still single-line cuts the text at the first line break, and the
        // autosave would then store the cut text.
        var box = new TextBox { AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = Ui.Double("NotesMinHeight"), PlaceholderText = "Add notes for this connection" };
        box.Text = ToBoxLines(text);
        AutomationProperties.SetName(box, "Notes");
        box.TextChanged += (_, _) => { _notesTimer?.Stop(); _notesTimer?.Start(); };
        box.LostFocus += (_, _) => SaveNotes();
        InspectorBody.Children.Add(box);
        (_notesBox, _notesFor, _notesSaved) = (box, c.Id, text);
        if (_notesTimer is not null) return;
        _notesTimer = DispatcherQueue.CreateTimer();
        _notesTimer.Interval = NotesSaveDelay;
        _notesTimer.IsRepeating = false;
        _notesTimer.Tick += (_, _) => SaveNotes();
    }

    /// <summary>Write pending notes; also called before the inspector is rebuilt, so switching rows never loses typing.</summary>
    private void SaveNotes()
    {
        _notesTimer?.Stop();
        if (_notesBox is not { } box || _notesFor is not { } id || FromBoxLines(box.Text) == _notesSaved) return;
        try
        {
            var text = FromBoxLines(box.Text);
            _library.SetNotes(id, text);
            SaveLibrary();
            _notesSaved = text;
        }
        catch (BastionException ex)
        {
            _ = ShowModal("Could not save the notes", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null);
        }
    }

    /// <summary>
    /// The library keeps line breaks as \n (as macOS writes them); a WinUI TextBox uses \r, so notes are converted on
    /// the way in and out and the file means the same on both systems.
    /// </summary>
    private static string ToBoxLines(string text) => text.Replace("\r\n", "\r").Replace('\n', '\r');

    private static string FromBoxLines(string text) => text.Replace("\r\n", "\n").Replace('\r', '\n');

    /// <summary>Save what the previous inspector's notes box held, then forget it.</summary>
    private void ReleaseNotes()
    {
        SaveNotes();
        (_notesBox, _notesFor) = (null, null);
    }

    /// <summary>Personal Overrides…: the user's own values for an imported host, as on macOS (OverridesSheet).</summary>
    private async Task OverridesAsync(ConnectionDto c, SshEffectiveDto effective)
    {
        if (_modal is not null) return;
        SshOverrideDto current;
        try { current = SshOverrides.Get(SessionDataDir, effective.Identity); }
        catch (BastionException ex) { await ShowModal("Personal Overrides", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }
        var form = _overridesForm = new OverridesForm(effective, current);
        bool Save()
        {
            if (form.Validate() is not { } value) return false;
            try
            {
                SshOverrides.Set(SessionDataDir, effective.Identity, value);
                return true;
            }
            catch (BastionException ex)
            {
                form.ShowError(ex.Message);
                return false;
            }
        }
        if (!await ShowModal($"Overrides for {c.Name}", form.Body, primary: "Save", cancel: "Cancel", validate: Save, focus: form.FirstField, wide: true)) return;
        UpdateInspector(Selected);
        Announce("Overrides saved");
    }

    // ---- Snapshot hooks (BASTION_SNAPSHOT_TREE) ----

    private OverridesForm? _overridesForm;

    /// <summary>Snapshot only: type into the Notes box and save as the timer would.</summary>
    internal void SetNotesForSnapshot(string text)
    {
        if (_notesBox is null) throw new InvalidOperationException("no notes box in the inspector");
        _notesBox.Text = ToBoxLines(text);
        SaveNotes();
    }

    internal string JumpHostsForSnapshot(string name)
    {
        try { return string.Join(" → ", Sessions.JumpHosts(_library, LibraryItemForSnapshot(name).Id).Select(h => $"{h.Username}@{h.Key}")); }
        catch (BastionException ex) { return "error: " + ex.Message; }
    }

    internal string NotesForSnapshot(string name) => _library.Notes(LibraryItemForSnapshot(name).Id);

    /// <summary>Snapshot only: the effective host, port and user of an imported connection.</summary>
    internal string EffectiveForSnapshot(string name) =>
        SshOverrides.Effective(SessionDataDir, _library, LibraryItemForSnapshot(name).Id) is { } e
            ? $"{e.User}@{e.Hostname}:{e.Port?.ToString() ?? "22"}, unresolved [{string.Join(", ", e.Unresolved)}]"
            : "not imported";

    /// <summary>Snapshot only: open Personal Overrides… for an imported connection.</summary>
    internal void OpenOverridesForSnapshot(string name)
    {
        var c = LibraryItemForSnapshot(name).Connection ?? throw new InvalidOperationException(name + " is not a connection");
        var e = SshOverrides.Effective(SessionDataDir, _library, c.Id) ?? throw new InvalidOperationException(name + " is not imported");
        _ = OverridesAsync(c, e);
    }

    internal void SetOverrideFieldForSnapshot(string header, string value) => _overridesForm?.Set(header, value);
}

/// <summary>The Personal Overrides dialog body: each field shows the config's value as its placeholder.</summary>
internal sealed class OverridesForm
{
    private readonly TextBox _user, _hostname, _port, _identityFile, _proxyJump, _credentialRef;
    private readonly Dictionary<string, TextBox> _answers = new();
    private readonly FieldMessage _error = new();

    public StackPanel Body { get; }
    public Control FirstField => _user;

    public OverridesForm(SshEffectiveDto effective, SshOverrideDto current)
    {
        TextBox Field(string header, string? value, string placeholder)
        {
            var t = new TextBox { Header = header, Text = value ?? "", PlaceholderText = placeholder, IsSpellCheckEnabled = false };
            t.TextChanged += (_, _) => _error.Hide();
            return t;
        }
        _user = Field("User", current.User, effective.User ?? "from config");
        _hostname = Field("HostName", current.Hostname, effective.Hostname);
        _port = Field("Port", current.Port?.ToString(), effective.Port?.ToString() ?? "22");
        _identityFile = Field("IdentityFile", current.IdentityFile, effective.IdentityFile ?? "none");
        _proxyJump = Field("ProxyJump", current.ProxyJump, effective.ProxyJump ?? "none");
        _credentialRef = Field("Credential reference", current.CredentialRef, "provider:item");
        var grid = new Grid { ColumnSpacing = Ui.Double("Space12"), RowSpacing = Ui.Double("Space8"), ColumnDefinitions = { new ColumnDefinition(), new ColumnDefinition() } };
        var fields = new[] { _user, _hostname, _port, _identityFile, _proxyJump, _credentialRef };
        for (var i = 0; i < fields.Length; i++)
        {
            if (i % 2 == 0) grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(fields[i], i / 2);
            Grid.SetColumn(fields[i], i % 2);
            grid.Children.Add(fields[i]);
        }
        var note = Ui.Text("Leave a field empty to use the value from the SSH config. Saved for you only, apart from the config files.", "CaptionSecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        Body = new StackPanel { Spacing = Ui.Double("Space12"), Children = { grid, note } };
        if (effective.SourcePlaceholders.Count > 0)
        {
            var answers = new StackPanel { Spacing = Ui.Double("Space8") };
            answers.Children.Add(Ui.Text("Placeholder values for this host", "SectionHeaderTextStyle"));
            foreach (var name in effective.SourcePlaceholders)
            {
                var box = Field($"<{name}>", current.Placeholders.GetValueOrDefault(name), "global value");
                _answers[name] = box;
                answers.Children.Add(box);
            }
            Body.Children.Add(answers);
        }
        Body.Children.Add(_error.Element);
    }

    /// <summary>The values to save, or null with the reason shown (only the port can be wrong here).</summary>
    public SshOverrideDto? Validate()
    {
        int? port = null;
        if (_port.Text.Trim() is { Length: > 0 } p)
        {
            if (!int.TryParse(p, out var n) || n is < 1 or > 65535)
            {
                ShowError("Port must be a number from 1 to 65535.");
                _port.Focus(FocusState.Programmatic);
                return null;
            }
            port = n;
        }
        return new SshOverrideDto(_user.Text, _hostname.Text, port, _identityFile.Text, _proxyJump.Text, _credentialRef.Text,
            _answers.ToDictionary(a => a.Key, a => a.Value.Text));
    }

    public void ShowError(string message) => _error.Show(message);

    /// <summary>Snapshot only: fill a field by its header.</summary>
    internal void Set(string header, string value) =>
        new[] { _user, _hostname, _port, _identityFile, _proxyJump, _credentialRef }.Concat(_answers.Values).First(t => (string)t.Header == header).Text = value;
}
