using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// Settings › SSH › SSH config sources: which OpenSSH files are read, the shared-config placeholders, and a preview of
/// what changed in those files since the last import (added / changed / removed hosts) with a Refresh that applies it.
/// Removed hosts are marked, never deleted. All rules live in the core (sshworkflow).
/// </summary>
internal sealed class SshSourcesForm
{
    private readonly string _dir;
    private readonly LibraryClient _library;
    private readonly Action _changed;
    private readonly CheckBox _configD = new() { Content = "Scan config.d for files not included by config" };
    private readonly CheckBox _usePlaceholders = new() { Content = "Placeholders such as <user>" };
    private readonly CheckBox _overrides = new() { Content = "Personal overrides" };
    private readonly CheckBox _detect = new() { Content = "Detect changes after a manual pull" };
    private readonly TextBox _sshDir = new() { Header = "SSH directory", PlaceholderText = "Default: %USERPROFILE%\\.ssh" };
    private readonly CheckBox _importAdded = new() { Content = "Import new hosts when refreshing", IsChecked = true };
    private readonly StackPanel _placeholders = new() { Spacing = Ui.Double("Space4") };
    private readonly StackPanel _changes = new() { Spacing = Ui.Double("Space4") };
    private readonly TextBlock _lastSynced = Ui.Text("", "CaptionSecondaryTextStyle");
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap };
    private SshWorkflowSettings _settings = new(false, false, false, false, null);

    public StackPanel Body { get; } = new() { Spacing = Ui.Double("Space12") };
    public Control Field => _detect;

    public SshSourcesForm(string dataDir, LibraryClient library, Action changed)
    {
        _dir = dataDir; _library = library; _changed = changed;
        AutomationProperties.SetAutomationId(_configD, "ssh-configd");
        AutomationProperties.SetAutomationId(_detect, "ssh-detect");
        AutomationProperties.SetAutomationId(_usePlaceholders, "ssh-placeholders");
        AutomationProperties.SetAutomationId(_overrides, "ssh-overrides");
        AutomationProperties.SetAutomationId(_sshDir, "ssh-dir");
        AutomationProperties.SetAutomationId(_status, "ssh-status");
        AutomationProperties.SetAutomationId(_lastSynced, "ssh-last-synced");
        AutomationProperties.SetLiveSetting(_status, AutomationLiveSetting.Assertive);
        var refresh = new Button { Content = "Check for changes" };
        var apply = new Button { Content = "Sync now" };
        AutomationProperties.SetAutomationId(refresh, "ssh-check");
        AutomationProperties.SetAutomationId(apply, "ssh-apply");
        Body.Children.Add(Ui.Text("OpenSSH config files", "BodyStrongTextStyle"));
        Body.Children.Add(_configD);
        Body.Children.Add(_usePlaceholders);
        Body.Children.Add(_overrides);
        Body.Children.Add(_detect);
        Body.Children.Add(_sshDir);
        var note = Ui.Text("Each option works on its own. Config files are only read: Gantry never edits, commits or pushes them. Manual connections need none of this.", "CaptionSecondaryTextStyle");
        note.TextWrapping = TextWrapping.Wrap;
        Body.Children.Add(note);
        Body.Children.Add(Ui.Text("Placeholders", "BodyStrongTextStyle"));
        Body.Children.Add(_placeholders);
        Body.Children.Add(Ui.Text("Changes since the last import", "BodyStrongTextStyle"));
        Body.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { refresh, apply } });
        Body.Children.Add(_lastSynced);
        Body.Children.Add(_importAdded);
        var keep = Ui.Text("Changed hosts are updated; your favourites, tags, notes and overrides stay. Removed hosts are kept and marked, not deleted.", "CaptionSecondaryTextStyle");
        keep.TextWrapping = TextWrapping.Wrap;
        Body.Children.Add(keep);
        Body.Children.Add(_changes);
        Body.Children.Add(_status);
        _configD.Click += (_, _) => Save();
        _detect.Click += (_, _) => Save();
        _usePlaceholders.Click += (_, _) => Save();
        _overrides.Click += (_, _) => Save();
        _sshDir.LostFocus += (_, _) => { if (_sshDir.Text.Trim() != (_settings.SshDir ?? "")) Save(); };
        refresh.Click += (_, _) => Run(ShowChanges);
        apply.Click += (_, _) => Run(Apply);
        Run(Load);
    }

    /// <summary>Snapshot runs only: what the dialog shows, as text.</summary>
    internal IEnumerable<string> LinesForSnapshot() =>
        _placeholders.Children.Concat(_changes.Children).Select(c => c switch { TextBox b => $"{b.Header} = {b.Text}", TextBlock t => t.Text, _ => "" })
            .Prepend($"config.d={_configD.IsChecked} placeholders={_usePlaceholders.IsChecked} overrides={_overrides.IsChecked} watch={_detect.IsChecked} dir={_sshDir.Text}").Append("status: " + _status.Text);

    private void Load()
    {
        _settings = SshWorkflow.Settings(_dir);
        _configD.IsChecked = _settings.ScanConfigD;
        _detect.IsChecked = _settings.ChangeDetection;
        _usePlaceholders.IsChecked = _settings.Placeholders;
        _overrides.IsChecked = _settings.Overrides;
        _sshDir.Text = _settings.SshDir ?? "";
        ShowPlaceholders();
        ShowChanges();
    }

    private void ShowPlaceholders()
    {
        _placeholders.Children.Clear();
        if (_usePlaceholders.IsChecked != true) { _placeholders.Children.Add(Note("Placeholders are off.")); return; }
        var p = SshWorkflow.Placeholders(_dir);
        var names = p.Values.Keys.Union(p.Used.Keys).OrderBy(n => n).ToList();
        if (names.Count == 0) _placeholders.Children.Add(Note("No placeholders are used in the config files."));
        foreach (var name in names)
        {
            var box = new TextBox { Header = name + (p.Used.TryGetValue(name, out var n) ? $" (used {n}×)" : ""), Text = p.Values.GetValueOrDefault(name, "") };
            AutomationProperties.SetName(box, "Placeholder " + name);
            box.LostFocus += (_, _) => Run(() => { SshWorkflow.SetPlaceholder(_dir, name, box.Text); Say("Saved placeholder " + name + "."); });
            _placeholders.Children.Add(box);
        }
    }

    private void Save() => Run(() =>
    {
        var dir = _sshDir.Text.Trim();
        var next = _settings with
        {
            ScanConfigD = _configD.IsChecked == true, Placeholders = _usePlaceholders.IsChecked == true,
            Overrides = _overrides.IsChecked == true, ChangeDetection = _detect.IsChecked == true, SshDir = dir.Length == 0 ? null : dir,
        };
        SshWorkflow.SetSettings(_dir, next);
        _settings = next;
        Say("Saved.");
        ShowPlaceholders();
        ShowChanges();
    });

    private void ShowChanges()
    {
        _changes.Children.Clear();
        if (_detect.IsChecked != true) { _changes.Children.Add(Note("Change watching is off.")); return; }
        var c = SshWorkflow.Changes(_dir);
        _lastSynced.Text = c.LastSyncedSecs is { } s ? "Last synced " + DateTimeOffset.FromUnixTimeSeconds(s).LocalDateTime.ToString("g") : "Never synced";
        // Like the macOS sheet: without a baseline the note comes first and every host is still listed as new.
        if (!c.HasBaseline) _changes.Children.Add(Note("No baseline yet: every host counts as new. Importing or refreshing sets the baseline."));
        if (c.Hosts.Count == 0) { _changes.Children.Add(Note("No changes: the library matches the config files.")); return; }
        foreach (var h in c.Hosts)
        {
            var detail = h.Kind == "changed" ? ": " + string.Join(", ", h.Fields.Select(f => $"{f.Field} {f.Old ?? "—"} → {f.New ?? "—"}")) : "";
            var t = Ui.Text($"{Char.ToUpper(h.Kind[0])}{h.Kind[1..]}: {h.Alias}{detail}", "BodyTextStyle");
            t.TextWrapping = TextWrapping.Wrap;
            _changes.Children.Add(t);
        }
    }

    private void Apply()
    {
        var r = SshWorkflow.ApplyRefresh(_dir, _library, _importAdded.IsChecked == true);
        _changed();
        ShowChanges();
        Say($"Synced: {r.Added} added, {r.Updated} updated, {r.MarkedRemoved} marked removed.");
    }

    /// <summary>A secondary line that wraps to the dialog width instead of running past its edge.</summary>
    private static TextBlock Note(string text)
    {
        var t = Ui.Text(text, "BodySecondaryTextStyle");
        t.TextWrapping = TextWrapping.Wrap;
        return t;
    }

    private void Run(Action a)
    {
        try { a(); }
        catch (BastionException ex) { Say(ex.Message); }
    }

    private void Say(string text) { _status.Text = text; AutomationProperties.SetName(_status, text); }
}
