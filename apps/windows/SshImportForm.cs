using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>
/// The "Import from OpenSSH" dialog body: what was read, then every host found with a check box, grouped as the
/// import will file them (one folder per group). Nothing in the configs is executed. Hosts already in the library are
/// skipped by the core, so ticking them again is harmless.
/// </summary>
internal sealed class SshImportForm
{
    private readonly List<(CheckBox Box, SshHostDto Host)> _rows = new();
    private readonly CheckBox _all = new() { Content = "Select all", IsThreeState = false };
    private readonly FieldMessage _error = new();
    private readonly List<(string Name, TextBox Box)> _answers = new();
    private bool _syncing;
    /// <summary>Forward rows (one check box each, unticked by default) and their keys in tick order.</summary>
    private readonly List<(CheckBox Box, StackPanel Text, string Key, string HostIdentity)> _fwdRows = new();
    private readonly List<string> _fwdTicked = new();
    private readonly Func<IReadOnlyList<string>, IReadOnlyList<SshForwardDto>>? _preview;

    /// <summary>Placeholder answers typed in this dialog (name → value; blank ones left out).</summary>
    public IReadOnlyDictionary<string, string> Answers => _answers.Where(a => a.Box.Text.Trim().Length > 0).ToDictionary(a => a.Name, a => a.Box.Text.Trim());

    public StackPanel Body { get; }
    public Control Field => _all;
    public IReadOnlyList<string> ChosenIdentities => _rows.Where(r => r.Box.IsChecked == true).Select(r => r.Host.Identity).ToList();
    /// <summary>Ticked forward rows whose host is ticked, in tick order.</summary>
    public IReadOnlyList<string> ChosenForwards
    {
        get
        {
            var hosts = ChosenIdentities.ToHashSet();
            return _fwdTicked.Where(k => _fwdRows.Any(r => r.Key == k && r.Box.IsEnabled && r.Box.IsChecked == true && hosts.Contains(r.HostIdentity))).ToList();
        }
    }

    /// <param name="forwardPreview">Rows for the given ticked keys (tick order); null hides forwards.</param>
    public SshImportForm(SshScanDto scan, IReadOnlyDictionary<string, string>? placeholderValues = null, Func<IReadOnlyList<string>, IReadOnlyList<SshForwardDto>>? forwardPreview = null)
    {
        _preview = forwardPreview;
        var forwards = forwardPreview?.Invoke(Array.Empty<string>()) ?? Array.Empty<SshForwardDto>();
        Body = new StackPanel { Spacing = Ui.Double("Space12") };
        var read = scan.Files.Count == 0 ? "No OpenSSH config files were found." : "Read " + string.Join(", ", scan.Files.Select(Path.GetFileName).Distinct()) + $" ({Plural(scan.Files.Count, "file")}).";
        var source = Ui.Text(read + " Nothing in them is run; only Host entries are read.", "BodySecondaryTextStyle");
        source.TextWrapping = TextWrapping.Wrap;
        ToolTipService.SetToolTip(source, string.Join("\n", scan.Files));
        Body.Children.Add(source);

        if (scan.Hosts.Count == 0)
        {
            Body.Children.Add(Ui.Text("No hosts to import.", "BodyTextStyle"));
        }
        else
        {
            Body.Children.Add(_all);
            var list = new StackPanel { Spacing = Ui.Double("Space4") };
            AutomationProperties.SetName(list, "Hosts");
            foreach (var group in scan.Hosts.GroupBy(h => h.Group).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
            {
                var header = Ui.Text(group.Key, "SectionHeaderTextStyle");
                header.Margin = new Thickness(0, list.Children.Count == 0 ? 0 : Ui.Double("Space8"), 0, 0);
                list.Children.Add(header);
                foreach (var h in group.OrderBy(h => h.Alias, StringComparer.OrdinalIgnoreCase))
                {
                    var target = (h.User is null ? "" : h.User + "@") + h.Hostname + (h.Port is { } p ? ":" + p : "");
                    var extra = new List<string>();
                    if (h.ProxyJump is { } j) extra.Add("via " + j);
                    if (h.Placeholders.Count > 0) extra.Add("needs " + string.Join(", ", h.Placeholders.Select(x => $"<{x}>")));
                    var text = new StackPanel
                    {
                        Children =
                        {
                            Ui.Text(h.Alias, "BodyTextStyle"),
                            Ui.Text(target + (extra.Count > 0 ? " · " + string.Join(" · ", extra) : ""), "BodySecondaryTextStyle"),
                        },
                    };
                    var box = new CheckBox { Content = text, IsChecked = true };
                    AutomationProperties.SetName(box, h.Alias);
                    box.Checked += (_, _) => Sync();
                    box.Unchecked += (_, _) => Sync();
                    _rows.Add((box, h));
                    list.Children.Add(box);
                    foreach (var f in forwards.Where(f => f.HostIdentity == h.Identity && f.Key.Length > 0))
                    {
                        var ftext = new StackPanel();
                        var fbox = new CheckBox { Content = ftext, IsChecked = false, VerticalContentAlignment = VerticalAlignment.Top, Margin = new Thickness(Ui.Double("Space24"), Ui.Double("Space4"), 0, 0) };
                        AutomationProperties.SetName(fbox, f.Description);
                        AutomationProperties.SetAutomationId(fbox, "ssh-import-fwd-" + f.Key);
                        var key = f.Key;
                        fbox.Checked += (_, _) => { if (!_syncing) { _fwdTicked.Remove(key); _fwdTicked.Add(key); RefreshForwards(); } };
                        fbox.Unchecked += (_, _) => { if (!_syncing) { _fwdTicked.Remove(key); RefreshForwards(); } };
                        _fwdRows.Add((fbox, ftext, f.Key, f.HostIdentity));
                        list.Children.Add(fbox);
                    }
                }
            }
            // Forward rows add three or four lines per host, so the list gets more room when there are any.
            Body.Children.Add(new ScrollViewer { Content = list, MaxHeight = forwards.Count > 0 ? 440 : 300, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
            if (forwards.FirstOrDefault(f => f.Key.Length == 0) is { } more)
            {
                var note = Ui.Text(more.Description + ". " + more.Blocked, "CaptionSecondaryTextStyle");
                note.TextWrapping = TextWrapping.Wrap;
                Body.Children.Add(note);
            }
            _all.IsChecked = true;
            _all.Checked += (_, _) => SetAll(true);
            _all.Unchecked += (_, _) => SetAll(false);
            ApplyForwards(forwards);
        }
        AddPlaceholderAnswers(scan, placeholderValues);
        Body.Children.Add(_error.Element);

        if (scan.Warnings.Count > 0)
        {
            var w = Ui.Text($"{Plural(scan.Warnings.Count, "warning")}: " + string.Join("; ", scan.Warnings.Take(3)) + (scan.Warnings.Count > 3 ? " …" : ""), "CaptionSecondaryTextStyle");
            w.TextWrapping = TextWrapping.Wrap;
            ToolTipService.SetToolTip(w, string.Join("\n", scan.Warnings));
            Body.Children.Add(w);
        }
    }

    /// <summary>One box per placeholder the hosts need, pre-filled with the saved answer (Settings › SSH config sources).</summary>
    private void AddPlaceholderAnswers(SshScanDto scan, IReadOnlyDictionary<string, string>? saved)
    {
        if (saved is null) return; // placeholders are off in the shared-config settings
        var names = scan.Hosts.SelectMany(h => h.Placeholders).Distinct(StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal).ToList();
        if (names.Count == 0) return;
        Body.Children.Add(Ui.Text("Placeholder answers", "BodyStrongTextStyle"));
        var hint = Ui.Text("Used for every host that needs them. Leave blank to answer later in Settings › SSH config sources.", "CaptionSecondaryTextStyle");
        hint.TextWrapping = TextWrapping.Wrap;
        Body.Children.Add(hint);
        foreach (var name in names)
        {
            var box = new TextBox { Header = $"<{name}>", Text = saved.GetValueOrDefault(name, "") };
            AutomationProperties.SetName(box, "Placeholder " + name);
            AutomationProperties.SetAutomationId(box, "ssh-import-ph-" + name);
            _answers.Add((name, box));
            Body.Children.Add(box);
        }
    }

    private void RefreshForwards()
    {
        if (_preview is null) return;
        try { ApplyForwards(_preview(_fwdTicked)); }
        catch (BastionException ex) { _error.ShowCoded("APP", ex.Message); }
    }

    /// <summary>Text, warning and enabled state of each forward row (a row needs its host ticked).</summary>
    private void ApplyForwards(IReadOnlyList<SshForwardDto> rows)
    {
        var hosts = ChosenIdentities.ToHashSet();
        foreach (var r in _fwdRows)
        {
            if (rows.FirstOrDefault(x => x.Key == r.Key) is not { } f) continue;
            r.Text.Children.Clear();
            r.Text.Children.Add(Ui.Text(f.Description, "BodyTextStyle"));
            if (f.Blocked.Length > 0) r.Text.Children.Add(Ui.Text(f.Blocked, "CaptionSecondaryTextStyle"));
            // Two lines per row (owner, 2026-11-14): title and Config line; the plain explanation is the
            // tooltip (and screen-reader help text); a warning line only on risky rows; a blocked row says why.
            var help = f.Blocked.Length > 0 ? f.Blocked : f.Explain + " If it cannot open, the terminal stays connected and the Tunnel Manager shows why.";
            ToolTipService.SetToolTip(r.Box, help);
            AutomationProperties.SetHelpText(r.Box, help);
            if (f.Blocked.Length == 0 && f.Warning.Length > 0)
            {
                var w = Ui.Text("⚠ " + f.Warning, "CaptionTextStyle");
                AutomationProperties.SetAutomationId(w, "ssh-import-fwd-warning");
                if (Application.Current.Resources.TryGetValue("SystemFillColorCautionBrush", out var b) && b is Microsoft.UI.Xaml.Media.Brush fill) w.Foreground = fill;
                r.Text.Children.Add(w);
            }
            if (f.Line.Length > 0) r.Text.Children.Add(Ui.Text("Config: " + f.Line, "CaptionSecondaryTextStyle"));
            foreach (var t in r.Text.Children.OfType<TextBlock>()) t.TextWrapping = TextWrapping.Wrap;
            r.Box.IsEnabled = f.Blocked.Length == 0 && hosts.Contains(r.HostIdentity);
            if (f.Blocked.Length > 0 && r.Box.IsChecked == true) { _syncing = true; r.Box.IsChecked = false; _syncing = false; _fwdTicked.Remove(r.Key); }
        }
    }

    private void SetAll(bool on)
    {
        if (_syncing) return;
        _syncing = true;
        foreach (var r in _rows) r.Box.IsChecked = on;
        _syncing = false;
        _error.Hide();
        RefreshForwards();
    }

    private void Sync()
    {
        if (_syncing) return;
        _syncing = true;
        _all.IsChecked = _rows.All(r => r.Box.IsChecked == true);
        _syncing = false;
        _error.Hide();
        RefreshForwards();
    }

    public bool Validate()
    {
        if (_rows.Count == 0 || ChosenIdentities.Count > 0) return true;
        _error.Show("Select at least one host.");
        return false;
    }

    private static string Plural(int n, string word) => n == 1 ? $"1 {word}" : $"{n} {word}s";
}
