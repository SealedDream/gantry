using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.System;

namespace Bastion.Shell;

/// <summary>
/// The remote editor of the Files panel (core C ABI 59, as Native Mac #260): Edit opens the selected remote text
/// file in memory over SFTP (nothing is written to this PC). Save sends the fingerprint taken at open (or the last
/// save), so a copy changed on the server meanwhile is never overwritten silently: the save is refused and the user
/// picks Reload server copy or Overwrite. Close with unsaved changes asks first (Discard changes / Keep editing).
/// </summary>
public sealed partial class SftpPanel
{
    private readonly Grid _editor = new() { Visibility = Visibility.Collapsed, RowSpacing = 8 };
    private readonly TextBlock _editorTitle = new() { TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly TextBox _editorText = new()
    {
        AcceptsReturn = true,
        TextWrapping = TextWrapping.NoWrap,
        IsSpellCheckEnabled = false,
        FontFamily = new FontFamily("Cascadia Mono, Consolas"),
    };
    private readonly TextBlock _editorStatus = new() { TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
    private readonly Button _editorSave = new() { Content = "Save" };
    private readonly Button _editorRevert = new() { Content = "Revert" };
    private readonly Button _editorClose = new() { Content = "Close" };
    private readonly Button _editorReload = new() { Content = "Reload server copy", Visibility = Visibility.Collapsed };
    private readonly Button _editorOverwrite = new() { Content = "Overwrite", Visibility = Visibility.Collapsed };
    private readonly Button _editorDiscard = new() { Content = "Discard changes", Visibility = Visibility.Collapsed };
    private readonly Button _editorKeep = new() { Content = "Keep editing", Visibility = Visibility.Collapsed };
    private string? _editPath;
    private string? _editFingerprint;
    // What the TextBox shows for the server text (it turns every line break into "\r"), and the file's own line break.
    private string _editOriginal = "";
    private string _editNewline = "\n";
    private bool _editBusy;

    /// <summary>The path open in the editor, or null when it is closed (tests and snapshots).</summary>
    internal string? EditingPath => _editPath;

    private bool EditDirty => _editPath is not null && _editorText.Text != _editOriginal;

    private Grid BuildEditor()
    {
        void Paint() => _editor.Background = Ui.Brush(this, "LayerBackgroundBrush");
        Loaded += (_, _) => Paint();
        ActualThemeChanged += (_, _) => Paint();
        AutomationProperties.SetName(_editor, "Remote editor");
        _editor.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        _editor.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        _editor.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        _editor.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        _editorTitle.Style = Ui.Style("BodyStrongTextStyle");
        _editor.Children.Add(_editorTitle);

        AutomationProperties.SetName(_editorText, "Remote file text");
        ScrollViewer.SetHorizontalScrollBarVisibility(_editorText, ScrollBarVisibility.Auto);
        ScrollViewer.SetVerticalScrollBarVisibility(_editorText, ScrollBarVisibility.Auto);
        _editorText.TextChanged += (_, _) => UpdateEditorState();
        var save = new KeyboardAccelerator { Key = VirtualKey.S, Modifiers = VirtualKeyModifiers.Control };
        save.Invoked += (sender, args) => { args.Handled = true; var pending = SaveEdit(false); };
        _editorText.KeyboardAccelerators.Add(save);
        Grid.SetRow(_editorText, 1);
        _editor.Children.Add(_editorText);

        // The status is read by its text: keep the accessible name in step with it.
        _editorStatus.RegisterPropertyChangedCallback(TextBlock.TextProperty, (_, _) => AutomationProperties.SetName(_editorStatus, _editorStatus.Text));
        AutomationProperties.SetAutomationId(_editorStatus, "EditorStatus");
        AutomationProperties.SetLiveSetting(_editorStatus, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);
        _editorStatus.Style = Ui.Style("CaptionSecondaryTextStyle");
        Grid.SetRow(_editorStatus, 2);
        _editor.Children.Add(_editorStatus);

        _editorSave.Style = Ui.Style("AccentButtonStyle");
        AutomationProperties.SetName(_editorSave, "Save file");
        ToolTipService.SetToolTip(_editorSave, "Save (Ctrl+S)");
        AutomationProperties.SetName(_editorClose, "Close editor");
        _editorSave.Click += (_, _) => _ = SaveEdit(false);
        _editorOverwrite.Click += (_, _) => _ = SaveEdit(true);
        _editorReload.Click += (_, _) => { if (_editPath is { } p) _ = LoadEdit(p); };
        _editorRevert.Click += (_, _) => _editorText.Text = _editOriginal;
        _editorClose.Click += (_, _) => RequestCloseEditor();
        _editorDiscard.Click += (_, _) => CloseEditor();
        _editorKeep.Click += (_, _) => { ShowCloseAsk(false); UpdateEditorState(); _editorText.Focus(FocusState.Programmatic); };
        _editor.KeyDown += (_, e) => { if (e.Key == VirtualKey.Escape) { e.Handled = true; RequestCloseEditor(); } };

        // Scrolls sideways rather than clipping when the Files panel is narrow (layout-fit).
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right };
        foreach (var b in new[] { _editorReload, _editorOverwrite, _editorDiscard, _editorKeep, _editorRevert, _editorClose, _editorSave }) buttons.Children.Add(b);
        var bar = new ScrollViewer
        {
            Content = buttons,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
            HorizontalScrollMode = ScrollMode.Auto,
            VerticalScrollMode = ScrollMode.Disabled,
        };
        Grid.SetRow(bar, 3);
        _editor.Children.Add(bar);
        return _editor;
    }

    /// <summary>Open the selected remote file in the editor.</summary>
    public Task EditSelected()
    {
        if (Selected is not { IsDir: false } e) { Report("Select a file to edit."); return Task.CompletedTask; }
        return LoadEdit(SftpSession.Join(_dir, e.Name));
    }

    private async Task LoadEdit(string path)
    {
        _editPath = path;
        _editorTitle.Text = path;
        _editor.Visibility = Visibility.Visible;
        ShowConflict(false);
        ShowCloseAsk(false);
        _editorText.IsEnabled = false;
        _editorStatus.Text = $"Opening {path}…";
        var opened = await EditCall(() => _sftp.EditOpen(path));
        _editorText.IsEnabled = true;
        if (opened is not { } o) return;
        _editFingerprint = o.Fingerprint;
        _editNewline = o.Text.Contains("\r\n") ? "\r\n" : "\n";
        _editorText.Text = o.Text;
        _editOriginal = _editorText.Text;
        UpdateEditorState();
        _editorText.Focus(FocusState.Programmatic);
    }

    /// <summary>Save the editor's text; <paramref name="force"/> overwrites a changed server copy.</summary>
    internal async Task SaveEdit(bool force)
    {
        if (_editPath is not { } path || _editBusy) return;
        if (!force && !EditDirty) return;
        var shown = _editorText.Text;
        var text = ToFile(shown);
        _editorStatus.Text = "Saving…";
        var r = await EditCall(() => _sftp.EditSave(path, text, _editFingerprint, force));
        if (r is not { } result) return;
        if (!result.Saved)
        {
            ShowConflict(true);
            _editorStatus.Text = $"{path} changed on the server since you opened it. Nothing was written.";
            return;
        }
        _editFingerprint = result.Fingerprint;
        _editOriginal = shown;
        ShowConflict(false);
        UpdateEditorState();
        _editorStatus.Text = $"Saved {path}";
    }

    /// <summary>The TextBox's text with the file's own line breaks again.</summary>
    private string ToFile(string shown) => shown.Replace("\r\n", "\r").Replace("\n", "\r").Replace("\r", _editNewline);

    private void RequestCloseEditor()
    {
        if (!EditDirty) { CloseEditor(); return; }
        ShowCloseAsk(true);
        _editorStatus.Text = $"Close without saving? Your changes to {_editPath} have not been saved.";
    }

    private void CloseEditor()
    {
        var name = _editPath is { } p ? SftpLeaf(p) : null;
        _editPath = null;
        _editFingerprint = null;
        _editOriginal = "";
        _editorText.Text = "";
        _editor.Visibility = Visibility.Collapsed;
        ShowCloseAsk(false);
        ShowConflict(false);
        if (name is not null) _ = RefreshAfterEdit(name);
    }

    private async Task RefreshAfterEdit(string name)
    {
        await Navigate(_dir);
        Select(name);
        _list.Focus(FocusState.Programmatic);
    }

    private void ShowConflict(bool on)
    {
        _editorReload.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        _editorOverwrite.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowCloseAsk(bool on)
    {
        _editorDiscard.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        _editorKeep.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        _editorClose.Visibility = on ? Visibility.Collapsed : Visibility.Visible;
    }

    private void UpdateEditorState()
    {
        var dirty = EditDirty;
        _editorSave.IsEnabled = dirty && !_editBusy;
        _editorRevert.IsEnabled = dirty && !_editBusy;
        var asking = _editorReload.Visibility == Visibility.Visible || _editorDiscard.Visibility == Visibility.Visible;
        if (_editPath is { } p && !_editBusy && !asking) _editorStatus.Text = dirty ? "Edited" : p;
    }

    /// <summary>Run one editor SFTP call off the UI thread; errors go to the editor status, null means it failed.</summary>
    private async Task<T?> EditCall<T>(Func<T> call) where T : struct
    {
        if (_editBusy) return null;
        _editBusy = true;
        _editorSave.IsEnabled = _editorOverwrite.IsEnabled = _editorReload.IsEnabled = false;
        try { return await Task.Run(call); }
        catch (Exception ex) when (ex is BastionException or ObjectDisposedException or System.Text.Json.JsonException)
        {
            _editorStatus.Text = ex.Message;
            return null;
        }
        finally
        {
            _editBusy = false;
            _editorOverwrite.IsEnabled = _editorReload.IsEnabled = true;
            _editorSave.IsEnabled = _editorRevert.IsEnabled = EditDirty;
        }
    }
}
