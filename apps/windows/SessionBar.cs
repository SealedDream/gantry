using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;

namespace Bastion.Shell;

/// <summary>The session title bar's link state (owner spec §3): green, amber, red dot plus a word.</summary>
internal enum SessionBarState { Connected, Connecting, Disconnected }

/// <summary>
/// Bar above a saved SSH connection's session (owner spec §3; Native Mac SessionTitleBar): status dot and
/// <c>Name (user@host:port)</c> on the left, the state word, Reconnect and Hide on the right. It sits on the session
/// surface itself (no box, no divider), compact, in the session's own text colours, like Tabby's (owner 2026-11-15).
/// Hide (unpin) removes it from every tab; Settings › Terminal › Session bar brings it back. A disconnected session still
/// shows it, since Reconnect lives there. Reconnect is a quiet outlined button, never a filled accent one.
/// </summary>
internal sealed class SessionBar
{
    private const double DotSize = 8;
    private const double OutlineWidth = 1;

    private readonly FrameworkElement _scope;
    private readonly Grid _bar;
    private readonly Ellipse _dot;
    private readonly TextBlock _address;
    private readonly TextBlock _stateText;
    /// <summary>LOG-01: "Logging" (path in the tooltip) or "Log not started" (reason in the tooltip); collapsed when not logging.</summary>
    private readonly TextBlock _log;
    private readonly Button _reconnect;
    /// <summary>UI-01: "Production" for a privileged host, and the identity colour as a 2 px strip on the bar's bottom edge.</summary>
    private readonly TextBlock _production;
    private readonly Border _strip = new() { Height = 2, VerticalAlignment = VerticalAlignment.Bottom, IsHitTestVisible = false, Visibility = Visibility.Collapsed };
    private readonly Button _pin;
    private bool _stateKnown;

    public SessionBar(FrameworkElement scope, string address, bool pinned, Action reconnect, Action<bool> pinChanged, string? reconnectTip = null)
    {
        _scope = scope;
        Pinned = pinned;
        _dot = new Ellipse { Width = DotSize, Height = DotSize, VerticalAlignment = VerticalAlignment.Center };
        _stateText = Ui.Text("", "CaptionSecondaryTextStyle");
        _stateText.VerticalAlignment = VerticalAlignment.Center;
        _address = Ui.Text(address, "CaptionTextStyle");
        _address.VerticalAlignment = VerticalAlignment.Center;
        _address.TextTrimming = TextTrimming.CharacterEllipsis;
        _address.IsTextSelectionEnabled = true;
        _address.FontFamily = new FontFamily("Cascadia Mono, Consolas");
        AutomationProperties.SetName(_address, "Address " + address);
        _reconnect = BarButton("GlyphRefresh", "Reconnect");
        ToolTipService.SetToolTip(_reconnect, reconnectTip ?? "Close this session and connect again");
        _reconnect.Click += (_, _) => reconnect();
        AutomationProperties.SetAutomationId(_reconnect, "SessionBarReconnect");
        _pin = BarButton("GlyphUnpin", "Unpin");
        _pin.Content = Ui.Icon("GlyphUnpin", "SmallIconSize");
        ToolTipService.SetToolTip(_pin, "Hide the session bar (Settings › Terminal › Session bar shows it again)");
        _pin.Click += (_, _) => { SetPinned(false); pinChanged(false); };

        _bar = new Grid
        {
            ColumnSpacing = Ui.Double("Space8"),
            Padding = new Thickness(Ui.Double("Space8"), 0, Ui.Double("Space4"), 0),
            Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent),
        };
        foreach (var width in new[] { GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto, GridLength.Auto, GridLength.Auto, GridLength.Auto })
            _bar.ColumnDefinitions.Add(new ColumnDefinition { Width = width });
        _production = Ui.Text("Production", "CaptionTextStyle");
        _production.VerticalAlignment = VerticalAlignment.Center;
        _production.FontWeight = Microsoft.UI.Text.FontWeights.SemiBold;
        _production.Visibility = Visibility.Collapsed;
        ToolTipService.SetToolTip(_production, "Privileged host");
        AutomationProperties.SetAutomationId(_production, "SessionBarProduction");
        Place(new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { _dot, _production } }, 0);
        // The address takes the free space and truncates first; the state word and buttons keep their size.
        Place(_address, 1);
        _log = Ui.Text("", "CaptionSecondaryTextStyle");
        _log.VerticalAlignment = VerticalAlignment.Center;
        _log.Visibility = Visibility.Collapsed;
        AutomationProperties.SetAutomationId(_log, "SessionBarLog");
        Place(_log, 2);
        Place(_stateText, 3);
        Place(_reconnect, 4);
        Place(_pin, 5);
        AutomationProperties.SetName(_bar, "Session title bar");
        AutomationProperties.SetAutomationId(_bar, "SessionTitleBar");

        AutomationProperties.SetAutomationId(_strip, "SessionBarHostColor");
        Root = new Grid { Children = { _bar, _strip } };
        Repaint();
    }

    public Grid Root { get; }

    public bool Pinned { get; private set; }

    public SessionBarState State { get; private set; }

    /// <summary>A2-W26: a tab restored after a crash has no content to focus, so the keyboard starts on Reconnect.</summary>
    public void FocusReconnect(FocusState how) => _reconnect.Focus(how);

    /// <summary>The pin state changed on another tab's bar (it is one setting for all of them).</summary>
    public void SetPinned(bool pinned)
    {
        if (Pinned == pinned) return;
        Pinned = pinned;
        Refresh();
    }

    /// <summary>Theme switch: brushes are looked up per theme, so take them again. Text follows the session surface.</summary>
    public void Repaint()
    {
        _address.Foreground = Ui.Brush(_scope, "SessionForegroundBrush");
        foreach (var quiet in new[] { _stateText, _log }) quiet.Foreground = Ui.Brush(_scope, "SessionSecondaryForegroundBrush");
        foreach (var b in new[] { _reconnect, _pin }) b.Foreground = Ui.Brush(_scope, "SessionSecondaryForegroundBrush");
        _reconnect.BorderBrush = Ui.Brush(_scope, "SessionSecondaryForegroundBrush");
        SetState(State);
    }

    /// <summary>Show the session log state: <paramref name="path"/> while logging, <paramref name="problem"/> when an
    /// automatic start failed, both null to hide the indicator.</summary>
    public void SetLog(string? path, string? problem = null)
    {
        var text = path is not null ? "Logging" : problem is not null ? "Log not started" : "";
        _log.Text = text;
        _log.Visibility = text.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
        var tip = path ?? problem;
        ToolTipService.SetToolTip(_log, tip);
        AutomationProperties.SetName(_log, tip is null ? "" : $"{text}: {tip}");
    }

    /// <summary>The core stopped the log on its own (disk full, writer overflow): "Log stopped", the reason in the tooltip.</summary>
    public void SetLogStopped(string problem)
    {
        _log.Text = "Log stopped";
        _log.Visibility = Visibility.Visible;
        ToolTipService.SetToolTip(_log, problem);
        AutomationProperties.SetName(_log, "Log stopped: " + problem);
    }

    public void SetState(SessionBarState state)
    {
        var changed = _stateKnown && state != State;
        _stateKnown = true;
        State = state;
        var (brush, word) = state switch
        {
            SessionBarState.Connected => ("SessionConnectedBrush", "Connected"),
            SessionBarState.Connecting => ("SessionConnectingBrush", "Connecting"),
            _ => ("CriticalBrush", "Disconnected"),
        };
        _dot.Fill = Ui.Brush(_scope, brush);
        _stateText.Text = word;
        AutomationProperties.SetItemStatus(_bar, word);
        Refresh();
        // Screen readers hear the change once; the dot colour alone never carries the state.
        if (changed && FrameworkElementAutomationPeer.FromElement(_bar) is { } peer)
            peer.RaiseNotificationEvent(AutomationNotificationKind.Other, AutomationNotificationProcessing.MostRecent, "Session " + word, "SessionState");
    }

    /// <summary>Hidden once unpinned, except while disconnected: Reconnect has to stay reachable.</summary>
    private void Refresh()
    {
        Root.Visibility = Pinned || State == SessionBarState.Disconnected ? Visibility.Visible : Visibility.Collapsed;
        // Disconnected: an outline marks Reconnect as the next step; otherwise it is as quiet as the rest of the bar.
        var outline = State == SessionBarState.Disconnected;
        _reconnect.BorderThickness = new Thickness(outline ? OutlineWidth : 0);
        _reconnect.Foreground = Ui.Brush(_scope, outline ? "SessionForegroundBrush" : "SessionSecondaryForegroundBrush");
        _pin.Visibility = Pinned ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Place(FrameworkElement element, int column)
    {
        Grid.SetColumn(element, column);
        _bar.Children.Add(element);
    }

    private static StackPanel Label(string glyph, string text) => new()
    {
        Orientation = Orientation.Horizontal,
        Spacing = Ui.Double("Space4"),
        Children = { Ui.Icon(glyph, "SmallIconSize"), Ui.Text(text, "CaptionTextStyle") },
    };

    private static Button BarButton(string glyph, string label)
    {
        var button = new Button { Style = Ui.Style("SubtleButtonStyle"), Padding = new Thickness(Ui.Double("Space8"), 0, Ui.Double("Space8"), 0), MinHeight = 28, MinWidth = 28, Content = Label(glyph, label), VerticalAlignment = VerticalAlignment.Center };
        AutomationProperties.SetName(button, label);
        return button;
    }

    /// <summary>UI-01: paint the identity colour strip and the "Production" word (text keeps the theme brush in high contrast).</summary>
    public void SetIdentity(Brush? accent, Brush? nameTone, bool privileged)
    {
        _strip.Background = accent;
        _strip.Visibility = accent is null ? Visibility.Collapsed : Visibility.Visible;
        _production.Visibility = privileged ? Visibility.Visible : Visibility.Collapsed;
        if (nameTone is not null) _production.Foreground = nameTone; else _production.ClearValue(TextBlock.ForegroundProperty);
    }
}
