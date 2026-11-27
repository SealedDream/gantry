using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

/// <summary>What one Test Connection run checks: the dialog's unsaved values. <see cref="Login"/> null = no sign-in step.
/// <see cref="ConnectionId"/> is the saved connection the dialog is for (null for one not saved yet).</summary>
/// <param name="Jumps">The saved jump chain a real connect dials (A1-NW-JUMPS); null for a direct test.</param>
/// <param name="PluginTls">PVE-TLS: a plugin entry. The test is the core's TLS check under the entry's rule, never the
/// protocol probe (which does not know plugin types); <paramref name="PluginPin"/> is its pin, null for system trust.</param>
public sealed record ProbeRequest(string Protocol, string Host, int Port, string? Username, ProbeLogin? Login, string? ConnectionId = null,
    IReadOnlyList<ProbeHop>? Jumps = null, bool PluginTls = false, string? PluginPin = null, Func<ProbeStepDto>? PluginLogin = null);

/// <summary>
/// The Test button and its inline report, placed at the bottom of a connection dialog. One press tests everything
/// the dialog holds (the core's <c>probe</c>: DNS, TCP, handshake, host key, sign-in); a second press cancels. The
/// test runs off the UI thread and saves nothing. Each step shows ✓/✗ with its time, and a failed step its fix.
/// <para>SEC-07: a typed password is never sent to an SSH host whose key is new. Such a test stops before the
/// sign-in and the panel asks, in the words of the normal connect prompt, whether to trust the fingerprint for
/// this test only. Cancel is the default (focus, Enter and Escape). Nothing is written to known_hosts either way.</para>
/// </summary>
internal sealed class TestConnectionPanel
{
    private readonly Func<ProbeRequest?> _gather;
    private readonly Func<SessionManagerClient> _sessions;
    private readonly Func<LibraryClient>? _library;
    private readonly Button _test = new() { Content = "Test" };
    private readonly TextBlock _summary = new() { Style = Ui.Style("BodySecondaryTextStyle"), TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
    private readonly StackPanel _steps = new() { Spacing = Ui.Double("Space4") };
    /// <summary>TABBAR-WIN (Mac #1277, owner round 3 item 1): a failed test's steps show in this small popup on the
    /// button, closed with ✕ or Escape; a passed test shows only a tick that fades. No results area in the dialog.</summary>
    private readonly Flyout _failure = new() { Placement = Microsoft.UI.Xaml.Controls.Primitives.FlyoutPlacementMode.TopEdgeAlignedLeft };
    private readonly DispatcherTimer _fade = new() { Interval = TimeSpan.FromSeconds(OkSeconds) };
    /// <summary>How long "Connection OK" stays, as on the Mac.</summary>
    private const double OkSeconds = 3;
    private const double FailureWidth = 420;
    private readonly StackPanel _confirm = new() { Spacing = Ui.Double("Space12"), Visibility = Visibility.Collapsed };
    /// <summary>Holds the question's text and fingerprint; replaced for each question. The buttons stay in place.</summary>
    private readonly Border _confirmBody = new();
    private readonly Button _decline = new() { Content = "Cancel" };
    private readonly Button _trust = new() { Content = "Trust and test sign-in" };
    /// <summary>Cancel and Trust. Pinned outside the dialog's scroll while asking, so they are never off screen (SEC-07-FIT).</summary>
    private readonly StackPanel _decision;
    private bool _pinned;
    private ConnectionProbe? _running;
    /// <summary>The new host key on screen, waiting for the user's answer. Its yes is the only source of a trusted fingerprint.</summary>
    private PendingHostKey? _pending;
    /// <summary>The panel whose host-key question is open, so Escape in the dialog answers it first.</summary>
    private static TestConnectionPanel? _asking;

    public StackPanel Element { get; }

    /// <param name="gather">Reads the dialog; returns null when it is not complete (the form then shows what is missing).</param>
    /// <param name="library">The open library, for a dialog on a saved connection (the core checks a saved login against it).</param>
    public TestConnectionPanel(Func<ProbeRequest?> gather, Func<SessionManagerClient> sessions, Func<LibraryClient>? library = null)
    {
        _gather = gather;
        _sessions = sessions;
        _library = library;
        AutomationProperties.SetName(_test, "Test connection");
        ToolTipService.SetToolTip(_test, "Check name lookup, port, handshake and sign-in without saving anything");
        AutomationProperties.SetLiveSetting(_summary, AutomationLiveSetting.Polite);
        // A grid, not a horizontal StackPanel: the summary gets the width left beside the button, so a long one
        // wraps instead of running out of the dialog and being clipped.
        var row = new Grid { ColumnSpacing = Ui.Double("Space12") };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(_summary, 1);
        row.Children.Add(_test);
        row.Children.Add(_summary);
        AutomationProperties.SetName(_confirm, "Confirm the host key for this test");
        AutomationProperties.SetName(_decline, "Cancel, do not trust this host key");
        AutomationProperties.SetName(_trust, "Trust and test sign-in");
        ToolTipService.SetToolTip(_trust, "Trust this key for this test only and try the sign-in. Nothing is saved.");
        // Built once: a button can have one parent only, so a second question must not build a new row around them.
        _confirm.Children.Add(_confirmBody);
        _decision = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { _decline, _trust } };
        _summary.OpacityTransition = new ScalarTransition { Duration = TimeSpan.FromMilliseconds(400) };
        _fade.Tick += (_, _) => { _fade.Stop(); _summary.Opacity = 0; };
        var close = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphClose", "SmallIconSize"), HorizontalAlignment = HorizontalAlignment.Right };
        AutomationProperties.SetName(close, "Close");
        ToolTipService.SetToolTip(close, "Close");
        close.Click += (_, _) => _failure.Hide();
        var head = new Grid { Children = { new TextBlock { Text = "Test failed", Style = Ui.Style("BodyStrongTextStyle"), VerticalAlignment = VerticalAlignment.Center }, close } };
        var popup = new StackPanel { Spacing = Ui.Double("Space8"), Width = FailureWidth, Children = { head, _steps } };
        AutomationProperties.SetAutomationId(popup, "TestConnectionFailure");
        _failure.Content = popup;
        Element = new StackPanel { Spacing = Ui.Double("Space8"), Children = { row, _confirm } };
        _test.Click += (_, _) => _ = ToggleAsync();
        _decline.Click += (_, _) => Decline();
        _trust.Click += (_, _) => { if (_pending is { } confirmed) _ = RunAsync(confirmed); };
    }

    /// <summary>The dialog host: shows an element between the scrolled body and the dialog's buttons, and removes it.</summary>
    public static Action<UIElement>? PinDecision;
    public static Action<UIElement>? UnpinDecision;

    public bool IsRunning => _running is not null;

    /// <summary>Stop a running test and drop an open host-key question (the dialog closed). Safe to call at any time.</summary>
    public void Cancel()
    {
        _running?.Cancel();
        HidePrompt();
    }

    /// <summary>Escape in a dialog: answer an open host-key question with Cancel. False when none is open.</summary>
    internal static bool CancelOpenPrompt()
    {
        if (_asking is not { } panel) return false;
        panel.Decline();
        return true;
    }

    private Task ToggleAsync()
    {
        if (_running is { } running) { running.Cancel(); return Task.CompletedTask; }
        return RunAsync(confirmed: null); // a fresh press of Test never carries an earlier answer
    }

    /// <param name="confirmed">The host key the user just said yes to, or null for a plain test.</param>
    private async Task RunAsync(PendingHostKey? confirmed)
    {
        if (_running is not null) return;
        HidePrompt();
        if (_gather() is not { } request) return;
        // Only for the host and port the fingerprint was shown for: the form may have been edited meanwhile.
        var trust = confirmed?.TrustFor(request.Host, request.Port);
        _steps.Children.Clear();
        _failure.Hide();
        _fade.Stop();
        _summary.Opacity = 1;
        _summary.Text = $"Testing {request.Host}:{request.Port}…";
        if (request.PluginTls) { await RunPluginAsync(request); return; }
        try { _running = ConnectionProbe.Start(_sessions(), request.Protocol, request.Host, request.Port, request.Username, request.Login, _library?.Invoke(), request.ConnectionId, trust, request.Jumps); }
        catch (BastionException ex) { ShowFailure(ex.Message); return; }
        _test.Content = "Cancel test";
        try
        {
            var report = await _running.WaitAsync();
            Show(report, request, trust);
        }
        catch (BastionException ex) { ShowFailure(ex.Message); }
        // Never leave an old result on screen as if it were this run's: say that showing it failed.
        catch (Exception ex)
        {
            HidePrompt();
            _steps.Children.Clear();
            _summary.Text = "The test result could not be shown: " + ex.Message;
        }
        finally
        {
            _running.Dispose();
            _running = null;
            _test.Content = "Test";
        }
    }

    /// <summary>PVE-TLS: one "certificate" step from the core's TLS check, shown like any report.</summary>
    private async Task RunPluginAsync(ProbeRequest request)
    {
        _test.IsEnabled = false;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        string? failure = null;
        try { await Task.Run(() => PluginEntryClient.CheckCertificate(request.Host, request.Port, request.PluginPin)); }
        catch (BastionException ex) { failure = ex.Message.StartsWith("invalid input: ", StringComparison.Ordinal) ? ex.Message["invalid input: ".Length..] : ex.Message; }
        finally { _test.IsEnabled = true; }
        var ms = (ulong)watch.ElapsedMilliseconds;
        var step = failure is null
            ? new ProbeStepDto("certificate", "ok", request.PluginPin is null ? "Valid for the host name" : "Matches the pinned certificate", null, ms)
            : new ProbeStepDto("certificate", "failed", failure, failure.Contains("did not pass the TLS mode", StringComparison.Ordinal) ? "Use Trust Server Certificate… below" : null, ms);
        // PVE-AUTH: after a passed TLS check, the plugin's own calls with the entry's login (the list's calls).
        var steps = new List<ProbeStepDto> { step };
        if (failure is null && request.PluginLogin is { } login)
        {
            _test.IsEnabled = false;
            try { steps.Add(await Task.Run(login)); }
            finally { _test.IsEnabled = true; }
        }
        Show(new ProbeReportDto(steps.TrueForAll(s => s.Status != "failed"), false, steps), request, null);
    }

    private void Show(ProbeReportDto report, ProbeRequest request, string? sentTrust)
    {
        foreach (var step in report.Steps) _steps.Children.Add(StepRow(step));
        // The verdict reads the host-key question before Ok: a waiting report is never shown as a success.
        var verdict = ProbeVerdict.Of(report, sentTrust);
        _summary.Text = verdict.State == ProbeState.Passed ? "✓ Connection OK" : verdict.Summary;
        if (verdict.State == ProbeState.Passed) _fade.Start();
        else if (verdict.State == ProbeState.Failed) ShowFailure(null); // the summary keeps the reason ("Test failed: …")
        if (verdict is { State: ProbeState.WaitingForHostKey, Fingerprint: { } fingerprint })
            Ask(new PendingHostKey(request.Host, request.Port, fingerprint));
    }

    /// <summary>The failure popup on the Test button; <paramref name="message"/> when the test could not start.</summary>
    private void ShowFailure(string? message)
    {
        if (message is not null)
        {
            _summary.Text = "Test failed: " + message;
            _steps.Children.Clear();
            _steps.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
        }
        if (_test.XamlRoot is null) return;
        // Clicks reach the form under the popup: the first click into a field edits it instead of only closing the popup.
        _failure.OverlayInputPassThroughElement = _test.XamlRoot.Content;
        _failure.ShowAt(_test);
    }

    /// <summary>Show the fingerprint with Cancel (the default) and "Trust and test sign-in".</summary>
    private void Ask(PendingHostKey pending)
    {
        _pending = pending;
        _asking = this;
        _confirmBody.Child = HostKeyPrompt.Body(pending.Target, pending.Fingerprint, isJumpHost: false, testOnly: true);
        _confirm.Visibility = Visibility.Visible;
        _confirm.UpdateLayout();
        PinDecision?.Invoke(_decision); // also lays it out, so it can take focus
        _pinned = PinDecision is not null;
        // Cancel has the focus, so Enter and Space cancel; trusting takes a deliberate move to the other button.
        _decline.Focus(FocusState.Programmatic);
        _confirm.StartBringIntoView();
    }

    private void Decline()
    {
        if (_pending is null) return;
        HidePrompt();
        _summary.Text = ProbeVerdict.Declined;
        _test.Focus(FocusState.Programmatic);
    }

    private void HidePrompt()
    {
        _pending = null;
        if (_asking == this) _asking = null;
        _confirm.Visibility = Visibility.Collapsed;
        _confirmBody.Child = null;
        if (_pinned) { _pinned = false; UnpinDecision?.Invoke(_decision); }
    }

    internal static string StepLabel(string kind) => kind switch
    {
        "dns" => "Name lookup",
        "tcp" => "Port",
        "handshake" => "Handshake",
        "certificate" => "TLS",
        "host_key" => "Host key",
        "jump_host" => "Jump host",
        "login" => "Sign-in",
        _ => kind,
    };

    private static FrameworkElement StepRow(ProbeStepDto step)
    {
        var (mark, brush) = step.Status switch
        {
            "ok" => ("✓", "SystemFillColorSuccessBrush"),
            "warn" => ("!", "SystemFillColorCautionBrush"),
            "failed" => ("✗", "SystemFillColorCriticalBrush"),
            _ => ("–", "TextFillColorSecondaryBrush"),
        };
        var markText = new TextBlock { Text = mark, Width = Ui.Double("Space16") };
        if (Application.Current.Resources.TryGetValue(brush, out var b) && b is Microsoft.UI.Xaml.Media.Brush fill) markText.Foreground = fill;
        AutomationProperties.SetAccessibilityView(markText, Microsoft.UI.Xaml.Automation.Peers.AccessibilityView.Raw);
        var timing = step.Status == "skipped" ? "" : $" ({step.Millis} ms)";
        var text = new TextBlock { Text = $"{StepLabel(step.Kind)}: {step.Detail}{timing}", TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
        var body = new StackPanel { Children = { text } };
        if (step.Fix is { Length: > 0 } fix)
            body.Children.Add(new TextBlock { Text = fix, Style = Ui.Style("BodySecondaryTextStyle"), TextWrapping = TextWrapping.Wrap });
        var grid = new Grid { ColumnSpacing = Ui.Double("Space4") };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetColumn(body, 1);
        grid.Children.Add(markText);
        grid.Children.Add(body);
        AutomationProperties.SetName(grid, $"{StepLabel(step.Kind)} {step.Status}: {step.Detail}");
        return grid;
    }
}
