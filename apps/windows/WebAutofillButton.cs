using System.Text.Json;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;

namespace Bastion.Shell;

/// <summary>What a web tab needs from the main window for "Fill sign-in" (B13): whether to show it, and the core's decision.</summary>
public sealed record WebAutofillHooks(Func<bool> Offered, Func<string, bool, WebAutofillDto> Decide);

/// <summary>
/// "Fill sign-in" in the web tab's address bar (B13, docs/plans/B13-WEB-AUTOFILL.md). The core decides and builds the
/// script; this runs it once in the top frame (CoreWebView2.ExecuteScriptAsync, never a frame) and shows refusals.
/// WebView2 has no isolated world, so a script of the same page could watch the field; that page is the exact saved
/// origin, which receives the value anyway (T27.6 residual).
/// </summary>
internal sealed class WebAutofillButton
{
    private readonly WebAutofillHooks _hooks;
    private readonly Func<(CoreWebView2? Core, bool Secure, bool Navigating)> _page;
    private readonly TextBlock _notice = new() { TextWrapping = TextWrapping.Wrap, MaxWidth = 320 };
    // One flyout for the life of the button: a new Flyout per click took _notice while the previous one still held it
    // ("already the child of another element"), and the second refusal in a tab crashed the app (B13 suite run 2).
    private readonly Flyout _flyout = new();

    public Button Button { get; }

    public WebAutofillButton(WebAutofillHooks hooks, Func<(CoreWebView2? Core, bool Secure, bool Navigating)> page)
    {
        _hooks = hooks;
        _page = page;
        Button = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon("GlyphKey", "SmallIconSize") };
        AutomationProperties.SetName(Button, "Fill sign-in");
        AutomationProperties.SetAutomationId(Button, "WebFillSignIn");
        ToolTipService.SetToolTip(Button, "Fill this connection's saved login (only on its exact https address)");
        AutomationProperties.SetName(_notice, "Fill sign-in result");
        _flyout.Content = _notice;
        Button.Click += async (_, _) => await FillAsync();
        Refresh();
    }

    /// <summary>Show or hide the button (the switch or policy may have changed).</summary>
    public void Refresh()
    {
        bool offered;
        try { offered = _hooks.Offered(); } catch (BastionException) { offered = false; }
        Button.Visibility = offered ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>The last result, for the UI test (null after a fill).</summary>
    public string? LastNotice { get; private set; }

    private async Task FillAsync()
    {
        var (core, secure, navigating) = _page();
        if (core is null) return;
        LastNotice = navigating ? "Wait for the page to finish loading." : await WebAutofillRun.FillAsync(core, secure, _hooks, () => _page().Navigating);
        if (TestHooks.WebFillTrace is not null)
        {
            TraceForTest($"WEB-FILL notice={LastNotice ?? "filled"}", core.Source);
            // What the page received, read back from its own status line (fixtures\b13: user name and password length only).
            await Task.Delay(500); // the fixture page refreshes its status line every 200 ms
            string page;
            try { page = System.Text.Json.JsonSerializer.Deserialize(await core.ExecuteScriptAsync("(document.getElementById('s')||{}).textContent||''"), AotJsonContext.Default.String) ?? ""; }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or System.Text.Json.JsonException) { page = ""; }
            TraceForTest($"WEB-STATUS {page}", core.Source);
        }
        if (LastNotice is null) return;
        _notice.Text = LastNotice;
        _flyout.ShowAt(Button);
    }

    /// <summary>Test builds with BASTION_WEBFILL_TRACE only: one line with the page origin. Never a password.</summary>
    internal static void TraceForTest(string line, string? page)
    {
        if (TestHooks.WebFillTrace is not { } trace) return;
        var origin = Uri.TryCreate(page, UriKind.Absolute, out var u) ? u.GetLeftPart(UriPartial.Authority) : "?";
        try { File.AppendAllText(trace, $"{line} origin={origin}\n"); }
        catch (IOException) { }
    }
}

/// <summary>One fill: ask the core, run its script in the top frame, say what happened (null = filled).</summary>
internal static class WebAutofillRun
{
    public static async Task<string?> FillAsync(CoreWebView2 core, bool secure, WebAutofillHooks hooks, Func<bool> navigating)
    {
        var source = core.Source;
        WebAutofillDto decision;
        try { decision = hooks.Decide(source, secure); }
        catch (BastionException ex) { return ex.Message; }
        if (decision.Script is not { } script) return decision.Message;
        // The page must still be the one the core checked: same address, no navigation started since. The script then
        // re-checks location.origin itself before anything a page could patch (core webautofill FILL_FN).
        if (navigating() || core.Source != source) return "Not filled: the page changed address.";
        string status;
        try { status = JsonSerializer.Deserialize(await core.ExecuteScriptAsync(script), AotJson.Options.Info<string>()) ?? ""; }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or System.Text.Json.JsonException) { status = ""; }
        return Message(status);
    }

    public static string? Message(string status) => status switch
    {
        "filled" => null,
        "no-form" => "No sign-in form found.",
        "many-password-fields" => "Not filled: this page has more than one password field.",
        "origin-changed" => "Not filled: the page changed address.",
        _ => "Not filled: the page did not accept it.",
    };
}
