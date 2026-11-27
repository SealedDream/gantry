using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Windows.System;

namespace Bastion.Shell;

/// <summary>
/// The bar above a web tab, as on macOS: back, forward, reload/stop, a lock that shows whether the page is HTTPS, and an
/// editable address. Typed addresses go through <see cref="WebAddress.Parse"/>, so only http(s) ever loads; the history
/// is WebView2's own per-tab back/forward list (InPrivate, gone with the tab).
/// </summary>
public sealed partial class WebAddressBar : Grid
{
    private readonly Button _back, _forward, _reload;
    private readonly FontIcon _lock = Ui.Icon("GlyphLock", "SmallIconSize");
    private readonly TextBox _address = new() { MinWidth = 0, VerticalAlignment = VerticalAlignment.Center };
    private CoreWebView2? _core;
    private bool _loading;

    public WebAddressBar()
    {
        ColumnSpacing = 4;
        Padding = new Thickness(8, 4, 8, 4);
        foreach (var w in new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star) })
            ColumnDefinitions.Add(new ColumnDefinition { Width = w });
        _back = Tool("GlyphBack", "Back", () => { if (_core?.CanGoBack == true) _core.GoBack(); });
        _forward = Tool("GlyphForward", "Forward", () => { if (_core?.CanGoForward == true) _core.GoForward(); });
        _reload = Tool("GlyphRefresh", "Reload", () => { if (_loading) _core?.Stop(); else _core?.Reload(); });
        _lock.VerticalAlignment = VerticalAlignment.Center;
        _lock.Margin = new Thickness(4, 0, 0, 0);
        Add(_back, 0);
        Add(_forward, 1);
        Add(_reload, 2);
        Add(_lock, 3);
        Add(_address, 4);
        AutomationProperties.SetName(_address, "Address");
        _address.KeyDown += (_, e) =>
        {
            if (e.Key == VirtualKey.Enter) { e.Handled = true; Go(_address.Text); }
            else if (e.Key == VirtualKey.Escape) { e.Handled = true; ShowSource(); }
        };
        _address.GotFocus += (_, _) => _address.SelectAll();
        Attach(null);
    }

    private void Add(FrameworkElement e, int column)
    {
        SetColumn(e, column);
        Children.Add(e);
    }

    /// <summary>A control after the address box (B13 "Fill sign-in").</summary>
    public void AddTrailing(FrameworkElement e)
    {
        ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Add(e, ColumnDefinitions.Count - 1);
    }

    private static Button Tool(string glyph, string name, Action click)
    {
        var b = new Button { Style = Ui.Style("SubtleButtonStyle"), Content = Ui.Icon(glyph, "SmallIconSize") };
        AutomationProperties.SetName(b, name);
        ToolTipService.SetToolTip(b, name);
        b.Click += (_, _) => click();
        return b;
    }

    /// <summary>Follow <paramref name="core"/>: its address, history buttons, loading state and lock.</summary>
    public void Attach(CoreWebView2? core)
    {
        _core = core;
        if (core is not null)
        {
            core.SourceChanged += (_, _) => ShowSource();
            core.HistoryChanged += (_, _) => Refresh();
            core.NavigationStarting += (_, _) => { _loading = true; Refresh(); };
            core.NavigationCompleted += (_, _) => { _loading = false; Refresh(); };
        }
        ShowSource();
    }

    /// <summary>The address the user typed, if it parses to http(s). Returns whether it navigated.</summary>
    public bool Go(string typed)
    {
        if (_core is null || WebAddress.Parse(typed) is not { } url) { ShowSource(); return false; }
        _core.Navigate(url.AbsoluteUri);
        return true;
    }

    /// <summary>The text in the address box (for tests).</summary>
    internal string AddressText => _address.Text;

    private void ShowSource()
    {
        if (_core is not null && _core.Source is { Length: > 0 } src && src != "about:blank") _address.Text = src;
        Refresh();
    }

    private void Refresh()
    {
        _back.IsEnabled = _core?.CanGoBack == true;
        _forward.IsEnabled = _core?.CanGoForward == true;
        _reload.IsEnabled = _core is not null;
        var label = _loading ? "Stop" : "Reload";
        AutomationProperties.SetName(_reload, label);
        ToolTipService.SetToolTip(_reload, label);
        var secure = WebAddress.IsSecure(_core?.Source);
        _lock.Glyph = (string)Application.Current.Resources[secure ? "GlyphLock" : "GlyphUnlock"];
        var lockName = secure ? "Secure connection (HTTPS)" : "Not secure (HTTP)";
        AutomationProperties.SetName(_lock, lockName);
        ToolTipService.SetToolTip(_lock, lockName);
    }
}

/// <summary>Turns typed text into an address, as the macOS address bar does.</summary>
public static class WebAddress
{
    /// <summary>
    /// <c>https://</c> is added when no scheme is typed; only http and https are accepted, so <c>file:</c>,
    /// <c>javascript:</c> and the rest are refused (null). Spaces are not searches: offline app, no search engine.
    /// </summary>
    public static Uri? Parse(string typed)
    {
        var t = typed.Trim();
        if (t.Length == 0 || t.Any(char.IsWhiteSpace)) return null;
        var hasScheme = t.Contains("://") || t.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) || t.StartsWith("data:", StringComparison.OrdinalIgnoreCase) || t.StartsWith("file:", StringComparison.OrdinalIgnoreCase);
        if (!Uri.TryCreate(hasScheme ? t : "https://" + t, UriKind.Absolute, out var url)) return null;
        return (url.Scheme == Uri.UriSchemeHttps || url.Scheme == Uri.UriSchemeHttp) && url.Host.Length > 0 ? url : null;
    }

    public static bool IsSecure(string? source) => Uri.TryCreate(source, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps;
}
