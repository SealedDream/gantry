using System.Text.Json;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;

namespace Bastion.Shell;

/// <summary>
/// Where a web connection points, as WebTarget in WebTab.swift: the host field may hold a full http(s) URL, otherwise
/// <c>https://host[:port]</c>. Any other scheme (file:, javascript:, …) is refused.
/// </summary>
public static class WebTarget
{
    public static Uri? Url(string host, int? port)
    {
        var raw = host.Contains("://") ? host : $"https://{host}{(port is { } p ? ":" + p : "")}";
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var url)) return null;
        return (url.Scheme == Uri.UriSchemeHttps || url.Scheme == Uri.UriSchemeHttp) && url.Host.Length > 0 ? url : null;
    }

    /// <summary>Only http(s) (and about:blank) navigations stay in the tab; other schemes are cancelled.</summary>
    public static bool Allowed(string? uri) =>
        Uri.TryCreate(uri, UriKind.Absolute, out var u) && (u.Scheme is "https" or "http" or "about");
}

/// <summary>Where a web download is saved: a safe, unused file name in the Downloads folder.</summary>
public static class WebDownloads
{
    public static string TargetPath(string downloadsDir, string? suggestedPath)
    {
        var leaf = Path.GetFileName((suggestedPath ?? "").Replace('/', '\\'));
        foreach (var c in Path.GetInvalidFileNameChars()) leaf = leaf.Replace(c, '_');
        leaf = leaf.Trim().TrimEnd('.');
        if (leaf.Length == 0) leaf = "download";
        Directory.CreateDirectory(downloadsDir);
        var stem = Path.GetFileNameWithoutExtension(leaf);
        var ext = Path.GetExtension(leaf);
        var path = Path.Combine(downloadsDir, leaf);
        for (var n = 1; File.Exists(path) || Directory.Exists(path); n++) path = Path.Combine(downloadsDir, $"{stem} ({n}){ext}");
        return path;
    }
}

/// <summary>
/// A web page in a tab, in WebView2. Like the non-persistent WKWebsiteDataStore on macOS, each tab runs InPrivate in its
/// own throwaway user-data folder, so cookies and storage never outlive the tab or leak between connections. No host
/// objects or script bridges are installed, new windows open in the same tab, and downloads save to Downloads without overwriting. An address bar
/// (<see cref="WebAddressBar"/>) sits above the page.
/// </summary>
public sealed partial class WebTabView : UserControl, IDisposable
{
    private readonly WebView2 _web = new();
    private readonly WebAddressBar _bar = new();
    private readonly string _profile;
    /// <summary>True for a throwaway InPrivate folder deleted with the tab; false for a tunnel's own data folder.</summary>
    private readonly bool _ephemeral;
    /// <summary>A saved SOCKS tunnel's local port, or null.</summary>
    private readonly int? _socksPort;
    private readonly TextBlock _error = new() { Margin = new Thickness(16), TextWrapping = TextWrapping.Wrap, Visibility = Visibility.Collapsed, IsTextSelectionEnabled = true };
    private bool _disposed;

    public Uri Url { get; }

    /// <summary>Raised with the page title when it changes, for the tab header.</summary>
    public event EventHandler<string>? TitleChanged;

    private WebAutofillButton? _autofill;
    /// <summary>A resource of the current page came over plain http (mixed content): no sign-in fill (B13 T27.5).</summary>
    private bool _insecureContent;
    /// <summary>A navigation has started and not completed: no sign-in fill until the new page settles (review of #1008, item 1).</summary>
    private bool _navigating;

    /// <summary>The "Fill sign-in" button for a saved web connection (B13); shown only when the core offers it.</summary>
    public void EnableAutofill(WebAutofillHooks hooks)
    {
        _autofill = new WebAutofillButton(hooks, () => (_web.CoreWebView2, WebAddress.IsSecure(_web.CoreWebView2?.Source) && !_insecureContent, _navigating));
        _bar.AddTrailing(_autofill.Button);
    }

    /// <summary>The B13 button's last result, for the UI test (null after a fill).</summary>
    internal string? AutofillNotice => _autofill?.LastNotice;

    /// <summary>The SOCKS route through a gateway this tab loads over, closed with the tab; null for a direct page.</summary>
    private GatewayRoute? _route;

    /// <param name="socksPort">A running saved SOCKS tunnel's port: every request, DNS included, goes over it.</param>
    /// <param name="dataDir">A tunnel's own persistent data folder (from the core); null for a throwaway InPrivate one.</param>
    public WebTabView(Uri url, GatewayRoute? route = null, int? socksPort = null, string? dataDir = null)
    {
        Url = url;
        _route = route;
        _socksPort = route is { IsSocks: true } r ? r.Port : socksPort;
        _ephemeral = dataDir is null;
        _profile = dataDir ?? Path.Combine(Path.GetTempPath(), "Gantry-web-" + Guid.NewGuid().ToString("N"));
        IsTabStop = false;
        var page = new Grid { Children = { _web, _error } };
        var root = new Grid { RowDefinitions = { new RowDefinition { Height = GridLength.Auto }, new RowDefinition { Height = new GridLength(1, GridUnitType.Star) } } };
        Grid.SetRow(page, 1);
        root.Children.Add(_bar);
        root.Children.Add(page);
        Content = root;
        // The session host paints the terminal surface; a web page and its bar sit on the app's own layer instead,
        // so the bar's icons keep their contrast in both themes.
        void Paint() => root.Background = Ui.Brush(this, "LayerBackgroundBrush");
        ActualThemeChanged += (_, _) => Paint();
        Loaded += async (_, _) => { Paint(); await StartAsync(); };
    }

    private async Task StartAsync()
    {
        if (_web.CoreWebView2 is not null || _disposed) return;
        try
        {
            if (!_ephemeral) AllowBrowserSandbox(_profile);
            var env = await CoreWebView2Environment.CreateWithOptionsAsync(null, _profile, new CoreWebView2EnvironmentOptions
            {
                // Through a gateway every request, DNS included, goes over its loopback SOCKS proxy; no direct fallback.
                // WebRTC is kept on the proxy too, so UDP never goes around it.
                AdditionalBrowserArguments = _socksPort is { } port ? $"--proxy-server=socks5://127.0.0.1:{port} --host-resolver-rules=\"MAP * ~NOTFOUND , EXCLUDE 127.0.0.1\" --force-webrtc-ip-handling-policy=disable_non_proxied_udp" : null,
            });
            var options = env.CreateCoreWebView2ControllerOptions();
            options.IsInPrivateModeEnabled = _ephemeral;
            await _web.EnsureCoreWebView2Async(env, options);
        }
        catch (Exception ex)
        {
            // Most often: the WebView2 Runtime is not installed.
            ShowError("Could not start the web view (is the Microsoft Edge WebView2 Runtime installed?): " + ex.Message);
            return;
        }
        // EnsureCoreWebView2Async succeeded, so CoreWebView2 is set unless the tab was closed meanwhile.
        if (_disposed || _web.CoreWebView2 is not { } core) return;
        var s = core.Settings;
        s.AreHostObjectsAllowed = false;
        s.IsWebMessageEnabled = false;
        s.AreDevToolsEnabled = false;
        s.IsPasswordAutosaveEnabled = false;
        s.IsGeneralAutofillEnabled = false;
        if (TestHooks.WebFixtureDir is { Length: > 0 } fixture && Directory.Exists(fixture))
        {
            core.SetVirtualHostNameToFolderMapping("autofill.test", fixture, CoreWebView2HostResourceAccessKind.Allow);
            // A second origin with the same pages: the fill must refuse it (B13 suite, test builds only).
            core.SetVirtualHostNameToFolderMapping("other.autofill.test", fixture, CoreWebView2HostResourceAccessKind.Allow);
        }
        core.NavigationStarting += (_, e) => { if (!WebTarget.Allowed(e.Uri)) e.Cancel = true; };
        core.FrameNavigationStarting += (_, e) => { if (!WebTarget.Allowed(e.Uri)) e.Cancel = true; };
        core.NewWindowRequested += (_, e) =>
        {
            e.Handled = true;
            if (WebTarget.Allowed(e.Uri)) core.Navigate(e.Uri);
        };
        core.DownloadStarting += (_, e) =>
        {
            // Downloads go to the Downloads folder under a name that does not exist yet, never over a file (as on macOS).
            try { e.ResultFilePath = WebDownloads.TargetPath(SftpPanel.DownloadsDir, e.ResultFilePath); e.Handled = true; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { e.Cancel = true; }
        };
        core.DocumentTitleChanged += (_, _) => TitleChanged?.Invoke(this, core.DocumentTitle);
        core.NavigationCompleted += (_, e) =>
        {
            if (!e.IsSuccess && e.WebErrorStatus != CoreWebView2WebErrorStatus.OperationCanceled)
                ShowError($"Could not load {Url}: {e.WebErrorStatus}.");
        };
        core.NavigationStarting += (_, _) => _error.Visibility = Visibility.Collapsed;
        core.NavigationStarting += (_, _) => { _navigating = true; _insecureContent = false; _autofill?.Refresh(); };
        core.NavigationCompleted += (_, _) => _navigating = false;
        // Test builds with BASTION_WEBFILL_TRACE only: each loaded page's origin and title (UIA cannot see WebView2 content).
        if (TestHooks.WebFillTrace is not null) core.NavigationCompleted += (_, e) => WebAutofillButton.TraceForTest($"WEB-PAGE {(e.IsSuccess ? "loaded" : "failed")} title={core.DocumentTitle}", core.Source);
        core.SourceChanged += (_, _) => _autofill?.Refresh();
        // Mixed content: any plain http or ws response on this page marks it not secure until the next navigation.
        // Responses still arriving for the previous page during a navigation only make fill stricter.
        core.WebResourceResponseReceived += (_, e) =>
        {
            if (Uri.TryCreate(e.Request.Uri, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == "ws")) _insecureContent = true;
        };
        core.ServerCertificateErrorDetected += (_, _) => _insecureContent = true;
        _bar.Attach(core);
        core.Navigate(Url.AbsoluteUri);
    }

    /// <summary>
    /// The core creates a tunnel's data folder owner-only (protected DACL, the user alone). Edge's sandboxed network
    /// and storage services run as app containers, which that DACL shuts out, and WebView2 then never starts. Let the
    /// two app-package groups in, for this folder only; other users still have no access.
    /// </summary>
    private static void AllowBrowserSandbox(string dir)
    {
        var info = new DirectoryInfo(dir);
        var acl = System.IO.FileSystemAclExtensions.GetAccessControl(info);
        foreach (var sid in new[] { "S-1-15-2-1", "S-1-15-2-2" })
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid),
                System.Security.AccessControl.FileSystemRights.Modify,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        System.IO.FileSystemAclExtensions.SetAccessControl(info, acl);
    }

    /// <summary>Snapshot mode: type an address into the bar and press Enter.</summary>
    internal bool GoForSnapshot(string typed) => _bar.Go(typed);

    /// <summary>Snapshot mode: what the address bar shows.</summary>
    internal string AddressForSnapshot => _bar.AddressText;

    private void ShowError(string message)
    {
        _error.Text = message;
        _error.Visibility = Visibility.Visible;
    }

    /// <summary>
    /// Snapshot mode: RenderTargetBitmap cannot see WebView2's own surface, so put the page's preview (CapturePreviewAsync)
    /// in an Image over it before the window is rendered. Never used outside snapshot mode.
    /// </summary>
    internal async Task FreezeForSnapshot()
    {
        if (_web.CoreWebView2 is not { } core) return;
        using var stream = new Windows.Storage.Streams.InMemoryRandomAccessStream();
        await core.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png, stream);
        stream.Seek(0);
        var image = new Microsoft.UI.Xaml.Media.Imaging.BitmapImage();
        await image.SetSourceAsync(stream);
        ((Grid)((Grid)Content).Children[1]).Children.Add(new Image { Source = image, Stretch = Microsoft.UI.Xaml.Media.Stretch.Fill });
    }

    /// <summary>Snapshot mode: the page's body text, read by script (the snapshot's own check, not a bridge).</summary>
    internal async Task<string> BodyTextForSnapshot() =>
        _web.CoreWebView2 is { } core ? JsonSerializer.Deserialize(await core.ExecuteScriptAsync("document.body ? document.body.innerText : ''"), AotJson.Options.Info<string>()) ?? "" : "";

    /// <summary>Snapshot mode: the address the view is on now.</summary>
    internal string? SourceForSnapshot => _web.CoreWebView2?.Source;

    /// <summary>Snapshot mode: run a script in the page (to try a blocked navigation).</summary>
    internal async Task RunScriptForSnapshot(string script) { if (_web.CoreWebView2 is { } core) await core.ExecuteScriptAsync(script); }

    /// <summary>Snapshot mode: the page's own title once loaded, or null.</summary>
    public string? DocumentTitle => _web.CoreWebView2?.DocumentTitle;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _web.Close();
        _route?.Dispose();
        _route = null;
        if (!_ephemeral) return;
        // The browser process lets go of the folder shortly after Close; remove it then, best effort.
        var dir = _profile;
        _ = Task.Run(async () =>
        {
            for (var i = 0; i < 20 && Directory.Exists(dir); i++)
            {
                try { Directory.Delete(dir, recursive: true); }
                catch (IOException) { await Task.Delay(250); }
                catch (UnauthorizedAccessException) { await Task.Delay(250); }
            }
        });
    }
}
