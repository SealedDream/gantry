using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Services, Processes and Event Log of a connection (owner point 11, as Mac ConnectionTools.swift; C ABI 93). Read-only: the
// core runs fixed scripts over SSH (systemctl/ps/journalctl on Linux, BusyBox ps on Alpine, PowerShell on Windows). An SSH
// connection reads its own host; an RDP connection with "management via SSH" on reads the same host over SSH. Opened from
// the connection's right-click menu (and from the connection page through OpenSystemViewAsync).
public sealed partial class MainWindow
{
    private static readonly TimeSpan EventLogPollInterval = TimeSpan.FromSeconds(5);
    private const int MaxEventLines = 2000;
    private SysViewClient? _sysView;
    private DispatcherTimer? _sysViewTimer;

    internal static readonly (string Id, string Label)[] SystemViews = [("services", "Services"), ("processes", "Processes"), ("eventlog", "Event Log")];

    private void AddSystemViewEntries(List<MenuFlyoutItemBase> menu, TreeItem item)
    {
        if (item.Connection is not { HasTools: true }) return;
        var tools = new MenuFlyoutSubItem { Text = "Tools" };
        AutomationProperties.SetAutomationId(tools, "ConnectionTools");
        foreach (var (id, label) in SystemViews) tools.Items.Add(ExtraEntry(label + "…", "terminal", (_, _) => _ = OpenSystemViewAsync(item, id)));
        menu.Add(tools);
    }

    /// <summary>Sign in (or use the login the user gives), trust the host key once verified, then show the view as a page.</summary>
    internal async Task OpenSystemViewAsync(TreeItem item, string view)
    {
        if (_modal is not null || item.Connection is not { } c) return;
        var label = SystemViews.FirstOrDefault(v => v.Id == view).Label ?? view;
        // W23: the connection's own or inherited login opens the view without asking; the sheet comes back only when it
        // fails. A1-NW-01: a login saved for another connection on the host is selected in the sheet and used on Open.
        var logins = await SavedLoginsAsync(_library, c.Id, passwordsOnly: false);
        // RDP management over SSH with its own SSH user (rdp.ssh_user): only logins for that user may sign in on their own.
        if (c.Protocol == "rdp")
        {
            string? sshUser = null;
            try { sshUser = _library.PropertyValues(c.Id).FirstOrDefault(v => v.Key == "rdp.ssh_user")?.Effective?.Trim(); }
            catch (BastionException) { }
            if (!string.IsNullOrEmpty(sshUser))
                logins = logins.Where(l => string.Equals(l.Credential.Username, sshUser, StringComparison.OrdinalIgnoreCase)).ToList();
        }
        var login = new ConnectForm(c.Username, logins.Count > 0 ? logins[0].Credential : null);
        login.OfferLogins(logins);
        string? trusted = null;
        try
        {
            var ask = !MayUseUnasked(c.Id, logins);
            while (true)
            {
                if (ask && !await ShowModal($"{label} on {item.Name}", login.Body, primary: "Open", cancel: "Cancel",
                        caption: c.Protocol == "rdp" ? "Management via SSH" : c.Host, validate: login.Validate, focus: login.FirstField)) return;
                ask = true;
                var (user, kind, secret, keyPath, sessions, library, fp) = (login.UserName, login.Kind, login.Secret, login.KeyPath, Sessions, _library, trusted);
                if (kind == SshLoginKind.Vault) sessions.SetCredentials(OpenCredentials());
                SysViewOpenResult result;
                try { result = await Task.Run(() => SysViewClient.Open(sessions, library, c.Id, view, user, kind, secret, keyPath, fp)); }
                catch (BastionException ex) { await ShowModal($"Could not open {label}", CodedErrorText("APP", ex.Message), primary: "OK", cancel: null); return; }
                if (_windowClosed) { result.View?.Dispose(); return; }
                if (result.View is { } v)
                {
                    ShowSystemView(item.Name, view, label, v);
                    if (login.ChosenLogin is { } used) await OfferToKeepLoginAsync(item, c.Id, used.Login);
                    return;
                }
                switch (result.Outcome)
                {
                    case ConnectOutcome.HostKeyUnknown when result.Fingerprint is { } f:
                        if (!await ShowModal("Trust this host key?", HostKeyPrompt.Body(c.Host, f, false), primary: "Trust and open", cancel: "Cancel", focusCancel: true)) return;
                        trusted = f;
                        ask = false;
                        continue;
                    case ConnectOutcome.AuthFailed:
                        await ShowModal("Authentication failed", ErrorText("Check the user name and the password or key, then try again."), primary: "OK", cancel: null);
                        continue;
                    default:
                        await ShowModal($"Could not open {label}", CodedErrorText("APP", result.Error ?? "The connection failed."), primary: "OK", cancel: null);
                        return;
                }
            }
        }
        finally { login.ClearSecrets(); }
    }

    private void CloseSystemView()
    {
        _sysViewTimer?.Stop();
        _sysViewTimer = null;
        var v = _sysView;
        _sysView = null;
        if (v is not null) _ = Task.Run(v.Dispose);
    }

    private void ShowSystemView(string host, string view, string label, SysViewClient client)
    {
        CloseSystemView();
        _sysView = client;
        _pageKind = "sysview";
        var filter = new TextBox { PlaceholderText = "Filter", MinWidth = 200 };
        AutomationProperties.SetName(filter, "Filter");
        var status = Ui.Text("Loading…", "CaptionSecondaryTextStyle");
        AutomationProperties.SetAutomationId(status, "SysViewStatus");
        var rows = new TextBox
        {
            IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, MinHeight = 320,
            FontFamily = new Microsoft.UI.Xaml.Media.FontFamily(TaskOutputFont),
        };
        ScrollViewer.SetHorizontalScrollBarVisibility(rows, ScrollBarVisibility.Auto);
        AutomationProperties.SetName(rows, label);
        AutomationProperties.SetAutomationId(rows, "SysViewRows");
        var log = new ComboBox { ItemsSource = new[] { "System", "Application", "Setup", "Security" }, SelectedIndex = 0, Visibility = Visibility.Collapsed };
        AutomationProperties.SetName(log, "Log");
        var lines = new List<string>();
        var os = "";
        var busy = false;

        string Format(object r) => r switch
        {
            SysServiceDto s => $"{s.Name,-40} {s.State,-10} {s.Sub,-10} {s.StartType,-10} {s.Description}",
            SysProcessDto p => $"{p.Pid,8} {p.User,-16} {(p.CpuPercent is { } pc ? $"{pc,6:0.0}%" : p.CpuSeconds is { } cs ? $"{cs,6:0}s" : "      "),-8} {p.MemBytes / 1024 / 1024,8} MB  {p.Name}",
            SysEventDto e => $"{e.Time} {e.Level,-8} {e.Source,-24} {e.Message}",
            _ => "",
        };
        void Render()
        {
            var q = filter.Text.Trim();
            var shown = q.Length == 0 ? lines : lines.Where(l => l.Contains(q, StringComparison.CurrentCultureIgnoreCase)).ToList();
            rows.Text = string.Join("\n", shown);
            status.Text = $"{os} · {shown.Count} of {lines.Count}";
            AutomationProperties.SetName(status, status.Text);
        }
        async Task Load(bool reset)
        {
            if (busy || _sysView != client) return;
            busy = true;
            var logName = log.SelectedItem as string;
            try
            {
                var (info, fetched) = await Task.Run(() =>
                {
                    var i = client.Info();
                    IEnumerable<object> got = view switch
                    {
                        "services" => client.Services(),
                        "processes" => client.Processes(),
                        _ => client.Tail(i.Os == "windows" ? logName : null, null),
                    };
                    return (i, got.Select(Format).ToList());
                });
                if (_sysView != client) return;
                os = info.Os == "windows" ? "Windows" : "Linux";
                log.Visibility = view == "eventlog" && info.Os == "windows" ? Visibility.Visible : Visibility.Collapsed;
                if (view == "eventlog" && !reset) lines.AddRange(fetched); else { lines.Clear(); lines.AddRange(fetched); }
                if (lines.Count > MaxEventLines) lines.RemoveRange(0, lines.Count - MaxEventLines);
                Render();
            }
            catch (BastionException ex) { status.Text = "Failed: " + ex.Message; AutomationProperties.SetName(status, status.Text); }
            finally { busy = false; }
        }

        filter.TextChanged += (_, _) => Render();
        log.SelectionChanged += (_, _) => _ = Load(reset: true);
        var refresh = new Button { Content = "Refresh" }.Quiet("GlyphRefresh", "Refresh now");
        AutomationProperties.SetName(refresh, "Refresh");
        refresh.Click += (_, _) => _ = Load(reset: view != "eventlog");
        var bar = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { filter, log, refresh } };
        var content = new Grid { RowSpacing = Ui.Double("Space8") };
        foreach (var h in new[] { GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star) }) content.RowDefinitions.Add(new RowDefinition { Height = h });
        Grid.SetRow(status, 1);
        Grid.SetRow(rows, 2);
        content.Children.Add(bar);
        content.Children.Add(status);
        content.Children.Add(rows);
        ShowPage(null, $"{label} · {host}", content);
        _ = Load(reset: true);
        if (view != "eventlog") return;
        _sysViewTimer = new DispatcherTimer { Interval = EventLogPollInterval };
        _sysViewTimer.Tick += (_, _) =>
        {
            if (_pageKind != "sysview" || PageHost.Visibility != Visibility.Visible) { CloseSystemView(); return; }
            _ = Load(reset: false);
        };
        _sysViewTimer.Start();
    }
}
