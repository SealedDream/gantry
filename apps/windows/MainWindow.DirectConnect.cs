using Bastion.Shell.Interop;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Bastion.Shell;

// Owner points 2, 3, 5, 17, 23, 26 (ported from Native Mac #698, #710, #713): a connection whose login is already known
// connects straight from double-click, Connect, Recent and Reconnect with no sheet, behind a small "Connecting…" /
// "Reconnecting…" card. The sheet appears only to ask something: no saved login, a host key or certificate question,
// a second factor, or a failed attempt (with its reason). A hung connect times out instead of spinning for ever.
public sealed partial class MainWindow
{
    /// <summary>How long a connect may take before it is reported as timed out (a genuine wait limit, not a guess).</summary>
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    /// <summary>A login that worked this run, kept in memory only (never written): reused by Reconnect, Recent and
    /// the next double-click. Cleared on authentication failure and when the vault locks.</summary>
    private sealed record RememberedLogin(string User, SshLoginKind Kind, string? Secret, string? KeyPath, string? Domain = null);

    private readonly Dictionary<string, RememberedLogin> _lastLogins = new();

    /// <summary>A1-NW-01: the saved login (credential id, no secret) the user picked for a connection this run when the
    /// core only offered it (saved for another connection on the host). It is reused without the sheet while the core
    /// still lists it; cleared with the remembered logins (authentication failure, vault lock, a change to the logins).</summary>
    private readonly Dictionary<string, string> _confirmedLogins = new();

    /// <summary>Connections whose "use this login from now on?" question was shown this run. It is asked once per
    /// connection per run, so a No is not asked again after every connect. Never cleared while the app runs.</summary>
    private readonly HashSet<string> _askedToKeepLogin = new();

    /// <summary>SEC-03: the time of the last successful sign-in for each of the two maps above.</summary>
    private readonly LoginReuseTimes _lastLoginTimes = NewReuseTimes();
    private readonly LoginReuseTimes _confirmedLoginTimes = NewReuseTimes();

    private static LoginReuseTimes NewReuseTimes() =>
        new(LoginReuseTimes.MonotonicSeconds, (at, now, minutes) => Native.bastion_remembered_login_usable(at, now, minutes) == 1);

    /// <summary>Minutes in force now: the user's setting and the managed maximum (the core decides, fail closed).</summary>
    private uint LoginReuseMinutes() =>
        Native.bastion_session_login_reuse_minutes(LoginReuseTimes.UserMinutes(SettingValue(LoginReuseTimes.SettingId)));

    /// <summary>The login that worked this run while SEC-03 allows reusing it; a login past its time is forgotten.</summary>
    private RememberedLogin? LastLogin(string connectionId)
    {
        if (!_lastLogins.TryGetValue(connectionId, out var login)) return null;
        if (_lastLoginTimes.Usable(connectionId, LoginReuseMinutes())) return login;
        _lastLogins.Remove(connectionId);
        _lastLoginTimes.Forget(connectionId);
        return null;
    }

    /// <summary>The login confirmed this run (credential id) while SEC-03 allows reusing it; else forgotten.</summary>
    private string? ConfirmedLogin(string connectionId)
    {
        if (!_confirmedLogins.TryGetValue(connectionId, out var id)) return null;
        if (_confirmedLoginTimes.Usable(connectionId, LoginReuseMinutes())) return id;
        _confirmedLogins.Remove(connectionId);
        _confirmedLoginTimes.Forget(connectionId);
        return null;
    }

    /// <summary>Call after every successful sign-in: the remembered login's reuse time starts again.</summary>
    private void RememberLogin(string connectionId, RememberedLogin login)
    {
        // Vault, Vaultwarden and provider logins are found again from the connection itself.
        if (login.Kind is not (SshLoginKind.Password or SshLoginKind.KeyFile or SshLoginKind.Agent)) return;
        _lastLogins[connectionId] = login;
        _lastLoginTimes.Started(connectionId);
    }

    private void ForgetLogin(string connectionId)
    {
        _lastLogins.Remove(connectionId);
        _confirmedLogins.Remove(connectionId);
        _lastLoginTimes.Forget(connectionId);
        _confirmedLoginTimes.Forget(connectionId);
    }

    private void ForgetAllLogins()
    {
        _lastLogins.Clear();
        _confirmedLogins.Clear();
        _lastLoginTimes.Clear();
        _confirmedLoginTimes.Clear();
    }

    /// <summary>
    /// Owner point 5: save a typed password to the vault as this connection's credential and assign it, so the next
    /// connect needs no sheet. A connection that already has a credential keeps it. A vault problem is announced, never
    /// a dialog: the session is already open.
    /// </summary>
    private void SaveTypedPassword(TreeItem item, string connectionId, string user, string password)
    {
        if (user.Length == 0 || password.Length == 0) return;
        try
        {
            var store = OpenCredentials();
            var id = store.SavePassword(null, item.Name, null, user, password);
            SaveCredentials(store); // off the UI thread: the seal's key derivation stalled every first open (WIN-SSH-OPEN-STALL)
            _library.SetCredential(connectionId, id);
            // After the new tab's first frame, not in it: the reload's own layout stacked on the tab's (WIN-SSH-OPEN-STALL).
            // The assignment must survive a restart (owner points 5, 26): saved now (off the UI thread) and again after the reload.
            SaveLibrary();
            DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => { if (!_windowClosed) ReloadThenSave(item.Id); });
            Announce($"Password saved for {item.Name}");
        }
        catch (BastionException ex) { Announce("The password was not saved: " + ex.Message); }
    }

    /// <summary>W8: Properties › Credentials › Password. The user name falls back to the inherited one; the connection's
    /// existing credential is replaced by the typed login (the owner typed it to be used).</summary>
    private void SavePropertiesPassword(EditorTarget.Connection c, string user, string password)
    {
        if (user.Length == 0)
            user = _library.PropertyValues(c.Id).FirstOrDefault(p => p.Key == "username")?.Effective ?? "";
        if (user.Length == 0) { Announce("Enter a user name to save the password with"); return; }
        try
        {
            var id = OpenCredentials().SavePassword(null, c.Name, null, user, password);
            OpenCredentials().Save();
            _library.SetCredential(c.Id, id);
            SaveLibrary();
            ForgetLogin(c.Id);
            Announce($"Password saved for {c.Name}");
        }
        catch (BastionException ex) { Announce("The password was not saved: " + ex.Message); }
    }

    /// <summary>Run a blocking connect off the UI thread, giving up after <see cref="ConnectTimeout"/>. A connect that
    /// finishes after the timeout is closed by <paramref name="discard"/>.</summary>
    private static async Task<(bool TimedOut, T? Result)> WithConnectTimeout<T>(Func<T> connect, Action<T> discard) where T : class
    {
        var work = Task.Run(connect);
        var done = await Task.WhenAny(work, Task.Delay(ConnectTimeout));
        if (done == work) return (false, await work);
        _ = work.ContinueWith(t => { if (t.Status == TaskStatus.RanToCompletion) discard(t.Result); }, TaskScheduler.Default);
        return (true, null);
    }

    private static string TimedOutText(string name) =>
        $"{name} did not answer within {ConnectTimeout.TotalSeconds:0} seconds. Check the host and the network, then try again.";

    /// <summary>Owner point 18: selecting a connection that has a live session shows that session (SSH, files, RDP or
    /// web), with no "Show Session" click. The tree keeps focus so arrowing through it still works.</summary>
    private void ShowLiveSession(TreeItem? item)
    {
        if (item?.Connection is not { } c) return;
        if (_active is { } current && (current.ConnectionId == c.Id || current.HostColorId == c.Id)) return;
        var live = OpenTabFor(c.Id) ?? _tabs.FirstOrDefault(t => (t.Rdp is not null || t.Web is not null) && t.HostColorId == c.Id);
        if (live is not null) ActivateTab(live, focus: false);
    }

    // ---- "Connecting…" / "Reconnecting…" card (owner point 17) ----

    private Border? _connectingCard;

    /// <summary>Show the small card over the session area while a direct connect runs; the sign-in itself is not shown.</summary>
    private void ShowConnectingCard(string text)
    {
        HideConnectingCard();
        var ring = new ProgressRing { IsActive = true, Width = 16, Height = 16 };
        var label = Ui.Text(text, "BodyTextStyle");
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = Ui.Double("Space8"), Children = { ring, label } };
        _connectingCard = new Border
        {
            Child = row,
            Padding = Ui.Thickness("DialogPadding"),
            Background = Ui.Brush(RootGrid, "ShellBackgroundBrush"),
            CornerRadius = new CornerRadius(Ui.Double("Space8")),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
        };
        AutomationProperties.SetAutomationId(_connectingCard, "ConnectingCard");
        AutomationProperties.SetName(_connectingCard, text);
        AutomationProperties.SetLiveSetting(_connectingCard, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);
        Grid.SetRow(_connectingCard, 1);
        Grid.SetRowSpan(_connectingCard, 2);
        RootGrid.Children.Insert(RootGrid.Children.IndexOf(ModalHost), _connectingCard);
    }

    private void HideConnectingCard()
    {
        if (_connectingCard is null) return;
        RootGrid.Children.Remove(_connectingCard);
        _connectingCard = null;
    }
}
