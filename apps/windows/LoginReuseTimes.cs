namespace Bastion.Shell;

/// <summary>
/// SEC-03: when a login remembered for this run may still be reused. Holds the time of the last successful sign-in per
/// connection and asks the core's rule (<c>bastion_remembered_login_usable</c>, C ABI 105) on every read, with the
/// minutes in force (<c>bastion_session_login_reuse_minutes</c>: user setting and managed maximum, the smaller
/// non-zero one). No time recorded means not usable (fail closed). No WinUI and no interop here, so
/// tests\login-reuse-unit compiles this file as it is.
/// </summary>
internal sealed class LoginReuseTimes(Func<ulong> now, Func<ulong, ulong, uint, bool> usable)
{
    internal const string SettingId = "security.session-login-reuse-minutes";

    /// <summary>Told to the core so it offers the setting: this app applies it to remembered logins.</summary>
    internal const string Capability = "session-login-reuse";

    private readonly Dictionary<string, ulong> _since = new();

    /// <summary>Seconds on <c>GetTickCount64</c>: monotonic, counts during sleep, ignores clock changes.</summary>
    internal static ulong MonotonicSeconds() => (ulong)(Environment.TickCount64 / 1000);

    /// <summary>The user's stored value in whole minutes; anything unreadable is 0, as the core reads it
    /// (<c>session_login_reuse_user_minutes</c>). The managed maximum still applies on top in the core.</summary>
    internal static uint UserMinutes(string? stored) => uint.TryParse(stored, out var m) && m <= 1440 ? m : 0;

    /// <summary>After a successful sign-in with the remembered login: its time starts again.</summary>
    internal void Started(string connectionId) => _since[connectionId] = now();

    /// <summary>True while the rule allows reuse under <paramref name="minutes"/>, read by the caller at every use.</summary>
    internal bool Usable(string connectionId, uint minutes) =>
        _since.TryGetValue(connectionId, out var at) && usable(at, now(), minutes);

    internal void Forget(string connectionId) => _since.Remove(connectionId);

    internal void Clear() => _since.Clear();
}
