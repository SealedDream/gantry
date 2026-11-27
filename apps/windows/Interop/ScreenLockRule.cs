namespace Bastion.Shell.Interop;

/// <summary>
/// What a WM_WTSSESSION_CHANGE does (lock on OS screen lock). Pure, so the console check runs it without a window.
/// </summary>
public static class ScreenLockRule
{
    public const int WTS_CONSOLE_DISCONNECT = 0x2;
    public const int WTS_REMOTE_DISCONNECT = 0x4;
    public const int WTS_SESSION_LOCK = 0x7;

    /// <summary>The user is no longer at this desktop: screen lock, console switched away, RDP disconnected.</summary>
    public static bool LeavesDesktop(int reason) => reason is WTS_SESSION_LOCK or WTS_CONSOLE_DISCONNECT or WTS_REMOTE_DISCONNECT;

    /// <summary>
    /// Whether credentials lock, from the value of <c>security.lock-on-screen-lock</c> (default on). Fail closed: only an
    /// explicit "false" keeps them open. A value that could not be read ("" or null) locks, as the default does.
    /// </summary>
    public static bool LocksCredentials(string? setting) => setting != "false";
}
