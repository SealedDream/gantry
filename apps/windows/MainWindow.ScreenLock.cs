using Bastion.Shell.Interop;
using System.Runtime.InteropServices;

namespace Bastion.Shell;

// Lock on OS screen lock (Settings › Security › "Lock credentials when the screen locks", on by default): the window
// registers for WTS session notifications and Lock Credentials runs when the workstation locks, when the console is
// switched to another user (fast user switching) or when an RDP session to this PC is disconnected. Open sessions keep
// running; the next connect that needs a secret unwraps the vault key again (DPAPI) or asks for the Vaultwarden password.
public sealed partial class MainWindow
{
    private const uint WM_WTSSESSION_CHANGE = 0x02B1;
    private const uint NOTIFY_FOR_THIS_SESSION = 0;
    private const nuint ScreenLockSubclassId = 0x4241_5354; // "BAST"

    private delegate IntPtr SubclassProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam, nuint id, nuint refData);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSRegisterSessionNotification(IntPtr hwnd, uint flags);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wtsapi32.dll")]
    private static extern bool WTSUnRegisterSessionNotification(IntPtr hwnd);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("comctl32.dll", SetLastError = true)]
    private static extern bool SetWindowSubclass(IntPtr hwnd, SubclassProc proc, nuint id, nuint refData);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("comctl32.dll")]
    private static extern bool RemoveWindowSubclass(IntPtr hwnd, SubclassProc proc, nuint id);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("comctl32.dll")]
    private static extern IntPtr DefSubclassProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    /// <summary>Kept in a field so the delegate the native side calls is never collected.</summary>
    private SubclassProc? _screenLockProc;

    /// <summary>Whether a session-change reason means the user is no longer at this desktop.</summary>
    internal static bool LeavesDesktop(int reason) => ScreenLockRule.LeavesDesktop(reason);

    /// <summary>Start listening for screen lock. A failure is announced once; idle auto-lock still works.</summary>
    private void InitScreenLock()
    {
        _screenLockProc = OnSessionMessage;
        var hwnd = Hwnd;
        try
        {
            var subclassed = SetWindowSubclass(hwnd, _screenLockProc, ScreenLockSubclassId, 0);
            var subclassError = subclassed ? 0 : Marshal.GetLastWin32Error();
            var registered = subclassed && WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
            var registerError = subclassed && !registered ? Marshal.GetLastWin32Error() : 0;
            TraceLine($"screen-notify hwnd=0x{hwnd.ToInt64():X} subclass={subclassed} registered={registered} error={(subclassed ? registerError : subclassError)}");
            if (!registered)
            {
                // The subclass alone still sees a lock posted to the window; only the OS notification is missing.
                Announce($"Screen lock cannot be detected (error {(subclassed ? registerError : subclassError)}); idle auto-lock still applies");
                if (!subclassed) return;
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            TraceLine("screen-notify unavailable");
            Announce("Screen lock cannot be detected on this system; idle auto-lock still applies");
            return;
        }
        Closed += (_, _) =>
        {
            WTSUnRegisterSessionNotification(hwnd);
            RemoveWindowSubclass(hwnd, _screenLockProc, ScreenLockSubclassId);
        };
    }

    private IntPtr OnSessionMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam, nuint id, nuint refData)
    {
        if (msg == WM_WTSSESSION_CHANGE && LeavesDesktop((int)wParam))
        {
            // Lock after the message returns so no dialog ever runs inside the window procedure. Credentials follow
            // "Lock on screen lock" and fail closed: a setting that cannot be read locks, as the default does (an
            // unreadable value used to leave the vault open). Protected documents always lock on screen lock (Codex W03).
            var locks = ScreenLockRule.LocksCredentials(SettingValue("security.lock-on-screen-lock"));
            Action work = locks ? LockCredentials : LockDocumentsOnScreenLock;
            var queued = DispatcherQueue.TryEnqueue(() => work());
            ScreenLockTrace((int)wParam, locks, queued);
            // The queue refuses only while the window shuts down; lock here then rather than not at all.
            if (!queued) work();
        }
        return DefSubclassProc(hwnd, msg, wParam, lParam);
    }

    private void LockDocumentsOnScreenLock()
    {
        if (DocumentLockDue(TimeSpan.Zero, screenLocked: true, asleep: false) == AutoLockReason.ScreenLocked)
            LockDocumentsFor(AutoLockReason.ScreenLocked);
    }

    /// <summary>Test seam: each session-change message that leaves the desktop, so a missed lock shows where it stopped.</summary>
    private static void ScreenLockTrace(int reason, bool locks, bool queued) =>
        TraceLine($"screen reason={reason} credentials={(locks ? "lock" : "keep")} queued={queued}");

    private static void TraceLine(string line)
    {
        if (TestHooks.LockTrace is not { } path) return;
        try { System.IO.File.AppendAllText(path, line + "\n"); }
        catch (System.IO.IOException) { }
    }
}
