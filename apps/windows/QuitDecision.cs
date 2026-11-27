namespace Bastion.Shell;

/// <summary>
/// CLOSE-01: whether closing the window asks first, and the words it uses. The same rules and wording as the Mac
/// (<c>apps/macos/Sources/Bastion/QuitDecision.swift</c>): ask only when <c>terminal.confirm-close</c> is on, the quit is
/// not the app's own, and at least one session is live. Cancel is the default button.
/// </summary>
internal static class QuitDecision
{
    public const string Title = "Quit Gantry?";
    public const string QuitButton = "Quit";
    public const string CancelButton = "Cancel";

    public static bool ShouldAsk(bool confirmCloseOn, bool appDriven, int liveSessions) =>
        confirmCloseOn && !appDriven && liveSessions > 0;

    public static string Message(int liveSessions) => liveSessions == 1
        ? "1 session is still open. Quitting disconnects it."
        : $"{liveSessions} sessions are still open. Quitting disconnects them.";
}
