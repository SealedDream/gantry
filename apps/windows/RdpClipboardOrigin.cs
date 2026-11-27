namespace Bastion.Shell;

/// <summary>
/// App-wide record of the last RDP server write to the Windows clipboard (SEC-6). Text one session's server copied
/// must never be offered to another session's server: every session watches the same clipboard. A write is identified
/// by the Win32 clipboard sequence number right after it; any later copy (local or another server) changes that number,
/// so the tag clears itself. UI thread only.
/// </summary>
internal static class RdpClipboardOrigin
{
    private static object? s_owner;
    private static uint s_sequence;

    /// <summary>Record that <paramref name="owner"/>'s server just wrote the clipboard, now at <paramref name="sequence"/>.</summary>
    public static void MarkRemoteWrite(object owner, uint sequence)
    {
        s_owner = owner;
        s_sequence = sequence;
    }

    /// <summary>False when the clipboard at <paramref name="sequence"/> still holds another session's server text.</summary>
    public static bool MayOffer(object self, uint sequence) =>
        s_owner is null || ReferenceEquals(s_owner, self) || s_sequence != sequence;

    /// <summary>A closing session drops its tag; its text stays foreign to the others until the clipboard changes.</summary>
    public static void Forget(object owner)
    {
        // Keep the tag: the server text is still on the clipboard and must not reach other servers. Only the
        // reference goes, so a closed session is not kept alive; a fresh object still differs from every live session.
        if (ReferenceEquals(s_owner, owner)) s_owner = ClosedOwner;
    }

    private static readonly object ClosedOwner = new();

    internal static void ResetForTests() { s_owner = null; s_sequence = 0; }
}
