namespace Bastion.Shell;

/// <summary>No-op stand-in for the app's LeakProbe (LeakProbe.cs needs WinUI): TerminalNative.cs calls it since #1233.</summary>
internal static partial class LeakProbe
{
    public static void Track(object o, string kind) { }
    public static void MarkDisposed(object o) { }
    public static void SessionOpened() { }
    public static void SessionFreed() { }
}
