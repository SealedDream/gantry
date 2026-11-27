namespace Bastion.Shell;

/// <summary>W22: a window frame put back inside a monitor's work area. Plain ints, so the console test checks it.</summary>
public static class WindowFrame
{
    /// <summary>Shrink the frame to fit the work area, then move it inside.</summary>
    public static (int X, int Y, int Width, int Height) ClampToWorkArea((int X, int Y, int Width, int Height) frame, (int X, int Y, int Width, int Height) work)
    {
        var w = Math.Min(frame.Width, work.Width);
        var h = Math.Min(frame.Height, work.Height);
        var x = Math.Clamp(frame.X, work.X, work.X + work.Width - w);
        var y = Math.Clamp(frame.Y, work.Y, work.Y + work.Height - h);
        return (x, y, w, h);
    }
}
