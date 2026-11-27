using Microsoft.UI.Xaml;

namespace Bastion.Shell;

/// <summary>CLOSE-01: count every live session before the window closes, from state each view already keeps.</summary>
public sealed partial class MainWindow
{
    /// <summary>Task runs (single host, or one per host for Run on…) whose output dialog is open and not finished.</summary>
    private int _runningTaskRuns;

    /// <summary>
    /// Live sessions: each terminal pane whose program is alive, each connected RDP or VNC tab, each open web tab,
    /// each file transfer running or queued, and each task run not finished. A restored tab that has not connected
    /// yet counts as not live; so does an idle Files panel.
    /// </summary>
    internal int LiveSessionCount()
    {
        var count = 0;
        foreach (var tab in _tabs)
        {
            count += tab.AllPanes.Count(p => !p.Session.IsDisposed && p.Session.IsAlive);
            if (tab.Rdp is { IsLive: true }) count++;
            if (tab.Web is not null) count++;
            if (tab.Files is { } files) count += files.RunningTransfers;
        }
        return count + _runningTaskRuns;
    }

    /// <summary>The question; true when the user chose Quit. Cancel has focus, so Return and Esc both keep the app.</summary>
    private Task<bool> ConfirmQuit(int live)
    {
        var body = Ui.Text(QuitDecision.Message(live), "BodyTextStyle");
        body.TextWrapping = TextWrapping.Wrap;
        return ShowModal(QuitDecision.Title, body, primary: QuitDecision.QuitButton, cancel: QuitDecision.CancelButton, focusCancel: true);
    }
}
