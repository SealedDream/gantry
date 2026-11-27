using System;
using System.Globalization;
using Bastion.Shell.Interop;
using Microsoft.UI.Xaml;

namespace Bastion.Shell;

// The inspector footer (owner rule: exactly two lines): "Last connected: <time> as <user>" and "Last result: OK / <short
// error>". The core keeps the history next to the library, owner-only and secret-free; the app only records outcomes.
public sealed partial class MainWindow
{
    /// <summary>Show the footer for a connection, or hide it for folders and nothing selected.</summary>
    private void UpdateInspectorFooter(ConnectionDto? c)
    {
        if (c is null || _library.IsQuickConnect)
        {
            InspectorFooter.Visibility = Visibility.Collapsed;
            return;
        }
        ConnectionHistoryDto h;
        try { h = ConnectionHistory.Get(HistoryDir, c.Id); }
        catch (BastionException) { h = new(null, null, null); } // an unreadable history only blanks the footer
        LastConnectedText.Text = "Last connected: " + (h.LastConnectedAt is { } at
            ? FormatWhen(DateTimeOffset.FromUnixTimeSeconds(at).ToLocalTime(), DateTimeOffset.Now) + (h.LastUser is { Length: > 0 } u ? " as " + u : "")
            : "Never");
        LastResultText.Text = "Last result: " + (h.LastResult ?? "—");
        InspectorFooter.Visibility = Visibility.Visible;
    }

    /// <summary>"Today 14:05", "Yesterday 09:12", or a short date and time.</summary>
    internal static string FormatWhen(DateTimeOffset when, DateTimeOffset now)
    {
        var time = when.ToString("t", CultureInfo.CurrentCulture);
        var days = (now.Date - when.Date).Days;
        return days switch
        {
            0 => "Today " + time,
            1 => "Yesterday " + time,
            _ => when.ToString("d", CultureInfo.CurrentCulture) + " " + time,
        };
    }

    /// <summary>Record a successful connect and refresh the footer if it shows this connection.</summary>
    private void RecordConnected(string connectionId, string? user)
    {
        if (_library.IsQuickConnect) return;
        // B5: on the next turn, so an SSH tab is tied to its connection first (Supervise) and a snippet hook finds it.
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => RunHooks("after_connect", connectionId));
        try { ConnectionHistory.Success(HistoryDir, connectionId, user); }
        catch (BastionException) { } // history is informational; a failed write must never block a session
        RefreshInspectorFor(connectionId);
    }

    /// <summary>Record a failed connect (the core shortens the message and drops anything secret-looking).</summary>
    private void RecordFailed(string connectionId, string error)
    {
        if (_library.IsQuickConnect) return;
        RecordFailedActivity(connectionId, ActivityClient.FailureReason(error));
        try { ConnectionHistory.Failure(HistoryDir, connectionId, error); }
        catch (BastionException) { }
        RefreshInspectorFor(connectionId);
    }
}
