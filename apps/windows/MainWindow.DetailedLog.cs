using Microsoft.UI.Dispatching;

namespace Bastion.Shell;

// Settings › About › Detailed logging (LOG-ERRCODES, as the Mac's DetailedLog.swift): debug lines in the app log, off
// again 24 hours after it was turned on. The start time is kept in detailed-log-since next to the library.
public sealed partial class MainWindow
{
    private const string DetailedLogSetting = "diagnostics.detailed-log";
    private static readonly TimeSpan DetailedLogMax = TimeSpan.FromHours(24); // core: settings::DETAILED_LOG_MAX_SECS
    private DispatcherQueueTimer? _detailedLogTimer;

    private string DetailedLogSincePath => Path.Combine(SessionDataDir, "detailed-log-since");

    /// <summary>At launch and every hour: turn the switch off once its 24 hours have run.</summary>
    private void ApplyDetailedLog()
    {
        if (Settings.Get(DetailedLogSetting) != "true") { DetailedLogOff(); return; }
        var since = ReadDetailedLogSince();
        if (since is null) WriteDetailedLogSince(DateTimeOffset.UtcNow);
        else if (DetailedLogExpired(since.Value, DateTimeOffset.UtcNow))
        {
            Settings.Set(DetailedLogSetting, "false");
            DetailedLogOff();
            AppLog.Info("Detailed logging turned off after 24 hours");
            return;
        }
        DetailedLogOn();
    }

    /// <summary>The user flipped the switch (SetSetting).</summary>
    private void DetailedLogChanged(string value)
    {
        if (value == "true") { WriteDetailedLogSince(DateTimeOffset.UtcNow); AppLog.Info("Detailed logging on"); DetailedLogOn(); }
        else { DetailedLogOff(); AppLog.Info("Detailed logging off"); }
    }

    internal static bool DetailedLogExpired(DateTimeOffset since, DateTimeOffset now) => now < since || now - since >= DetailedLogMax;

    private void DetailedLogOn()
    {
        AppLog.Detailed = true;
        if (_detailedLogTimer is not null) return;
        _detailedLogTimer = DispatcherQueue.CreateTimer();
        _detailedLogTimer.Interval = TimeSpan.FromHours(1);
        _detailedLogTimer.Tick += (_, _) => ApplyDetailedLog();
        _detailedLogTimer.Start();
    }

    private void DetailedLogOff()
    {
        AppLog.Detailed = false;
        _detailedLogTimer?.Stop();
        _detailedLogTimer = null;
        try { File.Delete(DetailedLogSincePath); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { AppLog.Warn("Detailed logging: start time not removed: " + e.Message); }
    }

    private DateTimeOffset? ReadDetailedLogSince()
    {
        try { return long.TryParse(File.ReadAllText(DetailedLogSincePath).Trim(), out var s) ? DateTimeOffset.FromUnixTimeSeconds(s) : null; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    private void WriteDetailedLogSince(DateTimeOffset at)
    {
        try { File.WriteAllText(DetailedLogSincePath, at.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { AppLog.Warn("Detailed logging: start time not saved: " + e.Message); }
    }
}
