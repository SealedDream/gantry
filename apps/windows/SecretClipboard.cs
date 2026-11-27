using Microsoft.UI.Dispatching;
using Windows.ApplicationModel.DataTransfer;

namespace Bastion.Shell;

/// <summary>
/// A secret on the clipboard (QA S1, as Mac SecretPasteboard): kept out of clipboard history and cloud sync, and cleared after
/// its lifetime, but only while the clipboard still holds this copy, so a later copy by the user is left alone.
/// </summary>
internal static class SecretClipboard
{
    /// <summary>The setting "Clear copied passwords after" (A3-S1), read from <paramref name="settingsPath"/> now, at copy time.</summary>
    internal static TimeSpan ConfiguredLifetime(string settingsPath) => SecretClipboardLifetime.Read(() =>
    {
        using var settings = Interop.SettingsClient.Open(settingsPath);
        return settings.Get(SecretClipboardLifetime.SettingId);
    });

    internal static void Copy(string secret, TimeSpan lifetime)
    {
        var data = new DataPackage();
        data.SetText(secret);
        Clipboard.SetContentWithOptions(data, new ClipboardContentOptions { IsAllowedInHistory = false, IsRoamable = false });
        var queue = DispatcherQueue.GetForCurrentThread();
        _ = ClearLaterAsync(secret, lifetime, queue);
    }

    private static async Task ClearLaterAsync(string secret, TimeSpan lifetime, DispatcherQueue? queue)
    {
        await Task.Delay(lifetime).ConfigureAwait(false);
        if (queue is null) return;
        queue.TryEnqueue(async () =>
        {
            try
            {
                var view = Clipboard.GetContent();
                if (!view.Contains(StandardDataFormats.Text)) return;
                if (await view.GetTextAsync() == secret) Clipboard.Clear();
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"secret clipboard clear failed: {ex.Message}"); }
        });
    }
}
