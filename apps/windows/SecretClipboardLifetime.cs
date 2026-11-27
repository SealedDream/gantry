namespace Bastion.Shell;

/// <summary>
/// The setting "Clear copied passwords after" (A3-S1): how long a copied password stays on the clipboard. The same rule
/// as the core's <c>secret_clipboard_seconds</c> (core/src/settings.rs) and the Mac's SecretPasteboard: 30, 45 or 60 s,
/// and the shortest one when the stored value cannot be read or is anything else, so a fault never leaves a password
/// there longer. No WinUI and no interop here, so tests\secret-clipboard-unit compiles this file as it is.
/// </summary>
internal static class SecretClipboardLifetime
{
    internal const string SettingId = "security.clipboard-clear-seconds";

    /// <summary>Told to the core so it offers the setting: this app clears a copied password after that time.</summary>
    internal const string Capability = "secret-clipboard-lifetime";

    /// <summary>The stored values the core accepts, in seconds.</summary>
    internal static readonly string[] Choices = ["30", "45", "60"];

    internal const int FallbackSeconds = 30;

    /// <summary>The lifetime for a stored value; null means the settings could not be read.</summary>
    internal static TimeSpan From(string? stored) =>
        TimeSpan.FromSeconds(stored is not null && Array.IndexOf(Choices, stored) >= 0 ? int.Parse(stored) : FallbackSeconds);

    /// <summary>The lifetime for the value <paramref name="readStored"/> returns now, at copy time.</summary>
    internal static TimeSpan Read(Func<string> readStored)
    {
        string? stored;
        // Whatever stops the read (a damaged or locked settings.json, the core), the copy still happens and gets the
        // shortest lifetime.
        try { stored = readStored(); }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"clipboard lifetime setting not read, using {FallbackSeconds} s: {ex.Message}");
            stored = null;
        }
        return From(stored);
    }
}
