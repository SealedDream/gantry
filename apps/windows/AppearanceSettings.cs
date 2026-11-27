using System.Text.Json;
using System.Text.Json.Serialization;
using Bastion.Shell.Interop;

namespace Bastion.Shell;

/// <summary>
/// Appearance choices kept in <c>appearance.json</c> next to the library: the terminal colour theme (a core preset id)
/// and the navigation pane's collapsed and auto-hide state. A missing, unreadable or unknown value falls back to the default.
/// </summary>
internal sealed partial class AppearanceSettings
{
    internal sealed record Stored(string? TerminalTheme, bool NavHidden = false, bool NavAutoHide = false, bool FullScreenAutoDock = true, bool InspectorShown = false, int Version = 1);

    /// <summary>
    /// Version 2: a stored terminal theme is the user's own pick. Version 1 files wrote the old default (Bastion Dark) on
    /// every save, so there Bastion Dark means "never picked" and becomes Match app theme (owner 2026-11-15).
    /// </summary>
    private const int CurrentVersion = 2;

    /// <summary>The terminal theme value that follows the app's light or dark look (core termthemes::MATCH_APP), the default.</summary>
    public const string MatchAppTheme = "match-app";

    /// <summary>The theme a terminal.theme value stands for: Match app theme is Bastion Light in a light app and Bastion
    /// Dark otherwise (core termthemes::app_theme_id); any other value is itself.</summary>
    public static string TerminalThemeId(string value, bool lightApp) =>
        value == MatchAppTheme ? (lightApp ? "bastion-light" : "bastion-dark") : value;

    private readonly string _path;

    /// <summary>The terminal.theme value: Match app theme (the default), a bundled id or a custom one.</summary>
    public string TerminalTheme { get; private set; } = MatchAppTheme;
    /// <summary>The user collapsed the navigation pane (button, menu or Ctrl+Alt+N).</summary>
    public bool NavHidden { get; private set; }
    /// <summary>Collapse the navigation pane while a session tab has focus.</summary>
    public bool NavAutoHide { get; private set; }

    /// <summary>In full screen, the navigation pane leaves its column and slides in over the sessions from the left edge.</summary>
    public bool FullScreenAutoDock { get; private set; } = true;

    /// <summary>The details pane is open (one global choice; hidden for a new profile).</summary>
    public bool InspectorShown { get; private set; }

    private AppearanceSettings(string path) => _path = path;

    public static AppearanceSettings Load(string libraryPath)
    {
        var s = new AppearanceSettings(Path.Combine(Path.GetDirectoryName(libraryPath)!, "appearance.json"));
        try
        {
            var stored = JsonSerializer.Deserialize(File.ReadAllText(s._path), StoredJson.Default.Stored);
            // Custom ids too; the core falls back to Bastion Dark for a deleted one.
            if (stored?.TerminalTheme is { Length: > 0 } id && !(stored.Version < CurrentVersion && id == "bastion-dark")) s.TerminalTheme = id;
            s.NavHidden = stored?.NavHidden ?? false;
            s.NavAutoHide = stored?.NavAutoHide ?? false;
            s.FullScreenAutoDock = stored?.FullScreenAutoDock ?? true;
            s.InspectorShown = stored?.InspectorShown ?? false;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { /* defaults */ }
        return s;
    }

    /// <summary>Set and save (best effort: a failed write keeps the choice for this run).</summary>
    public void SetTerminalTheme(string id, bool save)
    {
        TerminalTheme = id;
        if (save) Save();
    }

    public void SetNav(bool hidden, bool autoHide, bool save)
    {
        NavHidden = hidden;
        NavAutoHide = autoHide;
        if (save) Save();
    }

    public void SetFullScreenAutoDock(bool on, bool save)
    {
        FullScreenAutoDock = on;
        if (save) Save();
    }

    public void SetInspector(bool shown, bool save)
    {
        InspectorShown = shown;
        if (save) Save();
    }

    private void Save()
    {
        try { File.WriteAllText(_path, JsonSerializer.Serialize(new Stored(TerminalTheme == MatchAppTheme ? null : TerminalTheme, NavHidden, NavAutoHide, FullScreenAutoDock, InspectorShown, CurrentVersion), StoredJson.Default.Stored)); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>Source-generated: no reflection warm-up on the start-up path, and safe to trim.</summary>
    [JsonSerializable(typeof(Stored))]
    internal sealed partial class StoredJson : JsonSerializerContext { }
}
