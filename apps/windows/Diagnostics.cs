using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bastion.Shell;

// Bastion menu › Export Diagnostics… (LOG-NATIVE-01 item 7, Native Windows; the Mac's Diagnostics.swift) and the app's own
// small log. No WinUI, so the activity console test compiles it as it is. The zip holds no host name, connection name,
// user name, password, key or transcript: settings keep only true/false and numbers, the library gives counts only, and
// the logs have the profile folder, account name and computer name replaced. It stays where the user saves it.

/// <summary>The app's own log: info, warn and error lines in bastion.log next to the library, capped at
/// <see cref="MaxBytes"/> with one older file kept. Callers never pass secrets, host names, connection names or
/// transcript text.</summary>
public static class AppLog
{
    public const int MaxBytes = 512 * 1024;
    private static readonly object Gate = new();
    public static string? Path { get; set; }

    public static void Info(string message) => Write("INFO", message);
    public static void Warn(string message) => Write("WARN", message);
    public static void Error(string message) => Write("ERROR", message);

    /// <summary>Detailed logging (LOG-ERRCODES): debug lines are written only while this is on.</summary>
    public static bool Detailed { get; set; }

    /// <summary>Cleans every debug and error line; the app sets the core's redaction. Identity in the console test.</summary>
    public static Func<string, string> Redactor { get; set; } = s => s;

    /// <summary>Only with Detailed logging on. Never pass secrets or keystrokes; the line is redacted too.</summary>
    public static void Debug(Func<string> message)
    {
        if (Detailed) Write("DEBUG", Redactor(message()));
    }

    /// <summary>An error shown to the user, with its support code, redacted.</summary>
    public static void Failure(string code, string message) => Write("ERROR", code + " " + Redactor(message));

    /// <summary>Appends one line; never throws (a log that cannot be written must not break the app).</summary>
    public static void Write(string level, string message, DateTimeOffset? now = null)
    {
        if (Path is not { } path) return;
        var line = $"{(now ?? DateTimeOffset.UtcNow).ToUniversalTime():yyyy-MM-ddTHH:mm:ssZ} {level} {message.Replace('\r', ' ').Replace('\n', ' ')}\r\n";
        lock (Gate)
        {
            try
            {
                var info = new FileInfo(path);
                if (info.Exists && info.Length + Encoding.UTF8.GetByteCount(line) > MaxBytes)
                    File.Move(path, path + ".1", overwrite: true);
                File.AppendAllText(path, line);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                System.Diagnostics.Debug.WriteLine($"Gantry: app log write failed: {e.Message}");
            }
        }
    }
}

/// <summary>Library counts for the summary. No names.</summary>
public sealed record DiagnosticsCounts(int Folders, int Connections, IReadOnlyDictionary<string, int> ByProtocol);

public static class DiagnosticsBundle
{
    /// <summary>What the export says is inside.</summary>
    public const string Contents = "app and Windows version, the app's log, the last crash, settings without secrets or names, and library counts (no names)";
    public const string FolderName = "Gantry diagnostics";

    /// <summary>Settings with every text value replaced: only the keys, true/false and numbers stay.</summary>
    public static string RedactSettings(string json)
    {
        JsonNode? node;
        try { node = JsonNode.Parse(json); }
        catch (JsonException) { return "{}\n"; }
        if (node is null) return "{}\n";
        return (Redact(node) ?? new JsonObject()).ToJsonString(new JsonSerializerOptions { WriteIndented = true, TypeInfoResolver = Bastion.Shell.Interop.AotJson.Resolver }) + "\n";
    }

    private static JsonNode? Redact(JsonNode? n) => n switch
    {
        JsonObject o => new JsonObject(o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => KeyValuePair.Create(p.Key, Redact(p.Value)))),
        JsonArray a => new JsonArray(a.Select(Redact).ToArray()),
        JsonValue v when v.GetValueKind() is JsonValueKind.True or JsonValueKind.False or JsonValueKind.Number => v.DeepClone(),
        JsonValue v when v.GetValueKind() == JsonValueKind.String => JsonValue.Create(v.GetValue<string>().Length == 0 ? "" : "(set)"),
        _ => null,
    };

    /// <summary>Replaces the profile folder, the account name and the computer name in a log.</summary>
    public static string Scrub(string text, string home, string user, string machine)
    {
        var o = text;
        if (home.Length > 0) o = o.Replace(home, "~", StringComparison.OrdinalIgnoreCase);
        if (user.Length >= 2) o = o.Replace(user, "(user)", StringComparison.OrdinalIgnoreCase);
        if (machine.Length >= 2) o = o.Replace(machine, "(computer)", StringComparison.OrdinalIgnoreCase);
        return o;
    }

    public static string Summary(string version, string os, DiagnosticsCounts counts, DateTimeOffset created, bool detailedLog = false)
    {
        var lines = new List<string>
        {
            "Gantry diagnostics",
            "Created: " + created.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            "App version: " + version,
            "Windows: " + os,
            "Folders: " + counts.Folders.ToString(CultureInfo.InvariantCulture),
            "Connections: " + counts.Connections.ToString(CultureInfo.InvariantCulture),
            "Detailed logging: " + (detailedLog ? "on" : "off"),
        };
        lines.AddRange(counts.ByProtocol.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"  {p.Key}: {p.Value.ToString(CultureInfo.InvariantCulture)}"));
        return string.Join("\n", lines) + "\n";
    }

    public sealed record Inputs(string Summary, string SettingsPath, IReadOnlyList<string> Logs, string? Crash, string Home, string User, string Machine);

    private static string? ReadShared(string path)
    {
        try
        {
            using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var r = new StreamReader(s, Encoding.UTF8);
            return r.ReadToEnd();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>The files of the bundle, by name. Unreadable inputs are left out, never guessed.</summary>
    public static IReadOnlyList<(string Name, string Text)> Entries(Inputs inputs)
    {
        string Clean(string text) => Scrub(text, inputs.Home, inputs.User, inputs.Machine);
        var entries = new List<(string, string)>
        {
            ("summary.txt", inputs.Summary),
            ("settings.json", RedactSettings(ReadShared(inputs.SettingsPath) ?? "{}")),
        };
        foreach (var log in inputs.Logs)
            if (ReadShared(log) is { } text) entries.Add((System.IO.Path.GetFileName(log), Clean(text)));
        if (inputs.Crash is { } crash && ReadShared(crash) is { } c) entries.Add(("last-crash.log", Clean(c)));
        return entries;
    }

    /// <summary>Writes the zip (System.IO.Compression: offline, part of .NET). A temporary file is renamed over the target
    /// only when complete, so a failed export never leaves half a zip behind.</summary>
    public static void Write(Inputs inputs, string zipPath)
    {
        var temp = zipPath + ".partial";
        try
        {
            using (var file = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var zip = new ZipArchive(file, ZipArchiveMode.Create))
            {
                foreach (var (name, text) in Entries(inputs))
                {
                    using var w = new StreamWriter(zip.CreateEntry(FolderName + "/" + name, CompressionLevel.Optimal).Open(), new UTF8Encoding(false));
                    w.Write(text);
                }
            }
            File.Move(temp, zipPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }
}
