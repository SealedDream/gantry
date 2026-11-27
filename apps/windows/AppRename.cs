using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace Bastion.Shell;

/// <summary>The product rename (Bastion -> Gantry, owner 2026-11-23). On the first launch of Gantry the old
/// %APPDATA%\Bastion (library, vault, settings, known_hosts, document keys, plugins) and %LOCALAPPDATA%\Bastion
/// (logs, layout state) folders are each copied to ...\Gantry once. The copy goes to a temporary folder, is verified
/// file by file (size and SHA-256), and only then takes the new name. The old folders are never changed, so nothing is
/// lost if a copy fails; the next launch tries again.</summary>
internal static class AppRename
{
    internal const string NewName = "Gantry";
    internal const string OldName = "Bastion";
    internal const string Marker = "migrated-from-bastion.json";

    internal enum Outcome { NotNeeded, Migrated, Failed, HasOwnLibrary }

    /// <summary>Both data folders, before anything reads them. They are decided together so Roaming and Local are
    /// never half migrated: a Gantry library of its own (device key, library.json or Personal.gantry) keeps both
    /// as they are; otherwise both are migrated from Bastion when no marker says it was done.</summary>
    internal static Outcome MigrateDataFolders() => MigrateDataFolders(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));

    internal static Outcome MigrateDataFolders(string roaming, string local, string documents)
    {
        if (HasOwnLibrary(Path.Combine(roaming, NewName), documents))
        {
            if (Directory.Exists(Path.Combine(roaming, OldName)) && !File.Exists(Path.Combine(roaming, NewName, Marker)))
                System.Diagnostics.Debug.WriteLine("Gantry: a Gantry library exists; Bastion data left as it is");
            return Outcome.HasOwnLibrary;
        }
        var r = MigrateFolder(roaming);
        if (r == Outcome.Failed) return r;
        var l = MigrateFolder(local);
        return r == Outcome.Migrated || l == Outcome.Migrated ? Outcome.Migrated : l;
    }

    /// <summary>A Gantry library of its own: its device key, an old-layout library.json, or Documents\Gantry\Personal.gantry.</summary>
    internal static bool HasOwnLibrary(string gantryData, string documents) =>
        !File.Exists(Path.Combine(gantryData, Marker))
        && (Directory.Exists(Path.Combine(gantryData, "device-key")) || File.Exists(Path.Combine(gantryData, "device-key"))
            || File.Exists(Path.Combine(gantryData, "library.json"))
            || File.Exists(Path.Combine(documents, NewName, "Personal.gantry")));

    /// <summary>Copies parent\Bastion to parent\Gantry once (no marker yet). A Gantry folder that is already there
    /// (no library of its own: a failed first start, a test seed) is renamed aside to Gantry.before-migration-*,
    /// never deleted, and only after the copy verified.</summary>
    internal static Outcome MigrateFolder(string parent)
    {
        var oldDir = Path.Combine(parent, OldName);
        var newDir = Path.Combine(parent, NewName);
        if (File.Exists(Path.Combine(newDir, Marker)) || !Directory.Exists(oldDir)) return Outcome.NotNeeded;
        var staging = Path.Combine(parent, $"{NewName}.migrating-{Guid.NewGuid():N}");
        try
        {
            var files = new List<string>();
            CopyTree(oldDir, staging, "", files);
            foreach (var rel in files) Verify(Path.Combine(oldDir, rel), Path.Combine(staging, rel), rel);
            if (Directory.Exists(newDir))
            {
                // A settings-only Gantry folder keeps its own files: they go over the Bastion copy (newer settings win;
                // the library and its device key come from Bastion, since this folder has none of its own).
                var own = new List<string>();
                CopyTree(newDir, staging, "", own, overwrite: true);
                foreach (var rel in own) Verify(Path.Combine(newDir, rel), Path.Combine(staging, rel), rel);
            }
            var aside = Directory.Exists(newDir) ? Path.Combine(parent, $"{NewName}.before-migration-{Guid.NewGuid():N}") : null;
            WriteMarker(Path.Combine(staging, Marker), oldDir, files.Count, aside);
            if (aside is not null) Directory.Move(newDir, aside);
            try { Directory.Move(staging, newDir); }
            catch (IOException) when (aside is not null) { Directory.Move(aside, newDir); throw; }
            System.Diagnostics.Debug.WriteLine($"Gantry: copied {files.Count} files from {oldDir} to {newDir}; the old folder is kept"
                + (aside is null ? "" : $"; the earlier Gantry folder is kept as {aside}"));
            return Outcome.Migrated;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            try { if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            System.Diagnostics.Debug.WriteLine($"Gantry: {oldDir} not migrated and left unchanged: {e.Message}");
            return Outcome.Failed;
        }
    }

    /// <summary>The Personal document. A pre-rename Personal.bastion is used where it is only when <paramref name="dataDir"/>
    /// was migrated from the Bastion folder (marker present): its device key came with that copy. Without the marker
    /// (a fresh or already-separate Gantry folder) the old document's key is not here, so the new path is used.</summary>
    internal static string PersonalDocument(string documents, string dataDir)
    {
        var current = Path.Combine(documents, NewName, "Personal.gantry");
        var legacy = Path.Combine(documents, OldName, "Personal.bastion");
        var migrated = File.Exists(Path.Combine(dataDir, Marker));
        return migrated && !File.Exists(current) && File.Exists(legacy) ? legacy : current;
    }

    /// <summary>The marker, written with Utf8JsonWriter (no reflection: the app ships AOT-compiled).</summary>
    private static void WriteMarker(string path, string from, int count, string? aside)
    {
        using var stream = File.Create(path);
        using var w = new Utf8JsonWriter(stream);
        w.WriteStartObject();
        w.WriteString("from", from);
        w.WriteNumber("files", count);
        if (aside is not null) w.WriteString("earlierGantryFolder", aside);
        w.WriteString("at", DateTime.UtcNow.ToString("o"));
        w.WriteEndObject();
    }

    private static void CopyTree(string src, string dst, string rel, List<string> files, bool overwrite = false)
    {
        Directory.CreateDirectory(dst);
        foreach (var dir in Directory.GetDirectories(src))
        {
            if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0) continue; // never follow a junction out of the folder
            var name = Path.GetFileName(dir);
            CopyTree(dir, Path.Combine(dst, name), Path.Combine(rel, name), files, overwrite);
        }
        foreach (var file in Directory.GetFiles(src))
        {
            var name = Path.GetFileName(file);
            File.Copy(file, Path.Combine(dst, name), overwrite);
            files.Add(Path.Combine(rel, name));
        }
    }

    private static void Verify(string a, string b, string rel)
    {
        using var fa = File.OpenRead(a);
        using var fb = File.OpenRead(b);
        if (fa.Length != fb.Length || !SHA256.HashData(fa).AsSpan().SequenceEqual(SHA256.HashData(fb)))
            throw new InvalidDataException($"copy of {rel} does not match");
    }
}
