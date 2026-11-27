using System.Runtime.InteropServices;
using Bastion.Shell.Interop;

// PLUG-06b (Native Windows): console checks of the Plugins page's words and of the core's plugin exports through
// bastion_cabi (C ABI 120 and the PLUG-02c broker). No window, no network (the catalogue refresh reads an empty mirror
// folder), no secrets; the test makes and deletes its own folders.
// Usage: plugins-console --core <path to bastion_cabi.dll or .dylib> [--fixtures <tests/fixtures>] | --no-core. Exit 1 on a failure.
var results = new List<string>();
void Step(string name, bool ok, string detail = "") => results.Add($"{(ok ? "PASS" : "FAIL")} {name}{(detail.Length > 0 ? " (" + detail + ")" : "")}");
PluginPolicyDto Pol(string? error = null, bool off = false, bool official = false, bool forbid = false, List<string>? ids = null) =>
    new(error, off, official, ids, forbid, false, false, false);

// ---- 1. Words (the same as Native Mac's PluginsText) ----
Step("no banner without a policy", PluginsText.PolicyBanner(Pol()) is null);
Step("unreadable policy wins", PluginsText.PolicyBanner(Pol(error: "bad", off: true)) == "Managed policy unreadable, plugins off: bad");
Step("plugins off", PluginsText.PolicyBanner(Pol(off: true)) == "Plugins are turned off by policy");
Step("official only", PluginsText.PolicyBanner(Pol(official: true, forbid: true)) == "Policy: Official plugins only");
Step("unverified forbidden", PluginsText.PolicyBanner(Pol(forbid: true)) == "Policy: unverified plugins forbidden");
Step("listed only", PluginsText.PolicyBanner(Pol(ids: [])) == "Policy: listed plugins only");
Step("badges", PluginsText.Badge("official") == "Official" && PluginsText.Badge("external") == "External" && PluginsText.Badge("unverified") == "Unverified" && PluginsText.Badge("new") == "Unverified");
Step("catalogue not checked", PluginsText.Catalogue(null) == "Catalogue not checked yet");
Step("catalogue outcomes", PluginsText.Catalogue("accepted") == "Catalogue up to date" && PluginsText.Catalogue("expired") == "Catalogue expired: revocation status unknown"
    && PluginsText.Catalogue("clock-wrong") == "Catalogue checked; this PC's clock looks wrong");
Step("catalogue unreachable or refused: nothing changed", PluginsText.Catalogue("unreachable: x") == "Catalogue unreachable; nothing changed" && PluginsText.Catalogue("refused: sig") == "Catalogue refused; nothing changed");
Step("install words", PluginsText.Install("installed", "a.bastionplugin") == "Installed a.bastionplugin" && PluginsText.Install("updated", "a") == "Updated from a"
    && PluginsText.Install("restored", "a") == "Restored the previous version" && PluginsText.Install("unchanged", "a") == "Already installed");
Step("file install refused by policy", PluginsText.FileInstallForbidden(Pol(off: true)) && PluginsText.FileInstallForbidden(Pol(official: true)) && PluginsText.FileInstallForbidden(Pol(forbid: true)) && !PluginsText.FileInstallForbidden(Pol()));
Step("update note", PluginsText.UpdateNote(new("a", "1", "2", "official", true)) == "Asks for new permissions" && PluginsText.UpdateNote(new("a", "1", "2", "official", false)) == "");

// ---- 2. The real core ----
if (!args.Contains("--no-core"))
{
    var core = Array.IndexOf(args, "--core") is >= 0 and var at && at + 1 < args.Length ? Path.GetFullPath(args[at + 1]) : "";
    if (!File.Exists(core)) { Console.WriteLine("ERROR give --core <path to bastion_cabi> or --no-core"); return 2; }
    NativeLibrary.SetDllImportResolver(typeof(LibraryClient).Assembly, (name, _, _) => name == "bastion_cabi" ? NativeLibrary.Load(core) : IntPtr.Zero);
    var dir = Directory.CreateTempSubdirectory("bastion-plug06b-").FullName;
    var mirror = Directory.CreateTempSubdirectory("bastion-plug06b-mirror-").FullName;
    try
    {
        Step("core: an empty data folder lists no plugins", PluginClient.Installed(dir).Count == 0);
        Step("core: and no updates", PluginClient.Updates(dir).Count == 0);
        var pol = PluginClient.Policy();
        Step("core: the policy parses", pol is not null, $"error={pol?.Error} off={pol?.PluginsDisabled}");
        var outcome = PluginClient.Refresh(dir, mirror);
        Step("core: an empty mirror is unreachable and nothing changes", outcome.StartsWith("unreachable", StringComparison.Ordinal) && PluginsText.Catalogue(outcome) == "Catalogue unreachable; nothing changed", outcome);
        Step("core: still no plugins after the refused refresh", PluginClient.Installed(dir).Count == 0 && PluginClient.Updates(dir).Count == 0);
        var bad = Path.Combine(dir, "not-a-plugin.bastionplugin");
        File.WriteAllText(bad, "not a zip");
        var refused = false;
        try { PluginClient.InstallFile(dir, bad, allowUnverified: true); } catch (BastionException) { refused = true; }
        Step("core: a damaged file is not installed", refused && PluginClient.Installed(dir).Count == 0);
        var removed = true;
        try { PluginClient.Remove(dir, "com.example.none", false); } catch (BastionException) { removed = false; }
        Step("core: removing a plugin that is not there fails", !removed);
        var block = PluginClient.MayLoad("com.example.x", "unverified", allowUnverified: false, safeMode: false);
        Step("core: an unverified plugin may not load while the setting is off", block is { Length: > 0 }, block ?? "null");
        var safe = PluginClient.MayLoad("com.example.x", "official", allowUnverified: false, safeMode: true);
        Step("core: Safe mode stops even an official plugin", safe is { Length: > 0 }, safe ?? "null");

        // PLUG-12: the Official Proxmox plugin signed with the pinned keys (tests/fixtures/pve-*; --fixtures <dir>).
        var fx = Array.IndexOf(args, "--fixtures") is >= 0 and var f && f + 1 < args.Length ? Path.GetFullPath(args[f + 1]) : "";
        if (fx.Length > 0)
        {
            string Copy(string stem, bool sig)
            {
                File.Copy(Path.Combine(fx, stem + ".bastionplugin"), Path.Combine(dir, stem + ".bastionplugin"), true);
                if (sig) File.Copy(Path.Combine(fx, stem + ".sig"), Path.Combine(dir, stem + ".sig"), true);
                return Path.Combine(dir, stem + ".bastionplugin");
            }
            bool Refused(string path) { try { PluginClient.InstallFile(dir, path, allowUnverified: true); return false; } catch (BastionException) { return true; } }
            Step("core: the Official plugin with no record is refused, setting on", Refused(Copy("pve-unsigned", false)) && PluginClient.Installed(dir).Count == 0);
            Step("core: the Official plugin with another plugin's record is refused", Refused(Copy("pve-wrongsig", true)) && PluginClient.Installed(dir).Count == 0);
            var kind = PluginClient.InstallSigned(dir, Copy("pve-signed", true));
            var pve = PluginClient.Installed(dir).FirstOrDefault(p => p.Id == "dev.bastion.proxmox");
            Step("core: the signed Official plugin installs with no question", kind == "installed" && pve?.Tier == "official", $"{kind} {pve?.Tier}");
            var load = PluginClient.MayLoad("dev.bastion.proxmox", pve?.Tier ?? "", allowUnverified: false, safeMode: false);
            Step("core: and may load at the release stage", load is null, load ?? "null");
        }
    }
    finally
    {
        try { Directory.Delete(dir, true); } catch (IOException) { }
        try { Directory.Delete(mirror, true); } catch (IOException) { }
    }
}

foreach (var r in results) Console.WriteLine(r);
var failed = results.Count(r => r.StartsWith("FAIL"));
Console.WriteLine($"{results.Count - failed} passed, {failed} failed");
return failed == 0 ? 0 : 1;
