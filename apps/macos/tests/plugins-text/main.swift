// PLUG-06a part 1: the Plugins page's wording (PluginsText.swift).
var failures = 0
func check(_ ok: Bool, _ what: String) { if !ok { failures += 1; print("FAIL \(what)") } else { print("ok \(what)") } }

check(PluginsText.badge("official") == "Official", "official badge")
check(PluginsText.badge("external") == "External", "external badge")
check(PluginsText.badge("unverified") == "Unverified", "unverified badge")
check(PluginsText.badge("something-new") == "Unverified", "an unknown tier is shown as Unverified, never as trusted")
check(PluginsText.catalogueText(nil) == "Catalogue not checked yet", "not checked")
check(PluginsText.catalogueText("accepted") == "Catalogue up to date", "accepted")
check(PluginsText.catalogueText("expired").contains("revocation status unknown"), "expired says revocation unknown")
check(PluginsText.catalogueText("unreachable: no index").hasSuffix("nothing changed"), "unreachable changes nothing")
check(PluginsText.catalogueText("refused: Rollback").hasSuffix("nothing changed"), "refused changes nothing")
check(PluginsText.catalogueText("clock-wrong").contains("clock"), "clock wrong")
check(PluginsText.installText("installed", file: "a.bastionplugin") == "Installed a.bastionplugin", "installed")
check(PluginsText.installText("unchanged", file: "a") == "Already installed", "unchanged")
check(PluginsText.policyBanner(error: nil, disabled: false, officialOnly: false, forbidUnverified: false, listedOnly: false) == nil, "no policy, no banner")
check(PluginsText.policyBanner(error: "bad", disabled: false, officialOnly: false, forbidUnverified: false, listedOnly: false)?.contains("plugins off") == true, "broken policy says plugins off")
check(PluginsText.policyBanner(error: nil, disabled: true, officialOnly: true, forbidUnverified: true, listedOnly: true) == "Plugins are turned off by policy", "off wins over the narrower keys")
check(PluginsText.policyBanner(error: nil, disabled: false, officialOnly: false, forbidUnverified: true, listedOnly: false) == "Policy: unverified plugins forbidden", "forbid unverified")
print(failures == 0 ? "PASS plugins-text" : "FAIL plugins-text \(failures)")
if failures != 0 { fatalError() }
