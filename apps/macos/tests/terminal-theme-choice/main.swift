// Unit test for TerminalThemeChoice: the Match app theme default and a kept choice.
var failures = 0
func check(_ ok: Bool, _ what: String) { print(ok ? "PASS" : "FAIL", what); if !ok { failures += 1 } }
check(TerminalThemeChoice.id(TerminalThemeChoice.matchApp, appIsDark: false) == "bastion-light", "match-app in a light app is Bastion Light")
check(TerminalThemeChoice.id(TerminalThemeChoice.matchApp, appIsDark: true) == "bastion-dark", "match-app in a dark app is Bastion Dark")
check(TerminalThemeChoice.id("dracula", appIsDark: false) == "dracula", "a saved dark theme stays in a light app")
check(TerminalThemeChoice.id("bastion-light", appIsDark: true) == "bastion-light", "a saved light theme stays in a dark app")
if failures > 0 { fatalError("\(failures) failed") }
