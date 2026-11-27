#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for Test Connection's host-key confirmation (SEC-07). Results are printed as
/// text, so a run checks them without reading the screen:
/// `tc-cred <name>` a password credential for user `tester` with the password from `BASTION_UI_PASSWORD_FILE` (never logged)
/// `tc-known-hosts drop <host>` | `alias <from> -> <to>` | `mark` | `same` edit or compare the throwaway library's known_hosts
/// `tc-capture prompt|dialog <name>` ask run.sh for a picture of the prompt or the property dialog and hold the state until the file exists
/// `tc-look light|dark` FAIL unless the property dialog (and the prompt, when open) is drawn in that appearance
/// `tc-wait <seconds>` until the running test ends
/// `tc-prompt return|escape|trust` answer the host-key prompt: the button on Return, the one on Escape, or the trust button
/// `tc-state <key=value …>` the open dialog's test state; FAIL unless every given pair matches
/// `tc-show <waiting|waiting-long|refused|jump-unknown|passed>` a made-up report, for layout-fit

extension Driver {
    private static var knownHostsMark: Data?
    private static var knownHosts: URL { LibraryModel.dataDir.appendingPathComponent("known_hosts") }

    /// Handles one of these steps; false when `cmd` is not one.
    func testConnectionStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "tc-cred": testConnectionCredential(arg)
        case "tc-known-hosts": testConnectionKnownHosts(arg)
        case "tc-capture": await testConnectionCapture(arg)
        case "tc-look": testConnectionLook(arg)
        case "tc-wait": await testConnectionWait(arg)
        case "tc-prompt": await testConnectionPrompt(arg)
        case "tc-state": testConnectionState(arg)
        case "tc-show": await testConnectionShow(arg)
        default: return false
        }
        return true
    }

    private func testConnectionCredential(_ name: String) {
        guard let credentials = UIDriver.services?.credentials, credentials.vault != nil else { return write("FAIL tc-cred: vault locked (run test-vault first)") }
        guard let file = ProcessInfo.processInfo.environment["BASTION_UI_PASSWORD_FILE"],
              let password = try? String(contentsOfFile: file, encoding: .utf8).trimmingCharacters(in: .newlines), !password.isEmpty else {
            return write("FAIL tc-cred: BASTION_UI_PASSWORD_FILE not readable")
        }
        let saved = credentials.mutate { _ = try $0.savePassword(id: nil, name: name, folder: nil, username: "tester", password: password) }
        write("\(saved ? "" : "FAIL ")TC-CRED \(name)")
    }

    private func testConnectionKnownHosts(_ arg: String) {
        let url = Self.knownHosts
        let parts = arg.split(separator: " ", maxSplits: 1).map(String.init)
        let current = (try? Data(contentsOf: url)) ?? Data()
        switch parts.first {
        case "mark":
            Self.knownHostsMark = current
            write("TC-KNOWN-HOSTS mark \(current.count) bytes")
        case "same":
            let same = Self.knownHostsMark == current
            write("\(same ? "" : "FAIL ")TC-KNOWN-HOSTS \(same ? "unchanged" : "changed") \(current.count) bytes")
        case "drop" where parts.count == 2:
            rewriteKnownHosts(current, to: url, step: arg) { lines in lines.filter { !$0.hasPrefix(parts[1] + " ") } }
        case "alias" where parts.count == 2:
            // The keys of one host listed under another name: that name then has a CHANGED key.
            let names = parts[1].components(separatedBy: " -> ")
            guard names.count == 2 else { return write("FAIL tc-known-hosts \(arg)") }
            rewriteKnownHosts(current, to: url, step: arg) { lines in
                lines + lines.filter { $0.hasPrefix(names[0] + " ") }.map { names[1] + $0.dropFirst(names[0].count) }
            }
        default:
            write("FAIL tc-known-hosts \(arg)")
        }
    }

    private func rewriteKnownHosts(_ current: Data, to url: URL, step: String, _ change: ([String]) -> [String]) {
        let before = String(decoding: current, as: UTF8.self).split(separator: "\n").map(String.init)
        let after = change(before)
        guard after != before else { return write("FAIL tc-known-hosts \(step): no line matched") }
        do {
            try Data((after.joined(separator: "\n") + "\n").utf8).write(to: url, options: .atomic)
            write("TC-KNOWN-HOSTS \(step): \(before.count) -> \(after.count) lines")
        } catch {
            write("FAIL tc-known-hosts \(step): \(error.localizedDescription)")
        }
    }

    /// The driver takes the picture itself (UIDriverCapture.swift) before the next step runs, so it
    /// shows this state. The suites set `capture-source window`: these pictures go into evidence.
    private func testConnectionCapture(_ arg: String) async {
        let parts = arg.split(separator: " ", maxSplits: 1).map(String.init)
        let dialog = window?.attachedSheet
        let prompt = topSheet.flatMap { $0 === dialog ? nil : $0 }
        guard parts.count == 2, ["prompt", "dialog"].contains(parts[0]), let target = parts[0] == "prompt" ? prompt : dialog else {
            return write("FAIL tc-capture \(arg): no such window")
        }
        await settle(0.3)
        await capture(target, parts[1])
    }

    /// What the topmost sheet is drawn in: a capture or fit line named light must be light.
    private var sheetLook: String {
        topSheet.map { $0.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? "dark" : "light" } ?? "none"
    }

    private func testConnectionLook(_ expected: String) {
        let look = sheetLook
        write("\(look == expected ? "" : "FAIL ")TC-LOOK \(look)\(look == expected ? "" : " (expected \(expected))")")
    }

    private func testConnectionWait(_ arg: String) async {
        guard let test = ConnectionTest.driverTarget else { return write("FAIL tc-wait: no property dialog") }
        let deadline = CFAbsoluteTimeGetCurrent() + (Double(arg) ?? 15)
        await settle(0.3)
        while test.running && CFAbsoluteTimeGetCurrent() < deadline { await settle(0.2) }
        if test.running { return write("FAIL TC-WAIT still running") }
        // A test that never produced a report says why (run of 2026-11-13: tests silently not started).
        if test.report == nil {
            let vault = UIDriver.services?.credentials.vault == nil ? "locked" : "open"
            return write("FAIL TC-WAIT no report: \(test.startError ?? "the test was not started") (vault \(vault))")
        }
        write("TC-WAIT ended")
    }

    private func testConnectionPrompt(_ arg: String) async {
        guard let test = ConnectionTest.driverTarget, test.hostKeyQuestion != nil, let prompt = topSheet, prompt !== window?.attachedSheet else {
            return write("FAIL tc-prompt \(arg): no host-key prompt")
        }
        let keys = ["return": "\r", "escape": "\u{1b}"]
        if arg == "trust" {
            // SwiftUI buttons carry no AppKit title: the prompt listens for its trust button's name.
            NotificationCenter.default.post(name: DriverEvents.pressButton, object: HostKeyQuestion.trustTitle)
        } else if let key = keys[arg], let button = prompt.contentView?.allSubviews(of: NSButton.self).first(where: { $0.keyEquivalent == key && $0.isEnabled }) {
            button.performClick(nil)
        } else if let key = keys[arg] {
            // SDK 27: SwiftUI's buttons are no NSButtons; .defaultAction / .cancelAction answer the key.
            await pressKey(key, in: prompt)
        } else {
            return write("FAIL tc-prompt \(arg): no such button")
        }
        await settle(0.8)
        write("TC-PROMPT \(arg) -> question \(test.hostKeyQuestion == nil ? "answered" : "still open")")
    }

    private func testConnectionState(_ expected: String) {
        guard let test = ConnectionTest.driverTarget else { return write("FAIL tc-state: no property dialog") }
        let verdict = switch test.verdict {
        case nil: test.running ? "running" : "none"
        case .waitingForHostKey: "waiting"
        case .cancelled: "cancelled"
        case .hostKeyRefused: "refused"
        case .failed: "failed"
        case .passed: "passed"
        }
        let steps = test.report?.steps ?? []
        func status(_ kind: String) -> String { steps.last { $0.kind == kind }?.status ?? "-" }
        // The prompt is the sheet on top of the property dialog's sheet.
        let promptShown = test.hostKeyQuestion != nil && topSheet != nil && topSheet !== window?.attachedSheet
        let state = [
            "verdict=\(verdict)",
            "prompt=\(promptShown ? "shown" : "none")",
            "fingerprint=\(test.hostKeyQuestion?.fingerprint ?? test.report?.needsHostKeyConfirmation ?? "-")",
            "host_key=\(status("host_key"))",
            "jump_host=\(status("jump_host"))",
            "login=\(status("login"))",
            "certificate=\(status("certificate"))",
            "headline=\(test.verdict?.headline.map { $0.isError ? "error" : "notice" } ?? "none")",
        ]
        let missing = expected.split(separator: " ").map(String.init).filter { want in
            // `fingerprint=SHA256:*` asks for any SHA-256 fingerprint.
            want.hasSuffix("*") ? !state.contains { $0.hasPrefix(want.dropLast()) } : !state.contains(want)
        }
        write("\(missing.isEmpty ? "" : "FAIL ")TC-STATE \(state.joined(separator: " "))\(missing.isEmpty ? "" : " (expected \(missing.joined(separator: " ")))")")
    }

    private func testConnectionShow(_ arg: String) async {
        guard let test = ConnectionTest.driverTarget else { return write("FAIL tc-show: no property dialog") }
        let fingerprint = "SHA256:" + String(repeating: "mK4vTq9ZxW2", count: 4).prefix(43)
        let longHost = "bastion-database-replica-07.management.datacentre-north.lab.example.internal"
        func step(_ kind: String, _ status: String, _ detail: String, fix: String? = nil) -> ProbeStepView {
            ProbeStepView(kind: kind, status: status, detail: detail, fix: fix, millis: status == "skipped" ? 0 : 12)
        }
        func report(ok: Bool, needs: String? = nil, failure: String? = nil, _ steps: [ProbeStepView]) -> ProbeReportView {
            ProbeReportView(ok: ok, cancelled: false, steps: steps, needsHostKeyConfirmation: needs, hostKeyFailure: failure)
        }
        let reached = [step("dns", "ok", "Resolved to 192.0.2.10"), step("tcp", "ok", "Port 22 open, 3 ms"), step("handshake", "ok", "SSH-2.0-OpenSSH_9.9")]
        let compare = "Compare it with the server administrator's copy; you will be asked to trust it on first connect."
        switch arg {
        case "waiting":
            let steps = reached + [step("host_key", "warn", "NEW host key \(fingerprint)", fix: compare), step("login", "skipped", "Not tested: confirm the host key first")]
            test.showForDriver(report(ok: true, needs: fingerprint, steps), host: "db01.lab.example", jumpHosts: [], lastConfirmed: nil)
        case "waiting-long":
            // The widest case: a long target behind two long jump hosts and the extra sentence
            // shown when the key differs from the confirmed one. The fingerprint has the only
            // length the core produces (SHA-256, 50 characters), with other characters.
            let second = "SHA256:" + String(repeating: "Wq7LmZ2xKp9", count: 4).prefix(43)
            let steps = [step("jump_host", "ok", "Jump host \(longHost): key known, logged in as 'operations-automation'"),
                         step("tcp", "skipped", "\(longHost):22022 is reached through the jump host"),
                         step("host_key", "warn", "NEW host key \(second)", fix: compare), step("login", "skipped", "Not tested: confirm the host key first")]
            test.showForDriver(report(ok: true, needs: second, steps), host: longHost,
                               jumpHosts: ["jump-east-01.perimeter.lab.example.internal", "jump-core-02.perimeter.lab.example.internal"], lastConfirmed: fingerprint)
        case "refused":
            let fix = "Do not connect. Ask the administrator whether the server was reinstalled; if so, remove the old key and verify the new one."
            let steps = reached + [step("host_key", "failed", "Host key CHANGED since last connect (known_hosts line 3)", fix: fix), step("login", "skipped", "Stopped: the host key changed")]
            test.showForDriver(report(ok: false, failure: "changed", steps), host: "db01.lab.example", jumpHosts: [], lastConfirmed: nil)
        case "refused-unreadable":
            // SEC-07-FU1: known_hosts could not be read; its own headline, not the changed-key one.
            let steps = reached + [step("host_key", "failed", "Cannot read known_hosts: Permission denied (os error 13)", fix: "Check the file's permissions.")]
            test.showForDriver(report(ok: false, failure: "known_hosts_unreadable", steps), host: "db01.lab.example", jumpHosts: [], lastConfirmed: nil)
        case "jump-unknown":
            let steps = [step("jump_host", "failed", "Jump host \(longHost): NEW host key \(fingerprint)", fix: "Connect to the jump host once on its own and trust its key after verifying it.")]
            test.showForDriver(report(ok: false, steps), host: "db01.lab.example", jumpHosts: [longHost], lastConfirmed: nil)
        case "passed":
            let steps = reached + [step("host_key", "warn", "NEW host key \(fingerprint)", fix: compare), step("login", "ok", "Logged in as 'tester'")]
            test.showForDriver(report(ok: true, steps), host: "db01.lab.example", jumpHosts: [], lastConfirmed: nil)
        case "passed-clean":
            let steps = reached + [step("host_key", "ok", "Host key known"), step("login", "ok", "Logged in as 'tester'")]
            test.showForDriver(report(ok: true, steps), host: "db01.lab.example", jumpHosts: [], lastConfirmed: nil)
        default:
            return write("FAIL tc-show \(arg)")
        }
        await settle(0.8)
        write("TC-SHOW \(arg) look=\(sheetLook)")
    }
}
#endif
