import SwiftUI
import BastionCore

/// Test Connection in the property dialog: tests what the dialog holds right now (nothing is
/// saved) through the core's probe, off the main thread, and can be cancelled.
///
/// SEC-07: a password is never sent to a host whose key the user has not confirmed. The core
/// stops such a test before the sign-in and returns the fingerprint; this class asks the user
/// (`hostKeyQuestion`) and only on their yes runs the same test again with that fingerprint.
/// Nothing is written to known_hosts by a test.
@MainActor @Observable
final class ConnectionTest {
    private(set) var report: ProbeReportView?
    private(set) var running = false
    private(set) var startError: String?
    /// Bumped when a driver-made report is shown, so the dialog reacts as to a finished test.
    private(set) var driverShown = 0
    /// The host key the last test is waiting on, shown as a prompt until the user answers.
    private(set) var hostKeyQuestion: HostKeyQuestion?
    private var task: ProbeTask?
    /// What the running or waiting test was started with. Kept in memory only while a test runs
    /// or its host-key question is open, so a yes repeats exactly the same test.
    private var pending: (manager: SessionManager, library: Library?, input: ProbeInput)?
    /// The fingerprint the user confirmed for the running test, if any.
    private var confirmed: String?

    /// What the last report means; nil while there is none.
    var verdict: ProbeVerdict? { report?.verdict }

    /// A new test from the dialog. It never carries a trusted fingerprint: that comes only from
    /// `confirmHostKey`.
    func start(manager: SessionManager?, library: Library?, input: ProbeInput) {
        run(manager: manager, library: library, input: input, confirmed: nil)
    }

    /// The user's yes to the fingerprint on screen: the same test again, trusting exactly that
    /// fingerprint for this run. If the server then shows another key, the user is asked again.
    func confirmHostKey() {
        guard let question = hostKeyQuestion, let pending else { return }
        run(manager: pending.manager, library: pending.library, input: pending.input, confirmed: question.fingerprint)
    }

    /// The user's no (Cancel, Return or Escape). No sign-in was sent and nothing is stored.
    func declineHostKey() {
        // Also called when the prompt closes after a yes: only an open question is answered here.
        guard hostKeyQuestion != nil else { return }
        hostKeyQuestion = nil
        pending = nil
    }

    func cancel() {
        if running { report = ProbeReportView(ok: false, cancelled: true, steps: [], needsHostKeyConfirmation: nil, hostKeyFailure: nil) }
        task?.cancel()
        task = nil
        running = false
        hostKeyQuestion = nil
        pending = nil
        confirmed = nil
    }

    /// What Test Connection runs after the TLS check on a saved plugin entry: the plugin itself,
    /// with the entry's login, over the route its tab would use. Nil when the dialog holds edits
    /// or the route needs a gateway the user has to start; the report then says so.
    struct PluginLoginTest {
        let library: Library
        let vault: CredentialVault?
        let connectionId: String
        let allowUnverified: Bool
        let via: PluginRoute?
    }

    /// Test Connection on a plugin entry (Proxmox, VMware, PostgreSQL…): the core's TLS handshake
    /// under the entry's own rule (the pin when one is set, else system trust and the host name),
    /// then the plugin's own calls with the entry's login (`pluginEntryTest`), so a login the
    /// server refuses, or one that sees nothing, fails here as it would in the entry's tab.
    func startPlugin(host: String, port: UInt16, pin: String?, login: PluginLoginTest?) {
        cancel()
        report = nil
        startError = nil
        running = true
        let started = Date()
        let dir = LibraryModel.dataDir.path
        Task.detached(priority: .userInitiated) {
            let tls = Result { try pluginCertificateCheck(host: host, port: port, pinSha256: pin) }
            let tlsMillis = UInt64(Date().timeIntervalSince(started) * 1000)
            var loginStep: ProbeStepView?
            if case .success = tls, let login {
                let t0 = Date()
                if let via = login.via {
                    let r = Result {
                        try PluginHelper.ensurePath()
                        return try pluginEntryTest(library: login.library, vault: login.vault, connectionId: login.connectionId, dataDir: dir, allowUnverified: login.allowUnverified, via: via)
                    }
                    loginStep = Self.pluginLoginStep(r, millis: UInt64(Date().timeIntervalSince(t0) * 1000))
                } else {
                    loginStep = ProbeStepView(kind: "login", status: "skipped", detail: "Not tested: the entry goes through a gateway. Open it to test the login.", fix: nil, millis: 0)
                }
            }
            await MainActor.run { [weak self] in
                guard let self, self.running else { return }
                self.running = false
                self.report = Self.pluginReport(tls, pinned: pin != nil, millis: tlsMillis, login: loginStep)
            }
        }
    }

    /// The "login" step: the plugin loaded with no error banner, or its own words.
    nonisolated static func pluginLoginStep(_ result: Result<PluginEntryTestView, Error>, millis: UInt64) -> ProbeStepView {
        switch result {
        case .success(let v) where v.ok:
            return ProbeStepView(kind: "login", status: "ok", detail: v.message.isEmpty ? "Logged in and listed" : v.message, fix: nil, millis: millis)
        case .success(let v):
            return ProbeStepView(kind: "login", status: "failed", detail: v.message, fix: nil, millis: millis)
        case .failure(let e):
            return ProbeStepView(kind: "login", status: "failed", detail: e.userMessage, fix: nil, millis: millis)
        }
    }

    /// One "certificate" step: passed, or the core's reason with the fix.
    nonisolated static func pluginReport(_ result: Result<Void, Error>, pinned: Bool, millis: UInt64, login: ProbeStepView? = nil) -> ProbeReportView {
        let step: ProbeStepView
        switch result {
        case .success:
            step = ProbeStepView(kind: "certificate", status: "ok", detail: pinned ? "Matches the pinned certificate" : "Valid for the host name", fix: nil, millis: millis)
        case .failure(let e):
            let message = e.userMessage
            let fix = PluginBanner.isCertificateRefusal(message) ? "Use Trust Server Certificate… under Certificate in the inspector" : nil
            step = ProbeStepView(kind: "certificate", status: "failed", detail: message, fix: fix, millis: millis)
        }
        let steps = [step] + (login.map { [$0] } ?? [])
        return ProbeReportView(ok: steps.allSatisfy { $0.status != "failed" }, cancelled: false, steps: steps, needsHostKeyConfirmation: nil, hostKeyFailure: nil)
    }

    /// UI driver only (layout-fit of the panel's states): a made-up report as if a test had just
    /// ended. There is no test behind it, so confirming its question does nothing.
    func showForDriver(_ report: ProbeReportView, host: String, jumpHosts: [String], lastConfirmed: String?) {
        guard TestHooks.isScripted else { return }
        cancel()
        startError = nil
        self.report = report
        hostKeyQuestion = HostKeyQuestion.from(report.verdict, host: host, jumpHosts: jumpHosts, lastConfirmed: lastConfirmed)
        driverShown += 1
    }

    private func run(manager: SessionManager?, library: Library?, input: ProbeInput, confirmed fingerprint: String?) {
        cancel()
        report = nil
        startError = nil
        guard let manager else { startError = "The session manager could not start."; return }
        var input = input
        input.trustedFingerprint = fingerprint
        do {
            let task = try manager.testConnection(library: library, input: input)
            self.task = task
            pending = (manager, library, input)
            confirmed = fingerprint
            running = true
            Task.detached(priority: .userInitiated) {
                let result = task.wait()
                await MainActor.run { [weak self] in
                    guard let self, self.task === task else { return }
                    self.finish(result)
                }
            }
        } catch {
            startError = errorText(error)
        }
    }

    private func finish(_ result: ProbeReportView) {
        report = result
        running = false
        task = nil
        hostKeyQuestion = pending.flatMap {
            HostKeyQuestion.from(result.verdict, host: $0.input.host, jumpHosts: $0.input.jumps.map(\.host), lastConfirmed: confirmed)
        }
        // The login is held no longer than the question it belongs to.
        if hostKeyQuestion == nil { pending = nil }
        confirmed = nil
    }
}

extension ProbeReportView {
    /// The one place the app reads a probe report's outcome. `needsHostKeyConfirmation` is looked
    /// at before `ok` (see `ProbeVerdict.of`): a waiting report has `ok == true`.
    var verdict: ProbeVerdict {
        ProbeVerdict.of(ok: ok, cancelled: cancelled, needsHostKeyConfirmation: needsHostKeyConfirmation,
                        steps: steps.map { ProbeStepFact(kind: $0.kind, status: $0.status) }, hostKeyFailure: hostKeyFailure)
    }
}

/// The host-key prompt of a waiting test: the connect prompt's wording and fingerprint format,
/// with Cancel on Return and a line saying the trust is for this test only.
struct TestHostKeyPrompt: View {
    let question: HostKeyQuestion
    let test: ConnectionTest

    var body: some View {
        HostKeyPrompt(host: question.subject, fingerprint: question.fingerprint, trustTitle: HostKeyQuestion.trustTitle,
                      note: question.note, cancelOnReturn: true,
                      trust: { test.confirmHostKey() }, cancel: { test.declineHostKey() })
            .accessibilityIdentifier("test-connection-host-key")
    }
}

/// The steps of the last test, each with its result and, where it failed, the fix.
struct ConnectionTestResults: View {
    let test: ConnectionTest

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            if test.running {
                HStack(spacing: DS.Space.xs) {
                    ProgressView().controlSize(.small)
                    Text("Testing…").foregroundStyle(.secondary)
                }
            } else if let message = test.startError {
                Label(message, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
            } else if let report = test.report {
                if report.cancelled {
                    Text("Test cancelled.").foregroundStyle(.secondary)
                }
                if let headline = report.verdict.headline {
                    Label {
                        Text(headline.text).fontWeight(.medium).fixedSize(horizontal: false, vertical: true)
                    } icon: {
                        Image(systemName: headline.isError ? "xmark.octagon.fill" : "exclamationmark.shield.fill")
                            .foregroundStyle(headline.isError ? .red : .orange)
                    }
                    .accessibilityIdentifier("test-connection-headline")
                }
                ForEach(Array(report.steps.enumerated()), id: \.offset) { _, step in
                    row(step)
                }
            }
        }
        .font(DS.Font.caption)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityIdentifier("test-connection-results")
    }

    private func row(_ step: ProbeStepView) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: DS.Space.xs) {
            Image(systemName: symbol(step.status)).foregroundStyle(color(step.status))
            Text(title(step.kind)).fontWeight(.medium).frame(width: 72, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(step.detail).foregroundStyle(step.status == "skipped" ? .secondary : .primary).textSelection(.enabled)
                if let fix = step.fix { Text(fix).foregroundStyle(.secondary) }
            }
            .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            if step.status != "skipped" { Text("\(step.millis) ms").foregroundStyle(.tertiary).monospacedDigit() }
        }
    }

    private func title(_ kind: String) -> String {
        switch kind {
        case "dns": "DNS"
        case "tcp": "Port"
        case "handshake": "Handshake"
        case "host_key": "Host key"
        case "jump_host": "Jump host"
        case "certificate": "TLS"
        default: "Login"
        }
    }

    private func symbol(_ status: String) -> String {
        switch status {
        case "ok": "checkmark.circle.fill"
        case "warn": "exclamationmark.triangle.fill"
        case "failed": "xmark.octagon.fill"
        default: "minus.circle"
        }
    }

    private func color(_ status: String) -> Color {
        switch status {
        case "ok": .green
        case "warn": .orange
        case "failed": .red
        default: .secondary
        }
    }
}

extension CredentialDraft {
    /// The login the dialog would use, in memory only; `nil` when nothing is entered.
    /// `connectionId` finds a stored inline secret; `inherited` is the effective assigned credential id.
    func probeLogin(connectionId: String, inherited: String?, vault: CredentialVault?) -> SshLogin? {
        switch mode {
        case .inline:
            if tab == .keyFile {
                if !keyPath.isEmpty { return .keyFile(path: (keyPath as NSString).expandingTildeInPath, passphrase: passphrase) }
                return storedInline == "ssh-key" ? .vault(credentialId: connectionId) : nil
            }
            if !password.isEmpty { return .password(password: password) }
            return storedInline == "password" ? .vault(credentialId: connectionId) : nil
        case .existing:
            return credentialId.map { .vault(credentialId: $0) }
        case .name:
            return vault?.findByName(name: credentialName).map { .vault(credentialId: $0) }
        case .parent:
            return inherited.map { .vault(credentialId: $0) }
        }
    }

    /// A pasted key that is not saved yet, tested in place of `probeLogin`.
    var pastedKey: String? {
        mode == .inline && tab == .keyFile && keyPath.isEmpty && !keyText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? keyText : nil
    }
}
