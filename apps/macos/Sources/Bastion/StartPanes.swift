import CryptoKit
import SwiftUI
import BastionCore

/// The start window's right half (StartWindow.swift): unlock, open, missing, welcome. The create
/// form is in StartCreatePane.swift. Errors are one line under the field they belong to.

/// Name and one quiet line under it, the same in every pane.
struct StartTitle: View {
    let title: String
    let detail: String?

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.xxs) {
            Text(title).font(DS.Font.title2.weight(.semibold)).lineLimit(2)
                .accessibilityAddTraits(.isHeader)
            if let detail {
                Text(detail).font(DS.Font.callout).foregroundStyle(.secondary)
                    .lineLimit(2).truncationMode(.middle).fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// One-line problem text under a field.
struct StartProblem: View {
    let text: String?
    var tint: Color = .red

    var body: some View {
        if let text {
            Text(text).font(DS.Font.callout).foregroundStyle(tint)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("start-problem")
        }
    }
}

struct StartUnlockPane: View {
    @Bindable var gate: DocumentGate
    @FocusState private var focused: Bool

    private var doc: OpenDocument? { gate.unlockingDocument }
    private var touchIDReady: Bool { doc.map(gate.touchIDReady) ?? false }
    private var recent: DocumentGate.Recent? { doc.flatMap { d in gate.recents.first { DocumentGate.samePath($0.path, d.info.path ?? "") } } }
    private var blocked: Bool { gate.waitSecs > 0 || gate.touchIDRunning }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            StartTitle(title: doc?.info.name ?? "Document",
                       detail: ["Encrypted", StartText.connections(recent?.connectionCount), StartText.lastOpened(recent?.lastOpenedAt).map { "last " + $0 }].compactMap { $0 }.joined(separator: " · "))
                .help(doc?.info.path ?? "")
            if touchIDReady {
                Button { gate.unlockWithBiometrics() } label: {
                    Label(gate.touchIDRunning ? "Waiting for Touch ID…" : "Unlock with Touch ID", systemImage: "touchid")
                        .frame(maxWidth: .infinity, minHeight: 28)
                }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(gate.touchIDRunning)
                .accessibilityIdentifier("start-touch-id")
                .startFit(.button, "Unlock with Touch ID")
                orDivider
            }
            VStack(alignment: .leading, spacing: DS.Space.xxs) {
                HStack(spacing: DS.Space.xs) {
                    SecureField("Password", text: $gate.password)
                        .textFieldStyle(.roundedBorder).controlSize(.large)
                        .focused($focused)
                        .disabled(blocked)
                        .onSubmit { gate.unlockWithPassword() }
                        .accessibilityLabel("Document password")
                        .accessibilityIdentifier("unlock-password")
                        .startFit(.field, "Password")
                    Button { gate.unlockWithPassword() } label: {
                        Image(systemName: "arrow.right").frame(minWidth: 20, minHeight: 20)
                    }
                    .buttonStyle(.bordered).controlSize(.large)
                    .keyboardShortcut(.defaultAction)
                    .disabled(blocked || gate.password.isEmpty)
                    .accessibilityLabel("Unlock")
                    .accessibilityIdentifier("start-unlock")
                    .startFit(.button, "Unlock")
                }
                status
            }
            VStack(alignment: .leading, spacing: DS.Space.xxs) {
                Toggle("Keep unlocked until screen locks", isOn: $gate.rememberUntilQuit).toggleStyle(.checkbox)
                    .help("No idle lock until Gantry quits. Screen lock and sleep still lock.")
                    .startFit(.toggle, "Keep unlocked")
                if DocumentTouchID.available && !touchIDReady {
                    Toggle("Use Touch ID next time", isOn: $gate.saveForTouchID).toggleStyle(.checkbox)
                        .help("Keeps this document's key on this Mac, sealed to your enrolled fingers. Never the password.")
                        .accessibilityIdentifier("unlock-touch-id-choice")
                        .startFit(.toggle, "Use Touch ID next time")
                }
            }
            .font(DS.Font.callout)
        }
        .onAppear { focused = !gate.touchIDRunning }
        .onChange(of: gate.touchIDRunning) { _, running in if !running { focused = true } }
        .onExitCommand { gate.showWelcome() }
        .accessibilityIdentifier("start-unlock-pane")
    }

    private var orDivider: some View {
        HStack(spacing: DS.Space.xs) {
            VStack { Divider() }
            Text("or password").font(DS.Font.caption).foregroundStyle(.secondary).fixedSize()
            VStack { Divider() }
        }
    }

    @ViewBuilder private var status: some View {
        if gate.waitSecs > 0 {
            StartProblem(text: "Too many wrong passwords. Try again in \(gate.waitSecs) s.", tint: .orange)
        } else if let p = gate.problem {
            StartProblem(text: p)
        } else if !gate.biometricAllowed && SecureEnclave.isAvailable {
            StartProblem(text: "Touch ID is turned off by your administrator.", tint: .secondary)
        }
    }
}

/// An unprotected recent: no password, so Open is the one action.
struct StartOpenPane: View {
    let gate: DocumentGate
    let recent: DocumentGate.Recent

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            StartTitle(title: recent.displayName,
                       detail: ["No password", StartText.connections(recent.connectionCount), StartText.lastOpened(recent.lastOpenedAt).map { "last " + $0 }].compactMap { $0 }.joined(separator: " · "))
            Button { gate.showUnlock(path: recent.path) } label: { Text("Open").frame(maxWidth: .infinity, minHeight: 28) }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("start-open-document")
                .startFit(.button, "Open")
            StartProblem(text: gate.problem)
        }
    }
}

/// The last document (or a picked one) whose file is gone or unreadable.
struct StartMissingPane: View {
    let gate: DocumentGate
    let recent: DocumentGate.Recent

    var body: some View {
        let file = (recent.path as NSString).lastPathComponent
        let damaged = FileManager.default.fileExists(atPath: recent.path)
        VStack(alignment: .leading, spacing: DS.Space.m) {
            StartTitle(title: recent.displayName, detail: StartText.shortPath(recent.path))
            Text(damaged ? "“\(file)” can’t be read: damaged or not a Gantry document." : "“\(file)” was moved or deleted.")
                .font(DS.Font.callout).foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: DS.Space.xs) {
                Button("Locate…") { gate.locate(recent) }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .startFit(.button, "Locate…")
                Button("Remove from Recents") { gate.removeRecent(recent) }
                    .startFit(.button, "Remove from Recents")
            }
            .controlSize(.large)
        }
        .accessibilityIdentifier("document-missing-notice")
    }
}

/// First run (no recents) or nothing selected: New document is the primary action.
struct StartWelcomePane: View {
    let gate: DocumentGate

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            StartTitle(title: gate.recents.isEmpty ? "Welcome to Gantry" : "No document selected",
                       detail: gate.recents.isEmpty ? "A document holds folders, connections and credentials, encrypted." : "Pick one on the left, or start another.")
            VStack(spacing: DS.Space.xs) {
                Button { gate.showCreate() } label: { Text("New document").frame(maxWidth: .infinity, minHeight: 28) }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("start-welcome-new")
                    .startFit(.button, "New document (welcome)")
                Button { gate.openAnother() } label: { Text("Open document…").frame(maxWidth: .infinity, minHeight: 28) }
                    .startFit(.button, "Open document… (welcome)")
            }
            .controlSize(.large)
            StartProblem(text: gate.problem)
        }
        .accessibilityIdentifier("start-welcome")
    }
}
