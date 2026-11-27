import AppKit
import SwiftUI
import BastionCore

/// New document, in place of the start window's right half: name, folder, password with its
/// strength, and Touch ID (policy text when turned off). Create saves straight to the folder.
struct StartCreatePane: View {
    @Bindable var gate: DocumentGate
    @State private var form = DocumentGate.NewDocument()
    @State private var folder = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        ?? URL(fileURLWithPath: NSHomeDirectory())
    @State private var createError: String?
    @FocusState private var nameFocused: Bool

    private var strength: Double { form.password.isEmpty ? 0 : passwordStrengthBits(password: form.password) }
    private var mismatch: Bool { !form.confirm.isEmpty && form.confirm != form.password }

    var body: some View {
        // Fits: fields, actions and footer centred as one group. Too short: the fields scroll and
        // Cancel / Create stay pinned under them.
        ViewThatFits(in: .vertical) {
            VStack(alignment: .leading, spacing: DS.Space.l) { fields; bottom }
                .frame(maxWidth: StartWindow.rightContent)
                .padding(DS.Space.xl)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            VStack(spacing: 0) {
                ScrollView(.vertical) {
                    fields
                        .frame(maxWidth: StartWindow.rightContent)
                        .padding(.horizontal, DS.Space.xl)
                        .padding(.top, DS.Space.xl)
                        .padding(.bottom, DS.Space.m)
                        .frame(maxWidth: .infinity)
                }
                .scrollBounceBehavior(.basedOnSize)
                bottom
                    .frame(maxWidth: StartWindow.rightContent)
                    .padding(.horizontal, DS.Space.xl)
                    .padding(.top, DS.Space.s)
                    .padding(.bottom, DS.Space.l)
                    .frame(maxWidth: .infinity)
            }
        }
        .onChange(of: gate.createFocusRequest) { _, _ in focusName() }
        .onAppear { focusName() }
        .accessibilityIdentifier("start-create-pane")
    }

    private var bottom: some View {
        VStack(alignment: .leading, spacing: DS.Space.l) { actions; StartFooter() }
    }

    private var fields: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            StartTitle(title: "New document", detail: "Encrypted with its own password.")
            VStack(alignment: .leading, spacing: DS.Space.s) {
                field("Name") {
                    TextField("Name", text: $form.name).textFieldStyle(.roundedBorder)
                        .focused($nameFocused)
                        .accessibilityIdentifier("create-document-name")
                        .startFit(.field, "Name")
                }
                field("Folder") {
                    HStack(spacing: DS.Space.xs) {
                        Text(StartText.shortPath(folder.path)).lineLimit(1).truncationMode(.middle)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .help(folder.path)
                        Button("Choose…") { chooseFolder() }.accessibilityIdentifier("create-document-folder").startFit(.button, "Choose…")
                    }
                }
                field("Password") {
                    VStack(alignment: .leading, spacing: DS.Space.xxs) {
                        SecureField("Password", text: $form.password).textFieldStyle(.roundedBorder)
                            .accessibilityIdentifier("create-document-password")
                            .startFit(.field, "Password (new)")
                        StrengthMeter(bits: strength)
                    }
                }
                field("Confirm") {
                    VStack(alignment: .leading, spacing: DS.Space.xxs) {
                        SecureField("Confirm password", text: $form.confirm).textFieldStyle(.roundedBorder)
                            .onSubmit(create)
                            .accessibilityIdentifier("create-document-confirm")
                            .startFit(.field, "Confirm")
                        StartProblem(text: mismatch ? "Passwords do not match." : nil)
                    }
                }
                VStack(alignment: .leading, spacing: DS.Space.xxs) {
                    Toggle("Unlock with Touch ID", isOn: $form.touchID).toggleStyle(.checkbox)
                        .disabled(!gate.biometricAllowed || form.password.isEmpty)
                    if !gate.biometricAllowed {
                        Text("Turned off by your administrator.").font(DS.Font.caption).foregroundStyle(.secondary)
                    } else if form.password.isEmpty {
                        Text("No password: the document is not encrypted.").font(DS.Font.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(.leading, StartCreatePane.labelWidth + DS.Space.xs)
                StartProblem(text: createError ?? gate.problem)
            }
        }
    }

    private var actions: some View {
            HStack(spacing: DS.Space.xs) {
                Spacer(minLength: 0)
                Button("Cancel") { gate.leaveCreate() }
                    .startFit(.button, "Cancel", pinned: true)
                    .keyboardShortcut(.cancelAction)
                    .disabled(!gate.canCancelCreate && !gate.recents.contains { $0.present })
                Button("Create", action: create)
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(form.name.trimmingCharacters(in: .whitespaces).isEmpty || mismatch)
                    .accessibilityIdentifier("create-document-create")
                    .startFit(.button, "Create", pinned: true)
            }
            .controlSize(.large)
    }

    static let labelWidth: CGFloat = 72

    private func field<C: View>(_ label: String, @ViewBuilder _ content: () -> C) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: DS.Space.xs) {
            Text(label).foregroundStyle(.secondary).frame(width: Self.labelWidth, alignment: .trailing)
                .accessibilityHidden(true)
            content()
        }
    }

    private func create() {
        guard !mismatch else { return }
        createError = gate.create(form, folder: folder)
    }

    private func chooseFolder() {
        if let url = DocumentDialogs.chooseFolder(title: "Choose Folder", start: folder) { folder = url }
    }

    /// Focus the Name field and select its text (File › New Document…).
    private func focusName() {
        nameFocused = true
        DispatchQueue.main.async { NSApp.keyWindow?.firstResponder.flatMap { $0 as? NSTextView }?.selectAll(nil) }
    }
}

/// Password strength as a thin bar and its bits; colour only past the bar's start.
private struct StrengthMeter: View {
    let bits: Double
    private var tint: Color { bits < 50 ? .red : bits < 80 ? .orange : .green }

    var body: some View {
        HStack(spacing: DS.Space.xs) {
            ProgressView(value: min(bits, 100), total: 100).tint(tint).controlSize(.small)
                .accessibilityLabel("Password strength")
                .accessibilityValue(bits == 0 ? "None" : "About \(Int(bits)) bits")
            Text(bits == 0 ? " " : "\(Int(bits)) bits").font(DS.Font.caption).foregroundStyle(.secondary)
                .monospacedDigit().frame(width: 52, alignment: .trailing)
        }
    }
}
