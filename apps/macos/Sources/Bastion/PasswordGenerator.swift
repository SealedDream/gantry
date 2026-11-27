import AppKit
import SwiftUI
import BastionCore

/// Password generator: the vault's generator (core `vault::generate_password`, rejection-sampled
/// from the OS RNG) with its strength estimate. Opened from the View menu (Copy only) or from the
/// credential editor, where Use Password also fills the password field. Copies are marked
/// concealed so clipboard managers and the RDP clipboard skip them.
struct PasswordGeneratorSheet: View {
    var onUse: ((String) -> Void)?
    private var dismiss = PanelDismiss()
    @State private var length = 24.0
    @State private var password = ""
    @State private var error: String?
    @State private var copied = false

    static let lengths = 12.0...128.0

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Password Generator").font(DS.Font.bodyStrong)
            Text(password)
                .font(DS.Font.size(13, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(4)
                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                .padding(DS.Space.xs)
                .background(RoundedRectangle(cornerRadius: 4).fill(.background.secondary))
                .accessibilityLabel("Generated password")
            LabeledContent("Length") {
                HStack {
                    // Whole lengths by rounding, not `step: 1`: a step makes NSSlider lay out a tick
                    // mark per value (117), ~150 ms of CoreUI measuring on every open (perf 2026-11-16).
                    Slider(value: Binding(get: { length }, set: { length = $0.rounded() }), in: Self.lengths).frame(width: 220)
                    Text("\(Int(length))").monospacedDigit().frame(width: 32, alignment: .trailing)
                }
            }
            Text(error ?? strength).font(DS.Font.caption).foregroundStyle(error == nil ? .secondary : Color.red)
            HStack {
                Button("Regenerate", action: generate)
                Button(copied ? "Copied" : "Copy", action: copy).disabled(password.isEmpty)
                Spacer()
                Button(onUse == nil ? "Done" : "Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                if let onUse {
                    Button("Use Password") { onUse(password); dismiss() }.keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(password.isEmpty)
                }
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth + 120)
        .onAppear(perform: generate)
        .onChange(of: length) { generate() }
    }

    private var strength: String {
        let bits = Int(passwordStrengthBits(password: password))
        let word = bits >= 128 ? "Very strong" : bits >= 80 ? "Strong" : bits >= 60 ? "Fair" : "Weak"
        return "\(word): about \(bits) bits"
    }

    private func generate() {
        copied = false
        do {
            password = try generatePassword(length: UInt32(length))
            error = nil
        } catch {
            self.error = "\(error)"
        }
    }

    private func copy() {
        SecretPasteboard.copy(password)
        copied = true
    }
}

/// A secret on the pasteboard (QA S1): marked concealed and transient so clipboard managers skip
/// it, and cleared after its lifetime, but only while the pasteboard still holds this copy.
@MainActor
enum SecretPasteboard {
    /// The setting "Clear copied passwords after" (A3-S1), read from `settings.json` now, at copy
    /// time: 30, 45 or 60 s. The core gives the shortest one when the file cannot be read.
    static var configuredLifetime: Duration {
        .seconds(Int64(secretClipboardSeconds(path: SettingsModel.path.path)))
    }
    private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    /// `lifetime` is for tests; every real copy uses the setting.
    static func copy(_ secret: String, to pb: NSPasteboard = .general, lifetime: Duration? = nil) {
        let lifetime = lifetime ?? configuredLifetime
        pb.clearContents()
        pb.setString(secret, forType: .string)
        pb.setString("", forType: concealed)
        pb.setString("", forType: transient)
        let change = pb.changeCount
        Task { @MainActor in
            try? await Task.sleep(for: lifetime)
            clearIfUnchanged(pb, changeCount: change, secret: secret)
        }
    }

    /// Clears only our own copy: a later copy by the user bumps `changeCount` and is left alone.
    static func clearIfUnchanged(_ pb: NSPasteboard, changeCount: Int, secret: String) {
        guard pb.changeCount == changeCount, pb.string(forType: .string) == secret else { return }
        pb.clearContents()
    }
}
