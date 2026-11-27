import SwiftUI
import BastionCore

/// One field: `user@host:port`, `rdp://host`, `vnc://host`, `sftp://host` or a web address.
/// The core parses it as you type; Return opens it through the normal connect sheet as an
/// unsaved connection (nothing is added to the library).
struct QuickConnectView: View {
    @Environment(Commands.self) private var commands
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @FocusState private var focused: Bool

    private var trimmed: String { text.trimmingCharacters(in: .whitespaces) }

    private var parsed: Result<QuickConnectTarget, Error>? {
        guard !trimmed.isEmpty else { return nil }
        return Result { try quickConnectTarget(target: trimmed) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            TextField("user@host, rdp://host or https://…", text: $text)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                .onSubmit(connect)
                .onExitCommand { dismiss() }
            HStack(spacing: DS.Space.xxs) {
                switch parsed {
                case .success(let t):
                    let icon = t.mode == "files" ? "sftp" : t.protocol
                    Image(systemName: Icons.symbol(icon)).foregroundStyle(.secondary)
                    Text("\(Icons.info(icon).label) · \(t.label)").lineLimit(1).truncationMode(.middle)
                case .failure(let e):
                    Text(e.userMessage).foregroundStyle(.red).lineLimit(1)
                case nil:
                    Text("Not saved to the library").foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .font(DS.Font.caption)
        }
        .padding(DS.Space.s)
        .frame(width: DS.Size.dialogWidth)
        // The popover's window becomes key after onAppear; focusing earlier is ignored.
        .task {
            if let prefill = commands.quickConnectPrefill { text = prefill; commands.quickConnectPrefill = nil }
            try? await Task.sleep(for: .milliseconds(50))
            focused = true
        }
    }

    private func connect() {
        guard case .success(let t)? = parsed else { return }
        do {
            let library = try Library.quickConnect(target: trimmed)
            guard let c = library.tree().connections.first else { return }
            dismiss()
            commands.requestConnect(c, t.mode == "files" ? .files : .terminal, library: library)
        } catch {
            commands.model.error = error.userMessage
        }
    }
}
