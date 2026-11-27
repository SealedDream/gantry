import SwiftUI
import BastionCore

/// Move to…: pick a destination folder. A folder's own subtree is not offered (the core refuses it too).
struct MoveSheet: View {
    let nodeId: String
    @Environment(LibraryModel.self) private var model
    @Environment(Commands.self) private var commands
    @Environment(\.dismiss) private var dismiss
    @State private var destination: String? = MoveSheet.root

    private static let root = "root"

    private var name: String { model.connection(id: nodeId)?.name ?? model.folder(id: nodeId)?.name ?? "" }

    /// Every folder that can receive the node, with its depth for indentation.
    private var targets: [(id: String, name: String, depth: Int)] {
        var out: [(id: String, name: String, depth: Int)] = [(Self.root, "Library", 0)]
        func walk(_ f: FolderView, depth: Int) {
            for sub in f.folders where sub.id != nodeId {
                out.append((sub.id, sub.name, depth))
                walk(sub, depth: depth + 1)
            }
        }
        if let tree = model.tree { walk(tree, depth: 1) }
        return out
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Move “\(name)”").font(DS.Font.bodyStrong)
            List(targets, id: \.id, selection: $destination) { t in
                Label(t.name, systemImage: t.id == Self.root ? "tray.full" : "folder")
                    .padding(.leading, CGFloat(t.depth) * DS.Space.s)
                    .tag(Optional(t.id))
            }
            .frame(height: 260)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Move", action: move).keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(destination == nil)
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth)
    }

    private func move() {
        let parent = destination == Self.root ? nil : destination
        model.patch(colours: true) { try $0.moveNodeBefore(id: nodeId, parent: parent, before: nil); return [nodeId] }
        if let parent { commands.tree.setExpanded(parent, true) }
        dismiss()
    }
}
