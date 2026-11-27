import SwiftUI

/// Points 14 and 15: shown once, after this launch moved the old Personal files into the document.
struct MigrationNoticeAlert: ViewModifier {
    @Environment(LibraryModel.self) private var model

    func body(content: Content) -> some View {
        content.alert("Personal Library Moved",
                      isPresented: Binding(get: { model.migrationNotice != nil && model.error == nil },
                                           set: { if !$0 { model.migrationNotice = nil } })) {
            Button("OK") { model.migrationNotice = nil }
        } message: { Text(model.migrationNotice ?? "") }
    }
}
