import Foundation
import BastionCore

/// Library entries of plugin connection types (PLUG-PVE-01, Native Mac). The core stores such an
/// entry under `<plugin id>/<type id>` and marks it unavailable, because the core alone cannot open
/// it; when an installed plugin offers that type, the app opens it through the plugin instead.
@MainActor
enum PluginEntries {
    /// The installed plugins' connection types, read at start and after an install or removal.
    private(set) static var types: [PluginTypeView] = []

    static func reload() {
        types = (try? pluginConnectionTypes(dataDir: LibraryModel.dataDir.path)) ?? []
        Icons.forgetPluginIcons()
    }

    /// The installed type of `c`, when it is a plugin entry this app can open.
    static func type(of c: ConnectionView) -> PluginTypeView? {
        guard c.unavailable != nil else { return nil }
        return types.first { $0.id == c.protocol }
    }

    /// The PostgreSQL type (PLUG-08): the Official plugin's, else a test copy's (`*.postgres/postgres`).
    static var postgres: PluginTypeView? {
        types.first { $0.id == "dev.gantry.postgres/postgres" || $0.id == "dev.bastion.postgres/postgres" } ?? types.first { $0.id.hasSuffix(".postgres/postgres") }
    }

    /// The core's "cannot open" text, unless an installed plugin opens the entry.
    static func unavailable(_ c: ConnectionView) -> String? {
        type(of: c) == nil ? c.unavailable : nil
    }
}
