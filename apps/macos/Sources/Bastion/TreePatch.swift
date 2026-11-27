import BastionCore

/// Replaces one node of the library tree with a fresh copy from the core (`Library.nodeView`), or
/// removes it, returning a new tree; the input is never changed. Nil when the node's new parent is
/// not in the tree (the caller then reads the whole tree).
enum TreePatch {
    static func applying(_ node: NodeView?, id: String, to root: FolderView) -> FolderView? {
        let without = removing(id, from: root) ?? root
        guard let node else { return without }
        return inserting(node, into: without)
    }

    /// `f` without the node `id`; nil when `id` is not under `f`.
    static func removing(_ id: String, from f: FolderView) -> FolderView? {
        var copy = f
        if let i = f.folders.firstIndex(where: { $0.id == id }) { copy.folders.remove(at: i); return copy }
        if let i = f.connections.firstIndex(where: { $0.id == id }) { copy.connections.remove(at: i); return copy }
        for (i, sub) in f.folders.enumerated() {
            if let changed = removing(id, from: sub) { copy.folders[i] = changed; return copy }
        }
        return nil
    }

    /// `f` with `node` placed under its parent at its index; nil when the parent is not under `f`.
    static func inserting(_ node: NodeView, into f: FolderView) -> FolderView? {
        var copy = f
        if f.id == node.parentId {
            if let folder = node.folder {
                copy.folders.insert(folder, at: min(Int(node.index), copy.folders.count))
            } else if let connection = node.connection {
                copy.connections.insert(connection, at: min(Int(node.index), copy.connections.count))
            }
            return copy
        }
        for (i, sub) in f.folders.enumerated() {
            if let changed = inserting(node, into: sub) { copy.folders[i] = changed; return copy }
        }
        return nil
    }
}
