import AppKit
import BastionCore

/// A1-CORE-01-FU5: a library opened by path that this Mac has never answered for is asked about
/// once ("Did you make this library?") before its tree is shown. Until it is answered the core
/// keeps every login the file names offered, not used. Closing the question sends nothing: the
/// marks hold for this session and the library is asked about again the next time it is opened.
@MainActor
enum OriginQuestion {
    enum Answer: Equatable { case madeByMe, sent, closed }

    static let title = "Did you make this library?"

    static func message(name: String) -> String {
        "“\(name)” has not been opened on this device before. If someone else sent it to you, Gantry will ask before using any saved login it names."
    }

    /// Asked this session and closed without an answer: not asked again until the document is reopened.
    private static var closedThisSession: Set<String> = []

    /// Once at launch, before the restore: record Personal, Recents and the restored paths as known.
    static func migrate(dataDir: String, personalId: String?, restorePaths: [String]) -> String? {
        do {
            _ = try migrateKnownDocuments(dataDir: dataDir, personalId: personalId, restorePaths: restorePaths)
            return nil
        } catch {
            // Not written: unknown documents are asked about, and the migration runs again next start.
            return "Could not record the libraries opened on this Mac: \(errorText(error))"
        }
    }

    /// For an unlocked document whose origin is unknown: ask, then send the answer. Returns an error text.
    static func askIfNeeded(_ doc: OpenDocument) -> String? {
        guard doc.handle.origin() == .unknown, !closedThisSession.contains(doc.id) else { return nil }
        let answer = ask(name: doc.info.name)
        guard answer != .closed else {
            closedThisSession.insert(doc.id)
            return nil
        }
        do {
            try doc.handle.answerOrigin(madeByMe: answer == .madeByMe)
            return nil
        } catch {
            return "Could not record the answer for \(doc.info.name): \(errorText(error))"
        }
    }

    /// The document was closed: the next open asks again while it is still unknown.
    static func forget(_ id: String) { closedThisSession.remove(id) }

    private static func ask(name: String) -> Answer {
        if let s = DocumentDialogs.nextScripted() {
            print("DOCUMENT-ORIGIN \(name): \(s.isEmpty ? "closed" : s)")
            return s == "made" ? .madeByMe : s == "sent" ? .sent : .closed
        }
        let a = NSAlert()
        a.messageText = title
        a.informativeText = message(name: name)
        // "Someone sent it" is the default (Return); "I made it" must be clicked.
        a.addButton(withTitle: "Someone sent it")
        a.addButton(withTitle: "I made it").keyEquivalent = ""
        switch a.runModalInFront() {
        case .alertFirstButtonReturn: return .sent
        case .alertSecondButtonReturn: return .madeByMe
        default: return .closed
        }
    }
}
