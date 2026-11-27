import Foundation

/// Reads accessibility attributes as plain objects, never bridged to Swift types.
///
/// Some element in the main window answers `accessibilityRole` or `accessibilityTitle` with an
/// object that is not a string. Bridging that object to `String` raises an Objective-C exception.
/// When that happened inside a Swift task (the UI driver), the exception unwound the task's job
/// without unwinding the Swift runtime's executor tracking. AppKit caught the exception and carried
/// on, and the next `MainActor.assumeIsolated` call (the vault auto-lock timer) read the dead state
/// and crashed with SIGSEGV.
enum AXTree {
    static let popUpRoles: Set<String> = ["AXPopUpButton", "AXMenuButton"]

    /// The attribute as an object, or nil when the element does not answer it.
    static func object(_ element: AnyObject, _ getter: String) -> AnyObject? {
        guard let o = element as? NSObject else { return nil }
        let selector = NSSelectorFromString(getter)
        guard o.responds(to: selector) else { return nil }
        return o.perform(selector)?.takeUnretainedValue()
    }

    /// The attribute as text: a string as it is, an attributed string's characters, anything else
    /// by its description, and "" when there is none.
    static func text(_ element: AnyObject, _ getter: String) -> String {
        guard let v = object(element, getter) else { return "" }
        if let s = v as? NSString { return s as String }
        if let a = v as? NSAttributedString { return a.string }
        return String(describing: v)
    }

    /// Depth-first: a pop-up or menu button whose value or title is `showing` ("*" for any).
    static func popUp(in node: Any?, showing: String, depth: Int = 0) -> NSObject? {
        guard depth < 60, let e = node as? NSObject else { return nil }
        if popUpRoles.contains(text(e, "accessibilityRole")) {
            if showing == "*" || text(e, "accessibilityValue") == showing || text(e, "accessibilityTitle") == showing { return e }
        }
        for child in (object(e, "accessibilityChildren") as? NSArray) ?? [] {
            if let found = popUp(in: child, showing: showing, depth: depth + 1) { return found }
        }
        return nil
    }
}
