import AppKit
import BastionCore

/// Prompt variables (`$Ask:Label$`, core `tasks::ask_labels`): one sheet per run asks each label
/// once; the answers go to every host of that run.
extension Commands {
    /// The answers for `task`'s prompt variables: empty when it has none, nil when cancelled.
    static func askTaskAnswers(_ task: TaskView, library: Library) async -> [String: String]? {
        let labels = (try? taskAskLabels(library: library, taskId: task.id)) ?? []
        guard !labels.isEmpty else { return [:] }
        let alert = NSAlert()
        alert.messageText = "Run “\(task.name)”"
        alert.informativeText = "Used for every host in this run."
        let fields = labels.map { label -> NSTextField in
            let f = NSTextField(string: "")
            f.placeholderString = label
            f.toolTip = "Replaces $Ask:\(label)$ in the task."
            f.setAccessibilityLabel(label)
            return f
        }
        let rows = zip(labels, fields).map { label, field -> NSView in
            let name = NSTextField(labelWithString: label)
            name.alignment = .right
            name.lineBreakMode = .byTruncatingTail
            name.widthAnchor.constraint(equalToConstant: 110).isActive = true
            field.widthAnchor.constraint(greaterThanOrEqualToConstant: 200).isActive = true
            return NSStackView(views: [name, field])
        }
        let stack = NSStackView(views: rows)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.setFrameSize(stack.fittingSize)
        alert.accessoryView = stack
        alert.addButton(withTitle: "Run")
        alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
        alert.window.initialFirstResponder = fields.first
        guard await present(alert) == .alertFirstButtonReturn else { return nil }
        return Dictionary(zip(labels, fields.map(\.stringValue)), uniquingKeysWith: { a, _ in a })
    }
}
