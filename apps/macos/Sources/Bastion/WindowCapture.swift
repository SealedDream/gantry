#if BASTION_TEST_HOOKS
import AppKit

/// Pictures of the app's own windows for test captures (`UIDriver`'s capture steps), taken inside the
/// app so they show the state at the moment of the step. Nothing here runs outside a UI-driver run.
///
/// Two sources, tried in order:
/// - the window server's image of the window: complete (sidebar and inspector materials included), no
///   Screen Recording permission needed for the app's own windows, but not available while the screen
///   is locked or the display sleeps;
/// - the views drawn into a bitmap (`cacheDisplay`): works with the screen locked, but leaves
///   materials such as the sidebar background empty.
/// A source whose picture is blank (`CaptureCheck`) counts as failed. Every CAPTURE log line names
/// the source used (`source=window` or `source=views`).
@MainActor
enum WindowCapture {
    enum Source: String {
        /// The window server's image: the complete picture. The one to use for evidence.
        case window
        /// The views drawn into a bitmap: the fallback, with materials such as the sidebar background missing.
        case views

        static let allInOrder: [Source] = [.window, .views]
    }

    struct Picture {
        let image: CGImage
        let source: Source
    }

    /// The sources to try, in order. `BASTION_UI_CAPTURE_SOURCE=window` (or the `capture-source window`
    /// step) allows only the complete picture, so a capture fails instead of falling back; `views`
    /// allows only the fallback, to test the locked-screen path on an unlocked screen.
    static var sources: [Source] = sources(for: ProcessInfo.processInfo.environment["BASTION_UI_CAPTURE_SOURCE"]) ?? Source.allInOrder

    /// The sources for `window`, `views` or `any`; nil for anything else.
    static func sources(for choice: String?) -> [Source]? {
        guard let choice else { return nil }
        if choice == "any" { return Source.allInOrder }
        return Source(rawValue: choice).map { [$0] }
    }

    /// Whether the login session's screen is locked (also true under the screen saver once it asks for the password).
    static var isScreenLocked: Bool {
        (CGSessionCopyCurrentDictionary() as? [String: Any])?["CGSSessionScreenIsLocked"] as? Bool ?? false
    }

    /// `window` followed by what is attached to it: sheets (alerts included), nested sheets and visible
    /// child windows such as popovers. Bottom first.
    static func stack(_ window: NSWindow) -> [NSWindow] {
        var seen = Set<ObjectIdentifier>()
        func walk(_ w: NSWindow) -> [NSWindow] {
            guard w.isVisible, seen.insert(ObjectIdentifier(w)).inserted else { return [] }
            let attached = (w.childWindows ?? []) + [w.attachedSheet].compactMap { $0 }
            return [w] + attached.flatMap(walk)
        }
        return walk(window)
    }

    /// The picture of `window` with everything attached to it, or nil when neither source gives one.
    static func take(_ window: NSWindow) -> Picture? {
        let windows = stack(window)
        guard !windows.isEmpty else { return nil }
        for source in sources {
            let images = windows.map { image(of: $0, from: source) }
            guard !images.contains(where: { $0 == nil }),
                  let whole = compose(zip(windows, images.compactMap { $0 }).map { ($0.frame, $1) }),
                  !CaptureCheck.isBlank(whole) else { continue }
            return Picture(image: whole, source: source)
        }
        return nil
    }

    /// PNG data of `image`.
    static func png(_ image: CGImage) -> Data? {
        NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
    }

    private static func image(of window: NSWindow, from source: Source) -> CGImage? {
        switch source {
        case .window:
            return Snapshot.windowImage(window.windowNumber)
        case .views:
            // The frame view (contentView's superview) includes the title bar and toolbar.
            guard let view = window.contentView?.superview, let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return nil }
            view.cacheDisplay(in: view.bounds, to: rep)
            return rep.cgImage
        }
    }

    /// The first picture with the others drawn over it where their window frames (screen points) put them.
    private static func compose(_ parts: [(frame: CGRect, image: CGImage)]) -> CGImage? {
        guard let base = parts.first else { return nil }
        guard parts.count > 1 else { return base.image }
        guard base.frame.width > 0, base.frame.height > 0,
              let context = CGContext(data: nil, width: base.image.width, height: base.image.height, bitsPerComponent: 8, bytesPerRow: 0,
                                      space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        else { return nil }
        let scaleX = CGFloat(base.image.width) / base.frame.width
        let scaleY = CGFloat(base.image.height) / base.frame.height
        for part in parts {
            context.draw(part.image, in: CGRect(x: (part.frame.minX - base.frame.minX) * scaleX, y: (part.frame.minY - base.frame.minY) * scaleY,
                                                width: part.frame.width * scaleX, height: part.frame.height * scaleY))
        }
        return context.makeImage()
    }
}
#endif
