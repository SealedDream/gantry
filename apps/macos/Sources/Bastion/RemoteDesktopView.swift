import AppKit
import SwiftUI

/// A picture of a remote desktop, 4 bytes per pixel in B, G, R, A order.
struct DesktopFrame {
    let width: Int
    let height: Int
    let serial: UInt64
    let bgra: Data
}

enum DesktopButton { case left, right, middle }

/// What the canvas needs from a remote-desktop protocol (RDP, VNC).
protocol RemoteDesktop: AnyObject {
    /// Non-nil once the session has ended.
    var closeReason: String? { get }
    /// The session object behind this desktop: tab previews find the canvas's picture by it (B11).
    var previewKey: ObjectIdentifier { get }
    /// The current picture, or nil when nothing changed since `serial`.
    func frame(after serial: UInt64) -> DesktopFrame?
    /// Pointer position in desktop pixels.
    func pointer(x: UInt16, y: UInt16)
    func button(_ button: DesktopButton, down: Bool)
    /// A key went down or up. `event` is nil for modifier flag changes.
    func key(_ event: NSEvent?, keyCode: UInt16, down: Bool)
    /// Focus left the canvas: release every key the server still has down.
    func releaseAllKeys()
    /// Exchange clipboard text with the server, if the session shares it. Called on every poll.
    func syncClipboard()
    /// The view settled at a new size in points; a desktop that can follow it asks the server to resize.
    func viewResized(width: Int, height: Int)
}

extension RemoteDesktop {
    func syncClipboard() {}
    func releaseAllKeys() {}
    func viewResized(width: Int, height: Int) {}
}

/// Shows a remote desktop and forwards mouse and keyboard to it. The picture is letterboxed to
/// keep the remote aspect ratio; pointer positions are mapped back to desktop pixels.
struct RemoteDesktopView: NSViewRepresentable {
    let desktop: RemoteDesktop
    let isActive: Bool
    var fit: DesktopFit = .fit
    var onClosed: (String?) -> Void = { _ in }

    func makeNSView(context: Context) -> RemoteDesktopCanvas {
        let view = RemoteDesktopCanvas(desktop: desktop, fit: fit)
        view.onClosed = onClosed
        return view
    }

    func updateNSView(_ view: RemoteDesktopCanvas, context: Context) {
        view.isActive = isActive
        if isActive, view.window?.firstResponder !== view { view.window?.makeFirstResponder(view) }
    }
}

final class RemoteDesktopCanvas: NSView {
    /// Polling rate for new frames; a frame is only copied when its serial changed.
    private static let framesPerSecond = 60.0

    private let desktop: RemoteDesktop
    private let fit: DesktopFit
    /// The newest size a desktop canvas settled at, for the size an RDP connect asks for.
    nonisolated(unsafe) static var lastViewSize: CGSize?
    private var image: CGImage?
    private var size = CGSize.zero
    private var serial: UInt64 = 0
    private var timer: Timer?
    private var reportedClose = false
    var isActive = true
    var onClosed: (String?) -> Void = { _ in }
    /// The picture on screen now, for tab previews (read only; previews never poll the desktop).
    var currentImage: CGImage? { image }

    init(desktop: RemoteDesktop, fit: DesktopFit = .fit) {
        self.desktop = desktop
        self.fit = fit
        super.init(frame: .zero)
        // The GPU scales the picture: the layer shows each frame as its contents. Any margin
        // (a server that keeps its size) is the window background, as in other tabs.
        wantsLayer = true
        layerContentsRedrawPolicy = .never
        layer?.masksToBounds = true
        if fit == .fixed {
            // One desktop pixel per point, centred; larger desktops are clipped at the edges.
            layer?.contentsGravity = .center
            layer?.contentsScale = 1
        } else {
            layer?.contentsGravity = .resizeAspect
        }
        layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError("not used") }

    override var acceptsFirstResponder: Bool { true }

    override func resignFirstResponder() -> Bool {
        desktop.releaseAllKeys()
        return super.resignFirstResponder()
    }
    override var isFlipped: Bool { true }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        timer?.invalidate()
        guard window != nil else { return }
        PreviewFrames.register(self, key: desktop.previewKey)
        timer = Timer.scheduledTimer(withTimeInterval: 1 / Self.framesPerSecond, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.poll() }
        }
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(rect: .zero, options: [.mouseMoved, .activeInKeyWindow, .inVisibleRect], owner: self))
    }

    private func poll() {
        if let reason = desktop.closeReason, !reportedClose {
            reportedClose = true
            onClosed(reason)
        }
        if !reportedClose { desktop.syncClipboard() }
        guard isActive, let frame = desktop.frame(after: serial) else { return }
        serial = frame.serial
        size = CGSize(width: frame.width, height: frame.height)
        image = Self.makeImage(frame)
        layer?.contents = image
    }

    private static func makeImage(_ frame: DesktopFrame) -> CGImage? {
        guard let provider = CGDataProvider(data: frame.bgra as CFData) else { return nil }
        let info = CGBitmapInfo(rawValue: CGImageAlphaInfo.noneSkipFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue)
        return CGImage(width: frame.width, height: frame.height, bitsPerComponent: 8, bitsPerPixel: 32, bytesPerRow: frame.width * 4,
                       space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: info, provider: provider,
                       decode: nil, shouldInterpolate: true, intent: .defaultIntent)
    }

    /// Where the desktop is drawn: as large as fits, never stretched (1:1 for Fixed size).
    private var desktopRect: CGRect {
        guard size.width > 0, size.height > 0 else { return .zero }
        let scale = fit == .fixed ? 1 : min(bounds.width / size.width, bounds.height / size.height)
        let fitted = CGSize(width: size.width * scale, height: size.height * scale)
        return CGRect(x: (bounds.width - fitted.width) / 2, y: (bounds.height - fitted.height) / 2, width: fitted.width, height: fitted.height)
    }

    /// Resizes are sent once the view has stopped changing for this long (window drags send many).
    private static let resizeSettle: TimeInterval = 0.4
    private var resizeWork: DispatchWorkItem?

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        resizeWork?.cancel()
        guard newSize.width >= 1, newSize.height >= 1 else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            Self.lastViewSize = newSize
            if self.fit == .fit { self.desktop.viewResized(width: Int(newSize.width), height: Int(newSize.height)) }
        }
        resizeWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.resizeSettle, execute: work)
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        }
    }

    // MARK: Pointer

    private func sendPosition(_ event: NSEvent) {
        let rect = desktopRect
        guard rect.width > 0 else { return }
        let p = convert(event.locationInWindow, from: nil)
        let x = (p.x - rect.minX) / rect.width * size.width
        let y = (p.y - rect.minY) / rect.height * size.height
        desktop.pointer(x: UInt16(max(0, min(size.width - 1, x))), y: UInt16(max(0, min(size.height - 1, y))))
    }

    private func button(_ event: NSEvent, _ button: DesktopButton, down: Bool) {
        if down { window?.makeFirstResponder(self) }
        sendPosition(event)
        desktop.button(button, down: down)
    }

    override func mouseMoved(with event: NSEvent) { sendPosition(event) }
    override func mouseDragged(with event: NSEvent) { sendPosition(event) }
    override func rightMouseDragged(with event: NSEvent) { sendPosition(event) }
    override func mouseDown(with event: NSEvent) { button(event, .left, down: true) }
    override func mouseUp(with event: NSEvent) { button(event, .left, down: false) }
    override func rightMouseDown(with event: NSEvent) { button(event, .right, down: true) }
    override func rightMouseUp(with event: NSEvent) { button(event, .right, down: false) }
    override func otherMouseDown(with event: NSEvent) { button(event, .middle, down: true) }
    override func otherMouseUp(with event: NSEvent) { button(event, .middle, down: false) }

    // MARK: Keyboard

    override func keyDown(with event: NSEvent) { desktop.key(event, keyCode: event.keyCode, down: true) }
    override func keyUp(with event: NSEvent) { desktop.key(event, keyCode: event.keyCode, down: false) }

    /// Modifier keys arrive as flag changes; the key is down when its flag is now set.
    override func flagsChanged(with event: NSEvent) {
        guard let flag = RdpScancodes.modifierFlag[event.keyCode] else { return }
        desktop.key(nil, keyCode: event.keyCode, down: event.modifierFlags.contains(flag))
    }
}
