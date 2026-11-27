import AppKit
import SwiftUI
import BastionCore

enum VncDefaults {
    static let port: UInt16 = 5900
}

/// Shows a VNC desktop in the shared remote-desktop canvas. Keys go out as X11 keysyms.
struct VncView: View {
    let viewer: VncViewer
    let isActive: Bool
    var fit: DesktopFit = .fit
    var onClosed: (String?) -> Void = { _ in }

    var body: some View {
        RemoteDesktopView(desktop: VncDesktop(viewer: viewer), isActive: isActive, fit: fit, onClosed: onClosed)
    }
}

final class VncDesktop: RemoteDesktop {
    private let viewer: VncViewer
    /// The keysym each held key sent, so the release matches even if modifiers changed meanwhile.
    private var held: [UInt16: UInt32] = [:]

    init(viewer: VncViewer) { self.viewer = viewer }

    var previewKey: ObjectIdentifier { ObjectIdentifier(viewer) }

    /// Asks the server to follow the tab (ExtendedDesktopSize); servers that refuse keep their size.
    func viewResized(width: Int, height: Int) {
        viewer.resize(width: UInt16(clamping: width), height: UInt16(clamping: height))
    }

    var closeReason: String? { viewer.isClosed() ? viewer.closeReason() ?? "closed" : nil }

    func frame(after serial: UInt64) -> DesktopFrame? {
        viewer.frame(afterSerial: serial).map { DesktopFrame(width: Int($0.width), height: Int($0.height), serial: $0.serial, bgra: $0.bgra) }
    }

    func pointer(x: UInt16, y: UInt16) { viewer.mouseMove(x: x, y: y) }

    func button(_ button: DesktopButton, down: Bool) {
        let b: VncButton = switch button {
        case .left: .left
        case .right: .right
        case .middle: .middle
        }
        viewer.mouseButton(button: b, down: down)
    }

    func key(_ event: NSEvent?, keyCode: UInt16, down: Bool) {
        let keysym = down ? VncKeysyms.keysym(keyCode: keyCode, event: event) : held.removeValue(forKey: keyCode)
        guard let keysym else { return }
        if down { held[keyCode] = keysym }
        viewer.key(keysym: keysym, down: down)
    }
}

/// macOS key events → X11 keysyms (RFC 6143 §7.5.4). Special keys by key code, everything else
/// by the character the key produces with Shift applied (the server applies its own Control).
enum VncKeysyms {
    static let special: [UInt16: UInt32] = [
        0x24: 0xFF0D, 0x4C: 0xFF8D, 0x30: 0xFF09, 0x33: 0xFF08, 0x35: 0xFF1B, 0x75: 0xFFFF,
        0x7B: 0xFF51, 0x7E: 0xFF52, 0x7C: 0xFF53, 0x7D: 0xFF54,
        0x73: 0xFF50, 0x77: 0xFF57, 0x74: 0xFF55, 0x79: 0xFF56,
        0x7A: 0xFFBE, 0x78: 0xFFBF, 0x63: 0xFFC0, 0x76: 0xFFC1, 0x60: 0xFFC2, 0x61: 0xFFC3,
        0x62: 0xFFC4, 0x64: 0xFFC5, 0x65: 0xFFC6, 0x6D: 0xFFC7, 0x67: 0xFFC8, 0x6F: 0xFFC9,
        // Modifiers: Shift, Control, Option → Alt, Command → Super, Caps Lock.
        0x38: 0xFFE1, 0x3C: 0xFFE2, 0x3B: 0xFFE3, 0x3E: 0xFFE4, 0x3A: 0xFFE9, 0x3D: 0xFFEA,
        0x37: 0xFFEB, 0x36: 0xFFEC, 0x39: 0xFFE5,
    ]

    static func keysym(keyCode: UInt16, event: NSEvent?) -> UInt32? {
        if let sym = special[keyCode] { return sym }
        let shift = event?.modifierFlags.intersection(.shift) ?? []
        guard let scalar = event?.characters(byApplyingModifiers: shift)?.unicodeScalars.first else { return nil }
        return keysym(for: scalar)
    }

    /// Latin-1 maps to itself; other Unicode uses the 0x01000000 plane.
    static func keysym(for scalar: Unicode.Scalar) -> UInt32? {
        switch scalar.value {
        case 0x0A, 0x0D: 0xFF0D
        case 0x20...0x7E, 0xA0...0xFF: scalar.value
        case 0x100...: 0x0100_0000 | scalar.value
        default: nil
        }
    }
}

extension SessionsModel {
    enum VncConnectResult: Sendable {
        case connected(VncViewer)
        case failed(String)
    }

    /// Runs the blocking connect off the main thread.
    func connectVnc(host: String, port: UInt16, password: String?) async -> VncConnectResult {
        await Task.detached {
            do {
                return .connected(try vncConnect(host: host, port: port, password: password))
            } catch FfiError.AuthFailed {
                return .failed("Authentication failed. Check the password.")
            } catch FfiError.Failed(let message, _) {
                return .failed(message)
            } catch {
                return .failed(error.userMessage)
            }
        }.value
    }
}

/// Password for one VNC connect; it lives only in this sheet's state until it is handed to the core.
struct VncConnectSheet: View {
    let connection: ConnectionView
    /// The unsaved Quick Connect library this connection lives in; nil for a saved connection.
    var quickLibrary: Library? = nil
    @Environment(SessionsModel.self) private var sessions
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var gateway: GatewayLogin?
    @State private var busy = false
    @State private var error: String?

    private var port: UInt16 { connection.port ?? VncDefaults.port }

    var body: some View {
        Form {
            LabeledContent("Host", value: "\(connection.host):\(port)")
            SecureField("Password (if the server asks)", text: $password)
            if let gateway, gateway.hop != nil {
                GatewaySection(login: gateway) { Task { await connect() } }
                Text("VNC traffic is encrypted between this Mac and the gateway, not between the gateway and the host.")
                    .font(DS.Font.callout).foregroundStyle(.secondary)
            } else {
                if let gateway { GatewaySection(login: gateway) { Task { await connect() } } }
                Text("VNC traffic is not encrypted. Outside a trusted network, connect through an SSH tunnel or a gateway.")
                    .font(DS.Font.callout).foregroundStyle(.secondary)
            }
            if let error { CodedError(area: "VNC", message: error) }
        }
        .scrollDisabled(true)
        .fixedSize(horizontal: false, vertical: true)
        .formStyle(.grouped)
        .frame(width: 440)
        .disabled(busy)
        .onAppear { if gateway == nil { gateway = GatewayLogin(library: quickLibrary ?? model.library, connectionId: connection.id) } }
        .onDisappear { gateway?.discard() }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button(busy ? "Connecting…" : "Connect") { Task { await connect() } }.disabled(busy || gateway?.ready == false)
            }
        }
    }

    private func connect() async {
        busy = true
        error = nil
        var host = connection.host, dialPort = port
        switch await gateway?.open(sessions: sessions, library: quickLibrary ?? model.library, connectionId: connection.id) ?? .direct {
        case .direct: break
        case .via(let local): (host, dialPort) = ("127.0.0.1", local)
        case .needsTrust: busy = false; return
        case .failed(let message): busy = false; error = message; return
        }
        let result = await sessions.connectVnc(host: host, port: dialPort, password: password.isEmpty ? nil : password)
        busy = false
        if case .failed(let message) = result { sessions.recordOutcome(connection.id, user: nil, failure: message) }
        else { sessions.recordOutcome(connection.id, user: nil, failure: nil) }
        switch result {
        case .connected(let viewer):
            let tab = TerminalTab(name: connection.name, content: .vnc(viewer), connectionId: connection.id)
            tab.gatewayRoute = gateway?.handOff()
            sessions.add(tab)
            password = ""
            dismiss()
        case .failed(let message):
            error = message
        }
    }
}
