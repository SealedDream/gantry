import SwiftUI
import WebKit
import BastionCore
import Network

/// Where a web connection points: the host field may hold a full http(s) URL, otherwise
/// `https://host[:port]`. Any other scheme (file:, javascript:, …) is refused.
enum WebTarget {
    static func url(host: String, port: UInt16?) -> URL? {
        let raw = host.contains("://") ? host : "https://\(host)\(port.map { ":\($0)" } ?? "")"
        guard let url = URL(string: raw), let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http", url.host?.isEmpty == false else { return nil }
        return url
    }

    /// What the user typed into the address bar: a full http(s) URL, or a bare host[:port][/path]
    /// that becomes https. Search terms and other schemes are refused.
    static func typed(_ text: String) -> URL? {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, !t.contains(" ") else { return nil }
        if t.contains("://") { return url(host: t, port: nil) }
        return url(host: "https://\(t)", port: nil)
    }
}

/// One web tab's page: a `WKWebView` with its own non-persistent data store (cookies and storage
/// never outlive the tab or leak between connections), no script bridges, and http(s) only.
/// The address bar and buttons observe it through KVO.
@MainActor @Observable
final class WebPage: NSObject, WKNavigationDelegate, WKDownloadDelegate {
    let view: WKWebView
    private(set) var address = ""
    private(set) var title = ""
    private(set) var canGoBack = false
    private(set) var canGoForward = false
    private(set) var isLoading = false
    /// https with no mixed content; false for http or when any resource came over http.
    private(set) var isSecure = false
    private(set) var failure: String?
    /// The latest download: its file once finished, or the reason it failed.
    private(set) var download: DownloadState?
    @ObservationIgnored private var observations: [NSKeyValueObservation] = []
    /// Called once with the first load's outcome (nil = it loaded), for the inspector footer.
    @ObservationIgnored var onFirstResult: ((String?) -> Void)?
    /// The most recently opened page, for the UI driver.
    @ObservationIgnored static weak var latest: WebPage?

    init(url: URL, socksPort: UInt16? = nil, storeId: UUID? = nil) {
        let config = WKWebViewConfiguration()
        // A tunnel's tabs share one persistent store of their own; everything else stays ephemeral.
        config.websiteDataStore = storeId.map { WKWebsiteDataStore(forIdentifier: $0) } ?? .nonPersistent()
        // Through a gateway every request of this tab (and its DNS lookups) goes over the SOCKS
        // proxy, so the page keeps its real URL and TLS name; nothing falls back to a direct load.
        if let socksPort, let port = NWEndpoint.Port(rawValue: socksPort) {
            config.websiteDataStore.proxyConfigurations = [ProxyConfiguration(socksv5Proxy: .hostPort(host: "127.0.0.1", port: port))]
        }
        view = WKWebView(frame: .zero, configuration: config)
        super.init()
        view.navigationDelegate = self
        observations = [
            view.observe(\.url, options: [.initial, .new]) { [weak self] v, _ in MainActor.assumeIsolated { self?.sync(v) } },
            view.observe(\.title, options: [.new]) { [weak self] v, _ in MainActor.assumeIsolated { self?.sync(v) } },
            view.observe(\.canGoBack, options: [.new]) { [weak self] v, _ in MainActor.assumeIsolated { self?.sync(v) } },
            view.observe(\.canGoForward, options: [.new]) { [weak self] v, _ in MainActor.assumeIsolated { self?.sync(v) } },
            view.observe(\.isLoading, options: [.new]) { [weak self] v, _ in MainActor.assumeIsolated { self?.sync(v) } },
            view.observe(\.hasOnlySecureContent, options: [.new]) { [weak self] v, _ in MainActor.assumeIsolated { self?.sync(v) } },
        ]
        view.load(URLRequest(url: url))
        Self.latest = self
    }

    private func sync(_ v: WKWebView) {
        address = v.url?.absoluteString ?? address
        title = v.title ?? ""
        canGoBack = v.canGoBack
        canGoForward = v.canGoForward
        isLoading = v.isLoading
        isSecure = v.url?.scheme?.lowercased() == "https" && v.hasOnlySecureContent
    }

    /// Navigate to what the user typed; returns false (and changes nothing) when it is not an http(s) address.
    @discardableResult
    func go(_ text: String) -> Bool {
        guard let url = WebTarget.typed(text) else {
            failure = "Enter an http or https address."
            return false
        }
        failure = nil
        view.load(URLRequest(url: url))
        return true
    }

    func back() { view.goBack() }
    func forward() { view.goForward() }
    func reloadOrStop() { if view.isLoading { view.stopLoading() } else { view.reload() } }

    /// Only http(s) navigations stay in the tab; other schemes are cancelled.
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
        let scheme = action.request.url?.scheme?.lowercased()
        guard scheme == "https" || scheme == "http" || scheme == "about" else { return decisionHandler(.cancel) }
        decisionHandler(action.shouldPerformDownload ? .download : .allow)
    }

    /// Responses the tab cannot show (attachments, archives, binaries) become downloads.
    func webView(_ webView: WKWebView, decidePolicyFor response: WKNavigationResponse,
                 decisionHandler: @escaping @MainActor (WKNavigationResponsePolicy) -> Void) {
        let isAttachment = (response.response as? HTTPURLResponse)?
            .value(forHTTPHeaderField: "Content-Disposition")?.lowercased().hasPrefix("attachment") == true
        decisionHandler(isAttachment || !response.canShowMIMEType ? .download : .allow)
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    /// Saved into ~/Downloads under the server's name, never overwriting an existing file.
    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse,
                  suggestedFilename: String) async -> URL? {
        let folder = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        let url = Downloads.uniqueDestination(in: folder, suggested: suggestedFilename)
        self.download = .running(url.lastPathComponent)
        return url
    }

    func downloadDidFinish(_ download: WKDownload) {
        guard case .running(let name) = self.download else { return }
        let folder = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        self.download = .finished(folder.appendingPathComponent(name))
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        self.download = .failed(error.localizedDescription)
    }

    func dismissDownload() { download = nil }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        // A navigation handed to a download ends this way; it is not a failure.
        let e = error as NSError
        if e.domain == "WebKitErrorDomain" && e.code == 102 { return }
        // Certificate errors are not overridable here: strict TLS.
        failure = error.localizedDescription
        reportFirst(failure)
    }

    private func reportFirst(_ failure: String?) {
        onFirstResult?(failure)
        onFirstResult = nil
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        failure = nil
        reportFirst(nil)
    }
}

enum DownloadState: Equatable {
    case running(String)
    case finished(URL)
    case failed(String)
}

enum Downloads {
    /// `name`, or `name 2`, `name 3`… before the extension, whichever does not exist yet.
    /// Path components in the server's name are dropped so it cannot leave the folder.
    static func uniqueDestination(in folder: URL, suggested: String) -> URL {
        let safe = (suggested as NSString).lastPathComponent.trimmingCharacters(in: .whitespaces)
        let name = safe.isEmpty || safe == "." || safe == ".." ? "download" : safe
        let base = (name as NSString).deletingPathExtension
        let ext = (name as NSString).pathExtension
        var candidate = folder.appendingPathComponent(name)
        var n = 2
        while FileManager.default.fileExists(atPath: candidate.path) {
            candidate = folder.appendingPathComponent(ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)")
            n += 1
        }
        return candidate
    }
}

/// A web tab: back, forward, reload or stop, an editable address with its TLS state, then the page.
/// The page is created once, on first appearance: SwiftUI may build this struct many times.
struct WebTabView: View {
    let url: URL
    /// Loopback SOCKS5 port through the connection's gateway, if it has one.
    var socksPort: UInt16? = nil
    var storeId: UUID? = nil
    /// The saved web connection this tab opened, for "Fill sign-in" (B13); nil for an address typed by hand.
    var connectionId: String? = nil
    var onFirstResult: ((String?) -> Void)? = nil
    @State private var page: WebPage?

    var body: some View {
        Group {
            if let page { WebPageView(page: page, connectionId: connectionId) } else { Color.clear }
        }
        .onAppear {
            guard page == nil else { return }
            let p = WebPage(url: url, socksPort: socksPort, storeId: storeId)
            p.onFirstResult = onFirstResult
            page = p
        }
    }
}

private struct WebPageView: View {
    let page: WebPage
    let connectionId: String?
    @State private var editing = ""
    @FocusState private var addressFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: DS.Space.xs) {
                Button("Back", systemImage: "chevron.left") { page.back() }
                    .disabled(!page.canGoBack).help("Back")
                Button("Forward", systemImage: "chevron.right") { page.forward() }
                    .disabled(!page.canGoForward).help("Forward")
                Button(page.isLoading ? "Stop" : "Reload", systemImage: page.isLoading ? "xmark" : "arrow.clockwise") { page.reloadOrStop() }
                    .help(page.isLoading ? "Stop loading" : "Reload")
                HStack(spacing: DS.Space.xxs) {
                    Image(systemName: page.isSecure ? "lock.fill" : "exclamationmark.triangle")
                        .foregroundStyle(page.isSecure ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
                        .help(page.isSecure ? "Encrypted connection (https, no insecure content)" : "Not secure: http or insecure content on this page")
                    TextField("Address", text: $editing)
                        .textFieldStyle(.plain)
                        .focused($addressFocused)
                        .onSubmit { if page.go(editing) { addressFocused = false } }
                }
                .padding(.horizontal, DS.Space.xs)
                .padding(.vertical, 3)
                .background(RoundedRectangle(cornerRadius: 5).fill(.background))
                .overlay(RoundedRectangle(cornerRadius: 5).strokeBorder(.separator))
                if let connectionId { WebAutofillButton(page: page, connectionId: connectionId) }
            }
            .labelStyle(.iconHitTarget)
            .buttonStyle(.borderless)
            .padding(.horizontal, DS.Space.s)
            .padding(.vertical, DS.Space.xxs + 2)
            .background(.bar)
            if let failure = page.failure {
                Text(failure).font(DS.Font.caption).foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, DS.Space.s).padding(.vertical, DS.Space.xxs)
                    .background(.bar)
            }
            if let download = page.download { DownloadBar(state: download, dismiss: page.dismissDownload) }
            Divider()
            WebViewHost(view: page.view)
        }
        // Follow the page unless the user is typing.
        .onChange(of: page.address) { _, a in if !addressFocused { editing = a } }
        .onAppear { editing = page.address }
    }
}

private struct DownloadBar: View {
    let state: DownloadState
    let dismiss: () -> Void

    var body: some View {
        HStack(spacing: DS.Space.xs) {
            switch state {
            case .running(let name):
                ProgressView().controlSize(.small)
                Text("Downloading \(name)…")
            case .finished(let url):
                Image(systemName: "arrow.down.circle").foregroundStyle(.secondary)
                Text("Downloaded \(url.lastPathComponent)")
                Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
            case .failed(let reason):
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                Text("Download failed: \(reason)")
            }
            Spacer()
            Button("Dismiss", systemImage: "xmark", action: dismiss).labelStyle(.iconHitTarget).help("Dismiss")
        }
        .font(DS.Font.caption)
        .buttonStyle(.borderless)
        .padding(.horizontal, DS.Space.s).padding(.vertical, DS.Space.xxs)
        .background(.bar)
    }
}

private struct WebViewHost: NSViewRepresentable {
    let view: WKWebView
    func makeNSView(context: Context) -> WKWebView { view }
    func updateNSView(_ view: WKWebView, context: Context) {}
}

/// Gateway sign-in for a web connection; the tab then loads every request over the gateway's
/// SOCKS proxy. Direct web connections open without a sheet.
struct WebGatewaySheet: View {
    let connection: ConnectionView
    /// The unsaved Quick Connect library this connection lives in; nil for a saved connection.
    var quickLibrary: Library? = nil
    @Environment(SessionsModel.self) private var sessions
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var gateway: GatewayLogin?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Form {
            LabeledContent("Address", value: WebTarget.url(host: connection.host, port: connection.port)?.absoluteString ?? connection.host)
            if let gateway { GatewaySection(login: gateway) { Task { await open() } } }
            if let error { Text(error).foregroundStyle(.red) }
        }
        .formStyle(.grouped)
        .scrollDisabled(true)
        .fixedSize(horizontal: false, vertical: true)
        .frame(width: 440)
        .disabled(busy)
        .onAppear { if gateway == nil { gateway = GatewayLogin(library: quickLibrary ?? model.library, connectionId: connection.id) } }
        .onDisappear { gateway?.discard() }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button(busy ? "Connecting…" : "Open") { Task { await open() } }.disabled(busy || gateway?.ready != true)
            }
        }
    }

    private func open() async {
        guard let url = WebTarget.url(host: connection.host, port: connection.port) else {
            return error = "Only http and https addresses can be opened."
        }
        busy = true
        error = nil
        let outcome = await gateway?.open(sessions: sessions, library: quickLibrary ?? model.library, connectionId: connection.id) ?? .direct
        busy = false
        switch outcome {
        case .direct, .via:
            let tab = TerminalTab(name: connection.name, content: .web(url), connectionId: connection.id)
            tab.gatewayRoute = gateway?.handOff()
            sessions.add(tab)
            dismiss()
        case .needsTrust: break
        case .failed(let message): error = message
        }
    }
}
