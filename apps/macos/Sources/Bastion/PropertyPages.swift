import SwiftUI
import BastionCore

/// One page of the property dialog's category list (Royal TS layout: grouped pages, each with a
/// large icon and a short explanation). Which page a setting lands on is decided here; which
/// settings exist comes from the core schema, so a page appears only when it has real settings.
struct EditorPage: Identifiable, Hashable {
    let id: String
    let group: String
    let title: String
    let symbol: String
    let blurb: String

    static let groupOrder = ["Common", "Advanced", "Organization"]

    /// Page for a schema property.
    static func pageId(for def: PropertyDefView) -> String {
        switch def.key {
        case "terminal_theme": return "colors"
        case "terminal_font_family", "terminal_font_size", "terminal_ligatures": return "fonts"
        case "session_log", "session_log_folder", "session_log_keep_days": return "logging"
        case "notes": return "notes"
        case "tags": return "custom"
        default: break
        }
        switch def.category {
        case "Credentials": return "credentials"
        case "Gateway": return "gateway"
        case "Security": return "security"
        case "Connection": return "advanced"
        case "Display": return "display"
        case "Input": return "input"
        case "Redirection": return "resources"
        default: return "main"
        }
    }

    /// The type's own group name, used as the first group and the main page's title.
    @MainActor static func mainGroup(for target: EditorTarget) -> String {
        switch target {
        case .folder: return "Folder"
        case .connection(_, _, let p), .type(let p, _):
            // A plugin type: the installed type's name (PVE-TLS), never a built-in group.
            if let type = PluginEntries.types.first(where: { $0.id == p }) { return type.name }
            switch p {
            case "ssh", "telnet", "serial": return "Terminal"
            case "local": return "Local Terminal"
            case "rdp": return "Remote Desktop"
            case "vnc": return "VNC"
            case "web": return "Web Page"
            default: return "File Transfer"
            }
        }
    }

    @MainActor static func all(for target: EditorTarget) -> [EditorPage] {
        let main = mainGroup(for: target)
        let isFolder: Bool = { if case .folder = target { return true }; return false }()
        let what = isFolder ? "connections in this folder and its sub-folders" : target.isDefaults ? "every connection of this type" : "this connection"
        return [
            EditorPage(id: "main", group: main, title: isFolder ? "Connection" : main, symbol: target.symbol, blurb: mainBlurb(target)),
            EditorPage(id: "display", group: main, title: "Display Options", symbol: "rectangle.on.rectangle",
                       blurb: "How large the remote screen is and how many colours it uses for \(what)."),
            EditorPage(id: "colors", group: main, title: "Colors", symbol: "paintpalette",
                       blurb: "The terminal colour theme for \(what). Set one on a folder to tell a customer's servers apart at a glance."),
            EditorPage(id: "fonts", group: main, title: "Fonts", symbol: "textformat",
                       blurb: "Terminal font, size and ligatures for \(what). Empty uses the app font (Settings › Terminal)."),
            EditorPage(id: "credentials", group: "Common", title: "Credentials", symbol: "key.horizontal",
                       blurb: isFolder || target.isDefaults
                           ? "Assign a saved credential, name one to look up, or leave it to the parent folder. Everything inside inherits it unless it sets its own."
                           : "Assign a credential by specifying a username and password, by selecting a saved credential, or by naming one (for shared libraries). You can also use the parent folder's credential."),
            EditorPage(id: "gateway", group: "Common", title: "Secure Gateway", symbol: "point.3.connected.trianglepath.dotted",
                       blurb: "Reach the host through an SSH gateway from the Gateway Manager. A gateway set on a folder applies to everything inside it."),
            EditorPage(id: "security", group: "Common", title: "Security", symbol: "lock.shield",
                       blurb: "Classification and protections for \(what). Production, customer-sensitive and privileged hosts ask before risky actions."),
            EditorPage(id: "advanced", group: "Advanced", title: "Advanced", symbol: "wrench.and.screwdriver",
                       blurb: "Keep-alive and automatic reconnect for \(what)."),
            EditorPage(id: "input", group: "Advanced", title: "Input", symbol: "keyboard",
                       blurb: "What keyboard, mouse and clipboard input is sent to the remote screen."),
            EditorPage(id: "resources", group: "Advanced", title: "Local Resources", symbol: "externaldrive.connected.to.line.below",
                       blurb: "What this Mac shares with the remote desktop: clipboard, sound and a folder."),
            EditorPage(id: "logging", group: "Advanced", title: "Logging", symbol: "doc.text",
                       blurb: "Save what the server prints to an owner-only session log. Your keystrokes are never logged."),
            EditorPage(id: "tunnels", group: "Advanced", title: "Tunnels", symbol: "arrow.left.arrow.right",
                       blurb: "Saved port forwards that run over this SSH connection. Add and start them in the Tunnel Manager."),
            EditorPage(id: "notes", group: "Organization", title: "Notes", symbol: "note.text",
                       blurb: "Free text kept with the connection: runbooks, contacts, change windows."),
            EditorPage(id: "custom", group: "Organization", title: "Custom Properties", symbol: "list.bullet.rectangle",
                       blurb: "Tags and your own named fields. Names that look like secrets are refused: keep secrets in the Credential Manager."),
        ]
    }

    @MainActor private static func mainBlurb(_ target: EditorTarget) -> String {
        switch target {
        case .folder: return "Default connection settings for everything in this folder. Each value applies to the connections and sub-folders inside unless they set their own."
        case .type(let p, _): return "Default Settings for every \(p.uppercased()) connection. A folder or a connection that sets its own value overrides them."
        case .connection(_, _, "local"): return "The shell or program this connection starts on this computer, its arguments and the folder it starts in."
        case .connection(_, _, let p) where p.contains("/"): return "The display name, the server's address and login, and the certificate it must present."
        case .connection: return "The display name shown in the library and the computer to connect to."
        }
    }
}

/// Shown wherever an inline secret is entered or about to be used.
enum InlineSecretWarning {
    static let text = "Secrets saved on a single connection are meant for quick tests. Save the login in the Credential Manager and assign it instead: it can be shared by many connections, rotated in one place and scoped by policy."
}

/// Large icon and explanation at the top of every page.
struct PageHeader: View {
    let page: EditorPage

    var body: some View {
        HStack(alignment: .top, spacing: DS.Space.m) {
            Image(systemName: page.symbol)
                .font(DS.Font.size(34, weight: .light))
                .foregroundStyle(.secondary)
                .frame(width: 48)
            Text(page.blurb)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.bottom, DS.Space.s)
    }
}
