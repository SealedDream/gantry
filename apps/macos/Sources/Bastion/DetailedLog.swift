import SwiftUI
import Foundation
import BastionCore

/// Settings ▸ About ▸ Detailed logging (LOG-ERRCODES): debug lines in the app log, off again
/// 24 hours after it was turned on. The start time is kept in UserDefaults.
@MainActor
enum DetailedLog {
    static let settingId = "diagnostics.detailed-log"
    private static let sinceKey = "detailedLogSince"
    private static var timer: Timer?

    static var now: UInt64 { UInt64(Date().timeIntervalSince1970) }

    /// At launch: turn the switch off if its 24 hours have run, else start the log level.
    static func apply(_ settings: SettingsModel) {
        guard settings.value(settingId) == "true" else { return off() }
        let since = UInt64(UserDefaults.standard.double(forKey: sinceKey))
        if since == 0 { UserDefaults.standard.set(Double(now), forKey: sinceKey) }
        if since != 0, detailedLogExpired(sinceUnix: since, nowUnix: now) {
            settings.set(settingId, "false") // calls `changed`
            AppLog.info("Detailed logging turned off after 24 hours")
            return
        }
        on(settings)
    }

    /// The user flipped the switch.
    static func changed(_ settings: SettingsModel) {
        if settings.value(settingId) == "true" {
            UserDefaults.standard.set(Double(now), forKey: sinceKey)
            AppLog.info("Detailed logging on")
            on(settings)
        } else {
            off()
            AppLog.info("Detailed logging off")
        }
    }

    private static func on(_ settings: SettingsModel) {
        AppLog.detailed = true
        timer?.invalidate()
        // Hourly check, so a Mac left running turns it off on time (to the hour).
        timer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { _ in
            Task { @MainActor in apply(settings) }
        }
    }

    private static func off() {
        AppLog.detailed = false
        timer?.invalidate(); timer = nil
        UserDefaults.standard.removeObject(forKey: sinceKey)
    }
}

/// An error line with its support code under it in small selectable text (LOG-ERRCODES). Each
/// message shown is written once to the app log with its code.
struct CodedError: View {
    let area: String
    let message: String
    var lineLimit: Int? = nil

    var body: some View {
        let code = errorCode(area: area, message: message)
        VStack(alignment: .leading, spacing: 2) {
            Text(message).foregroundStyle(.red).lineLimit(lineLimit)
            Text(code).font(DS.Font.caption).foregroundStyle(.secondary).textSelection(.enabled)
                .help("Support code: quote it when you ask for help.")
                .accessibilityIdentifier("error-code")
        }
        .task(id: message) { AppLog.failure(code: code, message) }
    }
}

/// Alert text with the support code on its own line, logged once per message (LOG-ERRCODES).
@MainActor
enum CodedAlert {
    private static var lastLogged = ""

    static func text(_ area: String, _ message: String?) -> Text {
        guard let message, !message.isEmpty else { return Text("") }
        let code = errorCode(area: area, message: message)
        if lastLogged != code + message {
            lastLogged = code + message
            AppLog.failure(code: code, message)
        }
        return Text("\(message)\n\n\(code)")
    }
}
