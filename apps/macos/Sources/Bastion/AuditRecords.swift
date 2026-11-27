import Foundation

// Audit log page (LOG-NATIVE-01, Native Mac): records from the core's `audit_read_json` and the
// status from `audit_verify_json`. Foundation only, so `tests/audit-log-test.sh` builds it alone.

/// One audit record, as `audit_read_json` returns it.
struct AuditRecord: Decodable, Identifiable, Equatable {
    let id: String
    let tsUnixMs: Double
    let category: String
    let action: String
    let actor: String?
    let target: String?
    let outcome: String
    let details: [String: String]

    enum CodingKeys: String, CodingKey {
        case id, category, action, actor, target, outcome, details
        case tsUnixMs = "ts_unix_ms"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        tsUnixMs = try c.decode(Double.self, forKey: .tsUnixMs)
        category = try c.decode(String.self, forKey: .category)
        action = try c.decode(String.self, forKey: .action)
        actor = try c.decodeIfPresent(String.self, forKey: .actor)
        target = try c.decodeIfPresent(String.self, forKey: .target)
        outcome = try c.decode(String.self, forKey: .outcome)
        details = try c.decodeIfPresent([String: String].self, forKey: .details) ?? [:]
    }

    var date: Date { Date(timeIntervalSince1970: tsUnixMs / 1000) }

    /// "credential_access" → "Credential access".
    var categoryText: String { AuditRecord.sentence(category) }
    var outcomeText: String { AuditRecord.sentence(outcome) }
    var isSuccess: Bool { outcome == "success" }

    /// "key=value, key=value", keys sorted.
    var detailsText: String { details.keys.sorted().map { "\($0)=\(details[$0] ?? "")" }.joined(separator: ", ") }

    static func sentence(_ snake: String) -> String {
        let words = snake.split(separator: "_").joined(separator: " ")
        return words.prefix(1).uppercased() + words.dropFirst()
    }

    func matches(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return true }
        return [categoryText, action, target ?? "", outcomeText, detailsText].contains { $0.localizedCaseInsensitiveContains(t) }
    }
}

struct AuditPage: Decodable {
    let total: Int
    let records: [AuditRecord]

    static func decode(_ json: String) throws -> AuditPage {
        try JSONDecoder().decode(AuditPage.self, from: Data(json.utf8))
    }
}

/// `audit_verify_json`: whether the hash chain holds.
struct AuditVerify: Decodable, Equatable {
    let intact: Bool
    let records: Int
    let changedAt: Int?

    static func decode(_ json: String) throws -> AuditVerify {
        try JSONDecoder().decode(AuditVerify.self, from: Data(json.utf8))
    }

    /// The agreed status text ("Log intact" / "Changed at record N").
    var text: String {
        if intact { return "Log intact" }
        return changedAt.map { "Changed at record \($0)" } ?? "Log changed"
    }
}
