import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS" : "FAIL", what)
    if !ok { failures += 1 }
}

// The shape `audit_read_json` returns (synthetic values).
let page = try! AuditPage.decode("""
{"total":2,"records":[
 {"id":"6f1c0f3e-0000-4000-8000-000000000001","ts_unix_ms":1700000000000,"category":"credential_access","action":"reveal",
  "actor":null,"target":"web-01","outcome":"denied","correlation_id":null,"details":{"source":"vault","field":"password"},"prev_hash":"ab"},
 {"id":"6f1c0f3e-0000-4000-8000-000000000002","ts_unix_ms":1699999990000,"category":"app_lock","action":"unlock",
  "outcome":"success","details":{},"prev_hash":"00"}]}
""")
check(page.total == 2 && page.records.count == 2, "decodes the page")
let r = page.records[0]
check(r.categoryText == "Credential access" && r.outcomeText == "Denied" && !r.isSuccess, "category and outcome text")
check(r.detailsText == "field=password, source=vault", "details sorted key=value")
check(r.date == Date(timeIntervalSince1970: 1_700_000_000), "time from ms")
check(page.records[1].target == nil && page.records[1].categoryText == "App lock" && page.records[1].isSuccess, "missing optional fields")
check(r.matches("vault") && r.matches("WEB-01") && !page.records[1].matches("web"), "search")

check(try! AuditVerify.decode(#"{"intact":true,"records":12,"changedAt":null}"#).text == "Log intact", "intact")
check(try! AuditVerify.decode(#"{"intact":false,"records":12,"changedAt":7}"#).text == "Changed at record 7", "changed at record N")
check(try! AuditVerify.decode(#"{"intact":true,"records":0}"#).text == "Log intact", "empty log is intact")
check((try? AuditPage.decode("not json")) == nil, "bad JSON is an error")

print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
