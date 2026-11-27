// SEC-6: text one RDP session's server put on the pasteboard is never offered to another session.
var failures = 0
func check(_ ok: Bool, _ name: String) { print((ok ? "PASS " : "FAIL ") + name); if !ok { failures += 1 } }

RdpClipboardOrigin.resetForTests()
let a = RdpClipboardOrigin.newSessionId(), b = RdpClipboardOrigin.newSessionId()
check(a != b, "session ids differ")
check(RdpClipboardOrigin.mayOffer(to: b, changeCount: 1), "local copy with no server write is offered")
RdpClipboardOrigin.markRemoteWrite(by: a, changeCount: 10)
check(!RdpClipboardOrigin.mayOffer(to: b, changeCount: 10), "server A's text is not offered to session B")
check(RdpClipboardOrigin.mayOffer(to: a, changeCount: 10), "session A keeps its own echo rule")
check(RdpClipboardOrigin.mayOffer(to: b, changeCount: 11), "a later local copy is offered to session B")
RdpClipboardOrigin.markRemoteWrite(by: b, changeCount: 12)
check(!RdpClipboardOrigin.mayOffer(to: a, changeCount: 12), "server B's text is not offered to session A")
let c = RdpClipboardOrigin.newSessionId()
check(!RdpClipboardOrigin.mayOffer(to: c, changeCount: 12), "a new session does not get B's server text")
print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
import Foundation
exit(failures == 0 ? 0 : 1)
