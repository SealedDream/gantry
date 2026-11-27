// SEC-07: tests for the Test Connection decisions that need no screen. Compiled together with
// Sources/Bastion/TestConnectionVerdict.swift by ../sec-07-verdict-test.sh (the app has no
// SwiftPM test target). Prints one line per test and exits non-zero when any fails.
import Foundation

var failures = 0
func test(_ name: String, _ check: () -> Bool) {
    let passed = check()
    if !passed { failures += 1 }
    print("\(passed ? "ok  " : "FAIL") \(name)")
}

let fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
let other = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
func step(_ kind: String, _ status: String) -> ProbeStepFact { ProbeStepFact(kind: kind, status: status) }
let waitingSteps = [step("dns", "ok"), step("tcp", "ok"), step("handshake", "ok"), step("host_key", "warn"), step("login", "skipped")]

// MARK: the verdict

test("a waiting report is waiting although ok is true") {
    ProbeVerdict.of(ok: true, cancelled: false, needsHostKeyConfirmation: fingerprint, steps: waitingSteps) == .waitingForHostKey(fingerprint: fingerprint)
}
test("a waiting report is never passed, whatever ok says") {
    [true, false].allSatisfy { ProbeVerdict.of(ok: $0, cancelled: false, needsHostKeyConfirmation: fingerprint, steps: waitingSteps) != .passed }
}
test("a blank fingerprint cannot be confirmed and is not a pass") {
    ["", "   ", "\n"].allSatisfy { ProbeVerdict.of(ok: true, cancelled: false, needsHostKeyConfirmation: $0, steps: waitingSteps) == .failed }
}
test("a cancelled test is cancelled") {
    ProbeVerdict.of(ok: false, cancelled: true, needsHostKeyConfirmation: nil, steps: []) == .cancelled
}
test("a failed host-key step is refused, not offered for confirmation") {
    ProbeVerdict.of(ok: false, cancelled: false, needsHostKeyConfirmation: nil, steps: [step("tcp", "ok"), step("host_key", "failed"), step("login", "skipped")]) == .hostKeyRefused(.unspecified)
}
test("a failed host-key step wins over a fingerprint in the same report") {
    ProbeVerdict.of(ok: false, cancelled: false, needsHostKeyConfirmation: fingerprint, steps: [step("host_key", "failed")]) == .hostKeyRefused(.unspecified)
}
test("a jump host with an unknown key is a plain failure") {
    ProbeVerdict.of(ok: false, cancelled: false, needsHostKeyConfirmation: nil, steps: [step("jump_host", "failed")]) == .failed
}
test("a failed login is failed") {
    ProbeVerdict.of(ok: false, cancelled: false, needsHostKeyConfirmation: nil, steps: [step("host_key", "ok"), step("login", "failed")]) == .failed
}
test("a finished test with no failure is passed") {
    ProbeVerdict.of(ok: true, cancelled: false, needsHostKeyConfirmation: nil, steps: [step("host_key", "ok"), step("login", "ok")]) == .passed
}
test("only waiting and refused have a headline, and neither says the connection works") {
    let waiting = ProbeVerdict.waitingForHostKey(fingerprint: fingerprint).headline
    let refused = ProbeVerdict.hostKeyRefused(.unspecified).headline
    let quiet: [ProbeVerdict] = [.passed, .failed, .cancelled]
    return waiting?.isError == false && refused?.isError == true
        && waiting?.text.contains("not tested") == true && refused?.text.contains("cannot be confirmed") == true
        && quiet.allSatisfy { $0.headline == nil }
}

test("SEC-07-FU1: the report's failure kind picks the refusal") {
    let failed = [step("host_key", "failed")]
    func of(_ kind: String?) -> ProbeVerdict { ProbeVerdict.of(ok: false, cancelled: false, needsHostKeyConfirmation: nil, steps: failed, hostKeyFailure: kind) }
    return of("changed") == .hostKeyRefused(.changed) && of("known_hosts_unreadable") == .hostKeyRefused(.knownHostsUnreadable)
        && of(nil) == .hostKeyRefused(.unspecified) && of("something_new") == .hostKeyRefused(.unspecified)
}
test("SEC-07-FU1: a failure kind without a failed host-key step changes nothing") {
    ProbeVerdict.of(ok: true, cancelled: false, needsHostKeyConfirmation: nil, steps: [step("host_key", "ok")], hostKeyFailure: "changed") == .passed
}
test("SEC-07-FU1: a changed key and an unreadable known_hosts get different red headlines") {
    let changed = ProbeVerdict.hostKeyRefused(.changed).headline
    let unreadable = ProbeVerdict.hostKeyRefused(.knownHostsUnreadable).headline
    return changed?.isError == true && unreadable?.isError == true && changed?.text != unreadable?.text
        && changed?.text.contains("changed") == true && changed?.text.contains("Do not connect") == true
        && unreadable?.text.contains("known_hosts") == true && unreadable?.text.contains("could not be read") == true
        && [changed, unreadable].allSatisfy { $0?.text.contains("no sign-in was sent") == true }
}

// MARK: the question put to the user

test("no question unless the test is waiting") {
    let verdicts: [ProbeVerdict] = [.passed, .failed, .cancelled, .hostKeyRefused(.changed), .hostKeyRefused(.knownHostsUnreadable)]
    return verdicts.allSatisfy { HostKeyQuestion.from($0, host: "db01", jumpHosts: [], lastConfirmed: nil) == nil }
}
test("the question carries exactly the fingerprint of the report") {
    let q = HostKeyQuestion.from(.waitingForHostKey(fingerprint: fingerprint), host: "db01", jumpHosts: [], lastConfirmed: nil)
    return q?.fingerprint == fingerprint && q?.subject == "db01" && q?.differsFromConfirmed == false
}
test("a jump-host route says the key is the target's and names the hops") {
    let one = HostKeyQuestion.from(.waitingForHostKey(fingerprint: fingerprint), host: "db01", jumpHosts: ["jump1"], lastConfirmed: nil)
    let two = HostKeyQuestion.from(.waitingForHostKey(fingerprint: fingerprint), host: "db01", jumpHosts: ["jump1", "jump2"], lastConfirmed: nil)
    return one?.subject == "db01 (the target, reached through jump host jump1)"
        && two?.subject == "db01 (the target, reached through jump hosts jump1, jump2)"
}
test("another key after a confirmation is asked again and says so") {
    let q = HostKeyQuestion.from(.waitingForHostKey(fingerprint: other), host: "db01", jumpHosts: [], lastConfirmed: fingerprint)
    return q?.fingerprint == other && q?.differsFromConfirmed == true && q?.note.contains("different key") == true
}
test("the same key again is asked again, never trusted silently") {
    let q = HostKeyQuestion.from(.waitingForHostKey(fingerprint: fingerprint), host: "db01", jumpHosts: [], lastConfirmed: fingerprint)
    return q != nil && q?.differsFromConfirmed == false
}
test("the note says nothing is saved and no sign-in was sent") {
    let q = HostKeyQuestion.from(.waitingForHostKey(fingerprint: fingerprint), host: "db01", jumpHosts: [], lastConfirmed: nil)
    return q?.note.contains("known_hosts") == true && q?.note.contains("this test only") == true && q?.note.contains("No sign-in has been sent") == true
}

print(failures == 0 ? "PASS sec-07-verdict" : "FAIL sec-07-verdict: \(failures) failed")
exit(failures == 0 ? 0 : 1)
