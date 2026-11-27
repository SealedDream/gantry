// A1-NM-01: the jump hosts the Test Connection dialog sends. See TestConnectionRoute.swift.
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if ok { print("ok   \(what)") } else { failures += 1; print("FAIL \(what) (line \(line))") }
}

let gw = SavedHop(key: "10.0.0.1:2200", username: "hop")
let pj = SavedHop(key: "jump.example:22", username: "tester")
let gwHop = TestRouteHop(host: "10.0.0.1", port: 2200, username: "hop")
let pjHop = TestRouteHop(host: "jump.example", port: 22, username: "tester")

// Keys
check(TestRouteHop(key: "10.0.0.1:2200", username: "u") == TestRouteHop(host: "10.0.0.1", port: 2200, username: "u"), "host:port key")
check(TestRouteHop(key: "fe80::1:22", username: "u") == TestRouteHop(host: "fe80::1", port: 22, username: "u"), "IPv6 key splits at the last colon")
check(TestRouteHop(key: "[fe80::1]:22", username: "u") == TestRouteHop(host: "fe80::1", port: 22, username: "u"), "bracketed IPv6 key")
check(TestRouteHop(key: "nohost", username: "u") == nil, "a key without a port is dropped")
check(TestRouteHop(key: "h:99999", username: "u") == nil, "a port out of range is dropped")

// Gateway unchanged: the saved chain as a connect resolves it (gateway first, then ProxyJump).
check(TestConnectionRoute.hops(saved: [gw, pj], savedGatewayId: "g1", dialogGatewayId: "g1", dialogGateway: nil) == [gwHop, pjHop], "saved gateway + ProxyJump chain")
check(TestConnectionRoute.hops(saved: [pj], savedGatewayId: "", dialogGatewayId: "", dialogGateway: nil) == [pjHop], "ProxyJump only")
check(TestConnectionRoute.hops(saved: [], savedGatewayId: "", dialogGatewayId: "", dialogGateway: nil).isEmpty, "direct connection")

// Gateway edited in the dialog: the dialog's gateway replaces the saved one; the ProxyJump tail
// stays. The core then refuses a saved login for it (the route differs); a typed one is tested.
let other = TestRouteHop(host: "10.9.9.9", port: 22, username: "x")
check(TestConnectionRoute.hops(saved: [gw, pj], savedGatewayId: "g1", dialogGatewayId: "g2", dialogGateway: other) == [other, pjHop], "changed gateway")
check(TestConnectionRoute.hops(saved: [gw, pj], savedGatewayId: "g1", dialogGatewayId: "", dialogGateway: nil) == [pjHop], "gateway removed")
check(TestConnectionRoute.hops(saved: [pj], savedGatewayId: "", dialogGatewayId: "g2", dialogGateway: other) == [other, pjHop], "gateway added")

if failures > 0 { print("\(failures) failed"); exit(1) }
print("all passed")
