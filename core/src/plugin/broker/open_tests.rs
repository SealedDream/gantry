//! Tests for the open rules: one block per threat row of `docs/specs/plugins-amendment-3.md`,
//! section 11.

use super::*;

fn host(s: &str) -> Host {
    parse_host(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}

const DIRECT_ENTRY: LoopbackRule = LoopbackRule { entry_target_loopback: false, entry_direct: true };

fn pve_spec() -> OpenSpec {
    OpenSpec {
        address_fields: vec![AddressField {
            path: "/api2/json/nodes/*/qemu/*/agent/network-get-interfaces".into(),
            fields: vec!["data.result[].ip-addresses[].ip-address".into()],
        }],
    }
}

const AGENT_PATH: &str = "/api2/json/nodes/pve1/qemu/101/agent/network-get-interfaces";

fn json_headers() -> Vec<(String, String)> {
    vec![("Content-Type".into(), "application/json;charset=utf-8".into())]
}

fn agent_body(ips: &[&str]) -> Vec<u8> {
    let addrs: Vec<_> = ips.iter().map(|ip| serde_json::json!({ "ip-address": ip, "ip-address-type": "ipv4" })).collect();
    serde_json::to_vec(&serde_json::json!({ "data": { "result": [ { "name": "eth0", "ip-addresses": addrs } ] } })).unwrap()
}

fn collect(set: &mut ReportedSet, spec: &OpenSpec, is_get: bool, path: &str, target: &str, req_headers: &[(String, String)], body: &[u8], now: Instant) -> usize {
    let headers = json_headers();
    set.collect(spec, &SeenRequest { is_get, path, target, headers: req_headers }, &SeenResponse { status: 200, headers: &headers, body }, now)
}

// ---- Row 1: scanning / pivoting needs a stamp, one at a time, 10 a minute ----

#[test]
fn a_request_needs_a_fresh_user_action_once() {
    let t0 = Instant::now();
    let mut s = Stamp::default();
    assert!(!s.take(t0), "no user action yet");
    s.stamp(t0);
    assert!(s.take(t0 + Duration::from_secs(9)));
    assert!(!s.take(t0 + Duration::from_secs(9)), "one action allows one request");
    s.stamp(t0);
    assert!(!s.take(t0 + Duration::from_secs(11)), "older than 10 s");
}

#[test]
fn the_eleventh_request_in_a_minute_is_refused() {
    let t0 = Instant::now();
    let mut r = Rate::default();
    for i in 0..10 {
        assert!(r.admit(t0 + Duration::from_millis(i)));
    }
    assert!(!r.admit(t0 + Duration::from_secs(30)));
    assert!(r.admit(t0 + Duration::from_secs(61)), "a new minute");
}

// ---- Row 3 (HIGH): the reported set cannot be steered by the plugin ----

#[test]
fn an_address_in_a_declared_field_of_a_get_response_is_reported() {
    let now = Instant::now();
    let mut set = ReportedSet::new();
    assert_eq!(collect(&mut set, &pve_spec(), true, AGENT_PATH, AGENT_PATH, &[], &agent_body(&["10.0.0.5", "fe80::1", "not an ip"]), now), 2);
    assert!(set.contains(&host("10.0.0.5"), now));
    assert!(!set.contains(&host("10.0.0.6"), now));
    assert!(!set.contains(&host("10.0.0.5"), now + REPORTED_TTL + Duration::from_secs(1)), "forgotten after 30 minutes");
}

#[test]
fn a_host_the_plugin_sent_in_the_target_or_a_header_is_not_reported() {
    let now = Instant::now();
    let body = agent_body(&["evil.example", "10.9.9.9"]);
    for target in [format!("{AGENT_PATH}?q=evil.example"), format!("{AGENT_PATH}?q=EVIL%2Eexample"), format!("{AGENT_PATH}?q=evil%252eexample")] {
        let mut set = ReportedSet::new();
        let headers = vec![("X-Filter".to_string(), "10.9.9.9".to_string())];
        collect(&mut set, &pve_spec(), true, AGENT_PATH, &target, &headers, &body, now);
        assert!(!set.contains(&host("evil.example"), now), "{target}");
        assert!(!set.contains(&host("10.9.9.9"), now), "{target}");
    }
}

#[test]
fn a_host_written_with_post_or_put_and_read_back_from_free_text_is_not_reported() {
    let now = Instant::now();
    let mut set = ReportedSet::new();
    // The plugin wrote the host into a VM name, description and tag, then reads the config.
    let config = serde_json::to_vec(&serde_json::json!({ "data": { "name": "evil.example", "description": "evil.example", "tags": "evil.example" } })).unwrap();
    assert_eq!(collect(&mut set, &pve_spec(), true, "/api2/json/nodes/pve1/qemu/101/config", "/api2/json/nodes/pve1/qemu/101/config", &[], &config, now), 0);
    // A write's own response is never collected, even on a declared path.
    assert_eq!(collect(&mut set, &pve_spec(), false, AGENT_PATH, AGENT_PATH, &[], &agent_body(&["evil.example"]), now), 0);
    // An error message on a declared path is not at a declared field.
    let err = serde_json::to_vec(&serde_json::json!({ "errors": { "vm": "no such vm: evil.example" }, "data": null })).unwrap();
    assert_eq!(collect(&mut set, &pve_spec(), true, AGENT_PATH, AGENT_PATH, &[], &err, now), 0);
    assert!(set.is_empty());
}

#[test]
fn only_2xx_json_responses_count_and_no_fields_means_nothing_is_reported() {
    let now = Instant::now();
    let mut set = ReportedSet::new();
    let body = agent_body(&["10.0.0.5"]);
    let html = vec![("Content-Type".to_string(), "text/html".to_string())];
    assert_eq!(set.collect(&pve_spec(), &SeenRequest { is_get: true, path: AGENT_PATH, target: AGENT_PATH, headers: &[] }, &SeenResponse { status: 200, headers: &html, body: &body }, now), 0);
    let json = json_headers();
    assert_eq!(set.collect(&pve_spec(), &SeenRequest { is_get: true, path: AGENT_PATH, target: AGENT_PATH, headers: &[] }, &SeenResponse { status: 500, headers: &json, body: &body }, now), 0);
    assert_eq!(collect(&mut set, &OpenSpec::default(), true, AGENT_PATH, AGENT_PATH, &[], &body, now), 0);
    assert_eq!(collect(&mut set, &pve_spec(), true, "/api2/json/nodes/pve1/qemu/101/agent/network-get-interfaces/x", "/x", &[], &body, now), 0, "segment count must match");
}

#[test]
fn the_set_holds_at_most_4096_and_drops_the_oldest() {
    let now = Instant::now();
    let mut set = ReportedSet::new();
    let ips: Vec<String> = (0..4_100u32).map(|i| format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, (i & 255).max(1))).collect();
    let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
    collect(&mut set, &pve_spec(), true, AGENT_PATH, AGENT_PATH, &[], &agent_body(&refs), now);
    assert!(set.len() <= MAX_REPORTED);
    assert!(set.contains(&host(refs[refs.len() - 1]), now));
}

#[test]
fn path_patterns_and_field_paths_are_strict() {
    assert!(valid_path_pattern("/api2/json/nodes/*/qemu/*/agent/network-get-interfaces"));
    for bad in ["", "/", "api", "/a//b", "/a/../b", "/a/%2e", "/a?x=1", "/a/b*"] {
        assert!(!valid_path_pattern(bad), "{bad}");
    }
    assert!(valid_field_path("data.result[].ip-addresses[].ip-address"));
    for bad in ["", "a..b", "a.[]", "a b", "a.$x"] {
        assert!(!valid_field_path(bad), "{bad}");
    }
    assert!(path_matches("/a/*/c", "/a/b/c"));
    assert!(!path_matches("/a/*/c", "/a//c"));
    assert!(!path_matches("/a/*/c", "/a/b/c/d"));
}

// ---- Row 4: confusing host strings ----

#[test]
fn confusing_host_forms_are_refused() {
    for bad in [
        "0x7f.1", "017.0.0.1", "2130706433", "127.1", "0x7f000001", "10.0.0.01", "256.1.1.1", "user@host", "host:22", "[::1]", "fe80::1%en0", "a b", "-a.example", "a-.example", "ex\u{202e}ample", "xn--\u{0430}pple.com", "http://x", "a/b",
        "",
    ] {
        assert!(parse_host(bad).is_err(), "{bad:?}");
    }
    assert_eq!(host("Server.Example.").canonical(), "server.example");
    assert_eq!(host("xn--pple-43d.com").canonical(), "xn--pple-43d.com", "punycode stays punycode");
    assert_eq!(host("2001:DB8:0:0::1").canonical(), "2001:db8::1");
    assert_eq!(host("10.0.0.1"), Host::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert!(parse_host(&"a".repeat(254)).is_err());
}

// ---- Row 5: loopback, link-local and metadata, directly or embedded ----

#[test]
fn loopback_link_local_and_metadata_targets_are_refused() {
    for bad in [
        "127.0.0.1", "::1", "::ffff:127.0.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::", "localhost", "a.localhost", "169.254.1.1", "169.254.169.254", "fe80::1", "febf::1", "100.100.100.200", "fd00:ec2::254", "metadata.google.internal",
        "metadata.azure.com", "0.0.0.0", "0.1.2.3", "::", "255.255.255.255", "224.0.0.1", "ff02::1", "64:ff9b:1::a00:1", "2001:0:a9fe:a9fe::", "::ffff:169.254.169.254", "2002:a9fe:a9fe::1",
    ] {
        assert!(check_class(&host(bad), RouteChoice::Entry, false, &DIRECT_ENTRY).is_err(), "{bad}");
    }
    for ok in ["10.0.0.5", "192.168.1.20", "2001:db8::5", "guest.lab.example", "64:ff9b::a00:5", "::ffff:10.0.0.5"] {
        assert!(check_class(&host(ok), RouteChoice::Entry, false, &DIRECT_ENTRY).is_ok(), "{ok}");
    }
}

#[test]
fn every_resolved_address_is_checked_and_one_bad_one_fails_the_name() {
    let good: IpAddr = "10.0.0.5".parse().unwrap();
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let meta: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(check_resolved(&[good], false).is_ok());
    assert!(check_resolved(&[good, lo], false).is_err(), "one loopback among several");
    assert!(check_resolved(&[good, meta], true).is_err());
    assert!(check_resolved(&[], false).is_err());
    assert!(check_resolved(&[lo], true).is_ok(), "only when the loopback exception allowed it");
}

// ---- Row 6: loopback through a gateway ----

#[test]
fn loopback_only_on_the_entrys_own_loopback_route_and_never_after_a_route_change() {
    let lo = host("127.0.0.1");
    let direct_loopback_entry = LoopbackRule { entry_target_loopback: true, entry_direct: true };
    let tunnelled_loopback_entry = LoopbackRule { entry_target_loopback: true, entry_direct: false };
    let gateway_entry = LoopbackRule { entry_target_loopback: false, entry_direct: false };
    assert!(check_class(&lo, RouteChoice::Entry, false, &direct_loopback_entry).is_ok());
    assert!(check_class(&lo, RouteChoice::Direct, false, &direct_loopback_entry).is_ok(), "direct is the entry's route");
    assert!(check_class(&lo, RouteChoice::Entry, false, &tunnelled_loopback_entry).is_ok());
    assert!(check_class(&lo, RouteChoice::Direct, false, &tunnelled_loopback_entry).is_err(), "a tunnelled loopback entry does not allow local loopback");
    assert!(check_class(&lo, RouteChoice::Direct, false, &gateway_entry).is_err(), "a gateway entry plus a direct loopback request");
    assert!(check_class(&lo, RouteChoice::Entry, false, &gateway_entry).is_err(), "the gateway host's own services");
    assert!(check_class(&lo, RouteChoice::Entry, true, &direct_loopback_entry).is_err(), "a route change refuses loopback");
    assert!(check_class(&host("::ffff:127.0.0.1"), RouteChoice::Entry, false, &direct_loopback_entry).is_err(), "embedded loopback is never allowed");
    assert!(is_loopback_literal("127.0.0.1") && is_loopback_literal("::1") && !is_loopback_literal("localhost"));
}

// ---- Row 7: audit and sheet spoofing ----

#[test]
fn audit_values_are_escaped_and_cut_and_labels_are_one_line() {
    let e = audit_escape("a\nb\u{202e}c\\");
    assert_eq!(e, "a\\x0ab\\xe2\\x80\\xaec\\x5c");
    assert!(!e.contains('\n'));
    assert!(audit_escape(&"\n".repeat(1000)).len() <= MAX_AUDIT_VALUE_BYTES);
    assert!(check_label("web-01 (Ubuntu)").is_ok());
    for bad in ["", " lead", "two\nlines", "bidi\u{202e}", "line\u{2028}sep", &"x".repeat(129)] {
        assert!(check_label(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn protocols_are_fixed_by_the_core() {
    assert_eq!(Protocol::parse("ssh").map(Protocol::default_port), Some(22));
    assert_eq!(Protocol::parse("rdp").map(Protocol::default_port), Some(3389));
    assert_eq!(Protocol::parse("vnc").map(Protocol::default_port), Some(5900));
    assert!(Protocol::parse("telnet").is_none() && Protocol::parse("SSH").is_none());
}

#[test]
fn policy_maps_to_the_three_modes() {
    let mut p = crate::policy::Policy::default();
    assert_eq!(OpenPolicy::from_policy(&p), OpenPolicy::Confirm);
    p.plugin_open_reported_only = true;
    assert_eq!(OpenPolicy::from_policy(&p), OpenPolicy::ReportedOnly);
    p.plugin_open_disabled = true;
    assert_eq!(OpenPolicy::from_policy(&p), OpenPolicy::Off);
}

#[test]
fn literals_resolve_to_themselves_and_are_checked() {
    assert_eq!(resolve_checked("10.0.0.5", 22, false).unwrap(), vec!["10.0.0.5:22".parse().unwrap()]);
    assert!(resolve_checked("169.254.169.254", 22, true).is_err());
    assert!(resolve_checked("127.0.0.1", 22, false).is_err());
    assert!(resolve_checked("127.0.0.1", 22, true).is_ok());
    assert!(resolve_checked("localhost", 22, false).is_err(), "refused before any lookup");
    assert!(resolve_checked("metadata.google.internal", 80, true).is_err());
    assert!(resolve_checked("0x7f.1", 22, true).is_err());
}

#[test]
fn an_ipv6_literal_the_plugin_sent_is_not_reported_when_the_server_respells_it() {
    let now = Instant::now();
    let mut set = ReportedSet::new();
    let body = agent_body(&["fd00::a", "fd00::b"]);
    let target = format!("{AGENT_PATH}?q=fd00:0:0::a");
    collect(&mut set, &pve_spec(), true, AGENT_PATH, &target, &[("X-Q".into(), "FD00:0000::B".into())], &body, now);
    assert!(!set.contains(&host("fd00::a"), now), "re-spelled from the target");
    assert!(!set.contains(&host("fd00::b"), now), "re-spelled from a header");
    let mut clean = ReportedSet::new();
    collect(&mut clean, &pve_spec(), true, AGENT_PATH, AGENT_PATH, &[], &body, now);
    assert!(clean.contains(&host("fd00::a"), now));
}
