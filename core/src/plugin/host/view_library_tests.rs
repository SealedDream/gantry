use super::*;

fn raw(label: &str, host: Option<&str>, protocol: &str, os: Option<&str>) -> RawProposal {
    RawProposal { label: label.into(), host: host.map(str::to_string), protocol: protocol.into(), os_hint: os.map(str::to_string) }
}

fn proposal(label: &str, host: Option<&str>, protocol: &str) -> Value {
    let opt = |s: Option<&str>| Value::Option(s.map(|s| Box::new(Value::String(s.into()))));
    record(vec![("label", Value::String(label.into())), ("host", opt(host)), ("protocol", Value::Enum(protocol.into())), ("os-hint", opt(None))])
}

#[test]
fn accepts_a_guest_with_a_canonical_host() {
    let c = check(&raw("web01", Some("10.0.0.5"), "ssh", Some("linux")), |_| false).unwrap();
    assert_eq!(c.host.as_deref(), Some("10.0.0.5"));
    assert_eq!(c.protocol, Protocol::Ssh);
    assert_eq!(c.os_hint.as_deref(), Some("linux"));
    assert!(!c.reported);
}

#[test]
fn a_name_is_lower_cased_and_marked_reported_when_the_server_said_it() {
    let c = check(&raw("dc", Some("DC01.Corp.Example."), "rdp", Some("windows")), |_| true).unwrap();
    assert_eq!(c.host.as_deref(), Some("dc01.corp.example"));
    assert!(c.reported);
}

#[test]
fn accepts_a_guest_without_a_host() {
    let c = check(&raw("no agent", None, "vnc", None), |_| panic!("no host to look up")).unwrap();
    assert_eq!(c.host, None);
}

#[test]
fn refuses_loopback_metadata_and_link_local_hosts() {
    for h in ["127.0.0.1", "localhost", "::1", "169.254.169.254", "metadata.google.internal", "0.0.0.0", "fe80::1"] {
        assert!(check(&raw("x", Some(h), "ssh", None), |_| false).is_err(), "{h} must be refused");
    }
}

#[test]
fn refuses_bad_labels_protocols_hosts_and_hints() {
    assert!(check(&raw("", Some("10.0.0.5"), "ssh", None), |_| false).is_err());
    assert!(check(&raw(" padded", Some("10.0.0.5"), "ssh", None), |_| false).is_err());
    assert!(check(&raw("two\nlines", Some("10.0.0.5"), "ssh", None), |_| false).is_err());
    assert!(check(&raw(&"a".repeat(129), Some("10.0.0.5"), "ssh", None), |_| false).is_err());
    assert!(check(&raw("x", Some("10.0.0.5"), "telnet", None), |_| false).is_err());
    assert!(check(&raw("x", Some("user@10.0.0.5"), "ssh", None), |_| false).is_err());
    assert!(check(&raw("x", Some("010.0.0.5"), "ssh", None), |_| false).is_err());
    assert!(check(&raw("x", Some("10.0.0.5"), "ssh", Some("Windows 11")), |_| false).is_err());
}

#[test]
fn reads_a_list_of_proposals() {
    let args = vec![Value::List(vec![proposal("a", Some("10.0.0.1"), "ssh"), proposal("b", None, "rdp")])];
    let raws = raw_of(&args).unwrap();
    assert_eq!(raws.len(), 2);
    assert_eq!(raws[1], raw("b", None, "rdp", None));
}

#[test]
fn refuses_an_empty_or_oversized_list() {
    assert!(raw_of(&[Value::List(vec![])]).is_err());
    let many: Vec<Value> = (0..=MAX_PROPOSALS).map(|i| proposal(&format!("g{i}"), None, "ssh")).collect();
    assert!(raw_of(&[Value::List(many)]).is_err());
    assert!(raw_of(&[]).is_err());
}

#[test]
fn reads_the_apps_answer() {
    let saved = answer_from_json(&serde_json::json!({ "type": "library", "request": 4, "saved": 3, "credential_linked": true })).unwrap();
    assert!(matches!(saved, AppEvent::LibraryAnswer { request: 4, saved: Some(3), credential_linked: true }));
    let cancelled = answer_from_json(&serde_json::json!({ "type": "library", "request": 4, "saved": null })).unwrap();
    assert!(matches!(cancelled, AppEvent::LibraryAnswer { saved: None, credential_linked: false, .. }));
    assert!(answer_from_json(&serde_json::json!({ "saved": 1 })).is_err());
    assert!(answer_from_json(&serde_json::json!({ "request": 1, "saved": -1 })).is_err());
}
