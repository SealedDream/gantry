//! Multi-host exec rules: review, production acknowledgement, retry set, export.
use bastion_core::model::{Connection, Protocol};
use bastion_core::multiexec::{self, HostResult, HostState, Plan};
use bastion_core::policy::Environment;

fn host(name: &str) -> Connection {
    Connection::new(name, Protocol::Ssh, "10.0.0.1")
}

#[test]
fn review_refuses_unsafe_plans_and_flags_production() {
    let ok = Plan { command: "uptime".into(), hosts: vec![host("a"), host("b")], concurrency: 4 };
    assert!(!multiexec::review(&ok).unwrap().needs_production_ack);
    let two_commands = Plan { command: "uptime\nrm -rf /tmp/x".into(), ..ok.clone() };
    assert!(multiexec::review(&two_commands).is_err(), "one line only");
    assert!(multiexec::review(&Plan { command: "  ".into(), ..ok.clone() }).is_err());
    assert!(multiexec::review(&Plan { concurrency: 0, ..ok.clone() }).is_err());
    assert!(multiexec::review(&Plan { concurrency: 17, ..ok.clone() }).is_err());
    let a = host("a");
    assert!(multiexec::review(&Plan { hosts: vec![a.clone(), a], ..ok.clone() }).is_err(), "duplicates");
    assert!(multiexec::review(&Plan { hosts: vec![Connection::new("w", Protocol::Rdp, "h")], ..ok.clone() }).is_err());
    let mut prod = host("db-prod");
    prod.classification.environment = Environment::Production;
    let r = multiexec::review(&Plan { hosts: vec![host("a"), prod], ..ok }).unwrap();
    assert!(r.needs_production_ack);
    assert_eq!(r.sensitive, ["db-prod"]);
}

#[test]
fn retry_takes_failures_and_non_zero_exits() {
    let mut rs: Vec<HostResult> = ["a", "b", "c", "d"].iter().map(|h| HostResult::waiting(h)).collect();
    rs[0].state = HostState::Done;
    rs[0].exit = Some(0);
    rs[1].state = HostState::Done;
    rs[1].exit = Some(2);
    rs[2].state = HostState::Failed;
    rs[3].state = HostState::Cancelled;
    assert_eq!(multiexec::retry_set(&rs), [1, 2, 3]);
}

#[test]
fn export_json_and_csv_without_formula_injection() {
    let mut r = HostResult::waiting("=cmd|' /C calc'!A0");
    r.state = HostState::Failed;
    r.error = Some("connection refused\nmore".into());
    let csv = multiexec::export("uptime", &[r.clone()], "csv").unwrap();
    assert!(csv.contains("\"'=cmd"), "{csv}");
    assert!(csv.lines().nth(1).unwrap().ends_with("\"connection refused\""));
    let json = multiexec::export("uptime", &[r], "json").unwrap();
    assert!(json.contains("\"command\": \"uptime\"") && json.contains("\"failed\""));
    assert!(multiexec::export("uptime", &[], "xml").is_err());
    assert!(multiexec::capture(&vec![b'x'; multiexec::MAX_OUTPUT + 10]).ends_with("[output truncated by Gantry]"));
}
