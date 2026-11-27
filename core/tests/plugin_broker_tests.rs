//! PLUG-02a: the plugin broker's decisions (`core/src/plugin/broker/`).
//! Each test names the spec rule or the THREAT_MODEL row it proves.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bastion_core::audit::{Category, Outcome};
use bastion_core::plugin::broker::abort::{AbortRegistry, MAX_ABORT_BYTES};
use bastion_core::plugin::broker::audit as paudit;
use bastion_core::plugin::broker::cache::{max_compiled_bytes, CacheCheck, CacheIndex, CacheKey, COMPILE_OUTPUT_MAX_BYTES};
use bastion_core::plugin::broker::caps::{ResultLedger, MAX_RESULT_BYTES_PER_VIEW};
use bastion_core::plugin::broker::gate::{may_load, Rollout};
use bastion_core::plugin::broker::grants::{Binding, Call, HelperGrants};
use bastion_core::plugin::broker::lock::{on_credentials_lock, on_document_lock, RunningHelper};
use bastion_core::plugin::broker::secret::{field_save, log_line_kept, FieldSave, SecretCheck};
use bastion_core::plugin::broker::stream::{Route, RoutedTarget, StreamCaps, StreamGate, TlsMode, MAX_PREAMBLE_BYTES};
use bastion_core::plugin::broker::view::{
    check_frame_len, check_message, check_view, FromHelper, HelperKind, NodeRef, UpdateRate, MAX_FRAME_BYTES, MAX_VIEW_BYTES, MAX_VIEW_DEPTH, MAX_VIEW_NODES,
};
use bastion_core::plugin::broker::{Failure, StopReason, MAX_HELPERS};
use bastion_core::plugin::{Permissions, Tier};
use bastion_core::policy::Policy;

const MIB: u64 = 1024 * 1024;

fn all_perms() -> Permissions {
    Permissions { network_entry: true, credentials_entry: true, storage: true, clipboard_write: true, files_save: true, files_open: true, http_entry: true, open_ssh: true, open_rdp: true, open_vnc: true, exec_entry: true, library_propose: true }
}

fn check_of(secret: &str) -> SecretCheck {
    let mut c = SecretCheck::new();
    c.add(secret.as_bytes());
    c
}

fn denied(r: Result<(), Failure>) -> bool {
    matches!(r, Err(Failure::Denied(_)))
}

fn invalid(r: Result<(), Failure>) -> bool {
    matches!(r, Err(Failure::Invalid(_)))
}

// ---------- Policy (section 10) ----------

#[test]
fn new_plugin_policy_keys_only_tighten_under_managed_policy() {
    let user = Policy { plugins_allowed_ids: Some(["a".to_string(), "b".to_string()].into()), ..Policy::default() };
    let managed = Policy {
        plugins_disabled: true,
        plugins_official_only: true,
        plugins_allowed_ids: Some(["b".to_string(), "c".to_string()].into()),
        forbid_unverified_plugins: true,
        stop_plugin_helpers_on_credentials_lock: true,
        forbid_plugin_unencrypted: true,
        forbid_plugin_tls_off: true,
        ..Policy::default()
    };
    let e = user.with_managed(&managed);
    assert!(e.plugins_disabled && e.plugins_official_only && e.forbid_unverified_plugins);
    assert!(e.stop_plugin_helpers_on_credentials_lock && e.forbid_plugin_unencrypted && e.forbid_plugin_tls_off);
    assert_eq!(e.plugins_allowed_ids, Some(BTreeSet::from(["b".to_string()])));
    // A user list cannot widen a managed one, and no list on one side keeps the other's.
    let e2 = Policy::default().with_managed(&managed);
    assert_eq!(e2.plugins_allowed_ids, managed.plugins_allowed_ids);
    // The keys are read from a managed policy file.
    let p: Policy = serde_json::from_str(r#"{"forbid_plugin_tls_off": true, "plugins_allowed_ids": ["dev.bastion.postgres"]}"#).unwrap();
    assert!(p.forbid_plugin_tls_off);
}

// ---------- Load gate (sections 7, 10, 13; T18.17) ----------

#[test]
fn only_official_plugins_load_before_plug_12() {
    let p = Policy::default();
    assert!(may_load(&p, Rollout::OFFICIAL_ONLY, "dev.bastion.postgres", Tier::Official, false, false).is_ok());
    assert!(denied(may_load(&p, Rollout::OFFICIAL_ONLY, "com.example.x", Tier::External, false, false)));
    assert!(denied(may_load(&p, Rollout::OFFICIAL_ONLY, "com.example.x", Tier::Unverified, true, false)));
}

#[test]
fn policy_and_safe_mode_stop_every_tier() {
    let open = Rollout { external_enabled: true, unverified_enabled: true };
    let id = "dev.bastion.postgres";
    assert!(denied(may_load(&Policy::default(), open, id, Tier::Official, true, true)), "Safe mode");
    assert!(denied(may_load(&Policy { plugins_disabled: true, ..Policy::default() }, open, id, Tier::Official, true, false)));
    let listed = Policy { plugins_allowed_ids: Some(BTreeSet::from(["other".to_string()])), ..Policy::default() };
    assert!(denied(may_load(&listed, open, id, Tier::Official, true, false)), "not on the list");
    let official_only = Policy { plugins_official_only: true, ..Policy::default() };
    assert!(denied(may_load(&official_only, open, "x.y", Tier::External, true, false)));
    let no_unverified = Policy { forbid_unverified_plugins: true, ..Policy::default() };
    assert!(denied(may_load(&no_unverified, open, "x.y", Tier::Unverified, true, false)));
    assert!(denied(may_load(&Policy::default(), open, "x.y", Tier::Unverified, false, false)), "user setting off");
    assert!(may_load(&Policy::default(), open, "x.y", Tier::Unverified, true, false).is_ok());
    assert!(may_load(&Policy::default(), open, "x.y", Tier::External, false, false).is_ok());
}

// ---------- Grants (section 5; T18.1, T18.2, T18.8) ----------

#[test]
fn every_call_needs_its_permission() {
    let none = Permissions { network_entry: false, credentials_entry: false, storage: false, clipboard_write: false, files_save: false, files_open: false, http_entry: false, open_ssh: false, open_rdp: false, open_vnc: false, exec_entry: false, library_propose: false };
    let g = HelperGrants::new("p", "1.0.0", none, Binding::Entry { entry_id: "e1".into(), temporary: false });
    for call in [Call::Connect, Call::EntryLogin, Call::StorageRead, Call::StorageWrite, Call::ClipboardWrite, Call::FileSave, Call::FileOpen] {
        assert!(denied(g.check(call)), "{call:?} without permission");
    }
    let g = HelperGrants::new("p", "1.0.0", all_perms(), Binding::Entry { entry_id: "e1".into(), temporary: false });
    for call in [Call::Connect, Call::EntryLogin, Call::StorageRead, Call::StorageWrite, Call::ClipboardWrite, Call::FileSave, Call::FileOpen] {
        assert!(g.check(call).is_ok(), "{call:?} with permission");
    }
}

#[test]
fn a_helper_with_no_entry_gets_no_network_credential_or_storage_grant() {
    let mut g = HelperGrants::new("p", "1.0.0", all_perms(), Binding::NoEntry);
    assert!(denied(g.check(Call::Connect)));
    assert!(denied(g.check(Call::StorageWrite)));
    assert!(denied(g.begin_release(Ok(()), false)));
    // Storage needs an entry too, reads included (spec section 5); the settings page gets the
    // core's read-only settings, not a storage grant.
    assert!(denied(g.check(Call::StorageRead)));
}

#[test]
fn a_quick_connect_has_no_storage_and_is_never_shared() {
    let g = HelperGrants::new("p", "1.0.0", all_perms(), Binding::Entry { entry_id: "qc-1".into(), temporary: true });
    assert!(denied(g.check(Call::StorageWrite)));
    assert!(!g.can_serve("p", "1.0.0", Some("qc-1")));
}

#[test]
fn no_helper_ever_serves_two_entries() {
    let g = HelperGrants::new("p", "1.0.0", all_perms(), Binding::Entry { entry_id: "e1".into(), temporary: false });
    assert!(g.can_serve("p", "1.0.0", Some("e1")));
    assert!(!g.can_serve("p", "1.0.0", Some("e2")));
    assert!(!g.can_serve("p", "1.0.0", None));
    assert!(!g.can_serve("p", "1.0.1", Some("e1")), "another version");
    assert!(!g.can_serve("q", "1.0.0", Some("e1")), "another plugin");
    let s = HelperGrants::new("p", "1.0.0", all_perms(), Binding::NoEntry);
    assert!(!s.can_serve("p", "1.0.0", Some("e1")));
}

#[test]
fn one_release_per_entry_per_helper_and_none_while_locked() {
    let mut g = HelperGrants::new("p", "1.0.0", all_perms(), Binding::Entry { entry_id: "e1".into(), temporary: false });
    assert!(denied(g.begin_release(Ok(()), true)), "locked");
    assert!(denied(g.begin_release(Err(Failure::Denied("the login waits until TLS is up".into())), false)), "the login gate did not pass");
    assert!(!g.holds_release());
    assert!(g.begin_release(Ok(()), false).is_ok());
    assert!(g.holds_release());
    assert!(denied(g.begin_release(Ok(()), false)), "second release");
}

// ---------- Secret check (section 5, "Released secrets"; T18.15, T18.19, T18.21) ----------

#[test]
fn the_secret_check_matches_exact_bytes_and_each_defined_encoding() {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    let secret = "pa ss/w?rd~\u{e9}";
    let c = check_of(secret);
    let b = secret.as_bytes();
    let forms: Vec<String> = vec![
        secret.to_string(),
        STANDARD.encode(b),
        STANDARD_NO_PAD.encode(b),
        URL_SAFE.encode(b),
        URL_SAFE_NO_PAD.encode(b),
        hex::encode(b),
        hex::encode_upper(b),
        "pa%20ss%2Fw%3Frd~%C3%A9".to_string(),
        "pa%20ss%2fw%3frd~%c3%a9".to_string(),
    ];
    for f in &forms {
        assert!(c.matches(format!("x={f};").as_bytes()), "form {f}");
        assert!(c.refuse(f.as_bytes()).is_err());
    }
    assert!(!c.matches(b"nothing to see"));
}

#[test]
fn a_five_byte_secret_is_matched_only_exactly() {
    let c = check_of("abcde");
    assert!(c.matches(b"..abcde.."));
    assert!(!c.matches(hex::encode("abcde").as_bytes()));
    let c6 = check_of("abcdef");
    assert!(c6.matches(hex::encode("abcdef").as_bytes()));
}

#[test]
fn a_password_equal_to_a_common_word_refuses_text_holding_it() {
    // The price of the check, stated in the spec: the user sees the core's reason.
    let c = check_of("postgres");
    assert_eq!(c.refuse(b"SELECT * FROM postgres_tables"), Err(Failure::Denied("holds a saved password".into())));
    assert!(!log_line_kept(&c, "connected to postgres"));
    assert!(log_line_kept(&c, "connected"));
}

#[test]
fn an_empty_secret_matches_nothing() {
    let mut c = SecretCheck::new();
    c.add(b"");
    assert!(c.is_empty());
    assert!(!c.matches(b"anything"));
}

#[test]
fn a_field_value_equal_to_the_entry_password_warns_and_never_refuses() {
    assert_eq!(field_save("analytics", Some(b"analytics")), FieldSave::WarnMatchesPassword);
    assert_eq!(field_save("analytics", Some(b"other-password")), FieldSave::Save);
    assert_eq!(field_save("analytics", None), FieldSave::Save, "credentials locked: nothing to compare");
}

// ---------- Streams and TLS (section 5, `network`; T18.24) ----------

fn direct(ip: IpAddr) -> Route {
    Route::Direct { peer: ip }
}

#[test]
fn local_is_decided_per_route() {
    assert!(direct(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).is_local());
    assert!(direct(IpAddr::V4(Ipv4Addr::new(127, 9, 9, 9))).is_local());
    assert!(direct(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_local());
    assert!(direct("::ffff:127.0.0.1".parse().unwrap()).is_local());
    assert!(!direct("10.1.2.3".parse().unwrap()).is_local());
    assert!(!direct("192.168.1.10".parse().unwrap()).is_local());
    assert!(!direct("169.254.1.1".parse().unwrap()).is_local());
    assert!(Route::Routed { target: RoutedTarget::Ip("127.0.0.1".parse().unwrap()) }.is_local());
    assert!(Route::Routed { target: RoutedTarget::Ip("::1".parse().unwrap()) }.is_local());
    assert!(!Route::Routed { target: RoutedTarget::Name("localhost".into()) }.is_local());
    assert!(!Route::Socks.is_local());
}

#[test]
fn the_unspecified_addresses_are_refused() {
    let p = Policy::default();
    for ip in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
        let ip: IpAddr = ip.parse().unwrap();
        assert!(denied(StreamGate::open(&direct(ip), TlsMode::VerifyFull, false, &p).map(|_| ())), "{ip}");
        assert!(denied(StreamGate::open(&Route::Routed { target: RoutedTarget::Ip(ip) }, TlsMode::VerifyFull, false, &p).map(|_| ())));
    }
}

#[test]
fn login_and_long_writes_wait_for_tls_direct_and_through_a_gateway() {
    let p = Policy::default();
    let none = SecretCheck::new();
    for route in [direct("10.0.0.5".parse().unwrap()), Route::Routed { target: RoutedTarget::Name("db.internal".into()) }, Route::Socks] {
        let mut g = StreamGate::open(&route, TlsMode::VerifyFull, false, &p).unwrap();
        assert!(g.tls_required());
        assert!(denied(g.check_login()), "{route:?}: login before TLS");
        assert!(g.check_write(&[0u8; MAX_PREAMBLE_BYTES], &none).is_ok(), "512 bytes before TLS");
        assert!(denied(g.check_write(&[0u8; 1], &none)), "byte 513 before TLS");
        g.tls_started();
        assert!(g.check_login().is_ok());
        assert!(g.check_write(&[0u8; 4096], &none).is_ok());
    }
    // 513 bytes in one write is refused too.
    let mut g = StreamGate::open(&direct("10.0.0.5".parse().unwrap()), TlsMode::Pinned, false, &p).unwrap();
    assert!(denied(g.check_write(&[0u8; MAX_PREAMBLE_BYTES + 1], &none)));
}

#[test]
fn a_local_destination_needs_no_tls() {
    let p = Policy::default();
    let g = StreamGate::open(&direct("127.0.0.1".parse().unwrap()), TlsMode::VerifyFull, false, &p).unwrap();
    assert!(!g.tls_required());
    assert!(g.check_login().is_ok());
}

#[test]
fn a_preamble_holding_the_released_secret_is_refused() {
    let p = Policy::default();
    let released = check_of("hunter2-secret");
    let mut g = StreamGate::open(&direct("10.0.0.5".parse().unwrap()), TlsMode::VerifyFull, false, &p).unwrap();
    assert!(denied(g.check_write(hex::encode("hunter2-secret").as_bytes(), &released)));
    assert!(g.check_write(b"\x00\x00\x00\x08\x04\xd2\x16\x2f", &released).is_ok(), "SSLRequest");
}

#[test]
fn tls_off_rules_on_each_route_and_under_policy() {
    let p = Policy::default();
    let lan = direct("10.0.0.5".parse().unwrap());
    let gw = Route::Routed { target: RoutedTarget::Name("db".into()) };
    assert!(denied(StreamGate::open(&lan, TlsMode::Off, false, &p).map(|_| ())), "direct, Allow unencrypted off");
    let g = StreamGate::open(&lan, TlsMode::Off, true, &p).unwrap();
    assert!(!g.tls_required());
    assert!(StreamGate::open(&gw, TlsMode::Off, false, &p).is_ok(), "through a gateway: last leg is the residual");
    assert!(StreamGate::open(&direct("127.0.0.1".parse().unwrap()), TlsMode::Off, false, &p).is_ok(), "local");
    let no_unenc = Policy { forbid_plugin_unencrypted: true, ..Policy::default() };
    assert!(denied(StreamGate::open(&lan, TlsMode::Off, true, &no_unenc).map(|_| ())));
    assert!(StreamGate::open(&gw, TlsMode::Off, false, &no_unenc).is_ok());
    let no_off = Policy { forbid_plugin_tls_off: true, ..Policy::default() };
    assert!(denied(StreamGate::open(&gw, TlsMode::Off, false, &no_off).map(|_| ())), "policy forbids TLS off through a gateway");
    assert!(denied(StreamGate::open(&direct("127.0.0.1".parse().unwrap()), TlsMode::Off, false, &no_off).map(|_| ())));
}

#[test]
fn a_failed_certificate_names_the_tls_mode_and_cannot_be_accepted() {
    match StreamGate::tls_failed() {
        Failure::Denied(m) => assert!(m.contains("TLS mode")),
        f => panic!("{f:?}"),
    }
}

#[test]
fn stream_caps_count_attempts_and_open_streams() {
    let mut c = StreamCaps::new();
    for i in 0..16 {
        assert!(c.try_connect(i).is_ok(), "stream {}", i + 1);
    }
    assert!(invalid(c.try_connect(20)), "17th stream");
    c.closed();
    assert!(c.try_connect(21).is_ok());
    // Rate: 30 attempts a minute, failed ones included.
    let mut r = StreamCaps::new();
    for i in 0..30 {
        r.try_connect(i).unwrap();
        r.connect_failed();
    }
    assert!(invalid(r.try_connect(100)), "31st attempt in a minute");
    assert!(r.try_connect(60_100).is_ok(), "the window moved past the attempts and the refused one");
}

// ---------- Abort bytes and stops (section 5; T18.23) ----------

#[test]
fn abort_bytes_limits() {
    let none = SecretCheck::new();
    let mut a = AbortRegistry::new();
    assert!(a.register(1, 5432, true, &[1u8; MAX_ABORT_BYTES], &none).is_ok(), "512 bytes");
    assert!(invalid(a.register(2, 5432, true, &[1u8; MAX_ABORT_BYTES + 1], &none)), "513 bytes refused whole");
    assert!(invalid(a.register(2, 5432, true, &[], &none)));
    assert!(denied(a.register(2, 6000, false, &[1u8; 16], &none)), "port outside the grant");
    let released = check_of("hunter2-secret");
    assert!(denied(a.register(3, 5432, true, b"user=x pw=hunter2-secret", &released)));
    // One registration per stream: a new one replaces the old.
    a.register(1, 5432, true, &[7u8; 16], &none).unwrap();
    assert_eq!(a.len(), 1);
}

#[test]
fn abort_bytes_go_once_on_an_ordinary_stop_and_never_after_trust_is_withdrawn() {
    let none = SecretCheck::new();
    for reason in [StopReason::UserCancel, StopReason::TabClosed, StopReason::LimitKill, StopReason::HangKill, StopReason::Crash, StopReason::DocumentLocked, StopReason::CredentialsLockedByPolicy] {
        let mut a = AbortRegistry::new();
        a.register(1, 5432, true, &[1u8; 16], &none).unwrap();
        assert_eq!(a.on_stop(reason).len(), 1, "{reason:?}");
        assert!(a.on_stop(reason).is_empty(), "sent at most once");
        assert!(a.register(2, 5432, true, &[1u8; 16], &none).is_err(), "nothing new after a stop");
    }
    for reason in [StopReason::Revoked, StopReason::PolicyChanged, StopReason::TurnedOff, StopReason::Removed, StopReason::SafeMode, StopReason::ProtocolViolation, StopReason::NoSandbox] {
        let mut a = AbortRegistry::new();
        a.register(1, 5432, true, &[1u8; 16], &none).unwrap();
        assert!(a.on_stop(reason).is_empty(), "{reason:?} withdraws trust");
    }
}

#[test]
fn a_cleared_or_closed_registration_sends_nothing() {
    let none = SecretCheck::new();
    let mut a = AbortRegistry::new();
    a.register(1, 5432, true, &[1u8; 16], &none).unwrap();
    a.register(2, 5432, true, &[2u8; 16], &none).unwrap();
    a.clear(1).unwrap();
    a.stream_closed(2);
    assert!(a.on_stop(StopReason::UserCancel).is_empty());
}

// ---------- Frames, messages, views (section 5; T18.25) ----------

#[test]
fn frames_are_checked_before_allocation() {
    assert!(check_frame_len(0).is_err());
    assert_eq!(check_frame_len(MAX_FRAME_BYTES).unwrap(), MAX_FRAME_BYTES as usize);
    assert!(check_frame_len(MAX_FRAME_BYTES + 1).is_err());
    assert!(check_frame_len(u32::MAX).is_err());
}

#[test]
fn the_sandbox_report_comes_first_and_only_once() {
    assert!(check_message(HelperKind::View, false, FromHelper::Call).is_err());
    assert!(check_message(HelperKind::View, false, FromHelper::SandboxReport).is_ok());
    assert!(check_message(HelperKind::View, true, FromHelper::SandboxReport).is_err());
}

#[test]
fn a_view_helper_that_sends_compiled_code_is_a_protocol_violation() {
    assert!(check_message(HelperKind::View, true, FromHelper::CompiledCode).is_err());
    assert!(check_message(HelperKind::View, true, FromHelper::CompileDone).is_err());
    assert!(check_message(HelperKind::View, true, FromHelper::Call).is_ok());
    assert!(check_message(HelperKind::Compile, true, FromHelper::CompiledCode).is_ok());
    assert!(check_message(HelperKind::Compile, true, FromHelper::Call).is_err(), "a compile helper runs no plugin code");
    assert!(check_message(HelperKind::Compile, true, FromHelper::ViewUpdate).is_err());
}

fn chain(n: usize) -> Vec<NodeRef> {
    (0..n as u32).map(|i| NodeRef { id: i, parent: if i == 0 { None } else { Some(i - 1) } }).collect()
}

#[test]
fn view_depth_32_draws_and_33_is_refused_not_killed() {
    assert!(check_view(&chain(MAX_VIEW_DEPTH), 100).is_ok());
    assert!(invalid(check_view(&chain(MAX_VIEW_DEPTH + 1), 100)));
    assert!(invalid(check_view(&chain(MAX_VIEW_NODES), 100)), "a chain of 2,000 nodes is refused for depth");
}

#[test]
fn view_size_and_node_limits() {
    let flat = |n: usize| (0..n as u32).map(|i| NodeRef { id: i, parent: None }).collect::<Vec<_>>();
    assert!(check_view(&flat(MAX_VIEW_NODES), MAX_VIEW_BYTES).is_ok());
    assert!(invalid(check_view(&flat(MAX_VIEW_NODES + 1), 10)));
    assert!(invalid(check_view(&flat(1), MAX_VIEW_BYTES + 1)));
}

#[test]
fn unknown_parents_duplicate_ids_and_cycles_are_refused() {
    assert!(invalid(check_view(&[NodeRef { id: 1, parent: Some(9) }], 10)));
    assert!(invalid(check_view(&[NodeRef { id: 1, parent: None }, NodeRef { id: 1, parent: None }], 10)));
    assert!(invalid(check_view(&[NodeRef { id: 1, parent: Some(2) }, NodeRef { id: 2, parent: Some(1) }], 10)));
    assert!(invalid(check_view(&[NodeRef { id: 1, parent: Some(1) }], 10)), "self-parent");
    // A cycle hanging off a valid root.
    let v = [NodeRef { id: 0, parent: None }, NodeRef { id: 1, parent: Some(3) }, NodeRef { id: 2, parent: Some(1) }, NodeRef { id: 3, parent: Some(2) }];
    assert!(invalid(check_view(&v, 10)));
}

#[test]
fn a_wide_tree_is_checked_quickly() {
    // 2,000 nodes under 31 levels: well within limits, and the memoised walk stays linear.
    let mut v = chain(31);
    for i in 31..2000u32 {
        v.push(NodeRef { id: i, parent: Some(30) });
    }
    let t = std::time::Instant::now();
    assert!(check_view(&v, 1000).is_ok());
    assert!(t.elapsed().as_millis() < 200);
}

#[test]
fn the_31st_update_in_a_second_is_held_back_not_a_kill() {
    let mut r = UpdateRate::new();
    for i in 0..30 {
        assert!(r.admit(i));
    }
    assert!(!r.admit(500), "31st within a second");
    assert!(r.admit(1_000), "the window moved");
}

// ---------- Result caps (section 5; T18.4) ----------

#[test]
fn result_caps_per_view_plugin_and_total_with_no_names_for_the_plugin() {
    let mut l = ResultLedger::new();
    assert!(l.reserve(1, "p", MAX_RESULT_BYTES_PER_VIEW).is_ok());
    let e = l.reserve(1, "p", 1).unwrap_err();
    assert_eq!(e.plugin_failure, Failure::Invalid("result too large".into()), "bare, no names");
    // Two views of one plugin: the second is refused at the plugin cap.
    let e = l.reserve(2, "p", 10 * MIB).unwrap_err();
    assert_eq!(e.core_largest_views, vec![(1, MAX_RESULT_BYTES_PER_VIEW)], "the core's own message gets the views");
    // Another plugin can still open a view with result data.
    assert!(l.reserve(3, "q", 200 * MIB).is_ok());
    // Total 512 MiB.
    assert!(l.reserve(4, "r", 56 * MIB).is_ok());
    assert!(l.reserve(5, "s", 1).is_err(), "over the total");
    l.release_view(1);
    assert!(l.reserve(5, "s", 1).is_ok());
    assert_eq!(l.held(1), 0);
}

// ---------- Compiled-code store index (section 4; T18.22) ----------

fn key() -> CacheKey {
    CacheKey { component_sha256: "aa".into(), wasmtime_version: "48.0.8".into(), os: "macos".into(), target: "aarch64".into(), settings_hash: "f1dd".into() }
}

#[test]
fn a_tampered_cache_file_is_refused_and_forgotten() {
    let mut c = CacheIndex::new();
    assert_eq!(c.check(&key(), b"code"), CacheCheck::Missing);
    c.record(key(), 100, b"compiled-code").unwrap();
    assert_eq!(c.check(&key(), b"compiled-code"), CacheCheck::Valid);
    assert_eq!(c.check(&key(), b"compiled-codf"), CacheCheck::Mismatch);
    assert_eq!(c.check(&key(), b"compiled-code"), CacheCheck::Missing, "compile again");
    let mut other = key();
    other.target = "pulley64".into();
    c.record(key(), 100, b"x").unwrap();
    assert_eq!(c.check(&other, b"x"), CacheCheck::Missing, "another engine");
    c.forget_component("aa");
    assert_eq!(c.check(&key(), b"x"), CacheCheck::Missing);
}

#[test]
fn compile_output_and_helper_limits() {
    assert_eq!(max_compiled_bytes(1000), 16_000);
    assert_eq!(max_compiled_bytes(100 * MIB), COMPILE_OUTPUT_MAX_BYTES);
    let mut c = CacheIndex::new();
    assert!(invalid(c.record(key(), 10, &[0u8; 161])));
    assert!(c.record(key(), 10, &[0u8; 160]).is_ok());
    assert!(c.begin_compile("aa", 0).is_ok());
    assert!(invalid(c.begin_compile("aa", 1)), "one per plugin hash");
    assert!(invalid(c.begin_compile("bb", MAX_HELPERS)), "counts toward the 8");
    c.end_compile("aa");
    assert!(c.begin_compile("aa", 0).is_ok());
}

// ---------- Lock (owner decision 8; T18.27) ----------

#[test]
fn helpers_keep_running_on_lock_unless_the_document_closes_sessions_or_policy_says_so() {
    let hs = vec![
        RunningHelper { helper_id: 1, document_id: Some("d1".into()), holds_release: true },
        RunningHelper { helper_id: 2, document_id: Some("d2".into()), holds_release: true },
        RunningHelper { helper_id: 3, document_id: Some("d1".into()), holds_release: false },
    ];
    assert!(on_credentials_lock(&Policy::default(), &hs).is_empty());
    assert!(on_document_lock("d1", false, &hs).is_empty());
    assert_eq!(on_document_lock("d1", true, &hs), vec![(1, StopReason::DocumentLocked), (3, StopReason::DocumentLocked)]);
    let p = Policy { stop_plugin_helpers_on_credentials_lock: true, ..Policy::default() };
    let stopped = on_credentials_lock(&p, &hs);
    assert_eq!(stopped, vec![(1, StopReason::CredentialsLockedByPolicy), (2, StopReason::CredentialsLockedByPolicy)]);
    assert!(stopped.iter().all(|(_, r)| !r.withdraws_trust()), "ordinary stops: abort bytes are sent");
}

// ---------- Audit (T18.26) ----------

#[test]
fn audit_events_name_the_plugin_and_hold_no_secret_or_statement_text() {
    let a = paudit::credential_release("dev.bastion.postgres", "1.0.0", "e1", Outcome::Success);
    assert_eq!((a.category, a.action), (Category::CredentialAccess, "credential.release.plugin"));
    assert_eq!(a.details["plugin"], "dev.bastion.postgres");
    let text = "DROP TABLE customers_acme;";
    let c = paudit::confirm("p", "1.0.0", "e1", "Production", paudit::ConfirmKind::Drop, true, text);
    assert_eq!(c.category, Category::Plugin);
    assert!(c.details.values().all(|v| !v.contains("customers_acme")), "no statement text");
    assert_eq!(c.details["text_sha256"].len(), 64);
    assert_eq!(c.details["text_cut"], "false");
    let long = "x".repeat(paudit::MAX_PROMPT_TEXT_BYTES + 1);
    assert_eq!(paudit::confirm("p", "1", "e1", "Test", paudit::ConfirmKind::Other, false, &long).details["text_cut"], "true");
    let k = paudit::helper_stopped("p", "1", None, StopReason::ProtocolViolation, "compiled code from a view helper");
    assert_eq!((k.action, k.outcome), ("plugin.helper.stop", Outcome::Denied));
    assert_eq!(paudit::cache_mismatch("p", "1", "aa").action, "plugin.cache.mismatch");
    let s = paudit::abort_sent("p", "1", "e1", StopReason::UserCancel, 16);
    assert_eq!((s.action, s.details["bytes"].as_str()), ("plugin.abort.sent", "16"));
}

// ---------- Review round 1 (#911) ----------

#[test]
fn a_password_split_over_two_preamble_writes_is_refused() {
    let p = Policy::default();
    let released = check_of("hunter2-secret");
    let mut g = StreamGate::open(&direct("10.0.0.5".parse().unwrap()), TlsMode::VerifyFull, false, &p).unwrap();
    assert!(g.check_write(b"user=x pw=hunter2", &released).is_ok());
    assert!(denied(g.check_write(b"-secret", &released)), "the whole preamble is checked");
    // Split encoded too.
    let hex = hex::encode("hunter2-secret");
    let mut g = StreamGate::open(&direct("10.0.0.5".parse().unwrap()), TlsMode::VerifyFull, false, &p).unwrap();
    assert!(g.check_write(hex[..10].as_bytes(), &released).is_ok());
    assert!(denied(g.check_write(hex[10..].as_bytes(), &released)));
}

#[test]
fn refused_connect_attempts_are_recorded_so_spinning_stays_refused() {
    let mut r = StreamCaps::new();
    for i in 0..30 {
        r.try_connect(i).unwrap();
        r.connect_failed();
    }
    // A tight loop of refused connects keeps the record bounded (#911 re-check).
    for t in 0..1_000_000u64 {
        assert!(r.try_connect(30 + t / 100_000).is_err());
    }
    assert_eq!(r.recorded_attempts(), 30);
    assert!(r.try_connect(60_100).is_ok(), "the window moved");
    // Refusals at the stream cap are recorded while the record has room.
    let mut s = StreamCaps::new();
    for i in 0..16 {
        s.try_connect(i).unwrap();
    }
    assert!(s.try_connect(20).is_err());
    assert_eq!(s.recorded_attempts(), 17);
}

#[test]
fn result_data_is_kept_per_view_and_plugin() {
    let mut l = ResultLedger::new();
    l.reserve(1, "p", 10 * MIB).unwrap();
    // The same view id under another plugin is a separate ledger line.
    l.reserve(1, "q", 10 * MIB).unwrap();
    assert!(l.reserve(2, "p", 246 * MIB).is_ok());
    assert!(l.reserve(3, "p", 1).is_err(), "p is at 256 MiB; q's bytes do not count for p");
    l.release_view(1);
    assert_eq!(l.held(1), 0);
}

#[test]
fn after_a_stop_abort_registrations_can_be_neither_replaced_nor_cleared() {
    let none = SecretCheck::new();
    let mut a = AbortRegistry::new();
    a.register(1, 5432, true, &[1u8; 16], &none).unwrap();
    // Before a stop a new registration replaces the old (a new cancel key per query).
    a.register(1, 5432, true, &[2u8; 16], &none).unwrap();
    assert!(a.clear(1).is_ok());
    a.register(1, 5432, true, &[3u8; 16], &none).unwrap();
    let sent = a.on_stop(StopReason::UserCancel);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].bytes, vec![3u8; 16]);
    assert!(invalid(a.register(1, 5432, true, &[4u8; 16], &none)), "no replace after the stop");
    assert!(invalid(a.clear(1)), "no clear after the stop");
}

#[test]
fn open_needs_the_permission_and_an_entry() {
    let none = Permissions::default();
    let on_entry = Binding::Entry { entry_id: "e".into(), temporary: false };
    assert!(HelperGrants::new("p", "1", none, on_entry.clone()).check(Call::Open).is_err(), "no open permission");
    let ssh = Permissions { open_ssh: true, ..none };
    assert!(HelperGrants::new("p", "1", ssh, on_entry).check(Call::Open).is_ok());
    assert!(HelperGrants::new("p", "1", ssh, Binding::NoEntry).check(Call::Open).is_err(), "a helper with no entry");
}

#[test]
fn open_audit_records_escape_and_cut_plugin_values() {
    let r = paudit::OpenAuditRequest { protocol: "ssh", host: "evil\n{\"forged\":1}\u{202e}", port: Some(22), reported: None };
    let a = paudit::open_denied("p", "1", Some("e"), "syntax", &r);
    assert_eq!(a.action, "plugin.open.denied");
    assert_eq!(a.outcome, Outcome::Denied);
    let host = &a.details["host"];
    assert!(!host.contains('\n') && !host.contains('\u{202e}'), "{host}");
    let long = "x\n".repeat(1_000);
    let a = paudit::open_denied("p", "1", Some("e"), "syntax", &paudit::OpenAuditRequest { protocol: &long, host: &long, port: None, reported: None });
    assert!(a.details["host"].len() <= 256 && a.details["protocol"].len() <= 256);
    let ok = paudit::OpenAuditRequest { protocol: "rdp", host: "10.0.0.5", port: Some(3389), reported: Some(true) };
    let a = paudit::open_answer("p", "1", "e", 7, &ok, true, "entry", true, false);
    assert_eq!((a.details["answer"].as_str(), a.details["reported"].as_str(), a.details["credential_chosen"].as_str()), ("opened", "true", "true"));
    assert!(!a.details.values().any(|v| v.contains("password")));
}
