use std::sync::Arc;
use std::time::Duration;

use bastion_core::broker::{Broker, LeaseKey, LeaseLimits, ManualClock};
use bastion_core::model::{Connection, Protocol};
use bastion_core::policy::Policy;
use bastion_core::vault::Secret;
use bastion_core::CoreError;

const MIN: Duration = Duration::from_secs(60);

fn conn(customer: Option<&str>) -> Connection {
    let mut c = Connection::new("c", Protocol::Ssh, "h");
    c.classification.customer = customer.map(String::from);
    c
}

fn key(cred: &str, scope: Option<&str>) -> LeaseKey {
    LeaseKey { credential: cred.into(), scope: scope.map(String::from) }
}

fn broker() -> (Broker, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::default());
    (Broker::new(LeaseLimits::default(), Policy::default(), clock.clone()), clock)
}

#[test]
fn inactivity_expires_without_use() {
    let (b, clock) = broker();
    let k = key("cred-1", Some("acme"));
    b.unlock(k.clone(), Secret::new("pw")).unwrap();
    clock.advance(14 * MIN);
    assert!(b.get(&k, &conn(Some("acme"))).unwrap().is_some());
    clock.advance(14 * MIN);
    assert!(b.get(&k, &conn(Some("acme"))).unwrap().is_some(), "use resets inactivity");
    clock.advance(15 * MIN);
    assert!(b.get(&k, &conn(Some("acme"))).unwrap().is_none());
}

#[test]
fn activity_never_extends_absolute_lifetime() {
    let (b, clock) = broker();
    let k = key("cred-1", None);
    b.unlock(k.clone(), Secret::new("pw")).unwrap();
    for _ in 0..5 {
        clock.advance(11 * MIN);
        assert!(b.get(&k, &conn(None)).unwrap().is_some());
    }
    clock.advance(6 * MIN); // 61 min after unlock, last use 6 min ago
    assert!(b.get(&k, &conn(None)).unwrap().is_none());
}

#[test]
fn leases_are_never_reused_across_customers() {
    let (b, _) = broker();
    b.unlock(key("shared-key", Some("acme")), Secret::new("pw")).unwrap();
    let err = b.get(&key("shared-key", Some("acme")), &conn(Some("globex"))).unwrap_err();
    assert!(matches!(err, CoreError::PolicyDenied(_)));
    assert!(b.get(&key("shared-key", Some("globex")), &conn(Some("globex"))).unwrap().is_none());
    assert!(b.get(&key("other", Some("acme")), &conn(Some("acme"))).unwrap().is_none(), "keyed by credential identity");
}

#[test]
fn lock_all_and_status_show_no_secrets() {
    let (b, clock) = broker();
    b.unlock(key("a", None), Secret::new("TOPSECRET")).unwrap();
    b.unlock(key("b", Some("acme")), Secret::new("TOPSECRET")).unwrap();
    clock.advance(5 * MIN);
    let st = b.status().unwrap();
    assert_eq!(st.len(), 2);
    assert_eq!(st[0].remaining_inactivity, 10 * MIN);
    assert_eq!(st[0].remaining_absolute, 55 * MIN);
    assert!(!format!("{st:?}").contains("TOPSECRET"));
    assert_eq!(b.lock_all().unwrap(), 2);
    assert!(b.status().unwrap().is_empty());
}

#[test]
fn sweep_removes_expired_leases() {
    let (b, clock) = broker();
    b.unlock(key("a", None), Secret::new("x")).unwrap();
    clock.advance(16 * MIN);
    assert_eq!(b.sweep().unwrap(), 1);
}

#[test]
fn managed_limits_only_tighten() {
    let user = LeaseLimits { inactivity: 30 * MIN, absolute: 8 * 60 * MIN, allow_caching: true };
    let managed = LeaseLimits { inactivity: 5 * MIN, absolute: 600 * MIN, allow_caching: false };
    let eff = user.with_managed(&managed);
    assert_eq!(eff.inactivity, 5 * MIN);
    assert_eq!(eff.absolute, 8 * 60 * MIN);
    assert!(!eff.allow_caching);
    let clock = Arc::new(ManualClock::default());
    let b = Broker::new(eff, Policy::default(), clock);
    b.unlock(key("a", None), Secret::new("x")).unwrap();
    assert!(b.get(&key("a", None), &conn(None)).unwrap().is_none(), "caching disabled by policy");
}

/// TM-03: the broker hosts build expires leases at the policy's inactivity limit, not the
/// 15-minute default, and refuses the secret after expiry; the absolute limit is independent.
#[test]
fn policy_inactivity_limit_expires_leases_on_the_host_constructor() {
    let clock = Arc::new(ManualClock::default());
    let policy = Policy { inactivity_lock_secs: Some(1), ..Policy::default() };
    let b = Broker::for_policy(policy, clock.clone());
    assert_eq!(b.limits().inactivity, Duration::from_secs(1));
    assert_eq!(b.limits().absolute, LeaseLimits::default().absolute);
    b.unlock(key("generated", None), Secret::new("generated-secret")).unwrap();
    assert!(b.get(&key("generated", None), &conn(None)).unwrap().is_some());
    clock.advance(Duration::from_secs(2));
    assert!(b.get(&key("generated", None), &conn(None)).unwrap().is_none(), "expired after the managed 1 s");
}

#[test]
fn lease_limits_follow_policy_and_never_loosen() {
    assert_eq!(LeaseLimits::for_policy(&Policy::default()), LeaseLimits::default());
    let none = Policy { inactivity_lock_secs: None, ..Policy::default() };
    assert_eq!(LeaseLimits::for_policy(&none), LeaseLimits::default());
    let long = Policy { inactivity_lock_secs: Some(10 * 60 * 60), ..Policy::default() };
    assert_eq!(LeaseLimits::for_policy(&long).inactivity, LeaseLimits::default().inactivity, "a longer value never loosens the default");
    let zero = Policy { inactivity_lock_secs: Some(0), ..Policy::default() };
    assert!(!LeaseLimits::for_policy(&zero).allow_caching);
}
