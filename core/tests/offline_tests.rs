//! Offline guarantee: in offline mode (the internet-blocked test run) optional online features
//! fail at once without a packet leaving the LAN, and LAN destinations still work. Outside it,
//! an unreachable network still fails within the connect budget.
use std::time::{Duration, Instant};

use bastion_core::offline;
use bastion_core::CoreError;

/// Without offline mode an unroutable address (TEST-NET-3) fails inside the 3 s connect budget
/// rather than the OS default. Under `BASTION_OFFLINE=1` (the offline suite) the same call must be
/// refused as `Offline` instead, so the test asserts something in both modes (Codex T02). The
/// forced-offline scenario lives in its own test binary (`offline_forced_tests.rs`) so its
/// process-global flag never overlaps this test.
#[test]
fn unreachable_update_server_fails_within_the_connect_budget() {
    let t = Instant::now();
    let e = bastion_core::update::check("https://203.0.113.1/update-manifest.json", &[], "stable", "0.0.0", 0).unwrap_err();
    let took = t.elapsed();
    if offline::is_offline() {
        assert!(matches!(e, CoreError::Offline(_)), "{e:?}");
    }
    eprintln!("unreachable update server failed after {took:?}: {e}");
    assert!(took < offline::CONNECT_TIMEOUT + Duration::from_secs(1), "{took:?}");
}
