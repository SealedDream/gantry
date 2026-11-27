//! Audit TM-02: remember-until-quit cannot outlast a managed document idle maximum.
use bastion_core::docunlock::{document_lock_due, effective_auto_lock_minutes, LockReason};

/// Managed cap on/off × remember on/off × user timeout off/short/long, on a fake clock.
#[test]
fn managed_cap_bounds_every_combination() {
    const CAP: u32 = 5;
    for cap in [None, Some(0), Some(CAP)] {
        let enforced = cap.filter(|m| *m > 0);
        for remember in [false, true] {
            for user in [0u32, 2, 60] {
                let expected_minutes = match (remember, enforced) {
                    (true, Some(c)) => c,
                    (true, None) => 0,
                    (false, c) => effective_auto_lock_minutes(user, c),
                };
                for idle in [0u64, 119, 120, 299, 300, 3_599, 3_600, u64::MAX] {
                    let due = document_lock_due(user, cap, idle, false, false, remember);
                    let want = (expected_minutes > 0 && idle >= u64::from(expected_minutes) * 60).then_some(LockReason::Idle);
                    assert_eq!(due, want, "cap {cap:?} remember {remember} user {user} idle {idle}");
                    if enforced.is_some() && idle >= u64::from(CAP) * 60 {
                        assert_eq!(due, Some(LockReason::Idle), "an enforced maximum can never become never");
                    }
                    assert_eq!(document_lock_due(user, cap, idle, true, false, remember), Some(LockReason::ScreenLocked));
                    assert_eq!(document_lock_due(user, cap, idle, false, true, remember), Some(LockReason::Sleep));
                }
            }
        }
    }
}

/// The exact Codex probe: cap 1 minute, idle an hour, remember on.
#[test]
fn remember_until_quit_does_not_bypass_a_one_minute_cap() {
    assert_eq!(document_lock_due(1, Some(1), 3_600, false, false, true), Some(LockReason::Idle));
}
