//! Audit TM-01: a zero ("no cap") document auto-lock maximum cannot relax a positive one.
use bastion_core::docunlock::effective_auto_lock_minutes;
use bastion_core::policy::Policy;

fn cap(v: Option<u32>) -> Policy {
    Policy { document_auto_lock_max_minutes: v, ..Default::default() }
}

/// Exhaustive None/zero/positive merges: a positive managed cap never yields no cap, and a
/// user timeout of zero ("never") becomes the managed limit.
#[test]
fn zero_cap_cannot_relax_a_positive_managed_cap() {
    let values = [None, Some(0), Some(3), Some(5), Some(60)];
    for user in values {
        for managed in values {
            let merged = cap(user).with_managed(&cap(managed)).document_auto_lock_max_minutes;
            let positive: Vec<u32> = [user, managed].into_iter().flatten().filter(|m| *m > 0).collect();
            assert_eq!(merged, positive.iter().copied().min(), "user {user:?} managed {managed:?}");
            if let Some(m) = managed.filter(|m| *m > 0) {
                let limit = merged.expect("a positive managed cap survives the merge");
                assert!(limit <= m);
                assert_eq!(effective_auto_lock_minutes(0, merged), limit, "user 'never' becomes the managed limit");
            }
        }
    }
}
