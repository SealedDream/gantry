
/// TM-04: the OS-lock decision is user preference OR managed requirement, restrictive when the
/// managed policy cannot be read.
#[test]
fn os_lock_is_user_choice_or_managed_requirement() {
    use bastion_core::policy::{lock_on_os_lock, Policy};
    let forced = Ok(Policy { lock_credentials_on_os_lock: true, ..Policy::default() });
    let free = Ok(Policy::default());
    let broken: bastion_core::Result<Policy> = Err(bastion_core::CoreError::PolicyDenied("broken".into()));
    assert!(lock_on_os_lock(false, &forced), "a forced managed lock wins over the user's 'off'");
    assert!(lock_on_os_lock(true, &forced));
    assert!(lock_on_os_lock(true, &free));
    assert!(!lock_on_os_lock(false, &free));
    assert!(lock_on_os_lock(false, &broken), "a broken policy locks");
}

// ---------------------------------------------------------------------------------------------
// A1-CORE-02: how long a remembered login may be reused during the run (SEC-03).

mod session_login_policy {
    use bastion_core::policy::{effective_session_login_reuse_minutes, remembered_login_usable, Policy};

    fn reuse(minutes: u32) -> Policy {
        Policy { session_login_reuse_minutes: minutes, ..Policy::default() }
    }

    /// The default is today's behaviour: until Lock or quit.
    #[test]
    fn default_is_zero_until_lock_or_quit() {
        assert_eq!(Policy::default().session_login_reuse_minutes, 0);
        assert_eq!(effective_session_login_reuse_minutes(0, 0), 0);
    }

    /// Packet: `0` is always usable, however old the login is.
    #[test]
    fn zero_minutes_is_always_usable() {
        assert!(remembered_login_usable(1_000, 1_000, 0));
        assert!(remembered_login_usable(1_000, 1_000 + 10 * 365 * 24 * 3_600, 0));
        assert!(remembered_login_usable(0, u64::MAX, 0));
    }

    /// Packet: `5` is usable at 4 min 59 s and not at 5 min.
    #[test]
    fn five_minutes_is_usable_at_4_59_and_refused_at_5_00() {
        let at = 1_700_000_000;
        assert!(remembered_login_usable(at, at, 5));
        assert!(remembered_login_usable(at, at + 4 * 60 + 59, 5));
        assert!(!remembered_login_usable(at, at + 5 * 60, 5), "refused at exactly 5 minutes");
        assert!(!remembered_login_usable(at, at + 5 * 60 + 1, 5));
        assert!(!remembered_login_usable(at, u64::MAX, 5));
    }

    /// A clock that went backwards cannot extend a time limit: the age is unknown, so the login
    /// is not reused. With no limit there is nothing to extend.
    #[test]
    fn a_clock_that_went_backwards_is_refused_under_a_limit() {
        assert!(!remembered_login_usable(2_000, 1_999, 5));
        assert!(!remembered_login_usable(u64::MAX, 0, 1));
        assert!(remembered_login_usable(2_000, 1_999, 0));
    }

    /// The largest values do not overflow or wrap into "usable".
    #[test]
    fn the_largest_limit_does_not_overflow() {
        assert!(remembered_login_usable(0, u64::from(u32::MAX) * 60 - 1, u32::MAX));
        assert!(!remembered_login_usable(0, u64::from(u32::MAX) * 60, u32::MAX));
        assert!(!remembered_login_usable(0, u64::MAX, u32::MAX));
    }

    /// Packet: the effective value is the smaller non-zero one. A managed maximum wins over a
    /// larger user value; a user value of 0 with a managed maximum of 10 gives 10.
    #[test]
    fn managed_maximum_wins_and_zero_never_relaxes_it() {
        assert_eq!(effective_session_login_reuse_minutes(60, 10), 10, "managed maximum wins over a larger user value");
        assert_eq!(effective_session_login_reuse_minutes(0, 10), 10, "user 0 (until Lock) under a maximum of 10 gives 10");
        assert_eq!(effective_session_login_reuse_minutes(5, 10), 5, "the user's shorter value stays");
        assert_eq!(effective_session_login_reuse_minutes(10, 10), 10);
        assert_eq!(effective_session_login_reuse_minutes(5, 0), 5, "no managed maximum: the user's value");
        assert_eq!(effective_session_login_reuse_minutes(u32::MAX, 1), 1);
    }

    /// The same rule when two policies are combined, in both directions: a managed 0 does not
    /// relax a user limit and a user 0 does not relax a managed limit.
    #[test]
    fn with_managed_takes_the_smaller_non_zero_value() {
        for (user, managed, want) in [(0, 0, 0), (0, 10, 10), (10, 0, 10), (60, 10, 10), (5, 10, 5), (10, 10, 10)] {
            assert_eq!(reuse(user).with_managed(&reuse(managed)).session_login_reuse_minutes, want, "user {user}, managed {managed}");
        }
    }

    /// Adding the value changes no other policy value or default.
    #[test]
    fn no_other_policy_value_changes() {
        let merged = Policy::default().with_managed(&reuse(10));
        assert_eq!(Policy { session_login_reuse_minutes: 0, ..merged }, Policy::default());
        let d = Policy::default();
        assert_eq!((d.bulk_confirm_threshold, d.inactivity_lock_secs, d.document_auto_lock_max_minutes), (2, Some(15 * 60), None));
        assert!(d.confirm_sensitive_writes && !d.allow_cross_customer_credentials && !d.allow_session_recording && !d.lock_credentials_on_os_lock);
    }

    /// The managed file sets it by name; a file without it keeps 0; a wrong type, a negative
    /// number or a misspelt name is an error, never an ignored restriction.
    #[test]
    fn managed_policy_file_sets_the_maximum() {
        assert_eq!(Policy::parse_managed(br#"{"session_login_reuse_minutes": 10}"#).unwrap().session_login_reuse_minutes, 10);
        assert_eq!(Policy::parse_managed(br#"{"forbid_legacy": true}"#).unwrap().session_login_reuse_minutes, 0);
        for bad in [
            &br#"{"session_login_reuse_minutes": "10"}"#[..],
            br#"{"session_login_reuse_minutes": -1}"#,
            br#"{"session_login_reuse_minutes": 4294967296}"#,
            br#"{"session_login_reuse_minutes": 1.5}"#,
            br#"{"session_login_reuse_minute": 10}"#,
        ] {
            assert!(Policy::parse_managed(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    /// The policy round-trips through JSON with the value.
    #[test]
    fn policy_round_trips_through_json() {
        let json = serde_json::to_string(&reuse(15)).unwrap();
        assert!(json.contains(r#""session_login_reuse_minutes":15"#), "{json}");
        assert_eq!(serde_json::from_str::<Policy>(&json).unwrap(), reuse(15));
    }
}
