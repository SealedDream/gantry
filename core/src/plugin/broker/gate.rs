//! Whether a plugin may load (spec sections 7, 10 and 13; T18.17).
//!
//! Checked when a helper starts and again on every call (a policy change stops running
//! helpers with [`super::StopReason::PolicyChanged`]).

use crate::plugin::Tier;
use crate::policy::Policy;

use super::Failure;

/// The rollout stage the app is at. External plugins stay off until PLUG-12; Unverified ones
/// until PLUG-05 (OS sandbox) and PLUG-09 (hostile suites) and then only behind the user's
/// setting (sections 7 and 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rollout {
    pub external_enabled: bool,
    pub unverified_enabled: bool,
}

impl Rollout {
    /// Today's stage: only Official plugins load.
    pub const OFFICIAL_ONLY: Rollout = Rollout { external_enabled: false, unverified_enabled: false };

    /// The stage the app runs at: `OFFICIAL_ONLY`. A `test-hooks` build (the UI driver suites;
    /// release bundles never enable it) also honours `BASTION_TEST_PLUGIN_ROLLOUT=unverified`, so a
    /// proof run can open an unverified test plugin. In any other build the variable is never read:
    /// its name and the code path are compiled out.
    pub fn current() -> Rollout {
        #[cfg(feature = "test-hooks")]
        {
            if std::env::var("BASTION_TEST_PLUGIN_ROLLOUT").ok().as_deref() == Some("unverified") {
                return Rollout { external_enabled: false, unverified_enabled: true };
            }
        }
        Rollout::OFFICIAL_ONLY
    }
}

#[cfg(test)]
mod rollout_tests {
    use super::Rollout;

    #[test]
    fn only_a_test_hooks_build_honours_the_rollout_override() {
        std::env::set_var("BASTION_TEST_PLUGIN_ROLLOUT", "unverified");
        let set = Rollout::current();
        std::env::remove_var("BASTION_TEST_PLUGIN_ROLLOUT");
        if cfg!(feature = "test-hooks") {
            assert!(set.unverified_enabled && !set.external_enabled);
        } else {
            assert_eq!(set, Rollout::OFFICIAL_ONLY, "a release build ignores the variable");
        }
        assert_eq!(Rollout::current(), Rollout::OFFICIAL_ONLY, "unset: Official only");
    }
}

/// Decide whether plugin `id` of `tier` may load. `allow_unverified` is the user's "Allow
/// unverified plugins" setting; `safe_mode` is the app's Safe mode.
pub fn may_load(policy: &Policy, rollout: Rollout, id: &str, tier: Tier, allow_unverified: bool, safe_mode: bool) -> Result<(), Failure> {
    if safe_mode {
        return Err(Failure::Denied("Safe mode is on: every plugin is off".into()));
    }
    if policy.plugins_disabled {
        return Err(Failure::Denied("plugins are turned off by policy".into()));
    }
    if let Some(ids) = &policy.plugins_allowed_ids {
        if !ids.contains(id) {
            return Err(Failure::Denied("this plugin is not on the policy's list".into()));
        }
    }
    match tier {
        Tier::Official => Ok(()),
        Tier::External => {
            if policy.plugins_official_only {
                Err(Failure::Denied("policy allows Official plugins only".into()))
            } else if !rollout.external_enabled {
                Err(Failure::Denied("External plugins are not available yet".into()))
            } else {
                Ok(())
            }
        }
        Tier::Unverified => {
            if policy.plugins_official_only || policy.forbid_unverified_plugins {
                Err(Failure::Denied("policy forbids Unverified plugins".into()))
            } else if !rollout.unverified_enabled {
                Err(Failure::Denied("Unverified plugins are not available yet".into()))
            } else if !allow_unverified {
                Err(Failure::Denied("\"Allow unverified plugins\" is off".into()))
            } else {
                Ok(())
            }
        }
    }
}
