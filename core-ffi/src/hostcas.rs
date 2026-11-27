//! Bridge for SSH host certificate authorities (`bastion_core::hostcert`): the
//! `@cert-authority` lines of the app's known_hosts. Holds public keys only.
use bastion_core::hostcert::{self, CaEntry};

use crate::terminal::SessionManager;
use crate::FfiResult;

#[derive(uniffi::Record, Debug, PartialEq)]
pub struct HostCaView {
    /// Hosts it vouches for, e.g. `*.example.com,[10.0.0.5]:2222`.
    pub patterns: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
}

fn view(e: CaEntry) -> HostCaView {
    HostCaView { patterns: e.patterns, fingerprint: e.fingerprint, algorithm: e.algorithm, comment: e.comment }
}

#[uniffi::export]
impl SessionManager {
    pub fn host_cas(&self) -> Vec<HostCaView> {
        hostcert::list_cas(&self.known_hosts_path()).into_iter().map(view).collect()
    }

    /// Trust `public_key` (one OpenSSH public key line) to sign host certificates for `patterns`.
    pub fn add_host_ca(&self, patterns: String, public_key: String) -> FfiResult<HostCaView> {
        Ok(view(hostcert::add_ca(&self.known_hosts_path(), &patterns, &public_key)?))
    }

    pub fn remove_host_ca(&self, patterns: String, fingerprint: String) -> FfiResult<()> {
        Ok(hostcert::remove_ca(&self.known_hosts_path(), &patterns, &fingerprint)?)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::SessionManager;

    #[test]
    fn cas_round_trip_through_the_manager() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-ca-{}", Uuid::new_v4()));
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        assert!(mgr.host_cas().is_empty());
        let ca = include_str!("../../core/tests/fixtures/hostcert/ca.pub");
        let v = mgr.add_host_ca("*.lab".into(), ca.into()).unwrap();
        assert!(v.fingerprint.starts_with("SHA256:"));
        assert_eq!(SessionManager::new(dir.to_string_lossy().into_owned()).unwrap().host_cas(), [v.clone_view()]);
        mgr.remove_host_ca(v.patterns.clone(), v.fingerprint.clone()).unwrap();
        assert!(mgr.host_cas().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    impl super::HostCaView {
        fn clone_view(&self) -> Self {
            Self { patterns: self.patterns.clone(), fingerprint: self.fingerprint.clone(), algorithm: self.algorithm.clone(), comment: self.comment.clone() }
        }
    }
}
