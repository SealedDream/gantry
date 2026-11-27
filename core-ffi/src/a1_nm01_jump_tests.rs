//! A1-NM-01 (review of #846, LOW): Test Connection of a connection with a ProxyJump chain and a
//! saved login. The Mac dialog builds its hops from `SessionManager::jump_hosts` (the chain a
//! real connect dials), each hop with the target's login as a connect does when the hop has none
//! of its own. That chain must pass the saved-route check; any edit of it must still be refused.
//!
//! Offline: an imported SSH config on this computer's closed ports, so an allowed test fails at
//! the dial. Generated data only; the secret is `pw-admin`.
use std::sync::Arc;

use crate::terminal::{SessionManager, SshLogin};
use crate::{CredentialVault, FfiResult, Library, ProbeInput, ProbeJump, ProbeReportView, SshWorkflow};

const ROUTE_DIFFERS: &str = "differ from the saved connection";

fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Chain {
    _dir: tempfile::TempDir,
    lib: Arc<Library>,
    manager: Arc<SessionManager>,
    inner: String,
    inner_port: u16,
    admin: String,
}

/// `inner` (ProxyJump `gw`, user `tester`) and `gw`, both on closed ports, imported; `admin`
/// assigned to `inner`.
fn chain() -> Chain {
    chain_with_gw_user(Some("hop"))
}

/// As `chain`, with `gw` saved with this user, or none.
fn chain_with_gw_user(gw_user: Option<&str>) -> Chain {
    let dir = tempfile::tempdir().unwrap();
    let (gw_port, inner_port) = (closed_port(), closed_port());
    let ssh = dir.path().join("ssh");
    std::fs::create_dir_all(ssh.join("config.d")).unwrap();
    let gw_user = gw_user.map(|u| format!("  User {u}\n")).unwrap_or_default();
    let config = format!("Host gw\n  HostName 127.0.0.1\n  Port {gw_port}\n{gw_user}\nHost inner\n  HostName 127.0.0.1\n  Port {inner_port}\n  User tester\n  ProxyJump gw\n");
    std::fs::write(ssh.join("config.d/lab"), config).unwrap();
    let data = dir.path().join("data");
    let lib = Arc::new(Library::open(data.join("lib.json").display().to_string()).unwrap());
    let wf = SshWorkflow::open(data.display().to_string()).unwrap();
    let mut settings = wf.settings();
    settings.ssh_dir = Some(ssh.display().to_string());
    wf.set_settings(settings).unwrap();
    let ids = wf.scan().hosts.iter().map(|h| h.identity.clone()).collect();
    wf.import_hosts(lib.clone(), ids).unwrap();
    let inner = lib.tree().folders[0].connections.iter().find(|c| c.name == "inner").unwrap().id.clone();

    let vault = Arc::new(CredentialVault::open_ephemeral(dir.path().join("c.vault").display().to_string()).unwrap());
    let manager = SessionManager::new(data.display().to_string()).unwrap();
    manager.set_vault(vault.clone());
    let admin = vault.save_password(None, "admin login".into(), None, "admin".into(), "pw-admin".into()).unwrap();
    vault.add_login(lib.clone(), inner.clone(), admin.clone()).unwrap();
    Chain { _dir: dir, lib, manager, inner, inner_port, admin }
}

impl Chain {
    fn saved(&self) -> SshLogin {
        SshLogin::Vault { credential_id: self.admin.clone() }
    }

    /// The hops as the Mac dialog builds them: `jump_hosts`, keys split at the last colon, each
    /// with the target's login.
    fn dialog_hops(&self) -> Vec<ProbeJump> {
        let hops = self.manager.jump_hosts(self.lib.clone(), self.inner.clone()).unwrap();
        hops.into_iter()
            .map(|h| {
                let (host, port) = h.key.rsplit_once(':').unwrap();
                ProbeJump { host: host.into(), port: port.parse().unwrap(), username: h.username, login: self.saved() }
            })
            .collect()
    }

    fn probe(&self, host: &str, port: u16, jumps: Vec<ProbeJump>) -> FfiResult<ProbeReportView> {
        let input = ProbeInput {
            protocol: "ssh".into(),
            host: host.into(),
            port,
            username: "tester".into(),
            login: Some(self.saved()),
            jumps,
            pasted_key: None,
            pasted_key_passphrase: None,
            trusted_fingerprint: None,
            connection_id: Some(self.inner.clone()),
        };
        self.manager.test_connection(Some(self.lib.clone()), input).map(|t| t.wait())
    }
}

fn refused(r: FfiResult<ProbeReportView>) {
    match r {
        Ok(_) => panic!("an edited route must be refused"),
        Err(e) => {
            let e = e.to_string();
            assert!(e.contains(ROUTE_DIFFERS), "{e}");
            assert!(!e.contains("pw-") && !e.contains("admin login"), "{e}");
        }
    }
}

#[test]
fn a_saved_login_tests_through_the_saved_proxyjump_chain() {
    let c = chain();
    let hops = c.dialog_hops();
    assert_eq!(hops.len(), 1, "gw is the one hop");
    assert_eq!(hops[0].username, "hop");
    let report = c.probe("127.0.0.1", c.inner_port, hops).expect("the saved chain is the saved route");
    assert!(!report.ok && !report.cancelled && !report.steps.is_empty(), "{:?}", report.steps);
}

#[test]
fn a_saved_login_is_refused_for_an_edited_proxyjump_chain() {
    let c = chain();
    let hops = c.dialog_hops();

    // No hops (what the Mac sent before this fix): the chain is short.
    refused(c.probe("127.0.0.1", c.inner_port, vec![]));
    // The hop moved to another port.
    let mut moved = c.dialog_hops();
    moved[0].port = closed_port();
    refused(c.probe("127.0.0.1", c.inner_port, moved));
    // The hop moved to another host.
    let mut elsewhere = c.dialog_hops();
    elsewhere[0].host = "127.0.0.2".into();
    refused(c.probe("127.0.0.1", c.inner_port, elsewhere));
    // A hop added.
    let mut longer = c.dialog_hops();
    longer.extend(c.dialog_hops());
    refused(c.probe("127.0.0.1", c.inner_port, longer));
    // The hop logs in as another user (CORE-SEC-LOWS).
    let mut other_user = c.dialog_hops();
    other_user[0].username = "root".into();
    refused(c.probe("127.0.0.1", c.inner_port, other_user));
    // The saved chain to an edited target port.
    refused(c.probe("127.0.0.1", closed_port(), hops));
}

/// #875 review: a hop saved without a user logs in as the target's user, so a dialog that sends
/// the target's user (Windows) or no user (Mac) for it is the saved route. Another user is not.
#[test]
fn a_hop_saved_without_a_user_matches_the_target_user_and_refuses_another() {
    let c = chain_with_gw_user(None);
    let hops = c.dialog_hops();
    assert_eq!(hops.len(), 1, "gw is the one hop");
    for user in ["tester", ""] {
        let mut sent = c.dialog_hops();
        sent[0].username = user.into();
        c.probe("127.0.0.1", c.inner_port, sent).unwrap_or_else(|e| panic!("hop user {user:?}: {e}"));
    }
    let mut other = hops;
    other[0].username = "root".into();
    refused(c.probe("127.0.0.1", c.inner_port, other));
}
