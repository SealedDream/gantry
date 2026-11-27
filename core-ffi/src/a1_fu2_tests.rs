//! A1-CORE-01-FU2: an SSH connect (terminal, files, tunnels, tasks: everything that goes through
//! `SessionManager::prepare`) takes a saved credential only when the shared login rule
//! (`bastion_core::logins::may_use`) lists it for that connection. Nothing is dialled here:
//! `prepare` reads the secret and stops. Generated data only.
use std::collections::HashMap;
use std::sync::Arc;

use bastion_core::logins::LoginPurpose;

use super::{SessionManager, SshLogin};
use crate::{parse_id, CredentialVault, FfiResult, GatewayInputView, Library};

struct Bench {
    _dir: tempfile::TempDir,
    lib: Arc<Library>,
    vault: Arc<CredentialVault>,
    manager: Arc<SessionManager>,
}

fn bench() -> Bench {
    let dir = tempfile::tempdir().unwrap();
    let lib = Arc::new(Library::open(dir.path().join("library.json").display().to_string()).unwrap());
    let vault = Arc::new(CredentialVault::open_ephemeral(dir.path().join("c.vault").display().to_string()).unwrap());
    let manager = SessionManager::new(dir.path().join("data").display().to_string()).unwrap();
    manager.set_vault(vault.clone());
    Bench { _dir: dir, lib, vault, manager }
}

impl Bench {
    fn folder(&self, name: &str) -> String {
        self.lib.add_folder(None, name.into()).unwrap()
    }

    fn ssh(&self, parent: &str, name: &str, host: &str) -> String {
        self.lib.add_connection(Some(parent.into()), name.into(), "ssh".into(), host.into(), None, None).unwrap()
    }

    /// A saved password whose user name is `user` and whose secret is `pw-<user>`.
    fn password(&self, user: &str) -> String {
        self.vault.save_password(None, format!("{user} login"), None, user.into(), format!("pw-{user}")).unwrap()
    }

    /// The user name the prepared connect signs in with, taken from the saved credential.
    fn prepare(&self, connection: &str, credential: &str, jump_logins: HashMap<String, SshLogin>) -> FfiResult<String> {
        self.manager.prepare(&self.lib, connection, String::new(), vault_login(credential), HashMap::new(), jump_logins).map(|p| p.cred.username.clone())
    }
}

fn vault_login(credential: &str) -> SshLogin {
    SshLogin::Vault { credential_id: credential.into() }
}

fn refused(r: FfiResult<String>, expect: &str) {
    let message = r.expect_err("a login outside the connection's scope must not be read").to_string();
    assert!(message.contains(expect) && !message.contains("pw-"), "{message}");
}

#[test]
fn a_saved_login_from_another_top_level_folder_is_refused() {
    let b = bench();
    let (acme, globex) = (b.folder("Acme"), b.folder("Globex"));
    let a = b.ssh(&acme, "acme db", "10.0.0.5");
    let g = b.ssh(&globex, "globex db", "10.0.0.5");
    let dba = b.password("dba");
    b.vault.add_login(b.lib.clone(), a.clone(), dba.clone()).unwrap();

    refused(b.prepare(&g, &dba, HashMap::new()), "not offered for this connection");
    assert_eq!(b.prepare(&a, &dba, HashMap::new()).unwrap(), "dba", "its own login still works");
}

#[test]
fn a_loopback_connection_does_not_get_another_loopback_login() {
    let b = bench();
    let lab = b.folder("Lab");
    let first = b.ssh(&lab, "forward 2222", "127.0.0.1");
    let second = b.ssh(&lab, "forward 2223", "localhost");
    let root = b.password("root");
    b.vault.add_login(b.lib.clone(), first.clone(), root.clone()).unwrap();

    refused(b.prepare(&second, &root, HashMap::new()), "not offered for this connection");
    assert_eq!(b.prepare(&first, &root, HashMap::new()).unwrap(), "root");
}

#[test]
fn own_inherited_and_offered_logins_are_read() {
    let b = bench();
    let lab = b.folder("Lab");
    let one = b.ssh(&lab, "srv ssh", "srv.lab.example");
    let two = b.ssh(&lab, "srv files", "SRV.lab.example");
    let other = b.ssh(&lab, "other", "other.lab.example");
    let (admin, team, stranger) = (b.password("admin"), b.password("team"), b.password("stranger"));
    b.vault.add_login(b.lib.clone(), one.clone(), admin.clone()).unwrap();
    b.lib.set_property(lab, "credential_name".into(), Some("team login".into())).unwrap();

    assert_eq!(b.prepare(&one, &admin, HashMap::new()).unwrap(), "admin", "its own login");
    assert_eq!(b.prepare(&other, &team, HashMap::new()).unwrap(), "team", "the login its folder names");
    // Decision D1: a login saved for the same machine is offered; the user's pick is allowed.
    assert_eq!(b.prepare(&two, &admin, HashMap::new()).unwrap(), "admin", "an offered login the user picked");
    refused(b.prepare(&other, &admin, HashMap::new()), "not offered for this connection");
    refused(b.prepare(&one, &stranger, HashMap::new()), "not offered for this connection");
    // A typed password is the user's own input and has no saved credential to check.
    let typed = SshLogin::Password { password: "typed".into() };
    assert!(b.manager.prepare(&b.lib, &other, "me".into(), typed, HashMap::new(), HashMap::new()).is_ok());
}

/// An inline secret is stored under its connection's id, and the apps connect with that id.
#[test]
fn an_inline_secret_is_read_for_its_own_connection_only() {
    let b = bench();
    let lab = b.folder("Lab");
    let mine = b.ssh(&lab, "srv ssh", "srv.lab.example");
    let twin = b.ssh(&lab, "srv files", "srv.lab.example");
    b.vault.set_inline_password(mine.clone(), "inline".into(), "pw-inline".into()).unwrap();

    assert_eq!(b.prepare(&mine, &mine, HashMap::new()).unwrap(), "inline");
    refused(b.prepare(&twin, &mine, HashMap::new()), "not offered for this connection");
}

#[test]
fn a_jump_host_login_must_be_allowed_for_the_target() {
    let b = bench();
    let (acme, globex) = (b.folder("Acme"), b.folder("Globex"));
    let target = b.ssh(&acme, "acme app", "app.acme.example");
    let elsewhere = b.ssh(&globex, "globex app", "app.globex.example");
    let (deploy, foreign) = (b.password("deploy"), b.password("foreign"));
    b.vault.add_login(b.lib.clone(), target.clone(), deploy.clone()).unwrap();
    b.vault.add_login(b.lib.clone(), elsewhere, foreign.clone()).unwrap();
    let gateway = b.lib.add_gateway(GatewayInputView { name: "Acme jump".into(), host: "jump.acme.example".into(), port: None, username: Some("hop".into()), notes: String::new() }).unwrap();
    b.lib.set_property(target.clone(), "gateway_id".into(), Some(gateway)).unwrap();
    let hop_login = |credential: &str| HashMap::from([("jump.acme.example:22".to_string(), vault_login(credential))]);

    let e = b.prepare(&target, &deploy, hop_login(&foreign)).expect_err("a jump login from another scope").to_string();
    assert!(e.contains("Acme jump") && e.contains("not offered") && !e.contains("pw-"), "{e}");
    assert_eq!(b.prepare(&target, &deploy, hop_login(&deploy)).unwrap(), "deploy", "the target's login, chosen for the hop");
    assert_eq!(b.prepare(&target, &deploy, HashMap::new()).unwrap(), "deploy", "no hop login: the hop reuses the target's");
}

#[test]
fn a_login_is_allowed_when_any_named_connection_may_use_it() {
    let b = bench();
    let (acme, globex) = (b.folder("Acme"), b.folder("Globex"));
    let target = b.ssh(&acme, "acme app", "app.acme.example");
    let hop = b.ssh(&globex, "shared jump", "jump.globex.example");
    let jump = b.password("jump");
    b.vault.add_login(b.lib.clone(), hop.clone(), jump.clone()).unwrap();
    let (target, hop, jump) = (parse_id(&target).unwrap(), parse_id(&hop).unwrap(), parse_id(&jump).unwrap());
    let unknown = uuid::Uuid::new_v4();

    assert!(!b.vault.may_use_any(&b.lib, &[target], jump, LoginPurpose::Any).unwrap());
    assert!(b.vault.may_use_any(&b.lib, &[target, hop], jump, LoginPurpose::Any).unwrap(), "the hop's own login");
    // A hop that is not a library entry (a gateway, a literal ProxyJump host) has no logins.
    assert!(!b.vault.may_use_any(&b.lib, &[target, unknown], jump, LoginPurpose::Any).unwrap());
    assert!(b.vault.may_use_any(&b.lib, &[unknown], jump, LoginPurpose::Any).is_err(), "an unknown target is an error, not a quiet no");
}

/// The Services, Processes and Event Log views of an RDP connection sign in over SSH to the same
/// host (`dial_ssh_to`). Port 1 on this computer: nobody listens, so an allowed login fails at
/// the dial and nothing is sent.
#[test]
fn the_ssh_management_sign_in_of_an_rdp_connection_is_checked_too() {
    use bastion_core::model::{Connection, Node, Protocol};
    use bastion_core::properties::{RDP_SSH_MANAGEMENT, RDP_SSH_PORT};
    let b = bench();
    let (acme, globex) = (b.folder("Acme"), b.folder("Globex"));
    let mut rdp = Connection::new("acme desktop", Protocol::Rdp, "127.0.0.1");
    rdp.metadata.insert(RDP_SSH_MANAGEMENT.into(), "on".into());
    rdp.metadata.insert(RDP_SSH_PORT.into(), "1".into());
    let rdp_id = rdp.id.to_string();
    b.lib.with_doc(|d| d.insert(Some(parse_id(&acme).unwrap()), Node::Connection(rdp))).unwrap();
    let elsewhere = b.ssh(&globex, "globex db", "db.globex.example");
    let (own, foreign) = (b.password("own"), b.password("foreign"));
    b.vault.add_login(b.lib.clone(), rdp_id.clone(), own.clone()).unwrap();
    b.vault.add_login(b.lib.clone(), elsewhere, foreign.clone()).unwrap();
    let sign_in = |credential: &str| {
        let (ssh, _) = bastion_core::sysview::ssh_management(&b.lib.resolve(parse_id(&rdp_id).unwrap()).unwrap()).expect("SSH management is on");
        b.manager.dial_ssh_to(&b.lib, ssh, String::new(), vault_login(credential), None).map(|_| ()).expect_err("nothing listens on port 1").to_string()
    };

    let e = sign_in(&foreign);
    assert!(e.contains("not offered for this connection") && !e.contains("pw-"), "{e}");
    assert!(!sign_in(&own).contains("not offered"), "its own login reaches the dial");
}

/// `saved_login_allowed` lets a vault login pass when no vault is open, because nothing can be
/// read then. This pins that: the connect fails, and names no credential.
#[test]
fn with_no_vault_open_a_saved_login_is_not_released() {
    let b = bench();
    let lab = b.folder("Lab");
    let conn = b.ssh(&lab, "srv ssh", "srv.lab.example");
    let admin = b.password("admin");
    b.vault.add_login(b.lib.clone(), conn.clone(), admin.clone()).unwrap();
    let closed = SessionManager::new(b._dir.path().join("no-vault").display().to_string()).unwrap();

    let e = match closed.prepare(&b.lib, &conn, "admin".into(), vault_login(&admin), HashMap::new(), HashMap::new()) {
        Ok(_) => panic!("a saved login was read with no vault open"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("vault is not open") && !e.contains("pw-"), "{e}");
}
