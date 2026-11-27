//! A1-CORE-01-FU3: the three paths FU2 left take a saved credential only when the shared login
//! rule (`bastion_core::logins`) gives it to that connection.
//!
//! - `CredentialVault::rdp_login_for` and Test Connection have no step where the user confirms
//!   a login, so they read the connection's own inline secret or a login it may use without
//!   asking. A login that is only offered (saved for another connection of the same machine,
//!   or named by an imported library) is refused here.
//! - The gateway route refuses every saved (vault) login (coordinator ruling, option A).
//!
//! Nothing reaches a server: hosts are this computer on a port nobody listens on, so an allowed
//! login fails at the dial. Generated data only; every secret is `pw-<user>`.
use std::sync::Arc;

use bastion_core::model::{Connection, Node, Protocol};

use crate::terminal::{SessionManager, SshLogin};
use crate::{parse_id, CredentialVault, FfiResult, GatewayInputView, Library, ProbeInput, ProbeJump, ProbeReportView};

const NOT_OFFERED: &str = "not offered for this connection";
const NEEDS_SAVED: &str = "save the connection before testing it with a saved login";
const GATEWAY_REFUSAL: &str = "a gateway does not take a saved login";

struct Bench {
    dir: tempfile::TempDir,
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
    Bench { dir, lib, vault, manager }
}

/// A port on this computer that refuses connections.
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Bench {
    fn folder(&self, name: &str) -> String {
        self.lib.add_folder(None, name.into()).unwrap()
    }

    fn add(&self, parent: &str, name: &str, protocol: &str, host: &str) -> String {
        self.lib.add_connection(Some(parent.into()), name.into(), protocol.into(), host.into(), None, None).unwrap()
    }

    /// A saved password named `<user> login`, user name `user`, secret `pw-<user>`.
    fn password(&self, user: &str) -> String {
        self.vault.save_password(None, format!("{user} login"), None, user.into(), format!("pw-{user}")).unwrap()
    }

    fn assign(&self, connection: &str, credential: &str) {
        self.vault.add_login(self.lib.clone(), connection.into(), credential.into()).unwrap();
    }

    /// The user name `rdp_login_for` hands out, or `None`.
    fn rdp(&self, connection: &str, credential: Option<&str>) -> FfiResult<Option<String>> {
        self.vault.rdp_login_for(self.lib.clone(), connection.into(), credential.map(str::to_string)).map(|l| {
            l.map(|l| {
                assert_eq!(l.password, format!("pw-{}", l.username), "the password of that login");
                l.username
            })
        })
    }

    /// The vault's audit lines for a released RDP password.
    fn releases(&self) -> usize {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl")).unwrap_or_default().matches("credential.release.rdp").count()
    }

    /// An SSH connection on this computer at a port nobody listens on, so a test of it, with
    /// the saved host and port, fails at the dial.
    fn local(&self, parent: &str, name: &str) -> String {
        let id = self.add(parent, name, "ssh", "127.0.0.1");
        self.lib.set_property(id.clone(), "port".into(), Some(closed_port().to_string())).unwrap();
        id
    }

    /// Start a test as the saved connection `connection`, of its saved host and port (or of a
    /// closed port when there is none), and wait for its report.
    fn probe(&self, library: bool, connection: Option<&str>, login: Option<SshLogin>, jumps: Vec<ProbeJump>) -> FfiResult<ProbeReportView> {
        let saved = connection.and_then(|id| self.lib.resolve(parse_id(id).ok()?).ok());
        let (host, port) = saved.map_or(("127.0.0.1".to_string(), closed_port()), |c| (c.host, c.settings.port.unwrap_or(22)));
        self.probe_at(library, connection, &host, port, login, jumps)
    }

    /// The same, of `host:port` as the dialog holds it (maybe edited).
    fn probe_at(&self, library: bool, connection: Option<&str>, host: &str, port: u16, login: Option<SshLogin>, jumps: Vec<ProbeJump>) -> FfiResult<ProbeReportView> {
        let input = ProbeInput { host: host.into(), port, login, jumps, connection_id: connection.map(str::to_string), ..input() };
        self.manager.test_connection(library.then(|| self.lib.clone()), input).map(|task| task.wait())
    }

    /// Put `connection` behind a new gateway on this computer; its port.
    fn gateway_for(&self, connection: &str) -> u16 {
        let port = closed_port();
        let input = GatewayInputView { name: format!("gw {port}"), host: "127.0.0.1".into(), port: Some(port), username: Some("hop".into()), notes: String::new() };
        let gateway = self.lib.add_gateway(input).unwrap();
        self.lib.set_property(connection.into(), "gateway_id".into(), Some(gateway)).unwrap();
        port
    }

    fn probe_saved(&self, connection: &str, credential: &str) -> FfiResult<ProbeReportView> {
        self.probe(true, Some(connection), Some(vault_login(credential)), vec![])
    }

    /// Lines the manager's audit log holds for a started test.
    fn tests_started(&self) -> usize {
        std::fs::read_to_string(self.dir.path().join("data").join("audit.jsonl")).unwrap_or_default().matches("connection.test").count()
    }

    /// An RDP connection in `parent` behind a gateway on a closed port of this computer.
    fn behind_gateway(&self, parent: &str, name: &str) -> String {
        let gateway = GatewayInputView { name: format!("{name} jump"), host: "127.0.0.1".into(), port: Some(closed_port()), username: Some("hop".into()), notes: String::new() };
        let gateway = self.lib.add_gateway(gateway).unwrap();
        let conn = Connection::new(name, Protocol::Rdp, "10.0.0.9");
        let id = conn.id.to_string();
        self.lib.with_doc(|d| d.insert(Some(parse_id(parent).unwrap()), Node::Connection(conn))).unwrap();
        self.lib.set_property(id.clone(), "gateway_id".into(), Some(gateway)).unwrap();
        id
    }

    fn route(&self, connection: &str, login: SshLogin) -> String {
        match self.manager.open_gateway_route(self.lib.clone(), connection.into(), "hop".into(), login, None) {
            Ok(_) => panic!("nothing listens on the gateway's port"),
            Err(e) => e.to_string(),
        }
    }
}

/// What the dialog holds for an SSH host on a closed port, with nothing entered.
fn input() -> ProbeInput {
    ProbeInput {
        protocol: "ssh".into(),
        host: "127.0.0.1".into(),
        port: closed_port(),
        username: "tester".into(),
        login: None,
        jumps: vec![],
        pasted_key: None,
        pasted_key_passphrase: None,
        trusted_fingerprint: None,
        connection_id: None,
    }
}

fn vault_login(credential: &str) -> SshLogin {
    SshLogin::Vault { credential_id: credential.into() }
}

fn typed() -> SshLogin {
    SshLogin::Password { password: "typed".into() }
}

fn jump(login: SshLogin) -> ProbeJump {
    jump_to(closed_port(), login)
}

fn jump_to(port: u16, login: SshLogin) -> ProbeJump {
    ProbeJump { host: "127.0.0.1".into(), port, username: "hop".into(), login }
}

/// The refusal holds no secret (`pw-…`) and no saved credential's name (`… login`).
fn refused<T>(r: FfiResult<T>, expect: &str) {
    let message = match r {
        Ok(_) => panic!("a login outside the connection's own was read"),
        Err(e) => e.to_string(),
    };
    assert!(message.contains(expect), "{message}");
    assert!(!message.contains("pw-"), "{message}");
    for user in ["dba", "root", "admin", "team", "stranger", "foreign", "deploy"] {
        assert!(!message.contains(&format!("{user} login")), "{message}");
    }
}

/// An allowed login gets as far as the network: the test ran and failed at the name lookup or
/// at the closed port.
fn reached_the_dial(r: FfiResult<ProbeReportView>) {
    let report = r.expect("an allowed login starts the test");
    assert!(!report.ok && !report.cancelled);
    assert!(report.steps.iter().any(|s| (s.kind == "tcp" || s.kind == "dns") && s.status == "failed"), "{:?}", report.steps);
}

/// Import a library a sender made: one connection that names a credential called `name`.
fn import_naming(b: &Bench, name: &str, protocol: Protocol) -> String {
    let sender = Arc::new(Library::open(b.dir.path().join("sender.json").display().to_string()).unwrap());
    let mut c = Connection::new("sent", protocol, "127.0.0.1");
    c.settings.port = Some(closed_port());
    c.settings.credential_name = Some(name.into());
    sender.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
    let export = b.dir.path().join("sent.json");
    sender.export_to(export.display().to_string(), None).unwrap();
    b.lib.import_file(export.display().to_string()).unwrap();
    let received = b.lib.lock().connections().into_iter().find(|r| r.connection.name == "sent").expect("imported").connection;
    received.id.to_string()
}

// MARK: rdp_login_for

#[test]
fn rdp_returns_the_own_inline_password_first() {
    let b = bench();
    let lab = b.folder("Lab");
    let conn = b.add(&lab, "desktop", "rdp", "desk.lab.example");
    let admin = b.password("admin");
    b.assign(&conn, &admin);
    assert_eq!(b.rdp(&conn, None).unwrap(), None, "nothing inline, no credential named");

    b.vault.set_inline_password(conn.clone(), "inline".into(), "pw-inline".into()).unwrap();
    assert_eq!(b.rdp(&conn, None).unwrap().as_deref(), Some("inline"));
    assert_eq!(b.rdp(&conn, Some(&admin)).unwrap().as_deref(), Some("inline"), "the inline password wins, as before");
    assert_eq!(b.releases(), 2);
}

#[test]
fn rdp_returns_an_assigned_or_inherited_password() {
    let b = bench();
    let lab = b.folder("Lab");
    let own = b.add(&lab, "desktop", "rdp", "desk.lab.example");
    let heir = b.add(&lab, "other desktop", "rdp", "other.lab.example");
    let (admin, team) = (b.password("admin"), b.password("team"));
    b.assign(&own, &admin);
    b.lib.set_property(lab, "credential_name".into(), Some("team login".into())).unwrap();

    assert_eq!(b.rdp(&own, Some(&admin)).unwrap().as_deref(), Some("admin"), "its own login");
    assert_eq!(b.rdp(&heir, Some(&team)).unwrap().as_deref(), Some("team"), "the login its folder names");
    assert_eq!(b.releases(), 2);
}

#[test]
fn rdp_refuses_a_login_from_elsewhere_and_reads_nothing() {
    let b = bench();
    let (acme, globex) = (b.folder("Acme"), b.folder("Globex"));
    let a = b.add(&acme, "acme desktop", "rdp", "10.0.0.5");
    let g = b.add(&globex, "globex desktop", "rdp", "10.0.0.5");
    let first = b.add(&acme, "forward 3390", "rdp", "127.0.0.1");
    let second = b.add(&acme, "forward 3391", "rdp", "localhost");
    let (dba, root, stranger) = (b.password("dba"), b.password("root"), b.password("stranger"));
    b.assign(&a, &dba);
    b.assign(&first, &root);

    refused(b.rdp(&g, Some(&dba)), NOT_OFFERED);
    refused(b.rdp(&second, Some(&root)), NOT_OFFERED);
    refused(b.rdp(&a, Some(&stranger)), NOT_OFFERED);
    // An SSH key is not a password login, even the connection's own.
    let key = b.vault.save_ssh_key(None, "deploy key".into(), None, "deploy".into(), "not-a-real-key".into()).unwrap();
    b.assign(&a, &key);
    refused(b.rdp(&a, Some(&key)), NOT_OFFERED);
    assert_eq!(b.releases(), 0, "a refusal releases nothing");
}

/// Decision D1 and FU1: a login that is only offered needs the user's yes. `rdp_login_for` has
/// no such step (the sheet's pick goes through `release_login`), so it never hands one out.
#[test]
fn rdp_never_returns_a_login_that_is_only_offered() {
    let b = bench();
    let lab = b.folder("Lab");
    let ssh = b.add(&lab, "srv ssh", "ssh", "srv.lab.example");
    let rdp = b.add(&lab, "srv desktop", "rdp", "srv.lab.example");
    let admin = b.password("admin");
    b.assign(&ssh, &admin);
    let offered = b.vault.login_candidates(b.lib.clone(), rdp.clone(), true).unwrap();
    assert_eq!(offered.iter().map(|l| (l.credential_id.as_str(), l.auto_use)).collect::<Vec<_>>(), vec![(admin.as_str(), false)], "offered for the same machine");

    refused(b.rdp(&rdp, Some(&admin)), NOT_OFFERED);
    // The user's pick in the connect sheet still works, through the call made for it.
    assert_eq!(b.vault.release_login(b.lib.clone(), rdp.clone(), admin.clone()).unwrap().username, "admin");

    // A credential an imported library names is only offered until the user chooses it.
    let received = import_naming(&b, "admin login", Protocol::Rdp);
    refused(b.rdp(&received, Some(&admin)), NOT_OFFERED);
    b.assign(&received, &admin);
    assert_eq!(b.rdp(&received, Some(&admin)).unwrap().as_deref(), Some("admin"), "chosen by the user");
}

// MARK: Test Connection

#[test]
fn a_test_reads_own_inherited_and_inline_logins() {
    let b = bench();
    let lab = b.folder("Lab");
    let own = b.local(&lab, "srv");
    let heir = b.local(&lab, "other");
    let (admin, team) = (b.password("admin"), b.password("team"));
    b.assign(&own, &admin);
    b.lib.set_property(lab, "credential_name".into(), Some("team login".into())).unwrap();
    b.vault.set_inline_password(heir.clone(), "inline".into(), "pw-inline".into()).unwrap();

    reached_the_dial(b.probe_saved(&own, &admin));
    reached_the_dial(b.probe_saved(&heir, &team));
    // The Mac dialog sends the connection's id for a stored inline secret.
    reached_the_dial(b.probe_saved(&heir, &heir));
    assert_eq!(b.tests_started(), 3);
}

#[test]
fn a_test_refuses_a_login_from_elsewhere_before_it_starts() {
    let b = bench();
    let (acme, globex) = (b.folder("Acme"), b.folder("Globex"));
    let a = b.add(&acme, "acme db", "ssh", "10.0.0.5");
    let g = b.add(&globex, "globex db", "ssh", "10.0.0.5");
    let twin = b.add(&acme, "acme files", "sftp", "10.0.0.5");
    let (dba, stranger) = (b.password("dba"), b.password("stranger"));
    b.assign(&a, &dba);
    b.vault.set_inline_password(a.clone(), "inline".into(), "pw-inline".into()).unwrap();

    refused(b.probe_saved(&g, &dba), NOT_OFFERED);
    refused(b.probe_saved(&a, &stranger), NOT_OFFERED);
    // Another connection's inline secret.
    refused(b.probe_saved(&twin, &a), NOT_OFFERED);
    // Saved for the same machine: offered in the connect sheet, never sent by a test.
    refused(b.probe_saved(&twin, &dba), NOT_OFFERED);
    assert_eq!(b.tests_started(), 0, "nothing was dialled");
}

#[test]
fn a_test_never_sends_a_login_an_imported_library_names() {
    let b = bench();
    let admin = b.password("admin");
    let received = import_naming(&b, "admin login", Protocol::Ssh);

    refused(b.probe_saved(&received, &admin), NOT_OFFERED);
    refused(b.probe(true, Some(&received), Some(SshLogin::Agent), vec![jump(vault_login(&admin))]), NOT_OFFERED);
    assert_eq!(b.tests_started(), 0);
    b.assign(&received, &admin);
    reached_the_dial(b.probe_saved(&received, &admin));
}

#[test]
fn a_jump_host_login_in_a_test_must_be_the_connections_own() {
    let b = bench();
    let (acme, globex) = (b.folder("Acme"), b.folder("Globex"));
    let target = b.local(&acme, "acme app");
    let elsewhere = b.add(&globex, "globex app", "ssh", "app.globex.example");
    let (deploy, foreign) = (b.password("deploy"), b.password("foreign"));
    b.assign(&target, &deploy);
    b.assign(&elsewhere, &foreign);
    let gw = b.gateway_for(&target);

    refused(b.probe(true, Some(&target), Some(typed()), vec![jump(vault_login(&foreign))]), NOT_OFFERED);
    refused(b.probe(true, Some(&target), Some(vault_login(&deploy)), vec![jump(vault_login(&deploy)), jump(vault_login(&foreign))]), NOT_OFFERED);
    assert_eq!(b.tests_started(), 0);
    // The gateway of a saved connection signs in with a copy of the target's login.
    let report = b.probe(true, Some(&target), Some(vault_login(&deploy)), vec![jump_to(gw, vault_login(&deploy))]).expect("the target's own login, for the hop too");
    assert!(!report.ok && !report.steps.is_empty());
}

#[test]
fn an_unsaved_entry_is_tested_with_typed_logins_only() {
    let b = bench();
    let lab = b.folder("Lab");
    let conn = b.add(&lab, "srv", "ssh", "srv.lab.example");
    let admin = b.password("admin");
    b.assign(&conn, &admin);

    refused(b.probe(true, None, Some(vault_login(&admin)), vec![]), NEEDS_SAVED);
    refused(b.probe(false, Some(&conn), Some(vault_login(&admin)), vec![]), NEEDS_SAVED);
    refused(b.probe(false, None, Some(SshLogin::Agent), vec![jump(vault_login(&admin))]), NEEDS_SAVED);
    assert_eq!(b.tests_started(), 0);

    reached_the_dial(b.probe(false, None, Some(typed()), vec![]));
    reached_the_dial(b.probe(false, None, Some(SshLogin::KeyFile { path: "/nonexistent/id_ed25519".into(), passphrase: None }), vec![]));
    reached_the_dial(b.probe(false, None, Some(SshLogin::Agent), vec![]));
    reached_the_dial(b.probe(false, None, None, vec![]));
    reached_the_dial(b.probe(true, Some(&conn), Some(typed()), vec![]));
}

/// A pasted key replaces the login, which is then never read, so there is nothing to refuse.
#[test]
fn a_pasted_key_is_tested_in_place_of_the_login() {
    let b = bench();
    let stranger = b.password("stranger");
    let pasted = ProbeInput { login: Some(vault_login(&stranger)), pasted_key: Some("not-a-real-key".into()), ..input() };
    reached_the_dial(b.manager.test_connection(None, pasted).map(|t| t.wait()));
}

#[test]
fn a_test_with_no_vault_open_reads_no_saved_login() {
    let b = bench();
    let lab = b.folder("Lab");
    let conn = b.add(&lab, "srv", "ssh", "srv.lab.example");
    let admin = b.password("admin");
    b.assign(&conn, &admin);
    let closed = SessionManager::new(b.dir.path().join("no-vault").display().to_string()).unwrap();
    let saved = ProbeInput { login: Some(vault_login(&admin)), connection_id: Some(conn), ..input() };
    refused(closed.test_connection(Some(b.lib.clone()), saved).map(|_| ()), "vault is not open");
}

// MARK: Gateway route

#[test]
fn a_gateway_route_refuses_every_saved_login() {
    let b = bench();
    let lab = b.folder("Lab");
    let conn = b.behind_gateway(&lab, "desktop");
    let (admin, stranger) = (b.password("admin"), b.password("stranger"));
    b.assign(&conn, &admin);
    b.vault.set_inline_password(conn.clone(), "inline".into(), "pw-inline".into()).unwrap();

    for credential in [&admin, &stranger, &conn] {
        let e = b.route(&conn, vault_login(credential));
        assert!(e.contains(GATEWAY_REFUSAL), "{e}");
        assert!(!e.contains("pw-") && !e.contains("admin login") && !e.contains("stranger login") && !e.contains(credential.as_str()), "{e}");
    }
    // Refused before the gateway is looked up or dialled: also for a connection with no gateway.
    let plain = b.add(&lab, "plain", "rdp", "10.0.0.8");
    assert!(b.route(&plain, vault_login(&admin)).contains(GATEWAY_REFUSAL));
}

#[test]
fn a_gateway_route_still_dials_with_typed_key_file_and_agent_logins() {
    let b = bench();
    let lab = b.folder("Lab");
    let conn = b.behind_gateway(&lab, "desktop");

    for login in [typed(), SshLogin::PasswordAndCode { password: "typed".into(), code: "123456".into() }, SshLogin::KeyFile { path: "/nonexistent/id_ed25519".into(), passphrase: None }, SshLogin::Agent] {
        let e = b.route(&conn, login);
        assert!(!e.contains(GATEWAY_REFUSAL) && !e.contains("not offered"), "{e}");
    }
}

// MARK: Test Connection: the dialled route must be the saved one

const ROUTE_DIFFERS: &str = "differ from the saved connection";

/// Review of #846, MEDIUM: the login is checked against the saved connection, so it must only
/// go where the saved connection goes, not to a host, port or hop edited in the dialog.
#[test]
fn a_saved_login_is_not_sent_to_an_edited_host_port_or_jump_chain() {
    let b = bench();
    let lab = b.folder("Lab");
    let conn = b.local(&lab, "srv");
    let admin = b.password("admin");
    b.assign(&conn, &admin);
    b.vault.set_inline_password(conn.clone(), "inline".into(), "pw-inline".into()).unwrap();
    let saved = b.lib.resolve(parse_id(&conn).unwrap()).unwrap();
    let port = saved.settings.port.unwrap();
    let attacker = closed_port();

    for credential in [&admin, &conn] {
        let login = || Some(vault_login(credential));
        refused(b.probe_at(true, Some(&conn), "127.0.0.2", port, login(), vec![]), ROUTE_DIFFERS);
        refused(b.probe_at(true, Some(&conn), "127.0.0.1", attacker, login(), vec![]), ROUTE_DIFFERS);
        refused(b.probe_at(true, Some(&conn), "127.0.0.1", port, login(), vec![jump(SshLogin::Agent)]), ROUTE_DIFFERS);
        // A saved login for a hop only: the target is the saved one, the hop is not.
        refused(b.probe_at(true, Some(&conn), "127.0.0.1", port, Some(SshLogin::Agent), vec![jump(vault_login(credential))]), ROUTE_DIFFERS);
    }
    assert_eq!(b.tests_started(), 0, "nothing was dialled");

    // The same host in another spelling is the same host.
    reached_the_dial(b.probe_at(true, Some(&conn), "127.0.0.1.", port, Some(vault_login(&admin)), vec![]));
    // A typed password goes wherever the user typed.
    reached_the_dial(b.probe_at(true, Some(&conn), "127.0.0.1", attacker, Some(typed()), vec![]));
}

#[test]
fn a_saved_login_behind_a_gateway_needs_that_gateway_as_the_first_hop() {
    let b = bench();
    let lab = b.folder("Lab");
    let conn = b.local(&lab, "srv");
    let admin = b.password("admin");
    b.assign(&conn, &admin);
    let gw = b.gateway_for(&conn);

    refused(b.probe(true, Some(&conn), Some(vault_login(&admin)), vec![]), ROUTE_DIFFERS);
    refused(b.probe(true, Some(&conn), Some(vault_login(&admin)), vec![jump(vault_login(&admin))]), ROUTE_DIFFERS);
    refused(b.probe(true, Some(&conn), Some(vault_login(&admin)), vec![jump_to(gw, SshLogin::Agent), jump(SshLogin::Agent)]), ROUTE_DIFFERS);
    assert_eq!(b.tests_started(), 0);
    let report = b.probe(true, Some(&conn), Some(vault_login(&admin)), vec![jump_to(gw, vault_login(&admin))]).expect("the saved route");
    assert!(!report.ok && !report.steps.is_empty());
}
