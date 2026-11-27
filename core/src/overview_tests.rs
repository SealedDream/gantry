use super::*;
use crate::logins::{login_candidates, LoginPurpose, LoginSource};
use crate::model::{Connection, Document, Folder, Node, Protocol, INLINE_CREDENTIAL_KEY};
use crate::vault::{Credential, CredentialKind, Secret, Vault};

const SECRET: &str = "hunter2-do-not-show";

fn pw(v: &mut Vault, name: &str) -> Uuid {
    v.add(Credential { id: Uuid::new_v4(), name: name.into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: name.into(), password: Secret::new(SECRET) } })
}

fn key(v: &mut Vault, name: &str) -> Uuid {
    v.add(Credential { id: Uuid::new_v4(), name: name.into(), folder: None, scope: None, owner: None, kind: CredentialKind::SshKey { username: name.into(), private_key: Secret::new(SECRET), passphrase: None } })
}

fn folder(name: &str) -> Folder {
    Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Default::default(), children: Vec::new(), dynamic_task_id: None, extra: Default::default() }
}

fn add_folder(doc: &mut Document, parent: Option<Uuid>, name: &str) -> Uuid {
    let f = folder(name);
    let id = f.id;
    doc.insert(parent, Node::Folder(f)).unwrap();
    id
}

fn conn(doc: &mut Document, parent: Option<Uuid>, name: &str, p: Protocol, host: &str) -> Uuid {
    let c = Connection::new(name, p, host);
    let id = c.id;
    doc.insert(parent, Node::Connection(c)).unwrap();
    id
}

fn folder_mut(f: &mut Folder, id: Uuid) -> Option<&mut Folder> {
    if f.id == id {
        return Some(f);
    }
    f.children.iter_mut().find_map(|n| match n {
        Node::Folder(sub) => folder_mut(sub, id),
        Node::Connection(_) => None,
    })
}

fn connection_mut(f: &mut Folder, id: Uuid) -> Option<&mut Connection> {
    f.children.iter_mut().find_map(|n| match n {
        Node::Connection(c) if c.id == id => Some(c),
        Node::Folder(sub) => connection_mut(sub, id),
        Node::Connection(_) => None,
    })
}

/// Change a connection where it is.
fn edit(doc: &mut Document, id: Uuid, f: impl FnOnce(&mut Connection)) {
    f(connection_mut(&mut doc.root, id).expect("connection"));
}

fn no_history() -> BTreeMap<Uuid, History> {
    BTreeMap::new()
}

fn overview(doc: &Document, vault: Option<&Vault>, folder: Uuid, deep: bool) -> Vec<OverviewRow> {
    folder_overview(doc, vault, &no_history(), folder, deep).unwrap()
}

fn row(rows: &[OverviewRow], id: Uuid) -> &OverviewRow {
    rows.iter().find(|r| r.id == id).expect("row")
}

fn names(rows: &[OverviewRow]) -> Vec<&str> {
    rows.iter().map(|r| r.name.as_str()).collect()
}

#[test]
fn direct_mode_lists_child_connections_then_child_folders() {
    let mut doc = Document::new("t");
    let site = add_folder(&mut doc, None, "Site");
    let racks = add_folder(&mut doc, Some(site), "Racks");
    let web = conn(&mut doc, Some(site), "web", Protocol::Ssh, "web.lan");
    let nested = conn(&mut doc, Some(racks), "nested", Protocol::Ssh, "nested.lan");
    let db = conn(&mut doc, Some(site), "db", Protocol::Rdp, "db.lan");
    conn(&mut doc, None, "outside", Protocol::Ssh, "outside.lan");

    let rows = overview(&doc, None, site, false);

    assert_eq!(names(&rows), ["web", "db", "Racks"], "connections first, then folders; nothing nested or outside");
    assert!(rows.iter().all(|r| r.id != nested));
    assert_eq!((row(&rows, web).kind, row(&rows, db).kind), (RowKind::Connection, RowKind::Connection));
    let f = row(&rows, racks);
    assert_eq!((f.kind, f.protocol, f.type_label.as_str(), f.icon.id), (RowKind::Folder, None, "Folder", "folder"));
    assert_eq!((f.address.as_str(), &f.username, &f.login), ("", &None, &LoginState::None));
    assert!(rows.iter().all(|r| r.folder_path.is_empty()));
}

#[test]
fn subfolder_mode_lists_every_connection_below_in_tree_order_with_its_folder_path() {
    let mut doc = Document::new("t");
    let site = add_folder(&mut doc, None, "Site");
    conn(&mut doc, Some(site), "a", Protocol::Ssh, "a.lan");
    let racks = add_folder(&mut doc, Some(site), "Racks");
    conn(&mut doc, Some(racks), "b", Protocol::Ssh, "b.lan");
    let row3 = add_folder(&mut doc, Some(racks), "Row 3");
    conn(&mut doc, Some(row3), "c", Protocol::Vnc, "c.lan");
    conn(&mut doc, Some(site), "d", Protocol::Ssh, "d.lan");
    conn(&mut doc, None, "outside", Protocol::Ssh, "outside.lan");

    let rows = overview(&doc, None, site, true);

    assert_eq!(names(&rows), ["a", "b", "c", "d"]);
    assert!(rows.iter().all(|r| r.kind == RowKind::Connection), "no folder rows");
    let paths: Vec<Vec<String>> = rows.iter().map(|r| r.folder_path.clone()).collect();
    assert_eq!(paths, [vec![], vec!["Racks".to_string()], vec!["Racks".to_string(), "Row 3".to_string()], vec![]], "relative to the folder shown");
}

#[test]
fn the_library_root_has_an_overview_too() {
    let mut doc = Document::new("t");
    let site = add_folder(&mut doc, None, "Site");
    conn(&mut doc, Some(site), "inner", Protocol::Ssh, "inner.lan");
    conn(&mut doc, None, "top", Protocol::Ssh, "top.lan");
    let root = doc.root.id;
    assert_eq!(names(&overview(&doc, None, root, false)), ["top", "Site"]);
    assert_eq!(names(&overview(&doc, None, root, true)), ["inner", "top"]);
}

#[test]
fn an_unknown_folder_id_is_an_error_and_so_is_a_connection_id() {
    let mut doc = Document::new("t");
    let c = conn(&mut doc, None, "c", Protocol::Ssh, "c.lan");
    for id in [Uuid::new_v4(), c] {
        let got = folder_overview(&doc, None, &no_history(), id, false);
        assert!(matches!(got, Err(CoreError::NotFound(_))), "{got:?}");
    }
}

#[test]
fn address_hides_the_default_port_and_shows_any_other() {
    let mut doc = Document::new("t");
    let plain = conn(&mut doc, None, "plain", Protocol::Ssh, "plain.lan");
    let explicit_default = conn(&mut doc, None, "explicit", Protocol::Ssh, "explicit.lan");
    let other = conn(&mut doc, None, "other", Protocol::Ssh, "other.lan");
    let v6 = conn(&mut doc, None, "v6", Protocol::Rdp, "fd00::7");
    let url = conn(&mut doc, None, "url", Protocol::Web, "https://intranet.lan:8443/app");
    let local = conn(&mut doc, None, "shell", Protocol::Local, "");
    let f = add_folder(&mut doc, None, "Odd port");
    let inherits = conn(&mut doc, Some(f), "inherits", Protocol::Ssh, "inherits.lan");
    folder_mut(&mut doc.root, f).unwrap().defaults.port = Some(2200);
    edit(&mut doc, explicit_default, |c| c.settings.port = Some(22));
    edit(&mut doc, other, |c| c.settings.port = Some(2222));
    edit(&mut doc, v6, |c| c.settings.port = Some(3390));
    let root = doc.root.id;

    let rows = overview(&doc, None, root, true);

    let address = |id| row(&rows, id).address.as_str();
    assert_eq!(address(plain), "plain.lan");
    assert_eq!(address(explicit_default), "explicit.lan");
    assert_eq!(address(other), "other.lan:2222");
    assert_eq!(address(v6), "[fd00::7]:3390");
    assert_eq!(address(url), "https://intranet.lan:8443/app");
    assert_eq!(address(local), "");
    assert_eq!(address(inherits), "inherits.lan:2200", "a port inherited from the folder counts");
}

#[test]
fn rows_carry_type_user_tags_favourite_colour_and_icon() {
    let mut doc = Document::new("t");
    let f = add_folder(&mut doc, None, "Prod");
    {
        let d = &mut folder_mut(&mut doc.root, f).unwrap().defaults;
        d.username = Some("ops".into());
        d.host_color = Some("#ABC".into());
    }
    doc.type_defaults.entry(Protocol::Rdp).or_default().username = Some("Administrator".into());
    let mut own = Connection::new("own", Protocol::Ssh, "own.lan");
    own.settings.username = Some("root".into());
    own.settings.host_color = Some("not a colour".into());
    own.tags = vec!["db".into(), "eu".into()];
    own.favorite = true;
    let own_id = own.id;
    doc.insert(Some(f), Node::Connection(own)).unwrap();
    let inherits = conn(&mut doc, Some(f), "inherits", Protocol::Ssh, "inherits.lan");
    let rdp = conn(&mut doc, None, "rdp", Protocol::Rdp, "rdp.lan");
    let vnc = conn(&mut doc, None, "vnc", Protocol::Vnc, "vnc.lan");
    let root = doc.root.id;

    let rows = overview(&doc, None, root, true);

    let o = row(&rows, own_id);
    assert_eq!((o.protocol, o.type_label.as_str(), o.icon.id), (Some(Protocol::Ssh), "SSH Terminal", "ssh"));
    assert_eq!((o.username.as_deref(), o.favorite, o.tags.as_slice()), (Some("root"), true, &["db".to_string(), "eu".to_string()][..]));
    assert_eq!(o.host_color, None, "a stored value that is not a colour counts as unset");
    let i = row(&rows, inherits);
    assert_eq!((i.username.as_deref(), i.host_color.as_deref(), i.favorite), (Some("ops"), Some("#aabbcc"), false));
    assert_eq!(row(&rows, rdp).username.as_deref(), Some("Administrator"), "type default");
    assert_eq!((row(&rows, vnc).username.as_deref(), row(&rows, vnc).icon.id), (None, "vnc"));
}

#[test]
fn the_four_login_states() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let team = add_folder(&mut doc, None, "Team");
    let shared = add_folder(&mut doc, Some(team), "Shared login");
    let (admin, team_login, other) = (pw(&mut v, "admin"), pw(&mut v, "team"), pw(&mut v, "other"));
    folder_mut(&mut doc.root, shared).unwrap().defaults.credential_id = Some(team_login);

    let saved = conn(&mut doc, Some(team), "saved", Protocol::Ssh, "box.lan");
    let other_login = conn(&mut doc, Some(team), "other login", Protocol::Ssh, "second.lan");
    let named = conn(&mut doc, Some(team), "named", Protocol::Ssh, "third.lan");
    let inherited = conn(&mut doc, Some(shared), "inherited", Protocol::Ssh, "fourth.lan");
    let offered = conn(&mut doc, Some(team), "offered", Protocol::Rdp, "BOX.lan.");
    let none = conn(&mut doc, Some(team), "none", Protocol::Ssh, "lonely.lan");
    doc.set_credential(saved, Some(admin)).unwrap();
    edit(&mut doc, other_login, |c| c.settings.logins = vec![other]);
    edit(&mut doc, named, |c| c.settings.credential_name = Some("ADMIN".into()));

    let rows = overview(&doc, Some(&v), team, true);

    let login = |id| row(&rows, id).login.clone();
    assert_eq!(login(saved), LoginState::Saved);
    assert_eq!(login(other_login), LoginState::Saved);
    assert_eq!(login(named), LoginState::Saved);
    assert_eq!(login(inherited), LoginState::Inherited { from: "Shared login".into() });
    assert_eq!(login(offered), LoginState::Offered { from: "saved".into() });
    assert_eq!(login(none), LoginState::None);
}

#[test]
fn a_login_inherited_from_the_root_or_the_type_names_where_it_comes_from() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let everyone = pw(&mut v, "everyone");
    let rdp_default = pw(&mut v, "rdp default");
    doc.root.defaults.credential_id = Some(everyone);
    let ssh = conn(&mut doc, None, "ssh", Protocol::Ssh, "a.lan");
    let root = doc.root.id;
    for vault in [Some(&v), None] {
        assert_eq!(row(&overview(&doc, vault, root, false), ssh).login, LoginState::Inherited { from: "Library".into() });
    }
    doc.root.defaults.credential_id = None;
    doc.type_defaults.entry(Protocol::Rdp).or_default().credential_id = Some(rdp_default);
    let rdp = conn(&mut doc, None, "rdp", Protocol::Rdp, "b.lan");
    for vault in [Some(&v), None] {
        assert_eq!(row(&overview(&doc, vault, root, false), rdp).login, LoginState::Inherited { from: "rdp default".into() });
    }
}

#[test]
fn rdp_does_not_count_an_ssh_key_as_a_saved_login() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let k = key(&mut v, "deploy key");
    let rdp = conn(&mut doc, None, "rdp", Protocol::Rdp, "a.lan");
    let ssh = conn(&mut doc, None, "ssh", Protocol::Ssh, "b.lan");
    doc.set_credential(rdp, Some(k)).unwrap();
    doc.set_credential(ssh, Some(k)).unwrap();
    let rows = overview(&doc, Some(&v), doc.root.id, false);
    assert_eq!((&row(&rows, rdp).login, &row(&rows, ssh).login), (&LoginState::None, &LoginState::Saved));
}

#[test]
fn a_credential_that_left_the_vault_is_not_a_saved_login() {
    let (mut doc, v) = (Document::new("t"), Vault::default());
    let c = conn(&mut doc, None, "c", Protocol::Ssh, "a.lan");
    doc.set_credential(c, Some(Uuid::new_v4())).unwrap();
    assert_eq!(row(&overview(&doc, Some(&v), doc.root.id, false), c).login, LoginState::None);
}

#[test]
fn with_credentials_locked_the_state_comes_from_the_document_alone() {
    let mut doc = Document::new("t");
    let team = add_folder(&mut doc, None, "Team");
    folder_mut(&mut doc.root, team).unwrap().defaults.credential_name = Some("team login".into());
    let own = conn(&mut doc, Some(team), "own", Protocol::Ssh, "box.lan");
    let inherits = conn(&mut doc, Some(team), "inherits", Protocol::Rdp, "box.lan");
    let extra = conn(&mut doc, None, "extra login only", Protocol::Ssh, "c.lan");
    let nothing = conn(&mut doc, None, "nothing", Protocol::Rdp, "box.lan");
    doc.set_credential(own, Some(Uuid::new_v4())).unwrap();
    edit(&mut doc, extra, |c| c.settings.logins = vec![Uuid::new_v4()]);

    let rows = overview(&doc, None, doc.root.id, true);

    assert_eq!(row(&rows, own).login, LoginState::Saved);
    assert_eq!(row(&rows, inherits).login, LoginState::Inherited { from: "Team".into() });
    assert_eq!(row(&rows, extra).login, LoginState::Saved);
    assert_eq!(row(&rows, nothing).login, LoginState::None, "nothing is offered from another connection while locked");
}

#[test]
fn an_inline_secret_reads_as_saved_and_no_secret_is_in_any_row() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let inline = conn(&mut doc, None, "inline", Protocol::Ssh, "a.lan");
    let saved = conn(&mut doc, None, "saved", Protocol::Ssh, "b.lan");
    v.set_inline(inline, CredentialKind::Password { username: "root".into(), password: Secret::new(SECRET) });
    doc.set_metadata(inline, INLINE_CREDENTIAL_KEY, Some("password".into())).unwrap();
    let p = pw(&mut v, "admin");
    doc.set_credential(saved, Some(p)).unwrap();
    let root = doc.root.id;

    for vault in [Some(&v), None] {
        let rows = overview(&doc, vault, root, false);
        assert_eq!(row(&rows, inline).login, LoginState::Saved);
        let shown = format!("{rows:?}");
        assert!(!shown.contains(SECRET), "a secret reached a row");
        assert!(!shown.contains(&p.to_string()), "a credential id reached a row");
    }
}

#[test]
fn rows_carry_the_last_connect_and_the_last_result() {
    let mut doc = Document::new("t");
    let ok = conn(&mut doc, None, "ok", Protocol::Ssh, "a.lan");
    let failed = conn(&mut doc, None, "failed", Protocol::Ssh, "b.lan");
    let never = conn(&mut doc, None, "never", Protocol::Ssh, "c.lan");
    let history: BTreeMap<Uuid, History> = [
        (ok, History { last_connected_at: Some(1_700_000_000), last_user: Some("root".into()), last_attempt_at: Some(1_700_000_000), last_error: None }),
        (failed, History { last_connected_at: Some(1_600_000_000), last_user: None, last_attempt_at: Some(1_700_000_500), last_error: Some("Timed out".into()) }),
    ]
    .into();

    let rows = folder_overview(&doc, None, &history, doc.root.id, false).unwrap();

    let seen = |id| (row(&rows, id).last_connected_at, row(&rows, id).last_result.clone());
    assert_eq!(seen(ok), (Some(1_700_000_000), Some("OK".into())));
    assert_eq!(seen(failed), (Some(1_600_000_000), Some("Timed out".into())));
    assert_eq!(seen(never), (None, None));
}

#[test]
fn an_entry_of_an_unknown_type_is_listed_but_offers_nothing() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let mut odd = Connection::new("odd", Protocol::Unsupported, "odd.lan");
    odd.unknown_protocol = Some("acme/console".into());
    odd.settings.credential_id = Some(pw(&mut v, "admin"));
    let odd_id = odd.id;
    doc.insert(None, Node::Connection(odd)).unwrap();
    let root = doc.root.id;

    for vault in [Some(&v), None] {
        let rows = overview(&doc, vault, root, false);
        let r = row(&rows, odd_id);
        assert_eq!((r.protocol, r.type_label.as_str(), &r.login), (None, "acme/console", &LoginState::None));
        assert_eq!(r.icon.label, crate::unknown::NEEDS_NEWER);
    }
}

/// A library with every case the login rules know: scopes, boundaries, gateways, jump hosts,
/// this computer, shared hosts, named and missing credentials.
fn varied_library() -> (Document, Vault) {
    let (mut doc, mut v) = (Document::new("varied"), Vault::default());
    let creds: Vec<Uuid> = (0..6).map(|i| pw(&mut v, &format!("cred-{i}"))).collect();
    let ssh_key = key(&mut v, "key");
    let gateway = Uuid::new_v4();
    doc.type_defaults.entry(Protocol::Vnc).or_default().credential_name = Some("cred-5".into());
    doc.type_defaults.entry(Protocol::Telnet).or_default().username = Some("telnet-user".into());
    let hosts = ["shared.lan", "Shared.LAN.", "127.0.0.1", "localhost", "", "[fd00::1]", "fd00::1", "solo"];
    let protocols = [Protocol::Ssh, Protocol::Rdp, Protocol::Vnc, Protocol::Telnet, Protocol::Local, Protocol::Web];
    let mut n = 0usize;
    let mut fill = |f: &mut Folder, count: usize| {
        for _ in 0..count {
            let host = if n % 5 == 4 { format!("host-{n}.lan") } else { hosts[n % hosts.len()].to_string() };
            let mut c = Connection::new(format!("c{n}"), protocols[n % protocols.len()], host);
            match n % 7 {
                0 => c.settings.credential_id = Some(creds[n % 5]),
                1 => c.settings.logins = vec![creds[(n + 1) % 5], ssh_key],
                2 => c.settings.credential_name = Some(if n % 2 == 0 { "CRED-2" } else { "nobody" }.into()),
                3 => c.settings.credential_id = Some(if n % 2 == 0 { ssh_key } else { Uuid::new_v4() }),
                _ => {}
            }
            if n % 11 == 0 {
                c.settings.gateway_id = Some(gateway);
            }
            if n % 13 == 0 {
                c.metadata.insert("ProxyJump".into(), "jump.lan".into());
            }
            if n % 9 == 0 {
                c.settings.port = Some(2000 + n as u16);
            }
            if n % 4 == 0 {
                c.settings.username = Some(format!("user{n}"));
            }
            f.children.push(Node::Connection(c));
            n += 1;
        }
    };
    fill(&mut doc.root, 9);
    for t in 0..4 {
        let mut top = folder(&format!("Top {t}"));
        top.defaults.username = (t % 2 == 0).then(|| format!("top{t}"));
        top.defaults.credential_id = (t == 1).then_some(creds[3]);
        top.defaults.credential_name = (t == 2).then(|| "cred-4".to_string());
        top.defaults.gateway_id = (t == 3).then_some(gateway);
        fill(&mut top, 17);
        let mut sub = folder("Sub");
        sub.defaults.credential_boundary = (t % 2 == 1).then_some(true);
        sub.defaults.port = Some(2222);
        fill(&mut sub, 17);
        let mut deep = folder("Deep");
        deep.defaults.credential_id = (t == 0).then_some(creds[0]);
        fill(&mut deep, 11);
        sub.children.push(Node::Folder(deep));
        fill(&mut sub, 5);
        top.children.push(Node::Folder(sub));
        fill(&mut top, 5);
        doc.root.children.push(Node::Folder(top));
    }
    (doc, v)
}

fn all_folder_ids(f: &Folder, out: &mut Vec<Uuid>) {
    out.push(f.id);
    for n in &f.children {
        if let Node::Folder(sub) = n {
            all_folder_ids(sub, out);
        }
    }
}

/// The overview works the login out on a cut-down copy of the library, one per host. Whatever
/// folder is shown, it must say what `login_candidates` says on the whole library.
#[test]
fn login_state_is_what_login_candidates_says_first_on_the_whole_library() {
    let (doc, v) = varied_library();
    let mut folders = Vec::new();
    all_folder_ids(&doc.root, &mut folders);
    let mut seen = std::collections::BTreeSet::new();
    let mut checked = 0;
    for f in folders {
        for r in overview(&doc, Some(&v), f, true) {
            let purpose = if r.protocol == Some(Protocol::Rdp) { LoginPurpose::Password } else { LoginPurpose::Any };
            let want = match login_candidates(&doc, &v, r.id, purpose).unwrap().into_iter().next().map(|c| c.source) {
                None => LoginState::None,
                Some(LoginSource::Default | LoginSource::Connection | LoginSource::Named) => LoginState::Saved,
                Some(LoginSource::Inherited { folder, name }) => LoginState::Inherited { from: if folder == Some(doc.root.id) { "Library".into() } else { name } },
                Some(LoginSource::SameHost { name, .. }) => LoginState::Offered { from: name },
            };
            assert_eq!(r.login, want, "{} ({})", r.name, r.address);
            seen.insert(match r.login {
                LoginState::None => 0,
                LoginState::Saved => 1,
                LoginState::Inherited { .. } => 2,
                LoginState::Offered { .. } => 3,
            });
            checked += 1;
        }
    }
    assert_eq!(seen.len(), 4, "the library must exercise all four states");
    assert!(checked > 300, "{checked}");
}

/// The overview resolves user and port in its own single pass; `Document::resolve` is the rule.
#[test]
fn user_and_address_are_what_resolving_the_connection_gives() {
    let (doc, _) = varied_library();
    let rows = overview(&doc, None, doc.root.id, true);
    assert_eq!(rows.len(), doc.connections().len());
    for (r, want) in rows.iter().zip(doc.connections()) {
        assert_eq!(r.id, want.connection.id, "tree order");
        assert_eq!(r.username, want.effective.username.clone().filter(|u| !u.is_empty()), "{}", r.name);
        let c = &want.connection;
        assert_eq!(r.address, crate::actions::address(&c.host, want.effective.port, c.protocol.default_port()), "{}", r.name);
        assert_eq!(r.folder_path, want.path, "{}", r.name);
    }
}

/// Timed, not run by default:
/// `cargo test --release --lib overview -- --ignored --nocapture` on a quiet Mac.
/// 5,000 connections in 50 customers, every one with a login to work out (own, inherited or
/// offered from a shared host), credentials unlocked and locked.
#[test]
#[ignore = "timed: run on a quiet Mac with --release --ignored --nocapture"]
fn overview_of_5000_rows_takes_under_20_ms() {
    const CONNECTIONS: usize = 5_000;
    const FOLDERS: usize = 50;
    const RUNS: u32 = 20;
    const BUDGET: std::time::Duration = std::time::Duration::from_millis(20);
    let (mut doc, mut v) = (Document::new("big"), Vault::default());
    let creds: Vec<Uuid> = (0..200).map(|i| pw(&mut v, &format!("cred-{i}"))).collect();
    let mut history = BTreeMap::new();
    for f in 0..FOLDERS {
        let mut top = folder(&format!("Customer {f}"));
        let mut sub = folder("Servers");
        sub.defaults.credential_id = Some(creds[f]);
        for i in 0..CONNECTIONS / FOLDERS {
            let n = f * (CONNECTIONS / FOLDERS) + i;
            let host = if i % 10 == 0 { format!("shared-{f}.example") } else { format!("host-{n}.example") };
            let mut c = Connection::new(format!("c{n}"), if n % 2 == 0 { Protocol::Ssh } else { Protocol::Rdp }, host);
            c.tags = vec!["prod".into()];
            if i % 3 == 0 {
                c.settings.credential_id = Some(creds[n % creds.len()]);
            }
            history.insert(c.id, History { last_connected_at: Some(n as u64), last_user: None, last_attempt_at: Some(n as u64), last_error: None });
            let into = if i % 2 == 0 { &mut top } else { &mut sub };
            into.children.push(Node::Connection(c));
        }
        top.children.push(Node::Folder(sub));
        doc.root.children.push(Node::Folder(top));
    }
    let root = doc.root.id;
    for (label, vault) in [("unlocked", Some(&v)), ("locked", None)] {
        let mut times: Vec<std::time::Duration> = (0..RUNS)
            .map(|_| {
                let started = std::time::Instant::now();
                let rows = folder_overview(&doc, vault, &history, root, true).unwrap();
                let took = started.elapsed();
                assert_eq!(rows.len(), CONNECTIONS);
                took
            })
            .collect();
        times.sort();
        let (median, worst) = (times[times.len() / 2], times[times.len() - 1]);
        println!("folder_overview: {CONNECTIONS} rows, credentials {label}: median {median:?}, worst {worst:?} of {RUNS} runs");
        assert!(median < BUDGET, "{label}: median {median:?}");
    }
}
