use super::*;
use crate::model::{Connection, Document, Folder, Node, Protocol};
use crate::vault::{Credential, CredentialKind, Secret, Vault};

fn pw(v: &mut Vault, name: &str) -> Uuid {
    v.add(Credential { id: Uuid::new_v4(), name: name.into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: name.into(), password: Secret::new("x") } })
}

fn key(v: &mut Vault, name: &str) -> Uuid {
    v.add(Credential { id: Uuid::new_v4(), name: name.into(), folder: None, scope: None, owner: None, kind: CredentialKind::SshKey { username: name.into(), private_key: Secret::new("k"), passphrase: None } })
}

fn conn(doc: &mut Document, parent: Option<Uuid>, name: &str, p: Protocol, host: &str) -> Uuid {
    let c = Connection::new(name, p, host);
    let id = c.id;
    doc.insert(parent, Node::Connection(c)).unwrap();
    id
}

fn folder(name: &str) -> Folder {
    Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Default::default(), children: Vec::new(), dynamic_task_id: None, extra: Default::default() }
}

fn ids(doc: &Document, v: &Vault, c: Uuid, p: LoginPurpose) -> Vec<Uuid> {
    login_candidates(doc, v, c, p).unwrap().into_iter().map(|c| c.credential).collect()
}

#[test]
fn ssh_password_is_offered_to_rdp_on_the_same_host_whatever_the_case_or_port() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let ssh = conn(&mut doc, None, "K8s SSH", Protocol::Ssh, "Host-A.lan.");
    let rdp = conn(&mut doc, None, "K8s RDP", Protocol::Rdp, "host-a.lan");
    let other = conn(&mut doc, None, "Other", Protocol::Rdp, "host-b.lan");
    let p = pw(&mut v, "admin");
    doc.set_credential(ssh, Some(p)).unwrap();
    let got = login_candidates(&doc, &v, rdp, LoginPurpose::Password).unwrap();
    assert_eq!(got, vec![LoginCandidate { credential: p, source: LoginSource::SameHost { connection: ssh, name: "K8s SSH".into() }, auto_use: false }]);
    assert!(ids(&doc, &v, other, LoginPurpose::Any).is_empty());
}

#[test]
fn rdp_drops_ssh_keys_but_ssh_and_system_views_keep_them() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let ssh = conn(&mut doc, None, "a", Protocol::Ssh, "10.0.0.1");
    let rdp = conn(&mut doc, None, "b", Protocol::Rdp, "10.0.0.1");
    let k = key(&mut v, "k");
    doc.set_credential(ssh, Some(k)).unwrap();
    assert!(ids(&doc, &v, rdp, LoginPurpose::Password).is_empty());
    assert_eq!(ids(&doc, &v, rdp, LoginPurpose::Any), vec![k]);
}

#[test]
fn own_default_then_others_then_folder_then_same_host_without_duplicates() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let folder = folder("Lab");
    let fid = folder.id;
    doc.insert(None, Node::Folder(folder)).unwrap();
    let me = conn(&mut doc, Some(fid), "me", Protocol::Ssh, "h");
    let peer = conn(&mut doc, Some(fid), "peer", Protocol::Rdp, "h");
    let (a, b, f, s) = (pw(&mut v, "a"), pw(&mut v, "b"), pw(&mut v, "f"), pw(&mut v, "s"));
    crate::credtree::assign_credential(&mut doc, &v, fid, Some(f)).unwrap();
    // No own login: the folder's is inherited.
    assert_eq!(login_candidates(&doc, &v, me, LoginPurpose::Any).unwrap()[0].source, LoginSource::Inherited { folder: Some(fid), name: "Lab".into() });
    add_login(&mut doc, &v, me, a).unwrap();
    add_login(&mut doc, &v, me, b).unwrap();
    add_login(&mut doc, &v, peer, s).unwrap();
    add_login(&mut doc, &v, peer, a).unwrap();
    // The connection's own logins override the folder; the peer's adds `s` (a is not repeated).
    assert_eq!(ids(&doc, &v, me, LoginPurpose::Any), vec![a, b, s]);
    let got = login_candidates(&doc, &v, me, LoginPurpose::Any).unwrap();
    assert_eq!(got.iter().map(|c| c.auto_use).collect::<Vec<_>>(), vec![true, true, false]);
    assert!(!got.iter().any(|c| c.credential == f), "a connection default hides the inherited login");
}

#[test]
fn folder_credential_is_inherited_by_children_and_nearest_folder_wins() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let outer = folder("Outer");
    let oid = outer.id;
    doc.insert(None, Node::Folder(outer)).unwrap();
    let inner = folder("Inner");
    let iid = inner.id;
    doc.insert(Some(oid), Node::Folder(inner)).unwrap();
    let c = conn(&mut doc, Some(iid), "c", Protocol::Ssh, "");
    let (o, i) = (pw(&mut v, "o"), pw(&mut v, "i"));
    crate::credtree::assign_credential(&mut doc, &v, oid, Some(o)).unwrap();
    assert_eq!(ids(&doc, &v, c, LoginPurpose::Any), vec![o]);
    crate::credtree::assign_credential(&mut doc, &v, iid, Some(i)).unwrap();
    assert_eq!(ids(&doc, &v, c, LoginPurpose::Any), vec![i]);
}

#[test]
fn type_default_is_inherited_last() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let c = conn(&mut doc, None, "c", Protocol::Rdp, "x");
    let t = pw(&mut v, "t");
    doc.type_defaults.entry(Protocol::Rdp).or_default().credential_id = Some(t);
    assert_eq!(ids(&doc, &v, c, LoginPurpose::Password), vec![t]);
}

#[test]
fn missing_and_inline_credentials_are_skipped() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let a = conn(&mut doc, None, "a", Protocol::Ssh, "h");
    let b = conn(&mut doc, None, "b", Protocol::Rdp, "h");
    doc.set_credential(a, Some(Uuid::new_v4())).unwrap();
    v.set_inline(a, CredentialKind::Password { username: "u".into(), password: Secret::new("p") });
    assert!(ids(&doc, &v, b, LoginPurpose::Any).is_empty());
}

#[test]
fn add_remove_and_default_keep_one_ordered_list() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let c = conn(&mut doc, None, "c", Protocol::Ssh, "h");
    let (a, b, d) = (pw(&mut v, "a"), pw(&mut v, "b"), pw(&mut v, "d"));
    add_login(&mut doc, &v, c, a).unwrap();
    add_login(&mut doc, &v, c, b).unwrap();
    add_login(&mut doc, &v, c, d).unwrap();
    add_login(&mut doc, &v, c, b).unwrap(); // already there
    assert_eq!(ids(&doc, &v, c, LoginPurpose::Any), vec![a, b, d]);
    set_default_login(&mut doc, &v, c, d).unwrap();
    assert_eq!(ids(&doc, &v, c, LoginPurpose::Any), vec![d, b, a]);
    assert!(remove_login(&mut doc, c, d).unwrap());
    assert_eq!(ids(&doc, &v, c, LoginPurpose::Any), vec![b, a]);
    assert!(!remove_login(&mut doc, c, d).unwrap());
    assert!(add_login(&mut doc, &v, c, Uuid::new_v4()).is_err());
}

#[test]
fn deleting_a_credential_drops_it_from_every_login_list() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let c = conn(&mut doc, None, "c", Protocol::Ssh, "h");
    let (a, b) = (pw(&mut v, "a"), pw(&mut v, "b"));
    add_login(&mut doc, &v, c, a).unwrap();
    add_login(&mut doc, &v, c, b).unwrap();
    assert_eq!(crate::credtree::credential_usages(&doc, b).len(), 1);
    crate::credtree::clear_credential_references(&mut doc, a);
    assert_eq!(ids(&doc, &v, c, LoginPurpose::Any), vec![b]);
    assert!(doc.resolve(c).unwrap().connection.settings.logins.is_empty());
}

#[test]
fn may_use_refuses_credentials_outside_the_list() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let c = conn(&mut doc, None, "c", Protocol::Rdp, "h");
    let (a, stranger) = (pw(&mut v, "a"), pw(&mut v, "z"));
    add_login(&mut doc, &v, c, a).unwrap();
    assert!(may_use(&doc, &v, c, a, LoginPurpose::Password).unwrap());
    assert!(!may_use(&doc, &v, c, stranger, LoginPurpose::Password).unwrap());
}

#[test]
fn normalize_host_rules() {
    assert_eq!(normalize_host(" [FE80::1] "), "fe80::1");
    assert_eq!(normalize_host("Web.Example.com."), "web.example.com");
}

#[test]
fn logins_round_trip_and_old_files_load() {
    let mut s = crate::model::Settings::default();
    assert!(!serde_json::to_string(&s).unwrap().contains("logins"));
    s.logins.push(Uuid::nil());
    let back: crate::model::Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(back.logins, vec![Uuid::nil()]);
}

// --- A1-CORE-01: login scope and identity (audit/fable-review/A1_CREDENTIAL_DESIGN.md) ---------

fn add_folder(doc: &mut Document, parent: Option<Uuid>, name: &str) -> Uuid {
    let f = folder(name);
    let id = f.id;
    doc.insert(parent, Node::Folder(f)).unwrap();
    id
}

fn folder_mut(f: &mut Folder, id: Uuid) -> Option<&mut Folder> {
    if f.id == id {
        return Some(f);
    }
    f.children.iter_mut().find_map(|n| match n {
        Node::Folder(sub) => folder_mut(sub, id),
        _ => None,
    })
}

fn set_folder(doc: &mut Document, id: Uuid, edit: impl FnOnce(&mut crate::model::Settings)) {
    edit(&mut folder_mut(&mut doc.root, id).unwrap().defaults);
}

fn edit_conn(doc: &mut Document, id: Uuid, edit: impl FnOnce(&mut Connection)) {
    with_connection(doc, id, edit).unwrap();
}

fn gateway(doc: &mut Document, name: &str) -> Uuid {
    crate::gateway::add(doc, &crate::gateway::GatewayInput { name: name.into(), host: format!("{name}.gw.example"), ..Default::default() }).unwrap()
}

fn sources(doc: &Document, v: &Vault, c: Uuid) -> Vec<(Uuid, LoginSource, bool)> {
    login_candidates(doc, v, c, LoginPurpose::Any).unwrap().into_iter().map(|c| (c.credential, c.source, c.auto_use)).collect()
}

/// `credential` is neither listed for `c` nor released to it.
fn refused(doc: &Document, v: &Vault, c: Uuid, credential: Uuid) {
    assert!(!ids(doc, v, c, LoginPurpose::Any).contains(&credential), "must not be offered");
    assert!(!may_use(doc, v, c, credential, LoginPurpose::Any).unwrap(), "must not be released");
    assert!(!may_use(doc, v, c, credential, LoginPurpose::Password).unwrap(), "must not be released as a password");
}

#[test]
fn same_host_on_ports_22_and_3389_in_one_top_level_folder_is_offered_and_never_auto_used() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let lab = add_folder(&mut doc, None, "Lab");
    let ssh = conn(&mut doc, Some(lab), "srv ssh", Protocol::Ssh, "srv.lab.example");
    let rdp = conn(&mut doc, Some(lab), "srv rdp", Protocol::Rdp, "srv.lab.example");
    edit_conn(&mut doc, ssh, |c| c.settings.port = Some(22));
    edit_conn(&mut doc, rdp, |c| c.settings.port = Some(3389));
    let p = pw(&mut v, "admin");
    add_login(&mut doc, &v, ssh, p).unwrap();
    assert_eq!(sources(&doc, &v, ssh), vec![(p, LoginSource::Default, true)]);
    assert_eq!(sources(&doc, &v, rdp), vec![(p, LoginSource::SameHost { connection: ssh, name: "srv ssh".into() }, false)]);
    assert!(may_use(&doc, &v, rdp, p, LoginPurpose::Password).unwrap(), "an offered login may be released once the user confirms it");
}

#[test]
fn loopback_hosts_never_share_a_login() {
    for host in ["127.0.0.1", "localhost", "::1", "[::1]", "LOCALHOST.", "127.8.9.10", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "127.1", "0x7f.0.0.1", "2130706433", "dev.localhost", "::1%lo0", "0.0.0.0", "::"] {
        let (mut doc, mut v) = (Document::new("t"), Vault::default());
        let lab = add_folder(&mut doc, None, "Lab");
        let a = conn(&mut doc, Some(lab), "forward 2222", Protocol::Ssh, host);
        let b = conn(&mut doc, Some(lab), "forward 2223", Protocol::Ssh, host);
        edit_conn(&mut doc, a, |c| c.settings.port = Some(2222));
        edit_conn(&mut doc, b, |c| c.settings.port = Some(2223));
        let p = pw(&mut v, "root");
        add_login(&mut doc, &v, a, p).unwrap();
        assert_eq!(ids(&doc, &v, a, LoginPurpose::Any), vec![p], "{host}: its own login stays");
        assert!(sources(&doc, &v, b).is_empty(), "{host}");
        refused(&doc, &v, b, p);
    }
}

#[test]
fn addresses_that_only_look_like_loopback_still_share() {
    for host in ["10.0.0.5", "128.0.0.1", "localhost.example.com", "1.127.0.0", "fe80::1"] {
        let (mut doc, mut v) = (Document::new("t"), Vault::default());
        let a = conn(&mut doc, None, "a", Protocol::Ssh, host);
        let b = conn(&mut doc, None, "b", Protocol::Rdp, host);
        let p = pw(&mut v, "root");
        add_login(&mut doc, &v, a, p).unwrap();
        assert_eq!(ids(&doc, &v, b, LoginPurpose::Any), vec![p], "{host}");
    }
}

#[test]
fn the_same_host_under_two_top_level_folders_does_not_share() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let (acme, globex) = (add_folder(&mut doc, None, "Acme"), add_folder(&mut doc, None, "Globex"));
    let deep = add_folder(&mut doc, Some(globex), "Site 2");
    let a = conn(&mut doc, Some(acme), "acme db", Protocol::Ssh, "10.0.0.5");
    let g = conn(&mut doc, Some(globex), "globex db", Protocol::Ssh, "10.0.0.5");
    let g2 = conn(&mut doc, Some(deep), "globex db rdp", Protocol::Rdp, "10.0.0.5");
    let top = conn(&mut doc, None, "loose", Protocol::Ssh, "10.0.0.5");
    let top2 = conn(&mut doc, None, "loose rdp", Protocol::Rdp, "10.0.0.5");
    let (pa, pg, pt) = (pw(&mut v, "acme"), pw(&mut v, "globex"), pw(&mut v, "loose"));
    add_login(&mut doc, &v, a, pa).unwrap();
    add_login(&mut doc, &v, g, pg).unwrap();
    add_login(&mut doc, &v, top, pt).unwrap();
    assert_eq!(ids(&doc, &v, a, LoginPurpose::Any), vec![pa]);
    assert_eq!(ids(&doc, &v, g, LoginPurpose::Any), vec![pg]);
    // Inside one top-level folder, at any depth, the login is offered.
    assert_eq!(sources(&doc, &v, g2), vec![(pg, LoginSource::SameHost { connection: g, name: "globex db".into() }, false)]);
    // A connection directly under the root matches only other root-level connections.
    assert_eq!(ids(&doc, &v, top, LoginPurpose::Any), vec![pt]);
    assert_eq!(ids(&doc, &v, top2, LoginPurpose::Any), vec![pt]);
    for (c, creds) in [(a, [pg, pt]), (g, [pa, pt]), (g2, [pa, pt]), (top, [pa, pg]), (top2, [pa, pg])] {
        for cred in creds {
            refused(&doc, &v, c, cred);
        }
    }
}

#[test]
fn a_folder_marked_as_a_credential_boundary_does_not_share_with_its_sibling_or_its_parent() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let top = add_folder(&mut doc, None, "Customers");
    let (fenced, sibling) = (add_folder(&mut doc, Some(top), "Fenced"), add_folder(&mut doc, Some(top), "Sibling"));
    let below = add_folder(&mut doc, Some(fenced), "Below");
    set_folder(&mut doc, fenced, |s| s.credential_boundary = Some(true));
    let x = conn(&mut doc, Some(fenced), "x", Protocol::Ssh, "h.example");
    let x2 = conn(&mut doc, Some(below), "x2", Protocol::Rdp, "h.example");
    let y = conn(&mut doc, Some(sibling), "y", Protocol::Ssh, "h.example");
    let z = conn(&mut doc, Some(top), "z", Protocol::Rdp, "h.example");
    let (px, py) = (pw(&mut v, "x"), pw(&mut v, "y"));
    add_login(&mut doc, &v, x, px).unwrap();
    add_login(&mut doc, &v, y, py).unwrap();
    assert_eq!(ids(&doc, &v, x2, LoginPurpose::Any), vec![px], "shared inside the boundary");
    assert_eq!(ids(&doc, &v, z, LoginPurpose::Any), vec![py], "the sibling and the parent share one scope");
    for c in [y, z] {
        refused(&doc, &v, c, px);
    }
    for c in [x, x2] {
        refused(&doc, &v, c, py);
    }
    // `false` is the same as unset: the folder is not a boundary, and the top-level rule holds.
    set_folder(&mut doc, fenced, |s| s.credential_boundary = Some(false));
    assert_eq!(ids(&doc, &v, z, LoginPurpose::Any), vec![px, py]);
}

#[test]
fn the_same_host_through_a_different_gateway_or_jump_host_does_not_share() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let (g1, g2) = (gateway(&mut doc, "one"), gateway(&mut doc, "two"));
    let lab = add_folder(&mut doc, None, "Lab");
    let via = add_folder(&mut doc, Some(lab), "Via one");
    set_folder(&mut doc, via, |s| s.gateway_id = Some(g1));
    let direct = conn(&mut doc, Some(lab), "direct", Protocol::Ssh, "10.1.1.1");
    let own_gw = conn(&mut doc, Some(lab), "own gateway", Protocol::Ssh, "10.1.1.1");
    let inherited_gw = conn(&mut doc, Some(via), "folder gateway", Protocol::Rdp, "10.1.1.1");
    let other_gw = conn(&mut doc, Some(via), "other gateway", Protocol::Ssh, "10.1.1.1");
    let jump = conn(&mut doc, Some(lab), "jump", Protocol::Ssh, "10.1.1.1");
    edit_conn(&mut doc, own_gw, |c| c.settings.gateway_id = Some(g1));
    edit_conn(&mut doc, other_gw, |c| c.settings.gateway_id = Some(g2));
    edit_conn(&mut doc, jump, |c| drop(c.metadata.insert("ProxyJump".into(), "bastion.example".into())));
    let (pd, p1, p2, pj) = (pw(&mut v, "direct"), pw(&mut v, "one"), pw(&mut v, "two"), pw(&mut v, "jump"));
    add_login(&mut doc, &v, direct, pd).unwrap();
    add_login(&mut doc, &v, own_gw, p1).unwrap();
    add_login(&mut doc, &v, other_gw, p2).unwrap();
    add_login(&mut doc, &v, jump, pj).unwrap();
    // The same effective gateway, set on the connection or inherited from a folder: shared.
    assert_eq!(sources(&doc, &v, inherited_gw), vec![(p1, LoginSource::SameHost { connection: own_gw, name: "own gateway".into() }, false)]);
    assert_eq!(ids(&doc, &v, direct, LoginPurpose::Any), vec![pd]);
    for (c, creds) in [(direct, [p1, p2, pj]), (own_gw, [pd, p2, pj]), (inherited_gw, [pd, p2, pj]), (other_gw, [pd, p1, pj]), (jump, [pd, p1, p2])] {
        for cred in creds {
            refused(&doc, &v, c, cred);
        }
    }
    // A gateway from the connection type's Default Settings is part of the route too.
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let g = gateway(&mut doc, "rdp-only");
    let ssh = conn(&mut doc, None, "ssh", Protocol::Ssh, "10.1.1.2");
    let rdp = conn(&mut doc, None, "rdp", Protocol::Rdp, "10.1.1.2");
    let p = pw(&mut v, "p");
    add_login(&mut doc, &v, ssh, p).unwrap();
    assert_eq!(ids(&doc, &v, rdp, LoginPurpose::Any), vec![p]);
    doc.type_defaults.entry(Protocol::Rdp).or_default().gateway_id = Some(g);
    refused(&doc, &v, rdp, p);
}

#[test]
fn a_credential_another_connection_only_inherits_is_not_offered() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let top = add_folder(&mut doc, None, "Top");
    let sub = add_folder(&mut doc, Some(top), "Sub");
    let named = add_folder(&mut doc, Some(top), "Named");
    let me = conn(&mut doc, Some(top), "me", Protocol::Rdp, "h.example");
    let by_id = conn(&mut doc, Some(sub), "inherits an id", Protocol::Ssh, "h.example");
    let by_name = conn(&mut doc, Some(named), "inherits a name", Protocol::Ssh, "h.example");
    let by_type = conn(&mut doc, Some(top), "inherits the type default", Protocol::Vnc, "h.example");
    let (f, n, t) = (pw(&mut v, "folder"), pw(&mut v, "by-name"), pw(&mut v, "type"));
    crate::credtree::assign_credential(&mut doc, &v, sub, Some(f)).unwrap();
    set_folder(&mut doc, named, |s| s.credential_name = Some("by-name".into()));
    doc.type_defaults.entry(Protocol::Vnc).or_default().credential_id = Some(t);
    assert_eq!(ids(&doc, &v, by_id, LoginPurpose::Any), vec![f]);
    assert_eq!(ids(&doc, &v, by_name, LoginPurpose::Any), vec![n]);
    assert_eq!(ids(&doc, &v, by_type, LoginPurpose::Any), vec![t]);
    assert!(sources(&doc, &v, me).is_empty());
    for cred in [f, n, t] {
        refused(&doc, &v, me, cred);
    }
}

#[test]
fn a_credential_name_on_the_connection_is_named_and_on_a_folder_is_inherited() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let outer = add_folder(&mut doc, None, "Outer");
    let inner = add_folder(&mut doc, Some(outer), "Inner");
    let c = conn(&mut doc, Some(inner), "c", Protocol::Ssh, "h.example");
    let peer = conn(&mut doc, Some(outer), "peer", Protocol::Rdp, "h.example");
    let (d, l, named, by_folder) = (pw(&mut v, "d"), pw(&mut v, "l"), pw(&mut v, "Deploy"), pw(&mut v, "team"));
    edit_conn(&mut doc, c, |c| c.settings.credential_name = Some(" deploy ".into()));
    set_folder(&mut doc, outer, |s| s.credential_name = Some("TEAM".into()));
    // No default: its own named credential, then the inherited one. Both are used automatically.
    assert_eq!(sources(&doc, &v, c), vec![(named, LoginSource::Named, true), (by_folder, LoginSource::Inherited { folder: Some(outer), name: "Outer".into() }, true)]);
    // Its named credential is its own, so the other connection on the host is offered it.
    assert_eq!(sources(&doc, &v, peer), vec![(by_folder, LoginSource::Inherited { folder: Some(outer), name: "Outer".into() }, true), (named, LoginSource::SameHost { connection: c, name: "c".into() }, false)]);
    // Order: default, other logins, named. A default hides the inherited login.
    add_login(&mut doc, &v, c, d).unwrap();
    add_login(&mut doc, &v, c, l).unwrap();
    assert_eq!(sources(&doc, &v, c), vec![(d, LoginSource::Default, true), (l, LoginSource::Connection, true), (named, LoginSource::Named, true)]);
    // A name that is also the default is listed once.
    edit_conn(&mut doc, c, |c| c.settings.credential_name = Some("d".into()));
    assert_eq!(ids(&doc, &v, c, LoginPurpose::Any), vec![d, l]);
}

#[test]
fn inherited_login_is_the_nearest_folder_id_then_the_nearest_folder_name_then_the_type_default() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let outer = add_folder(&mut doc, None, "Outer");
    let inner = add_folder(&mut doc, Some(outer), "Inner");
    let c = conn(&mut doc, Some(inner), "c", Protocol::Ssh, "h.example");
    let (by_id, by_name, by_type) = (pw(&mut v, "by-id"), pw(&mut v, "by-name"), pw(&mut v, "by-type"));
    doc.type_defaults.entry(Protocol::Ssh).or_default().credential_name = Some("by-type".into());
    assert_eq!(sources(&doc, &v, c), vec![(by_type, LoginSource::Inherited { folder: None, name: "ssh default".into() }, true)]);
    set_folder(&mut doc, inner, |s| s.credential_name = Some("by-name".into()));
    assert_eq!(sources(&doc, &v, c), vec![(by_name, LoginSource::Inherited { folder: Some(inner), name: "Inner".into() }, true)]);
    // A folder further up that sets an id wins over a nearer folder that only names one.
    crate::credtree::assign_credential(&mut doc, &v, outer, Some(by_id)).unwrap();
    assert_eq!(sources(&doc, &v, c), vec![(by_id, LoginSource::Inherited { folder: Some(outer), name: "Outer".into() }, true)]);
}

#[test]
fn a_credential_name_matches_one_saved_credential_or_none() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let c = conn(&mut doc, None, "c", Protocol::Ssh, "h.example");
    let other = conn(&mut doc, None, "other", Protocol::Ssh, "elsewhere.example");
    edit_conn(&mut doc, c, |c| c.settings.credential_name = Some("ops".into()));
    assert!(sources(&doc, &v, c).is_empty(), "no credential of that name");
    // Another connection's inline secret is never found by name.
    v.set_inline(other, CredentialKind::Password { username: "u".into(), password: Secret::new("p") });
    edit_conn(&mut doc, c, |c| c.settings.credential_name = Some("Inline".into()));
    assert!(sources(&doc, &v, c).is_empty());
    refused(&doc, &v, c, other);
    edit_conn(&mut doc, c, |c| c.settings.credential_name = Some("ops".into()));
    let first = pw(&mut v, "ops");
    assert_eq!(sources(&doc, &v, c), vec![(first, LoginSource::Named, true)]);
    // Two credentials of one name: the name decides nothing, so neither is used.
    let second = pw(&mut v, "OPS");
    assert!(sources(&doc, &v, c).is_empty());
    for cred in [first, second] {
        refused(&doc, &v, c, cred);
    }
    // An SSH key found by name is dropped for a password login, like any other.
    let k = key(&mut v, "deploy-key");
    edit_conn(&mut doc, c, |c| c.settings.credential_name = Some("deploy-key".into()));
    assert_eq!(ids(&doc, &v, c, LoginPurpose::Any), vec![k]);
    assert!(ids(&doc, &v, c, LoginPurpose::Password).is_empty());
}

#[test]
fn deleted_credentials_are_skipped_and_nothing_is_listed_twice() {
    let (mut doc, mut v) = (Document::new("t"), Vault::default());
    let lab = add_folder(&mut doc, None, "Lab");
    let me = conn(&mut doc, Some(lab), "me", Protocol::Ssh, "h.example");
    let peer = conn(&mut doc, Some(lab), "peer", Protocol::Rdp, "h.example");
    let (a, gone) = (pw(&mut v, "a"), pw(&mut v, "gone"));
    add_login(&mut doc, &v, me, a).unwrap();
    add_login(&mut doc, &v, me, gone).unwrap();
    add_login(&mut doc, &v, peer, gone).unwrap();
    add_login(&mut doc, &v, peer, a).unwrap();
    edit_conn(&mut doc, peer, |c| c.settings.credential_name = Some("a".into()));
    v.remove(gone);
    assert_eq!(sources(&doc, &v, me), vec![(a, LoginSource::Default, true)]);
    assert_eq!(sources(&doc, &v, peer), vec![(a, LoginSource::Connection, true)]);
    refused(&doc, &v, me, gone);
}

#[test]
fn credential_boundary_is_a_folder_setting_that_old_documents_do_not_have() {
    // A document as saved before this change: no `credential_boundary` anywhere.
    let mut doc = Document::new("old");
    let f = add_folder(&mut doc, None, "Lab");
    let c = conn(&mut doc, Some(f), "c", Protocol::Ssh, "h.example");
    set_folder(&mut doc, f, |s| s.port = Some(2200));
    let old = serde_json::to_string(&doc).unwrap();
    assert!(!old.contains("credential_boundary"));
    let loaded: Document = serde_json::from_str(&old).unwrap();
    assert_eq!(loaded, doc);
    assert_eq!(serde_json::to_string(&loaded).unwrap(), old, "an old document saves byte for byte as it was");
    assert_eq!(loaded.folder(f).unwrap().defaults.credential_boundary, None);

    // Set, it is written, read back, and kept out of what connections inherit.
    set_folder(&mut doc, f, |s| s.credential_boundary = Some(true));
    let saved = serde_json::to_string(&doc).unwrap();
    assert_eq!(saved.matches("\"credential_boundary\":true").count(), 1);
    let back: Document = serde_json::from_str(&saved).unwrap();
    assert_eq!(back.folder(f).unwrap().defaults.credential_boundary, Some(true));
    assert!(back.folder(f).unwrap().defaults.extra.is_empty(), "a known setting, not kept as unknown data");
    let r = back.resolve(c).unwrap();
    assert_eq!((r.effective.port, r.effective.credential_boundary), (Some(2200), None), "not inherited");
}

#[test]
fn credential_boundary_is_edited_on_folders_only() {
    use crate::properties::{folder_schema, folder_values, set_type_value, set_value, type_values, CREDENTIAL_BOUNDARY_KEY};
    let mut doc = Document::new("t");
    let f = add_folder(&mut doc, None, "Lab");
    let c = conn(&mut doc, Some(f), "c", Protocol::Ssh, "h.example");
    let sub = add_folder(&mut doc, Some(f), "Sub");
    let of = |doc: &Document, folder: Uuid| folder_values(doc, folder).unwrap().into_iter().find(|v| v.key == CREDENTIAL_BOUNDARY_KEY);
    let own = |doc: &Document| of(doc, f).unwrap();
    assert!(folder_schema().iter().any(|d| d.key == CREDENTIAL_BOUNDARY_KEY && !d.inheritable));
    // Unset, the value says what holds: a top-level folder is a boundary, a deeper one is not.
    assert_eq!((own(&doc).own, own(&doc).effective.as_deref()), (None, Some("true")));
    assert_eq!(of(&doc, sub).unwrap().effective.as_deref(), Some("false"));
    assert!(of(&doc, doc.root.id).is_none());
    set_value(&mut doc, sub, CREDENTIAL_BOUNDARY_KEY, Some("true")).unwrap();
    assert_eq!(doc.folder(sub).unwrap().defaults.credential_boundary, Some(true));
    assert_eq!(of(&doc, sub).unwrap().own.as_deref(), Some("true"));
    set_value(&mut doc, f, CREDENTIAL_BOUNDARY_KEY, Some("true")).unwrap();
    assert_eq!(doc.folder(f).unwrap().defaults.credential_boundary, Some(true));
    assert_eq!(own(&doc).own.as_deref(), Some("true"));
    assert!(set_value(&mut doc, f, CREDENTIAL_BOUNDARY_KEY, Some("maybe")).is_err());
    set_value(&mut doc, f, CREDENTIAL_BOUNDARY_KEY, None).unwrap();
    assert_eq!(doc.folder(f).unwrap().defaults.credential_boundary, None);
    // Not a connection setting, not a type default, and the library root is no folder to fence.
    let root = doc.root.id;
    assert!(set_value(&mut doc, c, CREDENTIAL_BOUNDARY_KEY, Some("true")).is_err());
    assert!(set_value(&mut doc, root, CREDENTIAL_BOUNDARY_KEY, Some("true")).is_err());
    assert!(set_type_value(&mut doc, Protocol::Ssh, CREDENTIAL_BOUNDARY_KEY, Some("true")).is_err());
    assert!(!type_values(&doc, Protocol::Ssh).iter().any(|v| v.key == CREDENTIAL_BOUNDARY_KEY));
    assert!(!crate::properties::connection_values(&doc, c).unwrap().iter().any(|v| v.key == CREDENTIAL_BOUNDARY_KEY));
    assert!(!crate::properties::default_schema(None).iter().any(|d| d.key == CREDENTIAL_BOUNDARY_KEY), "the inheritable set is unchanged");
}

/// Timed, not run by default: `cargo test --release --lib logins -- --ignored --nocapture`.
/// 5,000 connections in 50 top-level folders; every tenth shares one host name, so the
/// same-host step has work to do.
#[test]
#[ignore = "timing; run alone with --ignored --nocapture"]
fn login_candidates_on_5000_connections_takes_under_a_millisecond() {
    const CONNECTIONS: usize = 5_000;
    const FOLDERS: usize = 50;
    const CALLS: u32 = 2_000;
    let (mut doc, mut v) = (Document::new("big"), Vault::default());
    let creds: Vec<Uuid> = (0..200).map(|i| pw(&mut v, &format!("cred-{i}"))).collect();
    let mut ids_in_tree = Vec::with_capacity(CONNECTIONS);
    for f in 0..FOLDERS {
        let mut top = folder(&format!("Customer {f}"));
        let mut sub = folder("Servers");
        sub.defaults.credential_id = Some(creds[f]);
        for i in 0..CONNECTIONS / FOLDERS {
            let n = f * (CONNECTIONS / FOLDERS) + i;
            let host = if i % 10 == 0 { "shared.example".to_string() } else { format!("host-{n}.example") };
            let mut c = Connection::new(format!("c{n}"), if n % 2 == 0 { Protocol::Ssh } else { Protocol::Rdp }, host);
            if i % 3 == 0 {
                c.settings.credential_id = Some(creds[n % creds.len()]);
                c.settings.logins = vec![creds[(n + 1) % creds.len()]];
            }
            ids_in_tree.push(c.id);
            let into = if i % 2 == 0 { &mut top } else { &mut sub };
            into.children.push(Node::Connection(c));
        }
        top.children.push(Node::Folder(sub));
        doc.root.children.push(Node::Folder(top));
    }
    // Worst case for the walk: the last connection, and one on the shared host.
    let targets = [*ids_in_tree.last().unwrap(), ids_in_tree[CONNECTIONS - CONNECTIONS / FOLDERS]];
    let mut worst = std::time::Duration::ZERO;
    for target in targets {
        let started = std::time::Instant::now();
        let mut found = 0;
        for _ in 0..CALLS {
            found += login_candidates(&doc, &v, target, LoginPurpose::Any).unwrap().len();
        }
        let per_call = started.elapsed() / CALLS;
        println!("login_candidates: {CONNECTIONS} connections, {per_call:?} per call ({} candidates)", found / CALLS as usize);
        worst = worst.max(per_call);
    }
    assert!(worst < std::time::Duration::from_millis(1), "{worst:?} per call");
}

// A1-CORE-01-FU1: a credential reference that arrived with a received library is offered,
// never used automatically, until the user confirms it.

/// The user's vault: `Team`, `Admin`, `Deploy`.
fn user_vault() -> (Vault, Uuid, Uuid, Uuid) {
    let mut v = Vault::default();
    let (team, admin, deploy) = (pw(&mut v, "Team"), pw(&mut v, "Admin"), pw(&mut v, "Deploy"));
    (v, team, admin, deploy)
}

/// What a sender can write: a folder that names a credential, with a connection that inherits
/// it, one that names a credential, and one that carries credential ids the sender knows.
/// Returns the document and `[folder, inherits, names, has_ids]`.
fn sender_library(admin: Uuid, deploy: Uuid) -> (Document, [Uuid; 4]) {
    let mut doc = Document::new("sent");
    let f = add_folder(&mut doc, None, "Servers");
    set_folder(&mut doc, f, |s| s.credential_name = Some("team".into()));
    let inherits = conn(&mut doc, Some(f), "plain", Protocol::Ssh, "a.sender.example");
    let names = conn(&mut doc, Some(f), "named", Protocol::Ssh, "b.sender.example");
    edit_conn(&mut doc, names, |c| c.settings.credential_name = Some("Admin".into()));
    let has_ids = conn(&mut doc, Some(f), "ids", Protocol::Ssh, "c.sender.example");
    edit_conn(&mut doc, has_ids, |c| {
        c.settings.credential_id = Some(admin);
        c.settings.logins = vec![deploy];
    });
    (doc, [f, inherits, names, has_ids])
}

/// Every login of the three received connections is listed, may be released once confirmed,
/// and is not used automatically.
fn all_offered_none_auto(doc: &Document, v: &Vault, [_, inherits, names, has_ids]: [Uuid; 4], team: Uuid, admin: Uuid, deploy: Uuid) {
    let folder_row = |row: &(Uuid, LoginSource, bool)| matches!(row, (c, LoginSource::Inherited { folder: Some(_), .. }, false) if *c == team);
    let got = sources(doc, v, inherits);
    assert!(got.len() == 1 && folder_row(&got[0]), "{got:?}");
    let got = sources(doc, v, names);
    assert!(got.len() == 2 && got[0] == (admin, LoginSource::Named, false) && folder_row(&got[1]), "{got:?}");
    assert_eq!(sources(doc, v, has_ids), vec![(admin, LoginSource::Default, false), (deploy, LoginSource::Connection, false)]);
    for (c, cred) in [(inherits, team), (names, admin), (has_ids, admin), (has_ids, deploy)] {
        assert!(may_use(doc, v, c, cred, LoginPurpose::Any).unwrap(), "still offered, so released after the user's yes");
    }
}

#[test]
fn a_bastion_export_that_is_read_in_offers_its_logins_and_uses_none() {
    let (v, team, admin, deploy) = user_vault();
    let (sent, nodes) = sender_library(admin, deploy);
    let bytes = crate::export::export(&sent, &crate::export::Selection::All).unwrap();

    let received = crate::export::import(&bytes).unwrap();

    all_offered_none_auto(&received, &v, nodes, team, admin, deploy);
}

#[test]
fn a_folder_merged_into_the_library_offers_its_logins_and_uses_none() {
    let (v, team, admin, deploy) = user_vault();
    let (sent, nodes) = sender_library(admin, deploy);
    let mut mine = Document::new("mine");
    let own = conn(&mut mine, None, "own", Protocol::Ssh, "mine.example");
    add_login(&mut mine, &v, own, admin).unwrap();
    let incoming = || Folder { name: "Imported sent".into(), ..sent.root.clone() };

    crate::import::merge_import(&mut mine, incoming());

    all_offered_none_auto(&mine, &v, nodes, team, admin, deploy);
    assert_eq!(sources(&mine, &v, own), vec![(admin, LoginSource::Default, true)], "a connection the user made is unchanged");

    // The same file again, merged into the folder that is already there, adds a new host.
    let mut again = incoming();
    let extra = Connection::new("late", Protocol::Ssh, "d.sender.example");
    let late = extra.id;
    again.children.push(Node::Connection(Connection { settings: crate::model::Settings { credential_name: Some("Deploy".into()), ..Default::default() }, ..extra }));
    crate::import::merge_import(&mut mine, again);
    assert_eq!(sources(&mine, &v, late), vec![(deploy, LoginSource::Named, false)]);
}

#[test]
fn a_received_login_is_used_automatically_once_the_user_chooses_it() {
    use crate::properties::set_value;
    let (v, team, admin, deploy) = user_vault();
    let received = || {
        let (mut doc, nodes) = sender_library(admin, deploy);
        mark_received(&mut doc.root);
        (doc, nodes)
    };
    let auto = |doc: &Document, c: Uuid| sources(doc, &v, c).into_iter().map(|(cred, _, auto)| (cred, auto)).collect::<Vec<_>>();

    // An edit that is not about the login confirms nothing.
    let (mut doc, [f, inherits, names, has_ids]) = received();
    set_value(&mut doc, names, "port", Some("2200")).unwrap();
    set_value(&mut doc, f, "port", Some("2200")).unwrap();
    remove_login(&mut doc, has_ids, deploy).unwrap();
    assert_eq!(auto(&doc, names), vec![(admin, false), (team, false)]);
    assert_eq!(auto(&doc, has_ids), vec![(admin, false)]);

    // Setting the credential in Properties, by name or by id, on the connection or the folder.
    set_value(&mut doc, names, "credential_name", Some("Admin")).unwrap();
    assert_eq!(auto(&doc, names), vec![(admin, true), (team, false)], "the folder's name is still unconfirmed");
    set_value(&mut doc, f, "credential_name", Some("team")).unwrap();
    assert_eq!(auto(&doc, inherits), vec![(team, true)]);
    set_value(&mut doc, has_ids, "credential_id", Some(&admin.to_string())).unwrap();
    assert_eq!(auto(&doc, has_ids), vec![(admin, true)]);

    // "Use this login from now on": `add_login` with the login that arrived, or a new default.
    let (mut doc, [_, _, names, has_ids]) = received();
    add_login(&mut doc, &v, has_ids, admin).unwrap();
    assert_eq!(auto(&doc, has_ids), vec![(admin, true), (deploy, false)], "only the login the user chose");
    set_default_login(&mut doc, &v, names, admin).unwrap();
    assert_eq!(auto(&doc, names), vec![(admin, true)]);
}

#[test]
fn an_unconfirmed_type_default_is_offered_and_the_mark_is_not_inherited() {
    let (v, team, _, _) = user_vault();
    let mut doc = Document::new("d");
    let c = conn(&mut doc, None, "c", Protocol::Ssh, "h.example");
    doc.type_defaults.entry(Protocol::Ssh).or_default().credential_id = Some(team);
    assert!(matches!(sources(&doc, &v, c).as_slice(), [(_, LoginSource::Inherited { folder: None, .. }, true)]));

    doc.type_defaults.entry(Protocol::Ssh).or_default().credential_unconfirmed = Some(true);

    assert!(matches!(sources(&doc, &v, c).as_slice(), [(_, LoginSource::Inherited { folder: None, .. }, false)]));
    assert_eq!(doc.resolve(c).unwrap().effective.credential_unconfirmed, None, "not inherited");
    crate::properties::set_type_value(&mut doc, Protocol::Ssh, "credential_id", Some(&team.to_string())).unwrap();
    assert!(matches!(sources(&doc, &v, c).as_slice(), [(_, LoginSource::Inherited { folder: None, .. }, true)]));
}

#[test]
fn only_nodes_with_a_login_reference_are_marked_and_old_documents_do_not_change() {
    let (_, _, admin, deploy) = user_vault();
    let (mut doc, [f, inherits, names, has_ids]) = sender_library(admin, deploy);
    let old = serde_json::to_string(&doc).unwrap();
    assert!(!old.contains("credential_unconfirmed"));
    let loaded: Document = serde_json::from_str(&old).unwrap();
    assert_eq!(serde_json::to_string(&loaded).unwrap(), old, "an old document saves byte for byte as it was");

    mark_received(&mut doc.root);

    let marked = |id: Uuid| doc.resolve(id).unwrap().connection.settings.credential_unconfirmed;
    assert_eq!((marked(inherits), marked(names), marked(has_ids)), (None, Some(true), Some(true)));
    assert_eq!((doc.folder(f).unwrap().defaults.credential_unconfirmed, doc.root.defaults.credential_unconfirmed), (Some(true), None));
    let saved = serde_json::to_string(&doc).unwrap();
    assert_eq!(saved.matches("\"credential_unconfirmed\":true").count(), 3);
    let back: Document = serde_json::from_str(&saved).unwrap();
    assert_eq!(back, doc);
    assert!(back.folder(f).unwrap().defaults.extra.is_empty(), "a known setting, not kept as unknown data");
}

/// `sender_library` as it is after an import: every reference marked.
fn received_library(admin: Uuid, deploy: Uuid) -> (Document, [Uuid; 4]) {
    let (mut doc, nodes) = sender_library(admin, deploy);
    mark_received(&mut doc.root);
    (doc, nodes)
}

/// Review of #813, M1: a choice confirms the login that was chosen, not the node.
#[test]
fn choosing_one_login_does_not_confirm_the_others_the_sender_wrote() {
    use crate::properties::set_value;
    let (v, team, admin, deploy) = user_vault();

    // The sender wrote Admin (default) and Deploy. The user adds their own Team login.
    let (mut doc, [_, _, _, has_ids]) = received_library(admin, deploy);
    add_login(&mut doc, &v, has_ids, team).unwrap();
    assert_eq!(
        sources(&doc, &v, has_ids),
        vec![(admin, LoginSource::Default, false), (deploy, LoginSource::Connection, false), (team, LoginSource::Connection, true)]
    );
    set_default_login(&mut doc, &v, has_ids, team).unwrap();
    assert_eq!(
        sources(&doc, &v, has_ids),
        vec![(team, LoginSource::Default, true), (deploy, LoginSource::Connection, false), (admin, LoginSource::Connection, false)]
    );

    // The sender wrote a name and an id. Resetting the id in Properties chooses nothing.
    let (mut doc, [f, _, names, _]) = received_library(admin, deploy);
    edit_conn(&mut doc, names, |c| c.settings.credential_id = Some(deploy));
    set_value(&mut doc, names, "credential_id", None).unwrap();
    let got = sources(&doc, &v, names);
    assert_eq!(got[0], (admin, LoginSource::Named, false), "{got:?}");
    // Setting an id confirms that id; the name the sender wrote stays offered.
    set_value(&mut doc, names, "credential_id", Some(&deploy.to_string())).unwrap();
    assert_eq!(sources(&doc, &v, names), vec![(deploy, LoginSource::Default, true), (admin, LoginSource::Named, false)]);
    // A folder: an id the user sets is confirmed, and it wins over the name the sender wrote.
    set_value(&mut doc, f, "credential_id", Some(&deploy.to_string())).unwrap();
    set_value(&mut doc, f, "credential_id", None).unwrap();
    assert!(matches!(sources(&doc, &v, f_child(&doc, f)).as_slice(), [(c, LoginSource::Inherited { .. }, false)] if *c == team), "back to the sender's name: offered");
}

/// The first connection directly in folder `f`.
fn f_child(doc: &Document, f: Uuid) -> Uuid {
    doc.folder(f).unwrap().children.iter().find_map(|n| match n {
        Node::Connection(c) => Some(c.id),
        _ => None,
    }).unwrap()
}

#[test]
fn the_mark_goes_once_every_reference_is_the_users_choice() {
    let (v, _, admin, deploy) = user_vault();
    let (mut doc, [_, _, _, has_ids]) = received_library(admin, deploy);
    let settings = |doc: &Document| doc.resolve(has_ids).unwrap().connection.settings;

    add_login(&mut doc, &v, has_ids, admin).unwrap();
    assert_eq!((settings(&doc).credential_unconfirmed, settings(&doc).credential_confirmed), (Some(true), vec![admin]));
    add_login(&mut doc, &v, has_ids, deploy).unwrap();

    assert_eq!(sources(&doc, &v, has_ids), vec![(admin, LoginSource::Default, true), (deploy, LoginSource::Connection, true)]);
    assert_eq!((settings(&doc).credential_unconfirmed, settings(&doc).credential_confirmed), (None, vec![]));
    let saved = serde_json::to_string(&doc).unwrap();
    assert!(!saved.contains("credential_confirmed"), "not written when empty");
}

/// Review of #813, L2: the type defaults in a Bastion export are marked on the way in.
#[test]
fn type_defaults_in_a_bastion_export_are_read_in_unconfirmed() {
    let (v, team, _, _) = user_vault();
    let mut sent = Document::new("sent");
    let c = conn(&mut sent, None, "c", Protocol::Ssh, "h.sender.example");
    sent.type_defaults.entry(Protocol::Ssh).or_default().credential_name = Some("Team".into());
    sent.type_defaults.entry(Protocol::Rdp).or_default().port = Some(3390);
    let bytes = crate::export::export(&sent, &crate::export::Selection::All).unwrap();

    let received = crate::export::import(&bytes).unwrap();

    assert_eq!(received.type_defaults[&Protocol::Ssh].credential_unconfirmed, Some(true));
    assert_eq!(received.type_defaults[&Protocol::Rdp].credential_unconfirmed, None, "no reference, no mark");
    assert!(matches!(sources(&received, &v, c).as_slice(), [(cred, LoginSource::Inherited { folder: None, .. }, false)] if *cred == team));
}

/// A sender cannot confirm for the user: a `credential_confirmed` list in a received file is
/// dropped on every way in, with or without a mark beside it.
#[test]
fn a_confirmed_list_the_sender_wrote_is_dropped_on_import() {
    let (v, team, admin, deploy) = user_vault();
    let (mut sent, nodes) = sender_library(admin, deploy);
    let [f, inherits, names, has_ids] = nodes;
    // The sender claims the user already chose everything, on nodes with and without a reference.
    set_folder(&mut sent, f, |s| s.credential_confirmed = vec![team]);
    for c in [inherits, names, has_ids] {
        edit_conn(&mut sent, c, |c| {
            c.settings.credential_unconfirmed = Some(true);
            c.settings.credential_confirmed = vec![team, admin, deploy];
        });
    }
    sent.type_defaults.entry(Protocol::Ssh).or_default().credential_confirmed = vec![team];
    let listed = |doc: &Document| doc.connections().iter().any(|r| !r.connection.settings.credential_confirmed.is_empty()) || !doc.folder(f).unwrap().defaults.credential_confirmed.is_empty();
    assert!(listed(&sent));

    // A Bastion export read in.
    let bytes = crate::export::export(&sent, &crate::export::Selection::All).unwrap();
    let received = crate::export::import(&bytes).unwrap();
    assert!(!listed(&received) && received.type_defaults.values().all(|t| t.credential_confirmed.is_empty()));
    all_offered_none_auto(&received, &v, nodes, team, admin, deploy);

    // A folder merged into the user's library (every file import ends here).
    let mut mine = Document::new("mine");
    crate::import::merge_import(&mut mine, Folder { name: "Imported sent".into(), ..sent.root.clone() });
    assert!(!listed(&mine));
    all_offered_none_auto(&mine, &v, nodes, team, admin, deploy);

    // What `docfile::import_into` calls on the folder it brings in.
    let mut folder = sent.root.clone();
    mark_received(&mut folder);
    let direct = Document { root: folder, ..Document::new("direct") };
    assert!(!listed(&direct));
    all_offered_none_auto(&direct, &v, nodes, team, admin, deploy);
}

/// Review of #813, H1: importing the same file again, onto nodes the user already has, neither
/// adds the sender's confirmed list to them nor takes away what the user confirmed.
#[test]
fn a_second_import_does_not_touch_what_the_user_confirmed() {
    let (v, team, admin, deploy) = user_vault();
    let (sent, nodes) = sender_library(admin, deploy);
    let [f, _, names, has_ids] = nodes;
    let incoming = |sent: &Document| Folder { name: "Imported sent".into(), ..sent.root.clone() };
    let mut mine = Document::new("mine");
    crate::import::merge_import(&mut mine, incoming(&sent));
    // The user confirms Admin on one connection; Deploy on it stays the sender's.
    add_login(&mut mine, &v, has_ids, admin).unwrap();
    let before = serde_json::to_string(&mine).unwrap();

    // The sender's file again, now claiming that everything is confirmed.
    let mut again = sent.clone();
    set_folder(&mut again, f, |s| s.credential_confirmed = vec![team]);
    for c in [names, has_ids] {
        edit_conn(&mut again, c, |c| c.settings.credential_confirmed = vec![team, admin, deploy]);
    }
    let (_, added) = crate::import::merge_import(&mut mine, incoming(&again));

    assert_eq!((added, serde_json::to_string(&mine).unwrap()), (0, before), "nothing the user has is changed");
    assert_eq!(mine.resolve(has_ids).unwrap().connection.settings.credential_confirmed, vec![admin], "the user's own list");
    assert_eq!(sources(&mine, &v, has_ids), vec![(admin, LoginSource::Default, true), (deploy, LoginSource::Connection, false)]);
    assert_eq!(sources(&mine, &v, names)[0], (admin, LoginSource::Named, false));
}
