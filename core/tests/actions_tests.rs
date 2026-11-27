use bastion_core::actions::{self, ActionContext, ActionId, Backend, ObjectKind, SessionState};
use bastion_core::icons;
use bastion_core::model::Protocol;
use bastion_core::policy::Policy;
use bastion_core::theme;

fn all() -> Vec<ActionId> {
    actions::all_ids()
}

fn ids(items: &[actions::MenuItem]) -> Vec<ActionId> {
    items.iter().map(|i| i.id).collect()
}

fn ssh(session: SessionState) -> ActionContext {
    ActionContext { kind: Some(ObjectKind::Connection), protocol: Some(Protocol::Ssh), session, has_username: true, ..Default::default() }
}

#[test]
fn ssh_menu_lists_implemented_actions_in_order_and_hides_missing_ones() {
    let m = actions::menu(&ssh(SessionState::Closed), &Policy::default(), &all());
    use ActionId::*;
    assert_eq!(
        ids(&m),
        vec![Connect, ConnectNewTab, Reconnect, Disconnect, OpenSftp, ConnectAs, ReconnectAs, CopySshCommand, CopyHostname, CopyUsername, CopyAddress, Rename, Duplicate, SaveAsTemplate, Move, ToggleFavorite, AddToWorkspace, Properties, Delete]
    );
    for missing in [ConnectNewWindow, OpenViaGateway, RunTask, Copy, CustomizeAppearance] {
        assert!(!ids(&m).contains(&missing), "{missing:?} has no implementation and must not be offered");
    }
    let connect = &m[0];
    assert!(connect.primary && connect.enabled && connect.label == "Connect");
    let disconnect = m.iter().find(|i| i.id == Disconnect).unwrap();
    assert!(!disconnect.enabled && disconnect.disabled_reason.as_deref() == Some("Not connected"));
    let delete = m.last().unwrap();
    assert!(delete.destructive && delete.confirm.is_some());
}

#[test]
fn add_to_workspace_is_offered_for_ssh_connections_only() {
    let p = Policy::default();
    let has = |cx: &ActionContext| ids(&actions::menu(cx, &p, &all())).contains(&ActionId::AddToWorkspace);
    assert!(has(&ssh(SessionState::Closed)));
    let rdp = ActionContext { protocol: Some(Protocol::Rdp), ..ssh(SessionState::Closed) };
    assert!(!has(&rdp), "workspaces restore terminal and files tabs only");
    let folder = ActionContext { kind: Some(ObjectKind::Folder), ..Default::default() };
    assert!(!has(&folder));
    assert!(!ids(&actions::menu(&ssh(SessionState::Closed), &p, &[ActionId::Connect])).contains(&ActionId::AddToWorkspace), "only with a handler");
}

#[test]
fn session_state_controls_connect_disconnect_and_reconnect() {
    let p = Policy::default();
    let get = |m: &[actions::MenuItem], id| m.iter().find(|i| i.id == id).cloned().unwrap();
    let open = actions::menu(&ssh(SessionState::Connected), &p, &all());
    assert_eq!(get(&open, ActionId::Connect).label, "Show Session");
    assert!(get(&open, ActionId::Disconnect).enabled);
    assert!(get(&open, ActionId::Reconnect).enabled);
    let failed = actions::menu(&ssh(SessionState::Failed), &p, &all());
    assert!(get(&failed, ActionId::Reconnect).enabled);
    assert!(!get(&failed, ActionId::Disconnect).enabled);
}

#[test]
fn frontend_without_a_handler_never_gets_the_action() {
    let handled = [ActionId::Connect, ActionId::Delete];
    let m = actions::menu(&ssh(SessionState::Closed), &Policy::default(), &handled);
    assert_eq!(ids(&m), vec![ActionId::Connect, ActionId::Delete]);
}

#[test]
fn rdp_and_vnc_menus_have_full_screen_but_no_sftp_or_ssh_command() {
    for proto in [Protocol::Rdp, Protocol::Vnc] {
        let cx = ActionContext { kind: Some(ObjectKind::Connection), protocol: Some(proto), session: SessionState::Connected, ..Default::default() };
        let m = actions::menu(&cx, &Policy::default(), &all());
        let i = ids(&m);
        assert!(i.contains(&ActionId::FullScreen) && i.contains(&ActionId::CopyAddress));
        assert!(!i.contains(&ActionId::OpenSftp) && !i.contains(&ActionId::CopySshCommand));
        let user = m.iter().find(|x| x.id == ActionId::CopyUsername).unwrap();
        assert!(!user.enabled, "no username set");
    }
}

#[test]
fn types_without_a_session_implementation_offer_no_connect() {
    let cx = ActionContext { kind: Some(ObjectKind::Connection), protocol: Some(Protocol::Ftp), ..Default::default() };
    let m = actions::menu(&cx, &Policy::default(), &all());
    assert!(!ids(&m).contains(&ActionId::Connect));
    assert!(ids(&m).contains(&ActionId::CopyAddress));
    assert_eq!(actions::default_action(&cx), Some(ActionId::Properties));
}

/// B7: a saved Telnet or serial connection has Connect, Connect in New Tab and a primary action
/// (double-click, Return), so the apps reach their own Telnet and serial tabs.
#[test]
fn telnet_and_serial_connections_are_connectable() {
    for p in [Protocol::Telnet, Protocol::Serial] {
        let cx = ActionContext { kind: Some(ObjectKind::Connection), protocol: Some(p), ..Default::default() };
        let m = actions::menu(&cx, &Policy::default(), &all());
        assert!(actions::opens_session(p), "{p:?}");
        assert!(ids(&m).contains(&ActionId::Connect), "{p:?} has Connect");
        assert!(ids(&m).contains(&ActionId::ConnectNewTab), "{p:?} has Connect in New Tab");
        assert_eq!(actions::default_action(&cx), Some(ActionId::Connect), "{p:?} double-click connects");
        // Enabled under the default policy: the user's Allow Telnet switch is checked at connect.
        assert!(m.iter().find(|i| i.id == ActionId::Connect).unwrap().enabled, "{p:?} Connect enabled");
        let open = ActionContext { session: SessionState::Connected, ..cx };
        let m = actions::menu(&open, &Policy::default(), &all());
        assert!(ids(&m).contains(&ActionId::Disconnect), "{p:?} has Disconnect while open");
    }
    // A managed policy that forbids Telnet still shows Connect, disabled with the reason.
    let mut forbid = Policy::default();
    forbid.denied_protocols.insert(Protocol::Telnet);
    let mut legacy_off = Policy::default();
    legacy_off.forbid_legacy = true;
    for forbid in [forbid, legacy_off] {
    let cx = ActionContext { kind: Some(ObjectKind::Connection), protocol: Some(Protocol::Telnet), ..Default::default() };
    let item = actions::menu(&cx, &forbid, &all()).into_iter().find(|i| i.id == ActionId::Connect).expect("Connect listed");
    assert!(!item.enabled && item.disabled_reason.is_some());
    }
}

#[test]
fn folder_menu_reflects_contents_and_root_restrictions() {
    use ActionId::*;
    let cx = ActionContext { kind: Some(ObjectKind::Folder), descendant_connections: 3, descendant_folders: 1, open_sessions: 2, ..Default::default() };
    let m = actions::menu(&cx, &Policy::default(), &all());
    assert_eq!(ids(&m), vec![NewConnection, NewSubfolder, ConnectAll, DisconnectAll, ReconnectAll, ExpandAll, CollapseAll, Sort, Rename, Duplicate, Move, Properties, Delete]);
    assert_eq!(m.iter().find(|i| i.id == Delete).unwrap().confirm.as_deref(), Some("Delete this folder and the 3 connections in it?"));
    assert_eq!(m.iter().find(|i| i.id == DisconnectAll).unwrap().confirm.as_deref(), Some("Close 2 sessions?"));
    let root = ActionContext { kind: Some(ObjectKind::Folder), is_root: true, ..Default::default() };
    let r = ids(&actions::menu(&root, &Policy::default(), &all()));
    for id in [Rename, Move, Duplicate, Delete, ExpandAll] {
        assert!(!r.contains(&id), "{id:?} on the root");
    }
    let empty = actions::menu(&ActionContext { kind: Some(ObjectKind::Folder), ..Default::default() }, &Policy::default(), &all());
    assert!(!empty.iter().find(|i| i.id == DisconnectAll).unwrap().enabled);
    assert!(!empty.iter().find(|i| i.id == Sort).unwrap().enabled);
}

#[test]
fn catalogue_documents_missing_backends() {
    let conn = actions::catalogue(ObjectKind::Connection);
    let gw = conn.iter().find(|a| a.id == ActionId::OpenViaGateway).unwrap();
    assert!(matches!(gw.backend, Backend::Missing(_)));
}

#[test]
fn action_ids_round_trip_through_their_wire_names() {
    for id in actions::all_ids() {
        assert_eq!(ActionId::parse(&id.as_str()), Some(id));
    }
    assert_eq!(ActionId::CopySshCommand.as_str(), "copy-ssh-command");
    assert_eq!(ActionId::parse("format-disk"), None);
}

#[test]
fn ssh_command_and_address_are_formatted_and_quoted() {
    assert_eq!(actions::ssh_command("10.0.0.5", Some(22), Some("ops")), "ssh ops@10.0.0.5");
    assert_eq!(actions::ssh_command("db", Some(2222), None), "ssh -p 2222 db");
    assert_eq!(actions::ssh_command("h", None, Some("a b;rm")), "ssh 'a b;rm@h'");
    assert_eq!(actions::address("fe80::1", Some(3390), Some(3389)), "[fe80::1]:3390");
    assert_eq!(actions::address("web", Some(443), Some(443)), "web");
    assert_eq!(actions::address("https://x.example/a", Some(8443), Some(443)), "https://x.example/a");
}

#[test]
fn every_protocol_has_a_distinct_icon_with_a_full_label_and_a_tint_token() {
    use std::collections::HashSet;
    let protos = [Protocol::Ssh, Protocol::Rdp, Protocol::Vnc, Protocol::Sftp, Protocol::Scp, Protocol::Ftp, Protocol::Ftps, Protocol::Web, Protocol::Telnet, Protocol::Serial];
    let icons: Vec<_> = protos.iter().map(|p| icons::for_protocol(*p)).collect();
    assert_eq!(icons.iter().map(|i| i.id).collect::<HashSet<_>>().len(), protos.len());
    assert!(icons.iter().all(|i| i.label.len() >= 3 && i.label.chars().next().unwrap().is_uppercase()));
    for dark in [true, false] {
        let names: HashSet<_> = theme::colors(dark).into_iter().map(|c| c.name).collect();
        for i in icons::ALL {
            assert!(names.contains(i.tint.token().as_str()), "{} missing for {}", i.tint.token(), i.id);
        }
    }
}

/// File-transfer connections open (SFTP, SCP, FTPS); plain FTP never does. Telnet and Serial open
/// through `opens_session`, not `connects`, so Connect All still skips them.
#[test]
fn file_transfer_protocols_connect_and_plain_ftp_does_not() {
    use bastion_core::actions::connects;
    use bastion_core::model::Protocol;
    for p in [Protocol::Sftp, Protocol::Scp, Protocol::Ftps] {
        assert!(connects(p), "{p:?}");
    }
    for p in [Protocol::Ftp, Protocol::Telnet, Protocol::Serial] {
        assert!(!connects(p), "{p:?}");
    }
    assert!(bastion_core::policy::Policy::default().check_protocol(Protocol::Ftp).is_err(), "plain FTP stays off by policy");
}

#[test]
fn every_accent_setting_has_a_colour() {
    let ids: Vec<&str> = bastion_core::settings::ACCENTS.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, theme::ACCENTS.iter().map(|(id, _)| *id).collect::<Vec<_>>(), "same ids, same order as the setting");
    for (id, hex) in theme::ACCENTS {
        assert!(hex.len() == 7 && hex.starts_with('#') && u32::from_str_radix(&hex[1..], 16).is_ok(), "{id}: {hex}");
        assert_eq!(theme::accent(id), Some(*hex));
    }
    assert_eq!(theme::accent("plaid"), None);
}

/// A saved local terminal connects (its default action starts the shell, not Properties).
#[test]
fn local_terminal_connects() {
    use bastion_core::actions::connects;
    use bastion_core::model::Protocol;
    assert!(connects(Protocol::Local));
}

#[test]
fn connect_as_is_ssh_only_and_reconnect_as_needs_a_session() {
    let p = Policy::default();
    let get = |m: &[actions::MenuItem], id| m.iter().find(|i| i.id == id).cloned();
    let closed = actions::menu(&ssh(SessionState::Closed), &p, &all());
    assert_eq!(get(&closed, ActionId::ConnectAs).unwrap().label, "Connect as…");
    assert!(get(&closed, ActionId::ConnectAs).unwrap().enabled);
    assert!(!get(&closed, ActionId::ReconnectAs).unwrap().enabled, "nothing to reconnect");
    let open = actions::menu(&ssh(SessionState::Connected), &p, &all());
    assert!(get(&open, ActionId::ReconnectAs).unwrap().enabled);
    let rdp = ActionContext { protocol: Some(Protocol::Rdp), ..ssh(SessionState::Closed) };
    assert!(get(&actions::menu(&rdp, &p, &all()), ActionId::ConnectAs).is_none());
    assert_eq!(ActionId::ConnectAs.as_str(), "connect-as");
    assert_eq!(ActionId::parse("reconnect-as"), Some(ActionId::ReconnectAs));
}

// --- B4: the plan for Connect All on a folder ---------------------------------------------------

mod connect_all {
    use bastion_core::actions::{self, plan_connect_all, ActionContext, ActionId, Backend, BulkConnectPlan, ObjectKind, CONNECT_ALL_CONFIRM_ABOVE};
    use bastion_core::model::{Connection, Document, Folder, Node, Protocol};
    use bastion_core::policy::Policy;
    use bastion_core::vault::{Credential, CredentialKind, Secret, Vault};
    use bastion_core::CoreError;
    use uuid::Uuid;

    fn pw(v: &mut Vault, name: &str) -> Uuid {
        v.add(Credential { id: Uuid::new_v4(), name: name.into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: name.into(), password: Secret::new("x") } })
    }

    fn key(v: &mut Vault, name: &str) -> Uuid {
        v.add(Credential { id: Uuid::new_v4(), name: name.into(), folder: None, scope: None, owner: None, kind: CredentialKind::SshKey { username: name.into(), private_key: Secret::new("k"), passphrase: None } })
    }

    fn folder(doc: &mut Document, parent: Option<Uuid>, name: &str) -> Uuid {
        folder_with_login(doc, parent, name, None)
    }

    /// A folder whose connections inherit `login`.
    fn folder_with_login(doc: &mut Document, parent: Option<Uuid>, name: &str, login: Option<Uuid>) -> Uuid {
        let mut f = Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Default::default(), children: Vec::new(), dynamic_task_id: None, extra: Default::default() };
        f.defaults.credential_id = login;
        let id = f.id;
        doc.insert(parent, Node::Folder(f)).unwrap();
        id
    }

    /// A connection under `parent`, with `login` as its default login.
    fn conn(doc: &mut Document, parent: Uuid, name: &str, p: Protocol, host: &str, login: Option<Uuid>) -> Uuid {
        let mut c = Connection::new(name, p, host);
        c.settings.credential_id = login;
        let id = c.id;
        doc.insert(Some(parent), Node::Connection(c)).unwrap();
        id
    }

    #[test]
    fn nested_folders_are_walked_in_tree_order() {
        let (mut doc, mut v) = (Document::new("t"), Vault::default());
        let cred = pw(&mut v, "ops");
        let top = folder(&mut doc, None, "Prod");
        let a = conn(&mut doc, top, "a", Protocol::Ssh, "a.example", Some(cred));
        let sub = folder(&mut doc, Some(top), "Web");
        let b = conn(&mut doc, sub, "b", Protocol::Ssh, "b.example", Some(cred));
        let deep = folder(&mut doc, Some(sub), "Deep");
        let c = conn(&mut doc, deep, "c", Protocol::Rdp, "c.example", Some(cred));
        let d = conn(&mut doc, top, "d", Protocol::Ssh, "d.example", Some(cred));
        let other = folder(&mut doc, None, "Other");
        let outside = conn(&mut doc, other, "outside", Protocol::Ssh, "o.example", Some(cred));

        let plan = plan_connect_all(&doc, &v, &Policy::default(), top, &[]).unwrap();
        assert_eq!(plan.ready, vec![a, b, c, d], "subfolders included, in the order the tree shows");
        assert!(!plan.ready.contains(&outside), "a sibling folder is not part of the plan");
        assert_eq!(plan_connect_all(&doc, &v, &Policy::default(), sub, &[]).unwrap().ready, vec![b, c]);
        // The root is a folder too: everything.
        assert_eq!(plan_connect_all(&doc, &v, &Policy::default(), doc.root.id, &[]).unwrap().ready, vec![a, b, c, d, outside]);
    }

    #[test]
    fn mixed_ready_needs_login_open_and_unsupported() {
        let (mut doc, mut v) = (Document::new("t"), Vault::default());
        let cred = pw(&mut v, "ops");
        let top = folder(&mut doc, None, "Prod");
        let ready = conn(&mut doc, top, "ready", Protocol::Ssh, "r.example", Some(cred));
        let none = conn(&mut doc, top, "none", Protocol::Ssh, "n.example", None);
        let open = conn(&mut doc, top, "open", Protocol::Ssh, "o.example", Some(cred));
        let open_without_login = conn(&mut doc, top, "open2", Protocol::Ssh, "o2.example", None);
        let telnet = conn(&mut doc, top, "telnet", Protocol::Telnet, "t.example", Some(cred));
        let rdp = conn(&mut doc, top, "rdp", Protocol::Rdp, "w.example", Some(cred));

        let plan = plan_connect_all(&doc, &v, &Policy::default(), top, &[open, open_without_login, Uuid::new_v4()]).unwrap();
        assert_eq!(plan, BulkConnectPlan { ready: vec![ready, rdp], needs_login: vec![none], skipped_open: vec![open, open_without_login], skipped_unsupported: vec![telnet], skipped_blocked: vec![] });
        assert_eq!(plan.to_connect(), 3, "ready and needs-login; the count the confirmation names");
    }

    #[test]
    fn a_login_saved_for_another_connection_on_the_same_host_is_never_used_silently() {
        let (mut doc, mut v) = (Document::new("t"), Vault::default());
        let cred = pw(&mut v, "admin");
        let top = folder(&mut doc, None, "Prod");
        let owner = conn(&mut doc, top, "ssh", Protocol::Ssh, "host.example", Some(cred));
        let borrower = conn(&mut doc, top, "rdp", Protocol::Rdp, "HOST.example", None);
        // The resolver does offer it; the plan still asks.
        let offered = bastion_core::logins::login_candidates(&doc, &v, borrower, bastion_core::logins::LoginPurpose::Password).unwrap();
        assert!(offered.iter().any(|c| c.credential == cred && !c.auto_use));
        let plan = plan_connect_all(&doc, &v, &Policy::default(), top, &[]).unwrap();
        assert_eq!(plan.ready, vec![owner]);
        assert_eq!(plan.needs_login, vec![borrower]);
    }

    #[test]
    fn inherited_logins_are_ready_and_rdp_needs_a_password() {
        let (mut doc, mut v) = (Document::new("t"), Vault::default());
        let (password, ssh_key) = (pw(&mut v, "ops"), key(&mut v, "deploy"));
        let with_pw = folder_with_login(&mut doc, None, "Passwords", Some(password));
        let inherits = conn(&mut doc, with_pw, "inherits", Protocol::Rdp, "a.example", None);
        let with_key = folder_with_login(&mut doc, None, "Keys", Some(ssh_key));
        let ssh = conn(&mut doc, with_key, "ssh", Protocol::Ssh, "b.example", None);
        let rdp = conn(&mut doc, with_key, "rdp", Protocol::Rdp, "c.example", None);
        let deleted = conn(&mut doc, with_key, "deleted", Protocol::Ssh, "d.example", Some(Uuid::new_v4()));

        assert_eq!(plan_connect_all(&doc, &v, &Policy::default(), with_pw, &[]).unwrap().ready, vec![inherits]);
        let plan = plan_connect_all(&doc, &v, &Policy::default(), with_key, &[]).unwrap();
        assert_eq!(plan.ready, vec![ssh]);
        assert_eq!(plan.needs_login, vec![rdp, deleted], "an SSH key is no RDP login; a deleted credential is no login");
    }

    #[test]
    fn a_connections_own_inline_secret_a_local_terminal_and_a_web_page_need_no_choice() {
        let (mut doc, mut v) = (Document::new("t"), Vault::default());
        let top = folder(&mut doc, None, "Lab");
        let inline = conn(&mut doc, top, "inline", Protocol::Ssh, "same.example", None);
        v.set_inline(inline, CredentialKind::Password { username: "me".into(), password: Secret::new("x") });
        let neighbour = conn(&mut doc, top, "neighbour", Protocol::Ssh, "same.example", None);
        let shell = conn(&mut doc, top, "shell", Protocol::Local, "", None);
        let page = conn(&mut doc, top, "page", Protocol::Web, "https://wiki.example", None);
        let rdp_with_key = conn(&mut doc, top, "rdp", Protocol::Rdp, "w.example", None);
        v.set_inline(rdp_with_key, CredentialKind::SshKey { username: "me".into(), private_key: Secret::new("k"), passphrase: None });

        let plan = plan_connect_all(&doc, &v, &Policy::default(), top, &[]).unwrap();
        assert_eq!(plan.ready, vec![inline, shell, page], "the inline secret is this connection's own; a local shell and a web page take no login");
        assert_eq!(plan.needs_login, vec![neighbour, rdp_with_key], "an inline secret never reaches the connection next to it");
    }

    #[test]
    fn an_empty_folder_gives_an_empty_plan() {
        let (mut doc, v) = (Document::new("t"), Vault::default());
        let top = folder(&mut doc, None, "Empty");
        folder(&mut doc, Some(top), "Also empty");
        let plan = plan_connect_all(&doc, &v, &Policy::default(), top, &[]).unwrap();
        assert_eq!(plan, BulkConnectPlan::default());
        assert_eq!(plan.to_connect(), 0);
        assert!(!plan.needs_confirmation());
    }

    #[test]
    fn an_unknown_folder_id_is_an_error_and_so_is_a_connection_id() {
        let (mut doc, v) = (Document::new("t"), Vault::default());
        let top = folder(&mut doc, None, "Prod");
        let c = conn(&mut doc, top, "c", Protocol::Ssh, "c.example", None);
        assert!(matches!(plan_connect_all(&doc, &v, &Policy::default(), Uuid::new_v4(), &[]), Err(CoreError::NotFound(_))));
        assert!(matches!(plan_connect_all(&doc, &v, &Policy::default(), c, &[]), Err(CoreError::NotFound(_))));
    }

    #[test]
    fn a_type_the_managed_policy_forbids_is_skipped_as_blocked_and_not_counted() {
        let (mut doc, mut v) = (Document::new("t"), Vault::default());
        let cred = pw(&mut v, "ops");
        let top = folder(&mut doc, None, "Prod");
        let ssh = conn(&mut doc, top, "ssh", Protocol::Ssh, "a.example", Some(cred));
        let rdp = conn(&mut doc, top, "rdp", Protocol::Rdp, "b.example", Some(cred));
        let rdp_open = conn(&mut doc, top, "rdp open", Protocol::Rdp, "c.example", Some(cred));
        let rdp_no_login = conn(&mut doc, top, "rdp bare", Protocol::Rdp, "d.example", None);
        let managed = Policy { denied_protocols: [Protocol::Rdp].into_iter().collect(), ..Policy::default() };
        let policy = Policy::default().with_managed(&managed);

        let plan = plan_connect_all(&doc, &v, &policy, top, &[rdp_open]).unwrap();
        assert_eq!(plan.ready, vec![ssh]);
        // Blocked wins over open and over needs-login: the policy is the reason it is not opened.
        assert_eq!(plan.skipped_blocked, vec![rdp, rdp_open, rdp_no_login]);
        assert!(plan.needs_login.is_empty() && plan.skipped_open.is_empty());
        assert_eq!(plan.to_connect(), 1, "blocked connections are not counted for the confirmation");
        // Without the managed file the same folder plans as before.
        assert!(plan_connect_all(&doc, &v, &Policy::default(), top, &[]).unwrap().skipped_blocked.is_empty());
    }

    #[test]
    fn more_than_the_cap_needs_a_confirmation_that_names_the_count() {
        let (mut doc, mut v) = (Document::new("t"), Vault::default());
        let cred = pw(&mut v, "ops");
        let top = folder(&mut doc, None, "Big");
        let mut ids: Vec<Uuid> = (0..CONNECT_ALL_CONFIRM_ABOVE).map(|i| conn(&mut doc, top, &format!("c{i}"), Protocol::Ssh, &format!("h{i}.example"), (i % 2 == 0).then_some(cred))).collect();
        let at_cap = plan_connect_all(&doc, &v, &Policy::default(), top, &[]).unwrap();
        assert_eq!(at_cap.to_connect(), CONNECT_ALL_CONFIRM_ABOVE);
        assert!(!at_cap.needs_confirmation());
        ids.push(conn(&mut doc, top, "one more", Protocol::Ssh, "more.example", None));
        let above = plan_connect_all(&doc, &v, &Policy::default(), top, &[]).unwrap();
        assert_eq!(above.to_connect(), CONNECT_ALL_CONFIRM_ABOVE + 1);
        assert!(above.needs_confirmation());
        // Open sessions do not count towards the cap: they are not connected again.
        assert!(!plan_connect_all(&doc, &v, &Policy::default(), top, &ids[..1]).unwrap().needs_confirmation());
    }

    #[test]
    fn connect_all_and_reconnect_all_are_implemented_and_follow_the_folder_state() {
        let folder_actions = actions::catalogue(ObjectKind::Folder);
        for id in [ActionId::ConnectAll, ActionId::DisconnectAll, ActionId::ReconnectAll] {
            assert_eq!(folder_actions.iter().find(|a| a.id == id).unwrap().backend, Backend::Implemented, "{id:?}");
        }
        let menu = |connections, open_sessions| {
            let cx = ActionContext { kind: Some(ObjectKind::Folder), descendant_connections: connections, open_sessions, ..Default::default() };
            actions::menu(&cx, &Policy::default(), &actions::all_ids())
        };
        let item = |m: &[actions::MenuItem], id| m.iter().find(|i| i.id == id).cloned().unwrap();
        let busy = menu(3, 2);
        let order: Vec<ActionId> = busy.iter().filter(|i| i.section == 4).map(|i| i.id).collect();
        assert_eq!(order, vec![ActionId::ConnectAll, ActionId::DisconnectAll, ActionId::ReconnectAll]);
        assert!(item(&busy, ActionId::ConnectAll).enabled && item(&busy, ActionId::ReconnectAll).enabled);
        let idle = menu(3, 0);
        assert!(item(&idle, ActionId::ConnectAll).enabled);
        assert_eq!(item(&idle, ActionId::ReconnectAll).disabled_reason.as_deref(), Some("No open sessions in this folder"));
        assert_eq!(item(&menu(0, 0), ActionId::ConnectAll).disabled_reason.as_deref(), Some("No connections in this folder"));
        // An app without a handler still does not show them.
        let cx = ActionContext { kind: Some(ObjectKind::Folder), descendant_connections: 3, ..Default::default() };
        assert!(actions::menu(&cx, &Policy::default(), &[ActionId::DisconnectAll]).iter().all(|i| i.id != ActionId::ConnectAll));
    }

    /// 5,000 connections in 50 top-level folders of 100; every tenth shares one host name, so
    /// the resolver's same-host step has work to do. Prints the time for one folder and for
    /// the whole library.
    #[test]
    #[ignore = "timing; run alone with --ignored --nocapture"]
    fn plan_connect_all_timing_on_5000_connections() {
        let (mut doc, mut v) = (Document::new("big"), Vault::default());
        let creds: Vec<Uuid> = (0..200).map(|i| pw(&mut v, &format!("cred-{i}"))).collect();
        let mut folders = Vec::new();
        for f in 0..50 {
            let top = folder(&mut doc, None, &format!("Customer {f}"));
            let sub = folder_with_login(&mut doc, Some(top), "Servers", (f % 2 == 0).then_some(creds[f]));
            for i in 0..100 {
                let n = f * 100 + i;
                let host = if i % 10 == 0 { "shared.example".to_string() } else { format!("host-{n}.example") };
                let p = if n % 2 == 0 { Protocol::Ssh } else { Protocol::Rdp };
                conn(&mut doc, if i % 2 == 0 { top } else { sub }, &format!("c{n}"), p, &host, (i % 3 == 0).then_some(creds[n % creds.len()]));
            }
            folders.push(top);
        }
        let time = |folder: Uuid, runs: u32| {
            let started = std::time::Instant::now();
            let mut plan = BulkConnectPlan::default();
            for _ in 0..runs {
                plan = plan_connect_all(&doc, &v, &Policy::default(), folder, &[]).unwrap();
            }
            (started.elapsed() / runs, plan)
        };
        let (one, plan) = time(*folders.last().unwrap(), 20);
        println!("plan_connect_all: folder of 100 in a library of 5000: {one:?} ({} ready, {} need a login)", plan.ready.len(), plan.needs_login.len());
        let (all, plan) = time(doc.root.id, 2);
        println!("plan_connect_all: whole library of 5000: {all:?} ({} ready, {} need a login)", plan.ready.len(), plan.needs_login.len());
        assert_eq!(plan.to_connect(), 5000);
        assert!(one < std::time::Duration::from_millis(100), "{one:?} for a folder of 100");
    }
}
