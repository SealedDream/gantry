use bastion_core::credtree::{assign_credential, credential_usages, effective_credential};
use bastion_core::export::{export, Selection};
use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use bastion_core::vault::{Credential, CredentialKind, Secret, Vault};
use uuid::Uuid;

const PASSWORD: &str = "pw-never-in-exports-5f1c";

fn password(name: &str, folder: Option<&str>) -> Credential {
    Credential {
        id: Uuid::new_v4(),
        name: name.into(),
        folder: folder.map(str::to_string),
        scope: None,
        owner: None,
        kind: CredentialKind::Password { username: "ops".into(), password: Secret::new(PASSWORD) },
    }
}

fn folder(name: &str) -> Folder {
    Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Settings::default(), children: vec![], dynamic_task_id: None, extra: Default::default() }
}

/// Library: Prod (folder) → Web (folder) → web1 (host); db1 (host) at the root.
fn library() -> (Document, Uuid, Uuid, Uuid, Uuid) {
    let mut doc = Document::new("Lib");
    let prod = folder("Prod");
    let web = folder("Web");
    let (prod_id, web_id) = (prod.id, web.id);
    let web1 = Connection::new("web1", Protocol::Ssh, "10.0.0.1");
    let db1 = Connection::new("db1", Protocol::Ssh, "10.0.0.2");
    let (web1_id, db1_id) = (web1.id, db1.id);
    doc.insert(None, Node::Folder(prod)).unwrap();
    doc.insert(Some(prod_id), Node::Folder(web)).unwrap();
    doc.insert(Some(web_id), Node::Connection(web1)).unwrap();
    doc.insert(None, Node::Connection(db1)).unwrap();
    (doc, prod_id, web_id, web1_id, db1_id)
}

#[test]
fn host_inherits_the_nearest_folder_credential_and_can_override_it() {
    let (mut doc, prod, web, web1, db1) = library();
    let mut vault = Vault::default();
    let a = vault.add(password("Prod admin", None));
    let b = vault.add(password("Web deploy", None));

    assign_credential(&mut doc, &vault, prod, Some(a)).unwrap();
    assert_eq!(effective_credential(&doc, web1), Some((a, prod)));
    assert_eq!(effective_credential(&doc, db1), None);

    assign_credential(&mut doc, &vault, web, Some(b)).unwrap();
    assert_eq!(effective_credential(&doc, web1), Some((b, web)));

    assign_credential(&mut doc, &vault, web1, Some(a)).unwrap();
    assert_eq!(effective_credential(&doc, web1), Some((a, web1)));
    assert_eq!(doc.resolve(web1).unwrap().effective.credential_id, Some(a));

    assign_credential(&mut doc, &vault, web1, None).unwrap();
    assert_eq!(effective_credential(&doc, web1), Some((b, web)), "None means inherit again");
}

#[test]
fn only_saved_credentials_can_be_assigned() {
    let (mut doc, prod, _, web1, _) = library();
    let mut vault = Vault::default();
    let cred_folder = vault.add_folder("Team", None).unwrap();
    vault.set_inline(web1, CredentialKind::Password { username: "x".into(), password: Secret::new("y") });

    assert!(assign_credential(&mut doc, &vault, prod, Some(cred_folder)).is_err(), "a folder cannot point at a credential folder");
    assert!(assign_credential(&mut doc, &vault, prod, Some(web1)).is_err(), "an inline secret is not shareable");
    assert!(assign_credential(&mut doc, &vault, prod, Some(Uuid::new_v4())).is_err());
    let c = vault.add(password("ok", None));
    assert!(assign_credential(&mut doc, &vault, Uuid::new_v4(), Some(c)).is_err(), "unknown node");
}

#[test]
fn rename_and_move_keep_references_working() {
    let (mut doc, prod, _, web1, _) = library();
    let mut vault = Vault::default();
    let c = vault.add(password("Prod admin", None));
    assign_credential(&mut doc, &vault, prod, Some(c)).unwrap();

    let team = vault.add_folder("Team", None).unwrap();
    let ops = vault.add_folder("Ops", Some(team)).unwrap();
    vault.move_credential(c, Some(ops)).unwrap();
    vault.rename_credential(c, "Root admin").unwrap();
    vault.rename_folder(team, "Platform").unwrap();
    assert_eq!(vault.folder_path(c).as_deref(), Some("Platform/Ops"));
    assert_eq!(vault.list()[0].folder.as_deref(), Some("Platform/Ops"));

    let infra = vault.add_folder("Infra", None).unwrap();
    vault.move_folder(ops, Some(infra)).unwrap();
    assert_eq!(vault.folder_path(c).as_deref(), Some("Infra/Ops"));
    assert_eq!(vault.folder_of(c), Some(ops), "the id never changes");
    assert_eq!(effective_credential(&doc, web1), Some((c, prod)));

    let tree = vault.credential_tree();
    let infra_node = tree.folders.iter().find(|f| f.name == "Infra").unwrap();
    assert_eq!(infra_node.folders[0].credentials[0].name, "Root admin");

    vault.move_credential(c, None).unwrap();
    assert_eq!(vault.folder_path(c), None);
    assert_eq!(vault.credential_tree().credentials[0].id, c);
}

#[test]
fn folder_rules_refuse_cycles_duplicates_and_bad_names() {
    let mut vault = Vault::default();
    let a = vault.add_folder("A", None).unwrap();
    let b = vault.add_folder("B", Some(a)).unwrap();
    assert!(vault.move_folder(a, Some(b)).is_err(), "into its own child");
    assert!(vault.move_folder(a, Some(a)).is_err(), "into itself");
    assert!(vault.add_folder("a", None).is_err(), "sibling names are unique, ignoring case");
    assert!(vault.add_folder("A", Some(b)).is_ok(), "the same name elsewhere is fine");
    for bad in ["", "   ", "x/y", "tab\there", &"n".repeat(129)] {
        assert!(vault.add_folder(bad, None).is_err(), "{bad:?}");
    }
    assert!(vault.add_folder("x", Some(Uuid::new_v4())).is_err(), "unknown parent");
    let mut parent = None;
    for i in 0..bastion_core::credtree::MAX_DEPTH {
        parent = Some(vault.add_folder(&format!("d{i}"), parent).unwrap());
    }
    assert!(vault.add_folder("too deep", parent).is_err());
}

#[test]
fn only_empty_folders_can_be_deleted() {
    let mut vault = Vault::default();
    let a = vault.add_folder("A", None).unwrap();
    let b = vault.add_folder("B", Some(a)).unwrap();
    let c = vault.add(password("c", None));
    vault.move_credential(c, Some(b)).unwrap();
    assert!(vault.remove_folder(a).is_err());
    assert!(vault.remove_folder(b).is_err());
    vault.move_credential(c, None).unwrap();
    vault.remove_folder(b).unwrap();
    vault.remove_folder(a).unwrap();
    assert!(vault.folders().is_empty());
}

#[test]
fn deleting_a_credential_in_use_warns_and_lists_its_users() {
    let (mut doc, prod, _, web1, db1) = library();
    let mut vault = Vault::default();
    let c = vault.add(password("Shared", None));
    assign_credential(&mut doc, &vault, prod, Some(c)).unwrap();
    assign_credential(&mut doc, &vault, db1, Some(c)).unwrap();

    let users = credential_usages(&doc, c);
    let names: Vec<_> = users.iter().map(|u| (u.name.as_str(), u.is_folder)).collect();
    assert_eq!(names, [("Prod", true), ("db1", false)], "web1 only inherits, so it is not listed");

    let out = vault.remove_checked(&mut doc, c, false).unwrap();
    assert!(!out.removed);
    assert_eq!(out.users.len(), 2);
    assert!(vault.get(c).is_some(), "nothing changed");
    assert_eq!(effective_credential(&doc, web1), Some((c, prod)));

    let out = vault.remove_checked(&mut doc, c, true).unwrap();
    assert!(out.removed);
    assert!(vault.get(c).is_none());
    assert!(credential_usages(&doc, c).is_empty());
    assert_eq!(effective_credential(&doc, web1), None);

    let unused = vault.add(password("Unused", None));
    assert!(vault.remove_checked(&mut doc, unused, false).unwrap().removed);
}

#[test]
fn the_tree_survives_seal_and_open_and_old_vaults_still_open() {
    let mut vault = Vault::default();
    let team = vault.add_folder("Team", None).unwrap();
    let c = vault.add(password("c", None));
    vault.move_credential(c, Some(team)).unwrap();
    let back = Vault::open(&vault.seal("master").unwrap(), "master").unwrap();
    assert_eq!(back.folders(), vault.folders());
    assert_eq!(back.folder_of(c), Some(team));

    let mut flat = Vault::default();
    let legacy = flat.add(password("legacy", Some("Old/Nested")));
    let plain = flat.add(password("plain", None));
    let back = Vault::open(&flat.seal("master").unwrap(), "master").unwrap();
    assert_eq!(back.folder_path(legacy).as_deref(), Some("Old/Nested"), "text folders become real folders");
    assert_eq!(back.folder_of(plain), None);
    assert_eq!(back.folders().len(), 2);
}

#[test]
fn library_exports_never_carry_a_secret() {
    let (mut doc, prod, _, _, db1) = library();
    let mut vault = Vault::default();
    let c = vault.add(password("Shared", None));
    assign_credential(&mut doc, &vault, prod, Some(c)).unwrap();
    assign_credential(&mut doc, &vault, db1, Some(c)).unwrap();
    let bytes = export(&doc, &Selection::All).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(PASSWORD));
    let tree = serde_json::to_string(&vault.credential_tree()).unwrap();
    assert!(!tree.contains(PASSWORD));
    let users = serde_json::to_string(&credential_usages(&doc, c)).unwrap();
    assert!(!users.contains(PASSWORD));
}
