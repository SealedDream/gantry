//! A1-CORE-01 through the UniFFI surface Native Mac uses: `auto_use` on each login, the `named`
//! source, and no release of a password the scope rules leave out. Generated data only.
use std::sync::Arc;

use bastion_ffi::{CredentialVault, Library};

fn setup() -> (tempfile::TempDir, Arc<Library>, CredentialVault) {
    let dir = tempfile::tempdir().unwrap();
    let lib = Library::open(dir.path().join("library.json").to_str().unwrap().to_owned()).unwrap();
    let vault = CredentialVault::open_ephemeral(dir.path().join("c.vault").to_str().unwrap().to_owned()).unwrap();
    (dir, Arc::new(lib), vault)
}

fn add(lib: &Library, parent: &str, name: &str, protocol: &str, host: &str) -> String {
    lib.add_connection(Some(parent.into()), name.into(), protocol.into(), host.into(), None, None).unwrap()
}

/// `(source, auto_use, credential id)` of every login offered to `connection`.
fn offered(vault: &CredentialVault, lib: &Arc<Library>, connection: &str) -> Vec<(String, bool, String)> {
    vault.login_candidates(lib.clone(), connection.into(), true).unwrap().into_iter().map(|l| (l.source, l.auto_use, l.credential_id)).collect()
}

#[test]
fn own_and_inherited_logins_are_auto_used_and_a_same_host_login_is_only_offered() {
    let (_dir, lib, vault) = setup();
    let lab = lib.add_folder(None, "Lab".into()).unwrap();
    let ssh = add(&lib, &lab, "srv ssh", "ssh", "srv.lab.example");
    let rdp = add(&lib, &lab, "srv rdp", "rdp", "srv.lab.example");
    let admin = vault.save_password(None, "Admin".into(), None, "admin".into(), "pw-admin".into()).unwrap();
    let deploy = vault.save_password(None, "Deploy".into(), None, "deploy".into(), "pw-deploy".into()).unwrap();
    let team = vault.save_password(None, "Team".into(), None, "team".into(), "pw-team".into()).unwrap();
    vault.add_login(lib.clone(), ssh.clone(), admin.clone()).unwrap();
    lib.set_property(ssh.clone(), "credential_name".into(), Some("deploy".into())).unwrap();
    lib.set_property(lab.clone(), "credential_name".into(), Some("Team".into())).unwrap();

    assert_eq!(offered(&vault, &lib, &ssh), vec![("default".to_string(), true, admin.clone()), ("named".to_string(), true, deploy.clone())]);
    assert_eq!(
        offered(&vault, &lib, &rdp),
        vec![("inherited".to_string(), true, team), ("same-host".to_string(), false, admin.clone()), ("same-host".to_string(), false, deploy)]
    );
    let same_host = vault.login_candidates(lib.clone(), rdp.clone(), true).unwrap().remove(1);
    assert_eq!((same_host.source_id.as_deref(), same_host.source_name.as_str()), (Some(ssh.as_str()), "srv ssh"));
    // Offered, so it is released once the app has the user's yes.
    assert_eq!(vault.release_login(lib.clone(), rdp, admin).unwrap().username, "admin");
}

#[test]
fn a_password_is_not_released_across_top_level_folders_a_boundary_or_loopback() {
    let (_dir, lib, vault) = setup();
    let acme = lib.add_folder(None, "Acme".into()).unwrap();
    let globex = lib.add_folder(None, "Globex".into()).unwrap();
    let fenced = lib.add_folder(Some(acme.clone()), "Fenced".into()).unwrap();
    let a = add(&lib, &acme, "acme db", "ssh", "10.0.0.5");
    let inside = add(&lib, &fenced, "fenced db", "rdp", "10.0.0.5");
    let g = add(&lib, &globex, "globex db", "rdp", "10.0.0.5");
    let forward_a = add(&lib, &acme, "forward 2222", "ssh", "127.0.0.1");
    let forward_b = add(&lib, &acme, "forward 2223", "rdp", "127.0.0.1");
    let pw = vault.save_password(None, "Acme db".into(), None, "dba".into(), "pw-acme".into()).unwrap();
    let local = vault.save_password(None, "Forward".into(), None, "root".into(), "pw-local".into()).unwrap();
    vault.add_login(lib.clone(), a.clone(), pw.clone()).unwrap();
    vault.add_login(lib.clone(), forward_a, local.clone()).unwrap();
    let refused = |connection: &str, credential: &str| {
        assert!(offered(&vault, &lib, connection).is_empty(), "nothing is offered");
        let e = vault.release_login(lib.clone(), connection.into(), credential.into()).map(|_| ()).expect_err("must not be released");
        let message = e.to_string();
        assert!(message.contains("not offered") && !message.contains("pw-"), "{message}");
    };

    assert_eq!(offered(&vault, &lib, &inside), vec![("same-host".to_string(), false, pw.clone())], "one top-level folder");
    refused(&g, &pw);
    refused(&forward_b, &local);
    lib.set_property(fenced.clone(), "credential_boundary".into(), Some("true".into())).unwrap();
    refused(&inside, &pw);
    lib.set_property(fenced, "credential_boundary".into(), None).unwrap();
    assert_eq!(offered(&vault, &lib, &inside).len(), 1);
}
