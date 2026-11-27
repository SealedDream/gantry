use super::*;

fn row(name: &str, host: &str, protocol: &str) -> Row {
    Row { name: name.into(), host: host.into(), protocol: protocol.into() }
}

fn lab() -> (Document, Uuid) {
    let mut doc = Document::new("t");
    let mut f = empty_folder("Lab".into());
    let id = f.id;
    let mut c = Connection::new("web", Protocol::Ssh, "10.0.0.5");
    c.settings.port = Some(22);
    f.children.push(Node::Connection(c));
    doc.insert(None, Node::Folder(f)).unwrap();
    (doc, id)
}

fn conns(doc: &Document, folder: Uuid) -> Vec<(String, String, Protocol, Option<u16>, Option<Uuid>)> {
    doc.folder(folder).unwrap().children.iter().filter_map(|n| match n {
        Node::Connection(c) => Some((c.name.clone(), c.host.clone(), c.protocol, c.settings.port, c.settings.credential_id)),
        _ => None,
    }).collect()
}

#[test]
fn saves_rows_into_the_folder_with_default_ports_and_the_credential() {
    let (mut doc, lab) = lab();
    let cred = Uuid::new_v4();
    let saved = save(&mut doc, &Target { folder: Some(lab), new_folder: None }, &[row("dc01", "DC01.corp.example", "rdp"), row("vnc", "10.0.0.9", "vnc")], Some(cred)).unwrap();
    assert_eq!(saved.ids.len(), 2);
    let c = conns(&doc, lab);
    assert_eq!(c[1], ("dc01".into(), "dc01.corp.example".into(), Protocol::Rdp, Some(3389), Some(cred)));
    assert_eq!(c[2].3, Some(5900));
}

#[test]
fn same_host_and_protocol_in_the_folder_is_a_duplicate_and_skipped() {
    let (mut doc, lab) = lab();
    let rows = [row("web again", "10.0.0.5", "ssh"), row("web rdp", "10.0.0.5", "rdp"), row("twice", "10.0.0.7", "ssh"), row("twice", "10.0.0.7", "ssh")];
    assert_eq!(duplicates(&doc, Some(lab), &rows), vec![true, false, false, true]);
    let saved = save(&mut doc, &Target { folder: Some(lab), new_folder: None }, &rows, None).unwrap();
    assert_eq!(saved.duplicates, vec![0, 3]);
    assert_eq!(conns(&doc, lab).len(), 3);
}

#[test]
fn a_new_folder_is_made_under_the_target() {
    let (mut doc, lab) = lab();
    let saved = save(&mut doc, &Target { folder: Some(lab), new_folder: Some(" Proxmox ".into()) }, &[row("web", "10.0.0.5", "ssh")], None).unwrap();
    let f = saved.folder.unwrap();
    assert_eq!(doc.folder(f).unwrap().name, "Proxmox");
    assert_eq!(doc.parent_of(f), Some(lab));
    assert!(saved.duplicates.is_empty(), "the new folder is empty, so nothing is a duplicate");
    assert_eq!(conns(&doc, f).len(), 1);
}

#[test]
fn one_bad_row_saves_nothing() {
    for bad in [row("x", "127.0.0.1", "ssh"), row("x", "169.254.169.254", "ssh"), row("x", "", "ssh"), row("", "10.0.0.8", "ssh"), row("x", "10.0.0.8", "telnet"), row("x", "a b", "ssh")] {
        let (mut doc, lab) = lab();
        assert!(save(&mut doc, &Target { folder: Some(lab), new_folder: None }, &[row("ok", "10.0.0.8", "ssh"), bad.clone()], None).is_err(), "{bad:?}");
        assert_eq!(conns(&doc, lab).len(), 1);
    }
}

#[test]
fn a_missing_folder_or_empty_list_is_refused() {
    let (mut doc, _) = lab();
    assert!(save(&mut doc, &Target { folder: Some(Uuid::new_v4()), new_folder: None }, &[row("a", "10.0.0.8", "ssh")], None).is_err());
    assert!(save(&mut doc, &Target::default(), &[], None).is_err());
    let top = save(&mut doc, &Target::default(), &[row("a", "10.0.0.8", "ssh")], None).unwrap();
    assert_eq!(top.ids.len(), 1);
}
