use bastion_core::ansible_inventory::{export_document, export_document_as, Format};
use bastion_core::export::Selection;
use bastion_core::model::{Connection, Document, Node, Protocol};

fn ssh(name: &str, host: &str) -> Connection {
    Connection::new(name, Protocol::Ssh, host)
}

#[test]
fn writes_ssh_hosts_and_skips_unsafe_or_other_protocols() {
    let mut d = Document::new("Lab");
    let mut web = ssh("web-1", "10.0.0.5");
    web.settings.username = Some("deploy".into());
    web.settings.port = Some(2222);
    web.metadata.insert("api_token".into(), "SHOULD-NOT-LEAK".into());
    d.insert(None, Node::Connection(web)).unwrap();
    d.insert(None, Node::Connection(ssh("bad name", "10.0.0.6"))).unwrap();
    d.insert(None, Node::Connection(ssh("evil", "h ansible_connection=local"))).unwrap();
    d.insert(None, Node::Connection(Connection::new("pc", Protocol::Rdp, "pc.home"))).unwrap();
    let (text, skipped) = export_document(&d, &Selection::All);
    assert!(text.contains("[bastion]\n"));
    assert!(text.contains("web-1 ansible_host=10.0.0.5 ansible_user=deploy ansible_port=2222\n"), "{text}");
    assert!(!text.contains("SHOULD-NOT-LEAK") && !text.contains("local") && !text.contains("bad name"));
    assert_eq!(skipped.len(), 3, "{skipped:?}");
}

#[test]
fn default_port_is_left_out() {
    let mut d = Document::new("Lab");
    let mut c = ssh("a", "h.example");
    c.settings.port = Some(22);
    d.insert(None, Node::Connection(c)).unwrap();
    let (text, _) = export_document(&d, &Selection::All);
    assert!(text.contains("a ansible_host=h.example\n") && !text.contains("ansible_port"), "{text}");
}

#[test]
fn yaml_has_the_same_hosts_quoted() {
    let mut d = Document::new("Lab");
    let mut c = ssh("web-1", "::1");
    c.settings.username = Some("deploy".into());
    d.insert(None, Node::Connection(c)).unwrap();
    let (text, skipped) = export_document_as(&d, &Selection::All, Format::Yaml);
    assert!(skipped.is_empty());
    assert!(text.contains("all:\n  children:\n    bastion:\n      hosts:\n        web-1:\n          ansible_host: \"::1\"\n          ansible_user: \"deploy\"\n"), "{text}");
    let (empty, _) = export_document_as(&Document::new("x"), &Selection::All, Format::Yaml);
    assert!(empty.contains("hosts: {}"));
}
