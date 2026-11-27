use super::*;
use crate::model::Protocol;

fn web_template() -> Template {
    let mut c = Connection::new("$Host$ console", Protocol::Web, "https://$Host$:$Port$");
    c.notes = "Customer $Customer$".into();
    Template { connection: c, port: None }
}

fn doc_with(t: Template) -> (Document, Uuid) {
    let mut d = Document::new("lib");
    let id = d.add_template(t).unwrap();
    (d, id)
}

fn vals(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn tokens_are_listed_once_in_order() {
    let (d, id) = doc_with(web_template());
    assert_eq!(d.template_tokens(id).unwrap(), vec!["Host", "Port", "Customer"]);
}

#[test]
fn two_token_template_makes_a_valid_connection() {
    let mut c = Connection::new("$Name$", Protocol::Ssh, "$Host$");
    c.settings.username = Some("admin".into());
    let (mut d, id) = doc_with(Template { connection: c, port: Some("22".into()) });
    let new_id = d.instantiate_template(id, &vals(&[("name", "web1"), ("HOST", "10.0.0.5")]), None).unwrap();
    let r = d.resolve(new_id).unwrap();
    assert_eq!((r.connection.name.as_str(), r.connection.host.as_str()), ("web1", "10.0.0.5"));
    assert_eq!(r.connection.settings.port, Some(22));
    assert_eq!(r.connection.settings.username.as_deref(), Some("admin"));
}

#[test]
fn web_console_from_an_rdp_host() {
    let (mut d, id) = doc_with(web_template());
    let new_id = d.instantiate_template(id, &vals(&[("Host", "srv1"), ("Port", "8443"), ("Customer", "Acme")]), None).unwrap();
    let c = d.resolve(new_id).unwrap().connection;
    assert_eq!(c.host, "https://srv1:8443");
    assert_eq!(c.notes, "Customer Acme");
}

#[test]
fn missing_and_extra_values_are_refused() {
    let (mut d, id) = doc_with(web_template());
    let missing = d.instantiate_template(id, &vals(&[("Host", "a"), ("Port", "1")]), None).unwrap_err();
    assert!(missing.to_string().contains("Customer"));
    let extra = vals(&[("Host", "a"), ("Port", "1"), ("Customer", "c"), ("Other", "x")]);
    assert!(d.instantiate_template(id, &extra, None).is_err());
    assert!(d.connections().is_empty(), "nothing written on error");
}

#[test]
fn invalid_host_gets_the_normal_message() {
    let (mut d, id) = doc_with(Template { connection: Connection::new("n", Protocol::Ssh, "$Host$"), port: None });
    let e = d.instantiate_template(id, &vals(&[("Host", "bad host")]), None).unwrap_err();
    assert!(e.to_string().contains("Computer name must be a single host name"), "{e}");
    let e = d.instantiate_template(id, &vals(&[("Host", "-oProxyCommand=x")]), None).unwrap_err();
    assert!(e.to_string().contains("Computer name"), "{e}");
}

#[test]
fn port_out_of_range_is_refused() {
    let t = Template { connection: Connection::new("n", Protocol::Ssh, "h"), port: Some("$Port$".into()) };
    let (mut d, id) = doc_with(t);
    assert!(d.instantiate_template(id, &vals(&[("Port", "0")]), None).is_err());
    assert!(d.instantiate_template(id, &vals(&[("Port", "70000")]), None).is_err());
    assert!(d.instantiate_template(id, &vals(&[("Port", "2222")]), None).is_ok());
}

#[test]
fn file_url_is_refused_on_save_and_on_use() {
    let mut d = Document::new("lib");
    let bad = Template { connection: Connection::new("n", Protocol::Web, "file://$Host$"), port: None };
    assert!(d.add_template(bad).is_err());
    let (mut d, id) = doc_with(Template { connection: Connection::new("n", Protocol::Web, "$Url$"), port: None });
    assert!(d.instantiate_template(id, &vals(&[("Url", "file:///etc/passwd")]), None).is_err());
    assert!(d.instantiate_template(id, &vals(&[("Url", "https://ok.example")]), None).is_ok());
}

#[test]
fn token_values_are_capped_and_control_free() {
    let (mut d, id) = doc_with(Template { connection: Connection::new("$N$", Protocol::Ssh, "h"), port: None });
    let long = "a".repeat(MAX_TOKEN_VALUE + 1);
    assert!(d.instantiate_template(id, &vals(&[("N", &long)]), None).is_err());
    assert!(d.instantiate_template(id, &vals(&[("N", "a\u{7}b")]), None).is_err());
}

#[test]
fn tokens_outside_the_token_fields_are_refused() {
    let mut c = Connection::new("n", Protocol::Ssh, "h");
    c.settings.wol_mac = Some("$Mac$".into());
    let mut d = Document::new("lib");
    assert!(d.add_template(Template { connection: c, port: None }).is_err());
}

#[test]
fn template_mode_lets_token_fields_save() {
    let t = Template { connection: Connection::new("x", Protocol::Ssh, "$Host$"), port: Some("$Port$".into()) };
    assert!(Document::new("lib").add_template(t).is_ok());
}

#[test]
fn secrets_never_expand() {
    // A value that looks like a token is inserted as text, never looked up again.
    let (mut d, id) = doc_with(Template { connection: Connection::new("$N$", Protocol::Ssh, "h"), port: None });
    let new_id = d.instantiate_template(id, &vals(&[("N", "$Password$")]), None).unwrap();
    assert_eq!(d.resolve(new_id).unwrap().connection.name, "$Password$");
}

#[test]
fn a_template_is_never_resolved() {
    let (d, id) = doc_with(web_template());
    assert!(d.resolve(id).is_err());
    assert!(d.resolve_many(&[id]).is_err());
    assert!(d.resolve_where(|_, _| true).is_empty());
}

#[test]
fn save_as_template_keeps_the_reference_and_drops_secrets() {
    let mut d = Document::new("lib");
    let mut c = Connection::new("srv", Protocol::Rdp, "srv1");
    let cred = Uuid::new_v4();
    c.settings.credential_id = Some(cred);
    c.settings.credential_confirmed = vec![cred];
    c.settings.wol_secureon = Some("secret".into());
    let src = c.id;
    d.insert(None, Node::Connection(c)).unwrap();
    let tid = d.save_as_template(src, "RDP template").unwrap();
    let t = d.template(tid).unwrap();
    assert_ne!(tid, src);
    assert_eq!(t.connection.settings.credential_id, Some(cred));
    assert!(t.connection.settings.credential_confirmed.is_empty());
    assert_eq!(t.connection.settings.wol_secureon, None);
}

#[test]
fn credential_use_starts_unconfirmed() {
    let mut c = Connection::new("n", Protocol::Ssh, "$Host$");
    c.settings.credential_id = Some(Uuid::new_v4());
    let (mut d, id) = doc_with(Template { connection: c, port: None });
    let new_id = d.instantiate_template(id, &vals(&[("Host", "h")]), None).unwrap();
    let s = d.resolve(new_id).unwrap().connection.settings;
    assert_eq!(s.credential_unconfirmed, Some(true));
    assert!(s.credential_confirmed.is_empty());
}

#[test]
fn update_and_delete() {
    let (mut d, id) = doc_with(web_template());
    let mut t = d.template(id).unwrap().clone();
    t.connection.name = "renamed".into();
    d.update_template(t).unwrap();
    assert_eq!(d.template(id).unwrap().connection.name, "renamed");
    d.delete_template(id).unwrap();
    assert!(d.delete_template(id).is_err());
}

#[test]
fn templates_survive_a_save_and_load_round_trip() {
    let (d, _) = doc_with(web_template());
    let json = serde_json::to_string(&d).unwrap();
    let back: Document = serde_json::from_str(&json).unwrap();
    assert_eq!(back.templates, d.templates);
}

#[test]
fn library_without_templates_does_not_write_the_field() {
    let json = serde_json::to_string(&Document::new("lib")).unwrap();
    assert!(!json.contains("\"templates\""));
}
