//! Journey 3: malformed CSV must not silently change connection destinations or data.
use bastion_core::import;

#[test]
fn unicode_csv_preserves_quoted_commas_and_escaped_quotes() {
    let rows = import::csv(
        "name,host,protocol,port,notes\n\"日本, café\",127.0.0.1,ssh,2222,\"say \"\"hello\"\"\"\n",
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "日本, café");
    assert_eq!(rows[0].settings.port, Some(2222));
    assert_eq!(rows[0].notes, "say \"hello\"");
}

#[test]
fn invalid_explicit_csv_ports_are_rejected() {
    for port in ["70000", "-1", "not-a-port"] {
        let text = format!("name,host,protocol,port\nlab,127.0.0.1,ssh,{port}\n");
        assert!(
            import::csv(&text).is_err(),
            "explicit invalid port {port} must not become the protocol default"
        );
    }
}

#[test]
fn malformed_csv_quotes_are_rejected() {
    assert!(import::csv("name,host,protocol,notes\nlab,127.0.0.1,ssh,\"unfinished\n").is_err());
}

#[test]
fn valid_multiline_csv_notes_round_trip() {
    let rows = import::csv("name,host,protocol,notes\nlab,127.0.0.1,ssh,\"line one\nline two\"\n")
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].notes, "line one\nline two");
}

#[test]
fn protected_export_keeps_credentials_inherited_from_type_defaults() {
    use bastion_core::docfile::{self, DocumentFile};
    use bastion_core::export::Selection;
    use bastion_core::model::{Connection, Document, Node, Protocol, Settings};
    use bastion_core::vault::{Credential, CredentialKind, Secret};
    use uuid::Uuid;

    let id = Uuid::new_v4();
    let mut document = Document::new("QA inherited credentials");
    document.type_defaults.insert(
        Protocol::Ssh,
        Settings {
            credential_id: Some(id),
            ..Default::default()
        },
    );
    document
        .insert(
            None,
            Node::Connection(Connection::new("lab", Protocol::Ssh, "127.0.0.1")),
        )
        .unwrap();
    let mut source = DocumentFile::from_document(document);
    source
        .set_password(Some("generated-source-password"))
        .unwrap();
    source
        .put_credential(Credential {
            id,
            name: "Inherited QA credential".into(),
            folder: None,
            scope: None,
            owner: None,
            kind: CredentialKind::Password {
                username: "tester".into(),
                password: Secret::new("generated-export-canary"),
            },
        })
        .unwrap();
    let (out, summary) = docfile::export(
        &source,
        &Selection::All,
        "Export",
        true,
        Some("generated-export-password"),
    )
    .unwrap();
    assert_eq!(
        out.document().unwrap().type_defaults[&Protocol::Ssh].credential_id,
        Some(id)
    );
    assert_eq!(
        summary.credentials, 1,
        "include-secrets export must include an effective credential"
    );
    assert_eq!(out.credentials().unwrap()[0].id, id);
}

#[test]
fn csv_accepts_crlf_bom_and_valid_ports_but_rejects_port_zero_and_stray_quotes() {
    let rows = import::csv("\u{feff}name,host,protocol,port\r\na,10.0.0.1,ssh,22\r\nb,10.0.0.2,ssh,\r\n").unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].settings.port, Some(22));
    assert_eq!(rows[1].settings.port, None, "an empty port cell keeps the protocol default");
    assert!(import::csv("name,host,protocol,port\na,10.0.0.1,ssh,0\n").is_err());
    assert!(import::csv("name,host,protocol\na\"b,10.0.0.1,ssh\n").is_err());
    assert!(import::csv("name,host,protocol\n\"a\"x,10.0.0.1,ssh\n").is_err());
}
