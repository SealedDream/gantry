use super::*;

const SAMPLE: &str = include_str!("../tests/fixtures/mremoteng/confCons.xml");

fn names(i: &Imported) -> Vec<(String, String)> {
    i.found
        .iter()
        .map(|f| (f.path.join("/"), f.connection.name.clone()))
        .collect()
}

fn s(a: &str, b: &str) -> (String, String) {
    (a.into(), b.into())
}

#[test]
fn fixture_imports_expected_tree() {
    let i = mremoteng(SAMPLE).unwrap();
    assert_eq!(
        names(&i),
        vec![
            s("Servers", "web01"),
            s("Servers/Windows", "dc01"),
            s("Servers/Windows", "intranet"),
            s("Servers", "switch"),
            s("", "vnc-lab")
        ]
    );
    let web01 = &i.found[0].connection;
    assert_eq!(
        (web01.protocol, web01.host.as_str(), web01.settings.port),
        (Protocol::Ssh, "web01.lan", Some(2222))
    );
    assert_eq!(web01.settings.username.as_deref(), Some("admin"));
    let dc01 = &i.found[1].connection;
    assert_eq!((dc01.protocol, dc01.settings.port), (Protocol::Rdp, None));
    assert_eq!(
        dc01.settings.username.as_deref(),
        Some("CORP\\ops"),
        "username and domain inherited from the Windows folder"
    );
    assert_eq!(dc01.notes, "Domain controller\nprimary");
    assert_eq!(i.found[2].connection.host, "https://intranet.lan:8443");
    assert_eq!(i.found[3].connection.protocol, Protocol::Telnet);
    for want in [
        "dc01: password not imported",
        "RAW connections are not supported",
        "Rlogin connections are not supported",
        "IntApp connections are not supported",
        "Port must be a number",
        "Computer name must be",
    ] {
        assert!(
            i.skipped.iter().any(|x| x.contains(want)),
            "missing skipped line {want}: {:?}",
            i.skipped
        );
    }
    assert_eq!(i.skipped.len(), 6);
    let all = format!("{:?}", i.found);
    assert!(
        !all.contains("secret-cipher"),
        "no password text reaches a connection"
    );
    assert!(!all.contains("calc.exe"), "external app fields are ignored");
}

fn wrap(body: &str) -> String {
    format!("<?xml version=\"1.0\"?><mrng:Connections xmlns:mrng=\"x\" Name=\"Connections\">{body}</mrng:Connections>")
}

#[test]
fn hostname_is_never_inherited() {
    let x = wrap(
        r#"<Node Name="f" Type="Container" Hostname="parent.lan"><Node Name="c" Type="Connection" Protocol="SSH2" InheritHostname="True"/></Node>"#,
    );
    let i = mremoteng(&x).unwrap();
    assert!(i.found.is_empty());
    assert!(i.skipped[0].contains("no host name"));
}

#[test]
fn inherited_port_is_validated() {
    let x = wrap(
        r#"<Node Name="f" Type="Container" Port="0"><Node Name="c" Hostname="h" Protocol="SSH2" InheritPort="True"/></Node>"#,
    );
    let i = mremoteng(&x).unwrap();
    assert!(i.found.is_empty() && i.skipped[0].contains("Port must be"));
}

#[test]
fn entity_and_doctype_are_refused_quickly() {
    let defs: String = (0..10)
        .map(|n| format!("<!ENTITY a{} \"{}\">", n + 1, format!("&a{n};").repeat(10)))
        .collect();
    let bomb = format!(
        "<?xml version=\"1.0\"?><!DOCTYPE l [<!ENTITY a0 \"aaaa\">{defs}]>{}",
        wrap("<Node Name=\"&a10;\" Hostname=\"h\"/>")
    );
    let t = std::time::Instant::now();
    assert!(mremoteng(&bomb).unwrap_err().to_string().contains("DTD"));
    assert!(t.elapsed().as_millis() < 100);
}

#[test]
fn too_large_file_is_refused() {
    let big = "a".repeat(crate::export::MAX_IMPORT_BYTES + 1024 * 1024);
    assert!(mremoteng(&big).unwrap_err().to_string().contains("64 MiB"));
}

#[test]
fn deep_tree_is_refused() {
    let open: String = (0..40)
        .map(|n| format!("<Node Name=\"f{n}\" Type=\"Container\">"))
        .collect();
    let x = wrap(&format!("{open}{}", "</Node>".repeat(40)));
    assert!(mremoteng(&x).unwrap_err().to_string().contains("deeper"));
}

#[test]
fn huge_attribute_is_refused() {
    let x = wrap(&format!(
        "<Node Name=\"c\" Hostname=\"h\" Descr=\"{}\"/>",
        "x".repeat(MAX_ATTR_BYTES + 1)
    ));
    assert!(mremoteng(&x).unwrap_err().to_string().contains("Descr"));
}

#[test]
fn too_many_nodes_are_refused() {
    let x = wrap(&"<Node Name=\"c\" Hostname=\"h\"/>".repeat(MAX_NODES + 1));
    assert!(mremoteng(&x).unwrap_err().to_string().contains("entries"));
}

#[test]
fn fully_encrypted_file_is_refused() {
    let x = "<mrng:Connections FullFileEncryption=\"true\">abc</mrng:Connections>";
    assert!(mremoteng(x)
        .unwrap_err()
        .to_string()
        .contains("fully encrypted"));
}

#[test]
fn non_mremoteng_text_is_refused() {
    assert!(mremoteng("<RDCMan/>").is_err());
    assert!(mremoteng("").is_err());
    assert!(mremoteng("<Node Name=\"c\" Hostname=\"h\"/>").is_err());
}

#[test]
fn every_truncation_of_the_fixture_is_handled() {
    for end in (0..SAMPLE.len()).filter(|e| SAMPLE.is_char_boundary(*e)) {
        let _ = mremoteng(&SAMPLE[..end]);
    }
}

#[test]
fn random_inputs_never_panic() {
    // Deterministic xorshift so a failure reproduces.
    let mut r: u64 = 0x9E37_79B9_7F4A_7C15;
    let alphabet: Vec<char> = "<>/=\"' !-?NodeTypeContainerConnectionsHostnamePortInherit&;#xA\né"
        .chars()
        .collect();
    for _ in 0..3000 {
        let mut t = String::from("<Connections>");
        for _ in 0..(r % 300) {
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            t.push(alphabet[(r % alphabet.len() as u64) as usize]);
        }
        let _ = mremoteng(&t);
    }
}
