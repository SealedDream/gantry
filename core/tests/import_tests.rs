use bastion_core::import::{decode_text, into_folder, putty_reg, rdcman, royal_json};
use bastion_core::model::{Node, Protocol};

#[test]
fn putty_reg_imports_ssh_telnet_and_serial_sessions() {
    let reg = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]
"HostName"=""

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\web%20server]
"HostName"="web.example.com"
"PortNumber"=dword:00000016
"Protocol"="ssh"
"UserName"="deploy"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\switch]
"HostName"="10.0.0.2"
"PortNumber"=dword:00000017
"Protocol"="telnet"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\console]
"SerialLine"="COM3"
"Protocol"="serial"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\raw]
"HostName"="h"
"Protocol"="raw"
"#;
    let r = putty_reg(reg).unwrap();
    let names: Vec<_> = r.found.iter().map(|f| (f.connection.name.as_str(), f.connection.protocol, f.connection.host.as_str(), f.connection.settings.port)).collect();
    assert_eq!(names, vec![("web server", Protocol::Ssh, "web.example.com", Some(22)), ("switch", Protocol::Telnet, "10.0.0.2", Some(23)), ("console", Protocol::Serial, "COM3", None)]);
    assert_eq!(r.found[0].connection.settings.username.as_deref(), Some("deploy"));
    assert_eq!(r.skipped, vec!["raw: raw sessions are not supported".to_string()]);
    assert!(putty_reg("HostName=x").is_err());
}

#[test]
fn utf16_reg_export_is_decoded() {
    let text = "Windows Registry Editor Version 5.00\r\n";
    let mut bytes = vec![0xff, 0xfe];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    assert_eq!(decode_text(&bytes).unwrap(), text);
    assert!(decode_text(&[0xc3, 0x28]).is_err());
}

#[test]
fn royal_json_keeps_folders_and_never_reads_passwords() {
    let json = r#"{"Objects":[
        {"Type":"Folder","Name":"Prod","Objects":[
            {"Type":"RemoteDesktopConnection","Name":"dc01","ComputerName":"10.1.0.10","Username":"CORP\\admin","Password":"hunter2"},
            {"Type":"TerminalConnection","Name":"web","ComputerName":"web.prod","Port":2222,"Path":"Linux/Web","Tags":"linux, web"}
        ]},
        {"Type":"WebConnection","Name":"portal","URL":"https://portal.example.com"},
        {"Type":"Credential","Name":"svc"}
    ]}"#;
    let r = royal_json(json).unwrap();
    assert_eq!(r.found.len(), 3);
    assert_eq!(r.found[0].path, vec!["Prod"]);
    assert_eq!(r.found[1].path, vec!["Prod", "Linux", "Web"]);
    assert_eq!(r.found[1].connection.settings.port, Some(2222));
    assert_eq!(r.found[1].connection.tags, vec!["linux", "web"]);
    assert_eq!(r.found[2].connection.host, "https://portal.example.com");
    assert!(r.skipped.iter().any(|s| s.contains("dc01: password not imported")));
    assert!(r.skipped.iter().any(|s| s.contains("Credential objects")));
    let all = format!("{:?}", r.found);
    assert!(!all.contains("hunter2"));
    assert!(royal_json("{}").is_err());
}

#[test]
fn rdcman_groups_become_folders_and_passwords_are_skipped() {
    let rdg = r#"<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.7" schemaVersion="3">
  <file>
    <properties><name>Lab</name></properties>
    <group>
      <properties><name>Prod &amp; DR</name></properties>
      <server>
        <properties><name>srv1.example.com</name><displayName>SRV1</displayName></properties>
        <logonCredentials inherit="None"><profileName scope="Local">Custom</profileName><userName>admin</userName><password>AQAAANCMnd8BFdER</password><domain>CORP</domain></logonCredentials>
        <connectionSettings inherit="None"><port>3390</port></connectionSettings>
      </server>
      <group><properties><name>Sub</name></properties>
        <server><properties><name>srv2</name></properties></server>
      </group>
    </group>
    <server><name>legacy-host</name></server>
    <!-- <server><name>commented</name></server> -->
  </file>
</RDCMan>"#;
    let r = rdcman(rdg).unwrap();
    let v: Vec<_> = r.found.iter().map(|f| (f.path.join("/"), f.connection.name.clone(), f.connection.host.clone(), f.connection.settings.port)).collect();
    assert_eq!(v, vec![("Prod & DR".into(), "SRV1".into(), "srv1.example.com".into(), Some(3390)), ("Prod & DR/Sub".into(), "srv2".into(), "srv2".into(), None), ("".into(), "legacy-host".into(), "legacy-host".into(), None)]);
    assert_eq!(r.found[0].connection.settings.username.as_deref(), Some("admin"));
    assert_eq!(r.skipped, vec!["SRV1: password not imported (use the vault)".to_string()]);
    assert!(!format!("{:?}", r.found).contains("AQAAANC"));
    assert!(rdcman("<xml/>").is_err());
}

#[test]
fn found_connections_are_placed_in_nested_folders() {
    let r = royal_json(r#"{"Objects":[{"Type":"TerminalConnection","Name":"a","ComputerName":"a","Path":"X/Y"},{"Type":"TerminalConnection","Name":"b","ComputerName":"b","Path":"X"}]}"#).unwrap();
    let f = into_folder("Imported", r.found);
    let Node::Folder(x) = &f.children[0] else { panic!() };
    assert_eq!(x.name, "X");
    assert_eq!(x.children.len(), 2);
    assert!(matches!(&x.children[0], Node::Folder(y) if y.name == "Y" && y.children.len() == 1));
}

#[test]
fn utf16_with_a_dangling_final_byte_is_refused_in_both_byte_orders() {
    for text in ["", "a", "Résumé ✓ 𝄞", "host=example\r\n"] {
        let le: Vec<u8> = [0xff, 0xfe].into_iter().chain(text.encode_utf16().flat_map(u16::to_le_bytes)).collect();
        let be: Vec<u8> = [0xfe, 0xff].into_iter().chain(text.encode_utf16().flat_map(u16::to_be_bytes)).collect();
        assert_eq!(decode_text(&le).unwrap(), text);
        assert_eq!(decode_text(&be).unwrap(), text);
        for extra in 0..=255u8 {
            let mut odd = le.clone();
            odd.push(extra);
            assert!(decode_text(&odd).is_err(), "LE {text:?} + {extra:#04x}");
            let mut odd = be.clone();
            odd.push(extra);
            assert!(decode_text(&odd).is_err(), "BE {text:?} + {extra:#04x}");
        }
    }
}
