//! FTPS against a throwaway `bastion-ftps-test` container (docs/TESTING.md):
//! `docker run -d --name ftps-test -p 127.0.0.1:2121:21 -p 127.0.0.1:30100-30109:30100-30109 bastion-ftps-test`
//! then `BASTION_FTPS_TEST=2121 BASTION_FTPS_PASSWORD=… cargo test --test ftp_integration`.
use std::time::Duration;

use bastion_core::ftp::{FtpParams, FtpSecurity, FtpSession};
use bastion_core::vault::Secret;
use bastion_core::CoreError;

fn params(port: u16, password: &str, pinned: Option<String>) -> FtpParams {
    FtpParams {
        host: "127.0.0.1".into(),
        port,
        username: "ftptest".into(),
        password: Secret::new(password),
        security: FtpSecurity::ExplicitTls { pinned },
        timeout: Duration::from_secs(10),
    }
}

#[ignore = "live: needs BASTION_FTPS_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn ftps_pins_then_transfers_files() {
    assert!(std::env::var_os("BASTION_FTPS_TEST").is_some(), "live test run without BASTION_FTPS_TEST: start the fixture (docs/TESTING.md)");
    let (Ok(port), Ok(pw)) = (std::env::var("BASTION_FTPS_TEST"), std::env::var("BASTION_FTPS_PASSWORD")) else {
        eprintln!("SKIPPED ftps: set BASTION_FTPS_TEST=<port> and BASTION_FTPS_PASSWORD with the container running");
        return;
    };
    let port: u16 = port.parse().unwrap();
    // A self-signed certificate is reported, not trusted.
    let fp = match FtpSession::connect(params(port, &pw, None)) {
        Err(CoreError::HostKeyUnknown { fingerprint }) => fingerprint,
        Err(e) => panic!("expected an unknown certificate, got {e:?}"),
        Ok(_) => panic!("a self-signed certificate must not be trusted"),
    };
    assert_eq!(fp.len(), 64);
    // A different pin is refused.
    assert!(FtpSession::connect(params(port, &pw, Some("00".repeat(32)))).is_err());
    assert!(matches!(FtpSession::connect(params(port, "wrong-password", Some(fp.clone()))), Err(CoreError::AuthFailed)));

    let mut s = FtpSession::connect(params(port, &pw, Some(fp))).expect("pinned login");
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("up.bin");
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
    std::fs::write(&local, &data).unwrap();
    let remote = format!("bastion-{}.bin", uuid::Uuid::new_v4());
    assert_eq!(s.upload(&local, &remote).unwrap(), data.len() as u64);
    let home = s.pwd().unwrap();
    assert!(s.list(&home).unwrap().iter().any(|e| e.name == remote && e.size == Some(data.len() as u64)));
    let back = dir.path().join("back.bin");
    assert_eq!(s.download(&remote, &back).unwrap(), data.len() as u64);
    assert_eq!(std::fs::read(&back).unwrap(), data);
    assert!(s.download(&remote, &back).is_err(), "never replaces a local file");
    s.delete(&remote).unwrap();
    s.quit().unwrap();
}
