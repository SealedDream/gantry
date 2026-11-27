//! Host certificates against fixtures made with `ssh-keygen -s` (tests/fixtures/hostcert): only
//! a host certificate from a trusted, matching CA, valid now, for this host's name passes.
use bastion_core::hostcert::{self, Authorities};
use russh::keys::{Certificate, PublicKey};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/hostcert/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn cert(name: &str) -> Certificate {
    Certificate::from_openssh(fixture(&format!("{name}-cert.pub")).trim()).unwrap()
}

fn trusted() -> Authorities {
    hostcert::authorities(&format!("@cert-authority 127.0.0.1,*.lab {}", fixture("ca.pub")), "127.0.0.1", 22)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn a_valid_host_certificate_from_the_trusted_ca_passes() {
    assert_eq!(hostcert::check(&cert("valid"), &trusted(), "127.0.0.1", now()), Ok(()));
    let lab = hostcert::authorities(&format!("@cert-authority *.lab {}", fixture("ca.pub")), "web.lab", 22);
    assert_eq!(hostcert::check(&cert("valid"), &lab, "web.lab", now()), Ok(()), "wildcard principal");
}

#[test]
fn every_other_certificate_is_refused_with_a_reason() {
    let a = trusted();
    let cases = [
        ("expired", "127.0.0.1", "expired"),
        ("user", "127.0.0.1", "user certificate"),
        ("other", "127.0.0.1", "not valid for 127.0.0.1"),
        ("foreign", "127.0.0.1", "not signed by a trusted CA"),
        ("valid", "10.9.9.9", "not valid for 10.9.9.9"),
    ];
    for (name, host, why) in cases {
        let err = hostcert::check(&cert(name), &a, host, now()).unwrap_err();
        assert!(err.contains(why), "{name}: {err}");
    }
    assert!(hostcert::check(&cert("valid"), &Authorities::default(), "127.0.0.1", now()).unwrap_err().contains("no @cert-authority"));
    let future = now() + 20 * 365 * 24 * 3600;
    assert!(hostcert::check(&cert("valid"), &a, "127.0.0.1", future).is_err(), "past valid-before");
}

#[test]
fn revoked_ca_is_refused_even_when_trusted() {
    let text = format!("@cert-authority * {ca}\n@revoked * {ca}\n", ca = fixture("ca.pub"));
    let a = hostcert::authorities(&text, "127.0.0.1", 22);
    assert!(hostcert::check(&cert("valid"), &a, "127.0.0.1", now()).unwrap_err().contains("@revoked"));
    // The revoked line also matches the host key itself.
    let host_key: PublicKey = cert("valid").public_key().clone().into();
    let text = format!("@cert-authority * {}\n@revoked * {}\n", fixture("ca.pub"), host_key.to_openssh().unwrap());
    assert!(hostcert::check(&cert("valid"), &hostcert::authorities(&text, "127.0.0.1", 22), "127.0.0.1", now()).is_err());
}
