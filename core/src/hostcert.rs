//! SSH host certificates, the way OpenSSH trusts them: a `@cert-authority <patterns> <key>` line
//! in known_hosts names a CA for the hosts its patterns match, and a server proving its identity
//! with a certificate that CA signed is accepted without a trust-on-first-use prompt. The
//! certificate must be a host certificate, signed by a CA for this host, inside its validity
//! window, list this host among its principals, and carry no critical options. `@revoked` lines
//! refuse a CA or host key outright. Hashed (`|1|`) host patterns are not read on CA lines.
use std::path::Path;

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::{Certificate, HashAlg, PublicKey};

use crate::error::{CoreError, Result};

/// Known_hosts lines that govern certificates for one host.
#[derive(Debug, Default)]
pub struct Authorities {
    pub cas: Vec<PublicKey>,
    pub revoked: Vec<PublicKey>,
}

/// How OpenSSH names a host in known_hosts: `host` on port 22, else `[host]:port`.
pub fn host_name(host: &str, port: u16) -> String {
    if port == 22 { host.to_ascii_lowercase() } else { format!("[{}]:{port}", host.to_ascii_lowercase()) }
}

/// `*` and `?` wildcards, case-insensitive (OpenSSH `match_pattern`).
pub fn wildcard(pattern: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], t) || (!t.is_empty() && go(p, &t[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => go(&p[1..], &t[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// A comma-separated pattern list: a `!pattern` match excludes, otherwise any match includes.
pub fn matches_patterns(list: &str, name: &str) -> bool {
    let mut hit = false;
    for p in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match p.strip_prefix('!') {
            Some(neg) if wildcard(neg, name) => return false,
            Some(_) => {}
            None => hit |= wildcard(p, name),
        }
    }
    hit
}

/// The `@cert-authority` and `@revoked` lines of known_hosts text that apply to `host:port`.
pub fn authorities(known_hosts: &str, host: &str, port: u16) -> Authorities {
    let name = host_name(host, port);
    let mut out = Authorities::default();
    for line in known_hosts.lines().map(str::trim) {
        let mut f = line.splitn(3, char::is_whitespace);
        let (Some(marker), Some(patterns), Some(key)) = (f.next(), f.next(), f.next()) else { continue };
        let Ok(key) = PublicKey::from_openssh(key.trim()) else { continue };
        match marker {
            "@cert-authority" if matches_patterns(patterns, &name) => out.cas.push(key),
            "@revoked" if patterns == "*" || matches_patterns(patterns, &name) => out.revoked.push(key),
            _ => {}
        }
    }
    out
}

impl Authorities {
    /// Whether a `@revoked` line names this exact key (comments are ignored).
    pub fn revokes(&self, key: &russh::keys::ssh_key::public::KeyData) -> bool {
        let want = key.fingerprint(HashAlg::Sha256);
        self.revoked.iter().any(|r| r.key_data().fingerprint(HashAlg::Sha256) == want)
    }
}

/// Reads `path` (a missing file trusts no CA).
pub fn authorities_in(path: &Path, host: &str, port: u16) -> Authorities {
    std::fs::read_to_string(path).map(|t| authorities(&t, host, port)).unwrap_or_default()
}

/// Whether the certificate may stand in for a known host key; the error says why not.
pub fn check(cert: &Certificate, auth: &Authorities, host: &str, now: u64) -> std::result::Result<(), String> {
    if auth.cas.is_empty() {
        return Err("the server presented a host certificate, but no @cert-authority line trusts a CA for this host".into());
    }
    let fp = |k: &russh::keys::ssh_key::public::KeyData| k.fingerprint(HashAlg::Sha256);
    if auth.revokes(cert.signature_key()) || auth.revokes(cert.public_key()) {
        return Err("the host key or its CA is marked @revoked".into());
    }
    if cert.cert_type() != CertType::Host {
        return Err("the server presented a user certificate as its host key".into());
    }
    let trusted: Vec<_> = auth.cas.iter().map(|k| fp(k.key_data())).collect();
    cert.validate_at(now, trusted.iter())
        .map_err(|_| "the host certificate is not signed by a trusted CA for this host, or is expired or not yet valid".to_string())?;
    if !cert.critical_options().is_empty() {
        return Err("the host certificate carries critical options".into());
    }
    let host = host.to_ascii_lowercase();
    if !cert.valid_principals().iter().any(|p| wildcard(p, &host)) {
        return Err(format!("the host certificate is not valid for {host} (principals: {})", cert.valid_principals().join(", ")));
    }
    Ok(())
}

/// A CA line for the app's known_hosts, after checking the parts.
pub fn ca_line(patterns: &str, public_key: &str) -> Result<String> {
    let patterns = patterns.trim();
    if patterns.is_empty() || patterns.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CoreError::Invalid("Host patterns: a comma-separated list such as *.example.com or [10.0.0.5]:2222, without spaces.".into()));
    }
    let key = PublicKey::from_openssh(public_key.trim()).map_err(|_| CoreError::Invalid("CA key: paste one OpenSSH public key line (for example ssh-ed25519 AAAA… ca).".into()))?;
    let key = key.to_openssh().map_err(|e| CoreError::Invalid(format!("CA key: {e}")))?;
    Ok(format!("@cert-authority {patterns} {key}"))
}

/// A `@cert-authority` line as the CA manager shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaEntry {
    pub patterns: String,
    /// `SHA256:…` of the CA key.
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
}

fn parse_ca(line: &str) -> Option<(CaEntry, &str)> {
    let mut f = line.trim().splitn(3, char::is_whitespace);
    let (Some("@cert-authority"), Some(patterns), Some(key)) = (f.next(), f.next(), f.next()) else { return None };
    let k = PublicKey::from_openssh(key.trim()).ok()?;
    Some((
        CaEntry { patterns: patterns.into(), fingerprint: k.fingerprint(HashAlg::Sha256).to_string(), algorithm: k.algorithm().to_string(), comment: k.comment().to_string() },
        line,
    ))
}

/// The CA lines of the known_hosts file at `path` (none when it does not exist).
pub fn list_cas(path: &Path) -> Vec<CaEntry> {
    std::fs::read_to_string(path).map(|t| t.lines().filter_map(parse_ca).map(|(e, _)| e).collect()).unwrap_or_default()
}

/// Appends a CA line; the same CA for the same patterns is refused as a duplicate.
pub fn add_ca(path: &Path, patterns: &str, public_key: &str) -> Result<CaEntry> {
    let line = ca_line(patterns, public_key)?;
    let (entry, _) = parse_ca(&line).ok_or_else(|| CoreError::Invalid("CA key could not be read".into()))?;
    if list_cas(path).iter().any(|e| e.patterns == entry.patterns && e.fingerprint == entry.fingerprint) {
        return Err(CoreError::Invalid(format!("This CA is already trusted for {}.", entry.patterns)));
    }
    let mut text = std::fs::read_to_string(path).unwrap_or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&line);
    text.push('\n');
    crate::store::write_atomic(path, text.as_bytes())?;
    Ok(entry)
}

/// Removes the CA line for `patterns` and `fingerprint`; every other line is kept as it was.
pub fn remove_ca(path: &Path, patterns: &str, fingerprint: &str) -> Result<()> {
    let text = std::fs::read_to_string(path)?;
    let keep: Vec<&str> = text.lines().filter(|l| !parse_ca(l).is_some_and(|(e, _)| e.patterns == patterns && e.fingerprint == fingerprint)).collect();
    if keep.len() == text.lines().count() {
        return Err(CoreError::NotFound(format!("CA {fingerprint} for {patterns}")));
    }
    let mut out = keep.join("\n");
    out.push('\n');
    crate::store::write_atomic(path, out.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str = include_str!("../tests/fixtures/hostcert/ca.pub");

    #[test]
    fn host_names_follow_openssh() {
        assert_eq!(host_name("Web.Example", 22), "web.example");
        assert_eq!(host_name("10.0.0.5", 2222), "[10.0.0.5]:2222");
    }

    #[test]
    fn wildcards_and_negation() {
        assert!(wildcard("*.example.com", "db.example.com"));
        assert!(!wildcard("*.example.com", "example.com"));
        assert!(wildcard("web-??", "web-01"));
        assert!(matches_patterns("*.example.com,!bad.example.com", "ok.example.com"));
        assert!(!matches_patterns("*.example.com,!bad.example.com", "bad.example.com"));
        assert!(!matches_patterns("!*.example.com", "x.example.com"), "negation alone never includes");
    }

    #[test]
    fn ca_and_revoked_lines_are_scoped_by_pattern() {
        let text = format!("# comment\n@cert-authority *.lab,[127.0.0.1]:2240 {CA}\n@cert-authority other.example {CA}\n@revoked * {CA}\n127.0.0.1 {CA}\n");
        let a = authorities(&text, "127.0.0.1", 2240);
        assert_eq!((a.cas.len(), a.revoked.len()), (1, 1));
        assert_eq!(authorities(&text, "web.lab", 22).cas.len(), 1);
        assert_eq!(authorities(&text, "127.0.0.1", 22).cas.len(), 0, "a plain known host line is not a CA");
        assert_eq!(authorities("garbage\n@cert-authority *", "h", 22).cas.len(), 0);
    }

    #[test]
    fn ca_lines_are_checked_before_saving() {
        assert_eq!(ca_line(" *.lab ", CA).unwrap(), format!("@cert-authority *.lab {}", CA.trim()));
        assert!(ca_line("a b", CA).is_err());
        assert!(ca_line("", CA).is_err());
        assert!(ca_line("*.lab", "not a key").is_err());
    }

    #[test]
    fn ca_lines_are_added_listed_and_removed_without_touching_host_keys() {
        let dir = std::env::temp_dir().join(format!("bastion-hostcert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        std::fs::write(&path, "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl").unwrap();
        let e = add_ca(&path, "*.lab", CA).unwrap();
        assert_eq!((e.patterns.as_str(), e.algorithm.as_str(), e.comment.as_str()), ("*.lab", "ssh-ed25519", "bastion-test-ca"));
        assert!(add_ca(&path, "*.lab", CA).is_err(), "duplicate");
        add_ca(&path, "[10.0.0.5]:2222", CA).unwrap();
        assert_eq!(list_cas(&path).len(), 2);
        remove_ca(&path, "*.lab", &e.fingerprint).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("[127.0.0.1]:2222 ssh-ed25519"), "host keys kept");
        assert_eq!(list_cas(&path).iter().map(|c| c.patterns.as_str()).collect::<Vec<_>>(), ["[10.0.0.5]:2222"]);
        assert!(remove_ca(&path, "*.lab", &e.fingerprint).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
