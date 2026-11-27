//! SSH algorithm selection: OpenSSH list syntax (`KexAlgorithms`, `Ciphers`, `MACs`,
//! `HostKeyAlgorithms`, with `+`/`-`/`^` prefixes), weak-algorithm opt-in with a policy veto, and
//! a precise explanation when negotiation fails.
//!
//! Defaults are russh's safe lists. Weak algorithms (SHA-1 key exchange, CBC ciphers, SHA-1 MACs,
//! `ssh-rsa` host keys) are only offered when the connection opts in and policy allows it;
//! `none` ciphers and MACs are never offered.

use std::borrow::Cow;
use std::str::FromStr;

use russh::keys::Algorithm;
use russh::{cipher, compression, kex, mac, Preferred};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgoKind {
    Kex,
    Cipher,
    Mac,
    HostKey,
    Compression,
}

impl AlgoKind {
    pub fn label(self) -> &'static str {
        match self {
            AlgoKind::Kex => "key exchange",
            AlgoKind::Cipher => "cipher",
            AlgoKind::Mac => "MAC",
            AlgoKind::HostKey => "host key",
            AlgoKind::Compression => "compression",
        }
    }
}

/// Weak but still implemented: offered only on explicit opt-in.
const WEAK: &[(AlgoKind, &str)] = &[
    (AlgoKind::Kex, "diffie-hellman-group1-sha1"),
    (AlgoKind::Kex, "diffie-hellman-group14-sha1"),
    (AlgoKind::Kex, "diffie-hellman-group-exchange-sha1"),
    (AlgoKind::Cipher, "3des-cbc"),
    (AlgoKind::Cipher, "aes128-cbc"),
    (AlgoKind::Cipher, "aes192-cbc"),
    (AlgoKind::Cipher, "aes256-cbc"),
    (AlgoKind::Mac, "hmac-sha1"),
    (AlgoKind::Mac, "hmac-sha1-etm@openssh.com"),
    (AlgoKind::HostKey, "ssh-rsa"),
];

/// Never offered, whatever the settings say.
const FORBIDDEN: &[&str] = &["none", "clear"];

/// OpenSSH algorithms russh 0.65 does not implement. Named in warnings so an imported config
/// that relies on them is explained instead of silently ignored.
pub const UNSUPPORTED: &[(AlgoKind, &str)] = &[
    (AlgoKind::Kex, "sntrup761x25519-sha512"),
    (AlgoKind::Kex, "sntrup761x25519-sha512@openssh.com"),
    (AlgoKind::Kex, "mlkem768nistp256-sha256"),
    (AlgoKind::Kex, "mlkem1024nistp384-sha384"),
    (AlgoKind::Cipher, "arcfour"),
    (AlgoKind::Cipher, "arcfour128"),
    (AlgoKind::Cipher, "arcfour256"),
    (AlgoKind::Cipher, "blowfish-cbc"),
    (AlgoKind::Cipher, "cast128-cbc"),
    (AlgoKind::Cipher, "rijndael-cbc@lysator.liu.se"),
    (AlgoKind::Mac, "umac-64@openssh.com"),
    (AlgoKind::Mac, "umac-128@openssh.com"),
    (AlgoKind::Mac, "umac-64-etm@openssh.com"),
    (AlgoKind::Mac, "umac-128-etm@openssh.com"),
    (AlgoKind::Mac, "hmac-md5"),
    (AlgoKind::Mac, "hmac-md5-96"),
    (AlgoKind::Mac, "hmac-sha1-96"),
    (AlgoKind::Mac, "hmac-ripemd160"),
    (AlgoKind::HostKey, "ssh-dss"),
    (AlgoKind::HostKey, "ssh-dss-cert-v01@openssh.com"),
];

pub fn is_weak(kind: AlgoKind, name: &str) -> bool {
    WEAK.iter().any(|(k, n)| *k == kind && *n == name)
}

/// Whether russh can negotiate `name` for `kind` in this build.
pub fn is_implemented(kind: AlgoKind, name: &str) -> bool {
    if FORBIDDEN.contains(&name) {
        return false;
    }
    match kind {
        AlgoKind::Kex => kex::Name::try_from(name).is_ok() && !is_kex_marker(name),
        AlgoKind::Cipher => cipher::Name::try_from(name).is_ok(),
        AlgoKind::Mac => mac::Name::try_from(name).is_ok(),
        AlgoKind::HostKey => Algorithm::from_str(name).is_ok_and(|a| !matches!(a, Algorithm::Dsa | Algorithm::Other(_))),
        AlgoKind::Compression => ["none", "zlib", "zlib@openssh.com"].contains(&name),
    }
}

/// Everything this build can negotiate for `kind`, strong first, weak last.
pub fn catalogue(kind: AlgoKind) -> Vec<String> {
    let mut all = defaults(kind);
    all.extend(WEAK.iter().filter(|(k, n)| *k == kind && is_implemented(kind, n)).map(|(_, n)| n.to_string()));
    all
}

fn defaults(kind: AlgoKind) -> Vec<String> {
    let p = Preferred::DEFAULT;
    let names: Vec<String> = match kind {
        AlgoKind::Kex => p.kex.iter().map(|n| n.as_ref().to_owned()).collect(),
        AlgoKind::Cipher => p.cipher.iter().map(|n| n.as_ref().to_owned()).collect(),
        AlgoKind::Mac => p.mac.iter().map(|n| n.as_ref().to_owned()).collect(),
        AlgoKind::HostKey => p.key.iter().map(|a| a.as_str().to_owned()).collect(),
        AlgoKind::Compression => p.compression.iter().map(|n| n.as_ref().to_owned()).collect(),
    };
    // Extension markers (`ext-info-c`, strict kex) are protocol flags, not user choices.
    names.into_iter().filter(|n| !(kind == AlgoKind::Kex && is_kex_marker(n)) && !is_weak(kind, n)).collect()
}

fn is_kex_marker(name: &str) -> bool {
    name.starts_with("ext-info-") || name.starts_with("kex-strict-")
}

/// OpenSSH wildcard match (`*`, `?`) on one algorithm name.
fn glob(pattern: &str, name: &str) -> bool {
    crate::sshconfig::host_matches(&[pattern.to_owned()], name)
}

/// Apply an OpenSSH algorithm list to `base`: `+a,b` appends, `-a*` removes (wildcards),
/// `^a,b` puts first, and a bare list replaces. Names this build cannot do are left out and
/// returned as the second value.
pub fn apply_spec(kind: AlgoKind, base: &[String], spec: &str) -> (Vec<String>, Vec<String>) {
    let spec = spec.trim();
    let (op, list) = match spec.chars().next() {
        Some(c @ ('+' | '-' | '^')) => (c, &spec[1..]),
        _ => ('=', spec),
    };
    let items: Vec<&str> = list.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if op == '-' {
        return (base.iter().filter(|n| !items.iter().any(|p| glob(p, n))).cloned().collect(), vec![]);
    }
    let mut unknown = vec![];
    let mut chosen: Vec<String> = vec![];
    let all = catalogue(kind);
    for item in items {
        if item.contains(['*', '?']) {
            let hits: Vec<String> = all.iter().filter(|n| glob(item, n) && !chosen.contains(n)).cloned().collect();
            chosen.extend(hits);
        } else if is_implemented(kind, item) {
            if !chosen.iter().any(|n| n == item) {
                chosen.push(item.to_owned());
            }
        } else {
            unknown.push(item.to_owned());
        }
    }
    let out = match op {
        '+' => base.iter().cloned().chain(chosen.into_iter().filter(|n| !base.contains(n))).collect(),
        '^' => chosen.iter().cloned().chain(base.iter().filter(|n| !chosen.contains(n)).cloned()).collect(),
        _ => chosen,
    };
    (out, unknown)
}

/// Per-connection algorithm settings (Properties → Advanced → Algorithms), inherited as a unit.
/// Each list uses OpenSSH syntax; `None` keeps the built-in safe list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlgorithmSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_keys: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<bool>,
    /// Explicit opt-in to the weak algorithms the lists name ("Allow for this host").
    pub allow_weak: bool,
}

/// The lists a connection will offer, plus what was left out and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedAlgorithms {
    pub kex: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    pub host_keys: Vec<String>,
    pub compression: Vec<String>,
    /// Weak algorithms in effect (the UI shows a warning while this is non-empty).
    pub weak_enabled: Vec<String>,
    pub warnings: Vec<String>,
}

impl ResolvedAlgorithms {
    /// Whether RSA user authentication may sign with SHA-1 (`ssh-rsa`): only after `ssh-rsa`
    /// was explicitly allowed for this host, which `resolve` already refuses under the veto.
    pub fn allows_rsa_sha1(&self) -> bool {
        self.weak_enabled.iter().any(|n| n == "ssh-rsa")
    }
}

impl Default for ResolvedAlgorithms {
    fn default() -> Self {
        AlgorithmSettings::default().resolve(false).expect("defaults resolve")
    }
}

impl AlgorithmSettings {
    /// Settings that also allow `names` (the weak algorithms a server offers), for the
    /// host-scoped "Allow for this host" action after a [`CoreError::NoCommonAlgorithm`].
    pub fn allowing(&self, kind: AlgoKind, names: &[String]) -> AlgorithmSettings {
        let add = format!("+{}", names.join(","));
        let merge = |cur: &Option<String>| Some(match cur {
            Some(c) if !c.starts_with(['+', '-', '^']) => format!("{c},{}", names.join(",")),
            Some(c) => format!("{c}\n{add}"),
            None => add.clone(),
        });
        let mut out = self.clone();
        match kind {
            AlgoKind::Kex => out.kex = merge(&self.kex),
            AlgoKind::Cipher => out.ciphers = merge(&self.ciphers),
            AlgoKind::Mac => out.macs = merge(&self.macs),
            AlgoKind::HostKey => out.host_keys = merge(&self.host_keys),
            AlgoKind::Compression => out.compression = Some(true),
        }
        out.allow_weak = true;
        out
    }

    /// Resolve against the safe defaults. Weak names are dropped unless `allow_weak` is set and
    /// `forbid_weak` (policy) is not; an empty result is an error rather than a silent fallback.
    pub fn resolve(&self, forbid_weak: bool) -> Result<ResolvedAlgorithms> {
        let allow = self.allow_weak && !forbid_weak;
        let mut warnings = vec![];
        let mut weak_enabled = vec![];
        let mut list = |kind: AlgoKind, spec: &Option<String>| -> Result<Vec<String>> {
            let mut names = defaults(kind);
            // Several specs (one per line) apply in order, e.g. a replace then an `+` opt-in.
            for line in spec.iter().flat_map(|s| s.lines()).filter(|l| !l.trim().is_empty()) {
                let (next, unknown) = apply_spec(kind, &names, line);
                names = next;
                for u in unknown {
                    let why = if UNSUPPORTED.iter().any(|(k, n)| *k == kind && *n == u) { "not implemented by Gantry's SSH library" } else { "unknown" };
                    warnings.push(format!("{} algorithm `{u}` ignored: {why}", kind.label()));
                }
            }
            let mut kept = vec![];
            for n in names {
                if !is_weak(kind, &n) {
                    kept.push(n);
                } else if allow {
                    weak_enabled.push(n.clone());
                    kept.push(n);
                } else {
                    let why = if forbid_weak { "forbidden by policy" } else { "weak; allow weak algorithms for this host to use it" };
                    warnings.push(format!("{} algorithm `{n}` not offered: {why}", kind.label()));
                }
            }
            if kept.is_empty() {
                return Err(CoreError::Invalid(format!("no usable {} algorithms left in `{}`", kind.label(), spec.as_deref().unwrap_or(""))));
            }
            Ok(kept)
        };
        let kex = list(AlgoKind::Kex, &self.kex)?;
        let ciphers = list(AlgoKind::Cipher, &self.ciphers)?;
        let macs = list(AlgoKind::Mac, &self.macs)?;
        let host_keys = list(AlgoKind::HostKey, &self.host_keys)?;
        let compression = match self.compression {
            Some(true) => vec!["zlib@openssh.com".into(), "zlib".into(), "none".into()],
            Some(false) => vec!["none".into()],
            None => defaults(AlgoKind::Compression),
        };
        Ok(ResolvedAlgorithms { kex, ciphers, macs, host_keys, compression, weak_enabled, warnings })
    }
}

impl ResolvedAlgorithms {
    /// The russh preference lists. Host-key certificate algorithms are left to the caller.
    pub fn preferred(&self) -> Preferred {
        let markers = Preferred::DEFAULT.kex.iter().filter(|n| is_kex_marker(n.as_ref())).copied();
        let kex: Vec<kex::Name> = self.kex.iter().filter_map(|n| kex::Name::try_from(n.as_str()).ok()).chain(markers).collect();
        Preferred {
            kex: Cow::Owned(kex),
            key: Cow::Owned(self.host_keys.iter().filter_map(|n| Algorithm::from_str(n).ok()).collect()),
            host_key_certificates: Cow::Borrowed(&[]),
            cipher: Cow::Owned(self.ciphers.iter().filter_map(|n| cipher::Name::try_from(n.as_str()).ok()).collect()),
            mac: Cow::Owned(self.macs.iter().filter_map(|n| mac::Name::try_from(n.as_str()).ok()).collect()),
            compression: Cow::Owned(
                self.compression
                    .iter()
                    .filter_map(|n| match n.as_str() {
                        "zlib" => Some(compression::ZLIB),
                        "zlib@openssh.com" => Some(compression::ZLIB_LEGACY),
                        "none" => Some(compression::NONE),
                        _ => None,
                    })
                    .collect(),
            ),
        }
    }
}

/// Turn russh's negotiation failure into [`CoreError::NoCommonAlgorithm`], naming what the
/// server offers and which of those Bastion could enable with an explicit weak opt-in.
pub fn explain_no_common(kind: russh::AlgorithmKind, theirs: Vec<String>) -> CoreError {
    let kind = match kind {
        russh::AlgorithmKind::Kex => AlgoKind::Kex,
        russh::AlgorithmKind::Key => AlgoKind::HostKey,
        russh::AlgorithmKind::Cipher => AlgoKind::Cipher,
        russh::AlgorithmKind::Mac => AlgoKind::Mac,
        russh::AlgorithmKind::Compression => AlgoKind::Compression,
    };
    let server_offers: Vec<String> = theirs.into_iter().filter(|n| !(kind == AlgoKind::Kex && is_kex_marker(n))).collect();
    let weak_allowable: Vec<String> = server_offers.iter().filter(|n| is_weak(kind, n) && is_implemented(kind, n)).cloned().collect();
    CoreError::NoCommonAlgorithm { kind, server_offers, weak_allowable }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn plus_minus_caret_and_replace() {
        let base = s(&["aes256-ctr", "aes128-ctr"]);
        assert_eq!(apply_spec(AlgoKind::Cipher, &base, "+aes128-cbc").0, s(&["aes256-ctr", "aes128-ctr", "aes128-cbc"]));
        assert_eq!(apply_spec(AlgoKind::Cipher, &base, "-aes1*").0, s(&["aes256-ctr"]));
        assert_eq!(apply_spec(AlgoKind::Cipher, &base, "^aes128-ctr").0, s(&["aes128-ctr", "aes256-ctr"]));
        assert_eq!(apply_spec(AlgoKind::Cipher, &base, "aes128-ctr, blowfish-cbc"), (s(&["aes128-ctr"]), s(&["blowfish-cbc"])));
    }

    #[test]
    fn defaults_have_no_weak_or_markers() {
        let r = ResolvedAlgorithms::default();
        assert!(r.weak_enabled.is_empty() && r.warnings.is_empty(), "{r:?}");
        assert!(r.kex.iter().all(|n| !n.starts_with("ext-info") && !is_weak(AlgoKind::Kex, n)));
        assert!(!r.host_keys.contains(&"ssh-rsa".to_string()));
        assert!(r.host_keys.contains(&"rsa-sha2-512".to_string()));
    }

    #[test]
    fn weak_needs_opt_in_and_policy_can_veto() {
        let mut a = AlgorithmSettings { kex: Some("+diffie-hellman-group14-sha1".into()), ..Default::default() };
        let r = a.resolve(false).unwrap();
        assert!(!r.kex.contains(&"diffie-hellman-group14-sha1".into()));
        assert!(r.warnings[0].contains("weak"));
        a.allow_weak = true;
        let r = a.resolve(false).unwrap();
        assert!(r.kex.contains(&"diffie-hellman-group14-sha1".into()));
        assert_eq!(r.weak_enabled, s(&["diffie-hellman-group14-sha1"]));
        let r = a.resolve(true).unwrap();
        assert!(r.weak_enabled.is_empty() && r.warnings[0].contains("policy"));
    }

    #[test]
    fn none_is_never_offered_and_empty_is_an_error() {
        let a = AlgorithmSettings { ciphers: Some("none".into()), ..Default::default() };
        assert!(a.resolve(false).is_err());
        let a = AlgorithmSettings { macs: Some("hmac-sha1".into()), ..Default::default() };
        assert!(a.resolve(false).is_err());
    }

    #[test]
    fn unsupported_is_named() {
        let a = AlgorithmSettings { macs: Some("+umac-64@openssh.com".into()), ..Default::default() };
        let r = a.resolve(false).unwrap();
        assert!(r.warnings[0].contains("not implemented"), "{r:?}");
    }

    #[test]
    fn preferred_round_trips_and_keeps_kex_markers() {
        let a = AlgorithmSettings { ciphers: Some("aes256-ctr".into()), compression: Some(true), ..Default::default() };
        let p = a.resolve(false).unwrap().preferred();
        assert_eq!(p.cipher.len(), 1);
        assert!(p.kex.iter().any(|n| n.as_ref() == "ext-info-c"));
        assert_eq!(p.compression.len(), 3);
    }

    #[test]
    fn allow_for_host_appends_server_offer() {
        let a = AlgorithmSettings { ciphers: Some("aes256-ctr".into()), ..Default::default() };
        let b = a.allowing(AlgoKind::Cipher, &s(&["aes128-cbc"]));
        let r = b.resolve(false).unwrap();
        assert_eq!(r.ciphers, s(&["aes256-ctr", "aes128-cbc"]));
        let c = AlgorithmSettings::default().allowing(AlgoKind::Kex, &s(&["diffie-hellman-group1-sha1"]));
        assert_eq!(c.resolve(false).unwrap().weak_enabled, s(&["diffie-hellman-group1-sha1"]));
    }

    #[test]
    fn negotiation_failure_names_server_offer() {
        let e = explain_no_common(russh::AlgorithmKind::Kex, s(&["diffie-hellman-group1-sha1", "ext-info-s"]));
        match &e {
            CoreError::NoCommonAlgorithm { kind, server_offers, weak_allowable } => {
                assert_eq!(*kind, AlgoKind::Kex);
                assert_eq!(*server_offers, s(&["diffie-hellman-group1-sha1"]));
                assert_eq!(weak_allowable, server_offers);
            }
            other => panic!("{other:?}"),
        }
        assert!(e.to_string().contains("diffie-hellman-group1-sha1"), "{e}");
        let msg = explain_no_common(russh::AlgorithmKind::Cipher, s(&["arcfour"])).to_string();
        assert!(msg.contains("arcfour"), "{msg}");
    }
}
