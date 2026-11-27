//! Quick Connect: parse what a user types (`ops@10.0.0.5:2222`, `rdp://build-win`,
//! `https://portal.example`) into a connection target. Nothing is saved; the frontend opens
//! the target as an unsaved connection through the normal connect flow.
use crate::error::{CoreError, Result};
use crate::model::Protocol;

const MAX_INPUT: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickTarget {
    pub protocol: Protocol,
    /// Host name or address; for web targets the whole URL.
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    /// `sftp://`: open the file browser instead of a terminal.
    pub files: bool,
}

impl QuickTarget {
    /// Name for the tab: what the user would type to get here again.
    pub fn label(&self) -> String {
        if self.protocol == Protocol::Web {
            return self.host.clone();
        }
        let host = if self.host.contains(':') && self.port.is_some() { format!("[{}]", self.host) } else { self.host.clone() };
        let user = self.user.as_ref().map(|u| format!("{u}@")).unwrap_or_default();
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        format!("{user}{host}{port}")
    }
}

fn invalid(msg: &str) -> CoreError {
    CoreError::Invalid(msg.to_string())
}

/// Parse a Quick Connect entry. Without a scheme the target is SSH.
pub fn parse(input: &str) -> Result<QuickTarget> {
    let text = input.trim();
    if text.is_empty() {
        return Err(invalid("enter a host, user@host or a URL"));
    }
    if text.chars().count() > MAX_INPUT || text.chars().any(char::is_whitespace) {
        return Err(invalid("the target cannot contain spaces"));
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        if text.split_once("://").is_some_and(|(_, rest)| rest.trim_matches('/').is_empty()) {
            return Err(invalid("the address has no host"));
        }
        return Ok(QuickTarget { protocol: Protocol::Web, host: text.to_string(), port: None, user: None, files: false });
    }
    let (protocol, files, rest) = match lower.split_once("://") {
        None => (Protocol::Ssh, false, text),
        Some((scheme, _)) => {
            let rest = &text[scheme.len() + 3..];
            match scheme {
                "ssh" => (Protocol::Ssh, false, rest),
                "sftp" => (Protocol::Ssh, true, rest),
                "rdp" => (Protocol::Rdp, false, rest),
                "vnc" => (Protocol::Vnc, false, rest),
                _ => return Err(CoreError::Invalid(format!("Quick Connect does not open {scheme}:// addresses"))),
            }
        }
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains('/') {
        return Err(invalid("only a host and port can follow the scheme"));
    }
    let (user, hostport) = match rest.rsplit_once('@') {
        Some(("", _)) => return Err(invalid("the user name before @ is empty")),
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, rest),
    };
    let (host, port) = split_host_port(hostport)?;
    Ok(QuickTarget { protocol, host, port, user, files })
}

fn split_host_port(s: &str) -> Result<(String, Option<u16>)> {
    let (host, port) = if let Some(v6) = s.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(|| invalid("missing ] after the IPv6 address"))?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or_else(|| invalid("expected :port after the IPv6 address"))?),
        };
        (h, port)
    } else if s.matches(':').count() > 1 {
        // A bare IPv6 address; a port needs the bracket form.
        (s, None)
    } else {
        match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    if host.is_empty() {
        return Err(invalid("the target has no host"));
    }
    if !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%')) {
        return Err(CoreError::Invalid(format!("“{host}” is not a host name or address")));
    }
    let port = port
        .map(|p| p.parse::<u16>().ok().filter(|&n| n > 0).ok_or_else(|| CoreError::Invalid(format!("“{p}” is not a port (1–65535)"))))
        .transpose()?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(protocol: Protocol, host: &str, port: Option<u16>, user: Option<&str>) -> QuickTarget {
        QuickTarget { protocol, host: host.into(), port, user: user.map(Into::into), files: false }
    }

    #[test]
    fn bare_targets_are_ssh() {
        assert_eq!(parse("db01").unwrap(), t(Protocol::Ssh, "db01", None, None));
        assert_eq!(parse("  ops@10.0.0.5:2222 ").unwrap(), t(Protocol::Ssh, "10.0.0.5", Some(2222), Some("ops")));
        assert_eq!(parse("ACME\\admin@host").unwrap().user.as_deref(), Some("ACME\\admin"));
        assert_eq!(parse("me@corp.example@jump").unwrap().user.as_deref(), Some("me@corp.example"));
    }

    #[test]
    fn schemes_pick_the_protocol() {
        assert_eq!(parse("rdp://build-win").unwrap(), t(Protocol::Rdp, "build-win", None, None));
        assert_eq!(parse("VNC://10.1.1.1:5901/").unwrap(), t(Protocol::Vnc, "10.1.1.1", Some(5901), None));
        assert_eq!(parse("ssh://root@h").unwrap(), t(Protocol::Ssh, "h", None, Some("root")));
        let f = parse("sftp://h").unwrap();
        assert!(f.files && f.protocol == Protocol::Ssh);
    }

    #[test]
    fn web_urls_keep_the_whole_address() {
        let w = parse("https://portal.example/login?x=1").unwrap();
        assert_eq!((w.protocol, w.host.as_str()), (Protocol::Web, "https://portal.example/login?x=1"));
        assert!(parse("https://").is_err());
    }

    #[test]
    fn ipv6_forms() {
        assert_eq!(parse("[::1]:2222").unwrap(), t(Protocol::Ssh, "::1", Some(2222), None));
        assert_eq!(parse("fe80::1%en0").unwrap(), t(Protocol::Ssh, "fe80::1%en0", None, None));
        assert_eq!(parse("[::1]:2222").unwrap().label(), "[::1]:2222");
        assert!(parse("[::1").is_err());
        assert!(parse("[::1]x").is_err());
    }

    #[test]
    fn bad_input_is_refused_with_a_reason() {
        for bad in ["", "   ", "a b", "h:0", "h:70000", "h:x", "@h", "telnet://h", "ssh://h/path", "ho$t", ":22", "ssh://"] {
            assert!(parse(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(parse(&"a".repeat(MAX_INPUT + 1)).is_err());
    }

    #[test]
    fn label_round_trips() {
        for s in ["ops@10.0.0.5:2222", "db01", "https://x.example", "fe80::1"] {
            assert_eq!(parse(s).unwrap().label(), s);
        }
    }
}
