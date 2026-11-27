//! FTP and FTPS (explicit TLS, `AUTH TLS`) file transfer over `suppaftp`, blocking: call it from a
//! blocking task. Plain FTP sends the password in clear text, so `Policy` blocks it by default
//! (`LEGACY_PROTOCOLS`); FTPS is allowed. Server certificates are checked against the standard
//! web roots, or pinned to the SHA-256 the user confirmed (servers are often self-signed): an
//! unconfirmed certificate fails with `HostKeyUnknown { fingerprint }` for the UI to show, as for
//! SSH host keys. Local files from downloads are written to a temp name and renamed, never
//! replacing an existing file; names from the server are never used as local paths.
use std::io::Write;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use suppaftp::{RustlsConnector, RustlsFtpStream};

use crate::error::{CoreError, Result};
use crate::vault::Secret;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpSecurity {
    /// Clear text (policy-gated by the caller).
    Plain,
    /// `AUTH TLS` on the control connection, protected data connections.
    ExplicitTls { pinned: Option<String> },
}

pub struct FtpParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Secret,
    pub security: FtpSecurity,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpEntry {
    pub name: String,
    pub size: Option<u64>,
    pub is_dir: bool,
}

/// Lower-case hex SHA-256 of a DER certificate: what the user pins.
pub fn cert_fingerprint(der: &[u8]) -> String {
    Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect()
}

/// Verifies against the web roots, or (when pinned) accepts exactly the pinned certificate.
/// The leaf it saw is kept so an unknown certificate can be reported with its fingerprint.
#[derive(Debug)]
struct Verifier {
    roots: Arc<rustls::client::WebPkiServerVerifier>,
    pinned: Option<String>,
    seen: Mutex<Option<String>>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = cert_fingerprint(end_entity);
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(fp.clone());
        match &self.pinned {
            Some(p) if p.eq_ignore_ascii_case(&fp) => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General("certificate does not match the pinned fingerprint".into())),
            None => self.roots.verify_server_cert(end_entity, intermediates, name, ocsp, now),
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.roots.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.roots.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.roots.supported_verify_schemes()
    }
}

fn tls_config(pinned: Option<String>) -> Result<(ClientConfig, Arc<Verifier>)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let web = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| CoreError::Invalid(format!("TLS setup: {e}")))?;
    let verifier = Arc::new(Verifier { roots: web, pinned, seen: Mutex::new(None) });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| CoreError::Invalid(format!("TLS setup: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    Ok((config, verifier))
}

fn ftp_err(e: suppaftp::FtpError) -> CoreError {
    CoreError::Ssh(format!("FTP: {e}"))
}

/// Names for remote paths: no line breaks (they would end the FTP command).
fn check_remote(path: &str) -> Result<()> {
    if path.is_empty() || path.contains(['\0', '\n', '\r']) {
        return Err(CoreError::Invalid("the remote path is empty or contains a line break".into()));
    }
    Ok(())
}

pub struct FtpSession {
    stream: RustlsFtpStream,
}

impl FtpSession {
    /// Connect, secure (for FTPS) and log in.
    pub fn connect(p: FtpParams) -> Result<FtpSession> {
        let addr = (p.host.as_str(), p.port).to_socket_addrs()?.next().ok_or_else(|| CoreError::NotFound(format!("cannot resolve {}", p.host)))?;
        let tcp = std::net::TcpStream::connect_timeout(&addr, p.timeout).map_err(|e| CoreError::Ssh(format!("FTP: {e}")))?;
        tcp.set_read_timeout(Some(p.timeout))?;
        tcp.set_write_timeout(Some(p.timeout))?;
        let mut stream = RustlsFtpStream::connect_with_stream(tcp).map_err(ftp_err)?;
        if let FtpSecurity::ExplicitTls { pinned } = p.security {
            let (config, verifier) = tls_config(pinned.clone())?;
            stream = match stream.into_secure(RustlsConnector::from(Arc::new(config)), &p.host) {
                Ok(s) => s,
                Err(e) => {
                    // A certificate the user has not confirmed: report it like an unknown host key.
                    let seen = verifier.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    return Err(match (seen, pinned) {
                        (Some(fingerprint), None) => CoreError::HostKeyUnknown { fingerprint },
                        _ => ftp_err(e),
                    });
                }
            };
        }
        match stream.login(p.username.as_str(), p.password.expose()) {
            Ok(()) => {}
            Err(suppaftp::FtpError::UnexpectedResponse(r)) if r.status.code() == 530 => return Err(CoreError::AuthFailed),
            Err(e) => return Err(ftp_err(e)),
        }
        stream.transfer_type(suppaftp::types::FileType::Binary).map_err(ftp_err)?;
        Ok(FtpSession { stream })
    }

    pub fn pwd(&mut self) -> Result<String> {
        self.stream.pwd().map_err(ftp_err)
    }

    /// Entries of `dir` from `LIST` (Unix or DOS format), without `.` and `..`.
    pub fn list(&mut self, dir: &str) -> Result<Vec<FtpEntry>> {
        check_remote(dir)?;
        let lines = self.stream.list(Some(dir)).map_err(ftp_err)?;
        Ok(lines.iter().filter_map(|l| parse_list_line(l)).filter(|e| e.name != "." && e.name != "..").collect())
    }

    /// Download `remote` into `local`, which must not exist yet. Returns the bytes written.
    pub fn download(&mut self, remote: &str, local: &Path) -> Result<u64> {
        check_remote(remote)?;
        if local.exists() {
            return Err(CoreError::Invalid(format!("{} already exists", local.display())));
        }
        let tmp = local.with_extension("bastion-part");
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let copied = self.stream.retr(remote, |r| {
            let mut buf = [0u8; 64 * 1024];
            let mut total = 0u64;
            loop {
                let n = r.read(&mut buf).map_err(suppaftp::FtpError::ConnectionError)?;
                if n == 0 {
                    return Ok(total);
                }
                file.write_all(&buf[..n]).map_err(suppaftp::FtpError::ConnectionError)?;
                total += n as u64;
            }
        });
        match copied {
            Ok(n) => {
                file.sync_all()?;
                drop(file);
                std::fs::rename(&tmp, local)?;
                Ok(n)
            }
            Err(e) => {
                drop(file);
                let _ = std::fs::remove_file(&tmp);
                Err(ftp_err(e))
            }
        }
    }

    /// Upload local file `local` to `remote` (the server replaces an existing file).
    pub fn upload(&mut self, local: &Path, remote: &str) -> Result<u64> {
        check_remote(remote)?;
        let mut file = std::fs::File::open(local)?;
        self.stream.put_file(remote, &mut file).map_err(ftp_err)
    }

    pub fn delete(&mut self, remote: &str) -> Result<()> {
        check_remote(remote)?;
        self.stream.rm(remote).map_err(ftp_err)
    }

    pub fn quit(mut self) -> Result<()> {
        self.stream.quit().map_err(ftp_err)
    }
}

/// One `LIST` line: Unix (`-rw-r--r-- 1 u g 12 Jan 1 00:00 name`) or DOS
/// (`01-01-25 12:00AM <DIR> name` / `… 12 name`). Unparseable lines are skipped.
pub fn parse_list_line(line: &str) -> Option<FtpEntry> {
    let line = line.trim_end();
    // The `total <blocks>` summary some servers put first is not an entry.
    if line.is_empty() || line.starts_with("total ") {
        return None;
    }
    if let Ok(f) = suppaftp::list::File::try_from(line) {
        return Some(FtpEntry { name: f.name().to_string(), size: (!f.is_directory()).then(|| f.size() as u64), is_dir: f.is_directory() });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_and_dos_list_lines_parse() {
        let f = parse_list_line("-rw-r--r--    1 1000     1000           12 Nov 03 07:00 note.txt").unwrap();
        assert_eq!(f, FtpEntry { name: "note.txt".into(), size: Some(12), is_dir: false });
        let d = parse_list_line("drwxr-xr-x    2 1000     1000         4096 Nov 03 07:00 logs").unwrap();
        assert!(d.is_dir && d.name == "logs" && d.size.is_none());
        let dos = parse_list_line("11-03-25  07:00AM       <DIR>          Reports").unwrap();
        assert!(dos.is_dir && dos.name == "Reports");
        assert!(parse_list_line("total 8").is_none());
    }

    #[test]
    fn fingerprints_are_lowercase_hex_sha256() {
        assert_eq!(cert_fingerprint(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn remote_paths_with_line_breaks_are_refused() {
        assert!(check_remote("a\r\nDELE b").is_err());
        assert!(check_remote("/pub/a b.txt").is_ok());
    }

    #[test]
    fn tls_config_builds_with_and_without_a_pin() {
        assert!(tls_config(None).is_ok());
        assert!(tls_config(Some("ab".repeat(32))).is_ok());
    }
}
