//! FTPS: FTP with explicit TLS (`AUTH TLS`, then `PBSZ 0` / `PROT P`), so the login and every
//! data connection are encrypted. Plain FTP is never offered. FTP servers mostly present
//! self-signed certificates, so trust works like SSH host keys and RDP: the certificate's SHA-256
//! is pinned on first use and must match afterwards, on the control and every data connection.
//! Transfers never overwrite unless asked and go through a temporary name.
use std::path::Path;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2_010::{Digest, Sha256};
use suppaftp::list::ListParser;
use suppaftp::types::FileType;
use suppaftp::tokio::{AsyncRustlsConnector, AsyncRustlsFtpStream};
use suppaftp::FtpError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{CoreError, Result};
use crate::sftp::{EntryKind, RemoteEntry};
use crate::vault::Secret;

const CHUNK: usize = 64 * 1024;
pub const DEFAULT_PORT: u16 = 21;

/// Lowercase hex SHA-256 of a DER certificate (what the trust prompt shows and the pin stores).
pub fn certificate_fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Accepts exactly the pinned certificate; records what the server presented either way.
#[derive(Debug)]
struct PinVerifier {
    pinned: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = certificate_fingerprint(end_entity.as_ref());
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(fp.clone());
        if self.pinned.as_deref() == Some(fp.as_str()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate not trusted yet".into()))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn ftp_err(e: FtpError) -> CoreError {
    match e {
        FtpError::UnexpectedResponse(r) if r.status.code() == 530 => CoreError::AuthFailed,
        e => CoreError::Ssh(format!("FTPS: {e}")),
    }
}

/// Entries from an MLSD listing (`mlsd`) or a UNIX `LIST` one.
pub fn parse_lines(lines: &[String], mlsd: bool) -> Vec<RemoteEntry> {
    lines
        .iter()
        .filter_map(|l| if mlsd { ListParser::parse_mlsd(l) } else { ListParser::parse_posix(l) }.ok())
        .filter(|f| f.name() != "." && f.name() != "..")
        .map(|f| {
            let kind = if f.is_directory() {
                EntryKind::Dir
            } else if f.is_symlink() {
                EntryKind::Symlink
            } else {
                EntryKind::File
            };
            let modified = f.modified().duration_since(std::time::UNIX_EPOCH).ok().and_then(|d| u32::try_from(d.as_secs()).ok());
            RemoteEntry { name: f.name().to_string(), kind, size: f.size() as u64, modified, permissions: None }
        })
        .filter(|e| crate::localfile::safe_file_name(&e.name))
        .collect()
}

pub struct Ftps {
    stream: AsyncRustlsFtpStream,
}

impl Ftps {
    /// Connects, upgrades with `AUTH TLS` and logs in. An untrusted certificate fails with
    /// `HostKeyUnknown { fingerprint }`; connect again with `pinned` set to it once the user
    /// verified it. A server that refuses `AUTH TLS` is refused (no plain FTP).
    pub async fn connect(host: &str, port: u16, user: &str, password: &Secret, pinned: Option<&str>) -> Result<Ftps> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let seen = Arc::new(Mutex::new(None));
        let verifier = Arc::new(PinVerifier { pinned: pinned.map(str::to_lowercase), seen: seen.clone(), provider: provider.clone() });
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| CoreError::Ssh(format!("FTPS: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let connector = AsyncRustlsConnector::from(tokio_rustls::TlsConnector::from(Arc::new(config)));
        let plain = AsyncRustlsFtpStream::connect((host, port)).await.map_err(ftp_err)?;
        let mut stream = match plain.into_secure(connector, host).await {
            Ok(s) => s,
            Err(e) => {
                return Err(match seen.lock().unwrap_or_else(|p| p.into_inner()).take() {
                    Some(fingerprint) if pinned.map(str::to_lowercase).as_deref() != Some(fingerprint.as_str()) => CoreError::HostKeyUnknown { fingerprint },
                    _ => CoreError::Ssh(format!("FTPS: the server did not accept AUTH TLS ({e}); plain FTP is not offered")),
                })
            }
        };
        stream.login(user, password.expose()).await.map_err(ftp_err)?;
        stream.transfer_type(FileType::Binary).await.map_err(ftp_err)?;
        Ok(Ftps { stream })
    }

    pub async fn home(&mut self) -> Result<String> {
        self.stream.pwd().await.map_err(ftp_err)
    }

    pub async fn list(&mut self, dir: &str) -> Result<Vec<RemoteEntry>> {
        match self.stream.mlsd(Some(dir)).await {
            Ok(lines) => Ok(parse_lines(&lines, true)),
            // Servers without MLSD (RFC 3659) get a UNIX `LIST`.
            Err(_) => Ok(parse_lines(&self.stream.list(Some(dir)).await.map_err(ftp_err)?, false)),
        }
    }

    pub async fn exists(&mut self, path: &str) -> Result<bool> {
        Ok(self.stream.size(path).await.is_ok() || self.stream.mlst(Some(path)).await.is_ok())
    }

    pub async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        if self.exists(to).await? {
            return Err(CoreError::Invalid(format!("{to} already exists")));
        }
        self.stream.rename(from, to).await.map_err(ftp_err)
    }

    pub async fn mkdir(&mut self, path: &str) -> Result<()> {
        self.stream.mkdir(path).await.map_err(ftp_err)
    }

    pub async fn remove_file(&mut self, path: &str) -> Result<()> {
        self.stream.rm(path).await.map_err(ftp_err)
    }

    /// Stores `local` under an unpredictable temporary name, then renames it into place. With
    /// `overwrite` an existing `remote` is set aside first and only removed once the new file is
    /// in place, so a failure never leaves `remote` missing.
    pub async fn upload(&mut self, local: &Path, remote: &str, overwrite: bool) -> Result<u64> {
        if !overwrite && self.exists(remote).await? {
            return Err(CoreError::Invalid(format!("{remote} already exists")));
        }
        let part = format!("{remote}.{}{}", uuid::Uuid::new_v4().simple(), crate::scp::PART_SUFFIX);
        let mut file = tokio::fs::File::open(local).await?;
        let sent = match self.stream.put_file(&part, &mut file).await {
            Ok(n) => n,
            Err(e) => {
                let _ = self.stream.rm(&part).await;
                return Err(ftp_err(e));
            }
        };
        if !(overwrite && self.exists(remote).await?) {
            if let Err(e) = self.stream.rename(part.as_str(), remote).await {
                let _ = self.stream.rm(&part).await;
                return Err(ftp_err(e));
            }
            return Ok(sent);
        }
        let backup = format!("{remote}.{}.bastion-old", uuid::Uuid::new_v4().simple());
        self.stream
            .rename(remote, backup.as_str())
            .await
            .map_err(|e| CoreError::Ssh(format!("FTPS: could not set {remote} aside to replace it ({e}); the upload is kept at {part}")))?;
        match self.stream.rename(part.as_str(), remote).await {
            Ok(()) => {
                let _ = self.stream.rm(&backup).await;
                Ok(sent)
            }
            Err(e) => match self.stream.rename(backup.as_str(), remote).await {
                Ok(()) => {
                    let _ = self.stream.rm(&part).await;
                    Err(ftp_err(e))
                }
                Err(restore) => Err(CoreError::Ssh(format!(
                    "FTPS: replacing {remote} failed ({e}) and restoring it failed ({restore}); the original is at {backup}, the upload at {part}"
                ))),
            },
        }
    }

    /// Fetches `remote` into `local` through an owner-only temporary file.
    pub async fn download(&mut self, remote: &str, local: &Path, overwrite: bool) -> Result<u64> {
        crate::localfile::check_download_target(local)?;
        if !overwrite && local.exists() {
            return Err(CoreError::Invalid(format!("{} already exists", local.display())));
        }
        let mut data = self.stream.retr_as_stream(remote).await.map_err(ftp_err)?;
        let mut part = crate::localfile::PartFile::create(local).await?;
        let mut buf = vec![0u8; CHUNK];
        let mut total = 0u64;
        loop {
            let n = data.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            part.file.write_all(&buf[..n]).await?;
            total += n as u64;
        }
        data.finish().await.map_err(ftp_err)?;
        part.commit(local, overwrite).await?;
        Ok(total)
    }

    pub async fn quit(&mut self) -> Result<()> {
        self.stream.quit().await.map_err(ftp_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlsd_and_unix_listings_parse() {
        let lines = vec![
            "type=cdir;modify=20261103072100; .".to_string(),
            "type=dir;modify=20261103072100;UNIX.mode=0755; reports".to_string(),
            "type=file;size=1234;modify=20261103072100; notes.txt".to_string(),
        ];
        let e = parse_lines(&lines, true);
        let got: Vec<_> = e.iter().map(|x| (x.name.as_str(), &x.kind, x.size)).collect();
        assert_eq!(got, [("reports", &EntryKind::Dir, 0), ("notes.txt", &EntryKind::File, 1234)]);
        let unix = vec!["total 4".to_string(), "-rw-r--r--    1 1000 1000    48 Nov  1 22:54 legacy.txt".to_string()];
        let e = parse_lines(&unix, false);
        assert_eq!(e.iter().map(|x| (x.name.as_str(), x.size)).collect::<Vec<_>>(), [("legacy.txt", 48)]);
    }

    #[test]
    fn fingerprint_is_lowercase_sha256_hex() {
        assert_eq!(certificate_fingerprint(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn verifier_accepts_only_the_pin_and_reports_what_it_saw() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let der = CertificateDer::from(b"not a real certificate".to_vec());
        let fp = certificate_fingerprint(der.as_ref());
        let name = ServerName::try_from("ftp.example").unwrap();
        for (pinned, ok) in [(None, false), (Some("00".repeat(32)), false), (Some(fp.clone()), true)] {
            let seen = Arc::new(Mutex::new(None));
            let v = PinVerifier { pinned, seen: seen.clone(), provider: provider.clone() };
            assert_eq!(v.verify_server_cert(&der, &[], &name, &[], UnixTime::now()).is_ok(), ok);
            assert_eq!(seen.lock().unwrap().as_deref(), Some(fp.as_str()));
        }
    }
}
