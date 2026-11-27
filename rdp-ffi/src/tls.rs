//! TLS upgrade that trusts exactly the pinned certificate fingerprint.
//!
//! `ironrdp-tls` checks the platform roots before its callback, and loading them reads the
//! macOS Keychain, which prompts on every connect. RDP servers present self-signed
//! certificates, so the roots never help: the pin is the only trust decision.
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::AsyncWriteExt as _;

use crate::certificate_fingerprint;

#[derive(Debug)]
struct PinVerifier {
    pinned: Option<String>,
    /// The fingerprint the server presented, so a refusal can show it to the user.
    seen: Arc<Mutex<Option<String>>>,
    provider: Arc<CryptoProvider>,
}

impl PinVerifier {
    /// Whether `der` is the certificate the user pinned.
    fn accepts(&self, der: &[u8]) -> bool {
        let fingerprint = certificate_fingerprint(der.to_vec());
        let ok = self.pinned.as_deref() == Some(fingerprint.as_str());
        *self.seen.lock().unwrap() = Some(fingerprint);
        ok
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.accepts(end_entity) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate is not pinned".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
pub enum UpgradeError {
    Unpinned(String),
    Other(String),
}

/// Upgrades `stream` to TLS. Fails with the presented fingerprint when it is not `pinned`.
pub async fn upgrade(
    stream: tokio::net::TcpStream,
    host: &str,
    pinned: Option<String>,
) -> Result<(ironrdp_tls::TlsStream<tokio::net::TcpStream>, Vec<u8>), UpgradeError> {
    let other = |e: &dyn std::fmt::Display| UpgradeError::Other(e.to_string());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let seen = Arc::new(Mutex::new(None));
    let verifier = PinVerifier { pinned, seen: Arc::clone(&seen), provider: Arc::clone(&provider) };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| other(&e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    // Servers are often named by IP; rustls needs a name, but only the pin is checked.
    let name = ServerName::try_from(host.to_owned())
        .unwrap_or_else(|_| ServerName::try_from("rdp.invalid").expect("valid DNS name"));
    let mut tls = match tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream).await {
        Ok(tls) => tls,
        Err(e) => {
            return Err(match seen.lock().unwrap().take() {
                Some(fingerprint) => UpgradeError::Unpinned(fingerprint),
                None => other(&e),
            })
        }
    };
    tls.flush().await.map_err(|e| other(&e))?;
    let cert = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec());
    let cert = cert.ok_or_else(|| other(&"peer certificate is missing"))?;
    Ok((tls, cert))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier(pinned: Option<&str>) -> PinVerifier {
        PinVerifier {
            pinned: pinned.map(str::to_owned),
            seen: Arc::default(),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }

    #[test]
    fn only_the_pinned_certificate_is_accepted_and_the_seen_one_is_recorded() {
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verifier(Some(abc)).accepts(b"abc"));
        let other = verifier(Some(abc));
        assert!(!other.accepts(b"abd"));
        assert!(other.seen.lock().unwrap().is_some());
        assert!(!verifier(None).accepts(b"abc"));
    }
}
