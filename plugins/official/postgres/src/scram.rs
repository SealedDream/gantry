//! SCRAM-SHA-256 (RFC 5802, RFC 7677), the client side, as PostgreSQL uses it.
//!
//! - No channel binding (`n,,`): the core runs TLS, so the plugin has no access to the
//!   server's certificate for `tls-server-end-point`.
//! - The user name is empty in the SCRAM messages: PostgreSQL takes it from the startup message.
//! - The password goes in as its UTF-8 bytes. SASLprep is not applied (no `stringprep` crate);
//!   PostgreSQL itself falls back to the raw bytes when SASLprep fails, so ASCII passwords and
//!   most others work. A password that SASLprep would change may be refused: a stated residual.
//! - The server's signature is checked: a server that does not know the password fails.
//! - The iteration count is bounded, so a hostile server cannot make the plugin spin.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const MECHANISM: &str = "SCRAM-SHA-256";
/// The fewest iterations accepted (RFC 7677 asks for at least 4096).
pub const MIN_ITERATIONS: u32 = 4096;
/// The most iterations accepted: enough for any real server, small enough to stay inside the
/// helper's compute limit.
pub const MAX_ITERATIONS: u32 = 100_000;
const GS2: &str = "n,,";

/// Why the login failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScramError(pub &'static str);

/// One SCRAM exchange.
pub struct Scram {
    client_nonce: String,
    client_first_bare: String,
    salted: Option<[u8; 32]>,
    auth_message: Option<String>,
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

fn attr(msg: &str, key: char) -> Option<&str> {
    msg.split(',').find_map(|p| p.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

impl Scram {
    /// Starts with a client nonce of printable characters (no comma).
    pub fn new(client_nonce: &str) -> Result<Scram, ScramError> {
        if client_nonce.len() < 18 || !client_nonce.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b',') {
            return Err(ScramError("bad client nonce"));
        }
        let client_first_bare = format!("n=,r={client_nonce}");
        Ok(Scram { client_nonce: client_nonce.into(), client_first_bare, salted: None, auth_message: None })
    }

    /// The client-first message.
    pub fn client_first(&self) -> Vec<u8> {
        format!("{GS2}{}", self.client_first_bare).into_bytes()
    }

    /// Takes the server-first message; returns the client-final message.
    pub fn client_final(&mut self, server_first: &[u8], password: &[u8]) -> Result<Vec<u8>, ScramError> {
        let server_first = std::str::from_utf8(server_first).map_err(|_| ScramError("server-first is not text"))?;
        if server_first.starts_with("m=") {
            return Err(ScramError("the server asks for a SCRAM extension"));
        }
        let nonce = attr(server_first, 'r').ok_or(ScramError("server-first has no nonce"))?;
        if !nonce.starts_with(&self.client_nonce) || nonce.len() <= self.client_nonce.len() {
            return Err(ScramError("the server's nonce does not extend ours"));
        }
        let salt = STANDARD.decode(attr(server_first, 's').ok_or(ScramError("server-first has no salt"))?).map_err(|_| ScramError("the salt is not base64"))?;
        let iterations: u32 = attr(server_first, 'i').and_then(|i| i.parse().ok()).ok_or(ScramError("server-first has no iteration count"))?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(ScramError("the iteration count is out of range"));
        }
        let mut salted = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password, &salt, iterations, &mut salted);
        let client_key = hmac(&salted, b"Client Key");
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let without_proof = format!("c={},r={nonce}", STANDARD.encode(GS2));
        let auth_message = format!("{},{server_first},{without_proof}", self.client_first_bare);
        let signature = hmac(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key.iter().zip(signature.iter()).map(|(a, b)| a ^ b).collect();
        self.salted = Some(salted);
        self.auth_message = Some(auth_message);
        Ok(format!("{without_proof},p={}", STANDARD.encode(proof)).into_bytes())
    }

    /// Checks the server-final message: the server proves it knows the password too.
    pub fn verify_server(&self, server_final: &[u8]) -> Result<(), ScramError> {
        let (Some(salted), Some(auth_message)) = (self.salted, self.auth_message.as_ref()) else {
            return Err(ScramError("server-final came too early"));
        };
        let server_final = std::str::from_utf8(server_final).map_err(|_| ScramError("server-final is not text"))?;
        if attr(server_final, 'e').is_some() {
            return Err(ScramError("the server refused the login"));
        }
        let given = STANDARD.decode(attr(server_final, 'v').ok_or(ScramError("server-final has no signature"))?).map_err(|_| ScramError("the signature is not base64"))?;
        let server_key = hmac(&salted, b"Server Key");
        let mut m = HmacSha256::new_from_slice(&server_key).expect("HMAC takes any key length");
        m.update(auth_message.as_bytes());
        // `verify_slice` compares in constant time.
        m.verify_slice(&given).map_err(|_| ScramError("the server's signature is wrong"))
    }
}

impl Drop for Scram {
    fn drop(&mut self) {
        if let Some(s) = self.salted.as_mut() {
            s.iter_mut().for_each(|b| *b = 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677 section 3, with PostgreSQL's empty user name: the proof depends on the user
    /// name through the auth message, so this recomputes the expected values with the server
    /// side below rather than copying the RFC's (whose user is "user").
    fn server_side(password: &[u8], salt: &[u8], iterations: u32, client_first_bare: &str, server_first: &str, client_final_no_proof: &str) -> ([u8; 32], [u8; 32]) {
        let mut salted = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut salted);
        let client_key = hmac(&salted, b"Client Key");
        let stored: [u8; 32] = Sha256::digest(client_key).into();
        let auth = format!("{client_first_bare},{server_first},{client_final_no_proof}");
        let client_sig = hmac(&stored, auth.as_bytes());
        let server_sig = hmac(&hmac(&salted, b"Server Key"), auth.as_bytes());
        let mut proof = [0u8; 32];
        for i in 0..32 {
            proof[i] = client_key[i] ^ client_sig[i];
        }
        (proof, server_sig)
    }

    #[test]
    fn the_rfc_7677_example_matches() {
        // RFC 7677 section 3: user "user", password "pencil".
        let client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let client_final_no_proof = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let salt = STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let (proof, server_sig) = server_side(b"pencil", &salt, 4096, client_first_bare, server_first, client_final_no_proof);
        assert_eq!(STANDARD.encode(proof), "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
        assert_eq!(STANDARD.encode(server_sig), "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
    }

    fn exchange(password: &[u8], server_password: &[u8]) -> (Result<(), ScramError>, Vec<u8>) {
        let mut c = Scram::new("rOprNGfwEbeRWgbNEkqO").unwrap();
        assert_eq!(c.client_first(), b"n,,n=,r=rOprNGfwEbeRWgbNEkqO".to_vec());
        let server_first = "r=rOprNGfwEbeRWgbNEkqOserverpart,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let fin = c.client_final(server_first.as_bytes(), password).unwrap();
        let fin_s = String::from_utf8(fin.clone()).unwrap();
        let (no_proof, _) = fin_s.rsplit_once(",p=").unwrap();
        let salt = STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let (_, sig) = server_side(server_password, &salt, 4096, "n=,r=rOprNGfwEbeRWgbNEkqO", server_first, no_proof);
        (c.verify_server(format!("v={}", STANDARD.encode(sig)).as_bytes()), fin)
    }

    #[test]
    fn a_full_exchange_proves_both_sides() {
        let (ok, fin) = exchange(b"pencil", b"pencil");
        assert_eq!(ok, Ok(()));
        // The final message carries the proof, never the password.
        assert!(!fin.windows(6).any(|w| w == b"pencil"));
    }

    #[test]
    fn a_server_that_does_not_know_the_password_fails() {
        assert!(exchange(b"pencil", b"other").0.is_err());
    }

    #[test]
    fn hostile_server_first_messages_are_refused() {
        let mut c = Scram::new("rOprNGfwEbeRWgbNEkqO").unwrap();
        for bad in [
            "r=someoneelse,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            "r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1",
            "r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4000000000",
            "r=rOprNGfwEbeRWgbNEkqOx,s=***,i=4096",
            "m=ext,r=rOprNGfwEbeRWgbNEkqOx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        ] {
            assert!(c.client_final(bad.as_bytes(), b"pencil").is_err(), "{bad}");
        }
        assert!(c.verify_server(b"v=AAAA").is_err());
        assert!(Scram::new("short").is_err());
        assert!(Scram::new("has,a,comma,in,it,xxxxxx").is_err());
    }
}
