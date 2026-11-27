//! Released secrets and the secret check (spec section 5, "Released secrets"; T18.21).
//!
//! One function, [`SecretCheck::matches`], decides whether a byte string holds a secret. It is
//! Residual (stated): base64 is matched only as the encoding of the secret on its own. A secret
//! encoded inside a longer value, at an offset that is not a multiple of 3 bytes, gives
//! different base64 characters and is not matched; nor are encodings the check does not know.
//! The check is a defence against mistakes and simple leaks, not against a plugin that hides a
//! secret on purpose (spec section 5, "Residuals"; T18.21).
//!
//! It is used for storage writes, log lines, clipboard writes, abort bytes, the pre-TLS preamble, and
//! the warning when a user saves a plugin field value equal to the entry's password.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use zeroize::Zeroizing;

use super::Failure;

/// Secrets shorter than this are matched only as exact bytes: their encoded forms collide with
/// ordinary text.
pub const MIN_ENCODED_SECRET_BYTES: usize = 6;

/// The needles one secret produces: the secret itself and, from 6 bytes, its encodings.
struct Needles(Vec<Zeroizing<Vec<u8>>>);

impl Needles {
    fn of(secret: &[u8]) -> Needles {
        let mut v: Vec<Zeroizing<Vec<u8>>> = vec![Zeroizing::new(secret.to_vec())];
        if secret.len() >= MIN_ENCODED_SECRET_BYTES {
            for e in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                v.push(Zeroizing::new(e.encode(secret).into_bytes()));
            }
            v.push(Zeroizing::new(hex::encode(secret).into_bytes()));
            v.push(Zeroizing::new(hex::encode_upper(secret).into_bytes()));
            v.push(Zeroizing::new(percent_encode(secret, false)));
            v.push(Zeroizing::new(percent_encode(secret, true)));
        }
        v.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        v.dedup_by(|a, b| a.as_slice() == b.as_slice());
        Needles(v)
    }
}

/// RFC 3986 percent-encoding: every byte outside the unreserved set as `%XX`.
fn percent_encode(secret: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut out = Vec::with_capacity(secret.len() * 3);
    for &b in secret {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(&[b'%', digits[(b >> 4) as usize], digits[(b & 15) as usize]]);
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// The secrets a check runs against: the passwords released to one helper, or the one saved
/// password of an entry. Wiped on drop.
#[derive(Default)]
pub struct SecretCheck {
    needles: Vec<Needles>,
}

impl std::fmt::Debug for SecretCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretCheck({} secrets)", self.needles.len())
    }
}

impl SecretCheck {
    pub fn new() -> SecretCheck {
        SecretCheck::default()
    }

    /// Add a secret. Empty secrets are ignored: they would match everything.
    pub fn add(&mut self, secret: &[u8]) {
        if !secret.is_empty() {
            self.needles.push(Needles::of(secret));
        }
    }

    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    /// Whether `bytes` holds any of the secrets, exactly or in a defined encoding.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.needles.iter().any(|n| n.0.iter().any(|needle| contains(bytes, needle)))
    }

    /// The refusal for a write that passes the check, in the core's words.
    pub fn refuse(&self, bytes: &[u8]) -> Result<(), Failure> {
        if self.matches(bytes) {
            Err(Failure::Denied("holds a saved password".into()))
        } else {
            Ok(())
        }
    }
}

/// What the core does when the user saves a plugin field value (A1-C1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldSave {
    /// Save it.
    Save,
    /// Warn in the core's words first; the user may cancel or confirm.
    WarnMatchesPassword,
}

/// The warning text for [`FieldSave::WarnMatchesPassword`].
pub const FIELD_MATCHES_PASSWORD_WARNING: &str = "This matches the entry's saved password. Fields are stored without encryption.";

/// Decide a field save. `entry_password` is `None` while credentials are locked or when the
/// entry has no saved password: then there is nothing to compare with, and the value is saved
/// (a stated residual).
pub fn field_save(value: &str, entry_password: Option<&[u8]>) -> FieldSave {
    let Some(pw) = entry_password else { return FieldSave::Save };
    let mut c = SecretCheck::new();
    c.add(pw);
    if c.matches(value.as_bytes()) {
        FieldSave::WarnMatchesPassword
    } else {
        FieldSave::Save
    }
}

/// What happens to a plugin log line (section 5): a line that passes the check is dropped
/// whole, and the drop is counted.
pub fn log_line_kept(check: &SecretCheck, line: &str) -> bool {
    !check.matches(line.as_bytes())
}
