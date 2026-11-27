//! SEC-2: bounds on a KeePass file checked before any key derivation, so a hostile or
//! damaged file cannot make an unlock read gigabytes or spend minutes (or gigabytes of
//! memory) deriving a key. The header is read here; `keepass` does the real parse after.
use crate::error::{CoreError, Result};

/// Largest KeePass file opened. Real databases are a few MiB; attachments make some larger.
pub(crate) const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// AES-KDF rounds. KeePassXC's one-second benchmark gives tens of millions on a fast CPU.
pub(crate) const MAX_AES_ROUNDS: u64 = 300_000_000;
/// Argon2 memory. KeePassXC's default is 64 MiB.
pub(crate) const MAX_ARGON2_MEMORY: u64 = 1024 * 1024 * 1024;
pub(crate) const MAX_ARGON2_ITERATIONS: u64 = 100;
pub(crate) const MAX_ARGON2_PARALLELISM: u64 = 64;
/// Memory × iterations, in MiB passes: 1 GiB × 4, 256 MiB × 16, 64 MiB × 64.
pub(crate) const MAX_ARGON2_MIB_PASSES: u64 = 4096;

const SIG1: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const KDB1: u32 = 0xb54b_fb65;
const KDBX: u32 = 0xb54b_fb67;
const KDBX3_TRANSFORM_ROUNDS: u8 = 10;
const KDBX4_KDF_PARAMETERS: u8 = 11;
const AES_KDF_UUIDS: [[u8; 16]; 2] = [
    // AES-KDF (KDBX 4)
    [0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea],
    // AES-KDF (KDBX 3.1 UUID, also accepted in KDBX 4)
    [0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64, 0x82, 0x38],
];

fn too_costly(what: &str) -> CoreError {
    CoreError::Invalid(format!("KeePass file refused: {what} is above Gantry's limit"))
}

fn short() -> CoreError {
    CoreError::Corrupt("KeePass file: header is cut short".into())
}

fn u16_at(b: &[u8], at: usize) -> Result<u16> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(short)
}

fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or_else(short)
}

fn u64_le(s: &[u8]) -> Option<u64> {
    match s.len() {
        4 => Some(u32::from_le_bytes(s.try_into().ok()?) as u64),
        8 => Some(u64::from_le_bytes(s.try_into().ok()?)),
        _ => None,
    }
}

/// Refuse a file whose key derivation would cost more than the limits above. Formats this
/// check does not know are left to `keepass`, which refuses them.
pub(crate) fn check_header(b: &[u8]) -> Result<()> {
    if b.len() < 12 || b[0..4] != SIG1 {
        return Ok(());
    }
    match u32_at(b, 4)? {
        KDB1 => check_rounds(u32_at(b, 120)? as u64),
        KDBX if u16_at(b, 10)? == 3 => check_kdbx3(b),
        KDBX if u16_at(b, 10)? == 4 => check_kdbx4(b),
        _ => Ok(()),
    }
}

fn check_rounds(rounds: u64) -> Result<()> {
    if rounds > MAX_AES_ROUNDS {
        return Err(too_costly("AES-KDF rounds"));
    }
    Ok(())
}

/// KDBX 3: fields are `id: u8, size: u16, data`, ending with id 0.
fn check_kdbx3(b: &[u8]) -> Result<()> {
    let mut at = 12;
    loop {
        let id = *b.get(at).ok_or_else(short)?;
        let size = u16_at(b, at + 1)? as usize;
        let data = b.get(at + 3..at + 3 + size).ok_or_else(short)?;
        match id {
            0 => return Ok(()),
            KDBX3_TRANSFORM_ROUNDS => check_rounds(u64_le(data).ok_or_else(short)?)?,
            _ => {}
        }
        at += 3 + size;
    }
}

/// KDBX 4: fields are `id: u8, size: u32, data`, ending with id 0; the KDF parameters are
/// a variant dictionary.
fn check_kdbx4(b: &[u8]) -> Result<()> {
    let mut at = 12;
    loop {
        let id = *b.get(at).ok_or_else(short)?;
        let size = u32_at(b, at + 1)? as usize;
        let data = b.get(at + 5..(at + 5).checked_add(size).ok_or_else(short)?).ok_or_else(short)?;
        match id {
            0 => return Ok(()),
            KDBX4_KDF_PARAMETERS => check_kdf_parameters(data)?,
            _ => {}
        }
        at += 5 + size;
    }
}

/// The variant dictionary: `version: u16`, then `type: u8, key_len: i32, key, value_len: i32,
/// value` until type 0.
fn check_kdf_parameters(d: &[u8]) -> Result<()> {
    let mut at = 2;
    let (mut uuid, mut rounds, mut memory, mut iterations, mut parallelism) = (None, None, None, None, None);
    loop {
        let kind = *d.get(at).ok_or_else(short)?;
        if kind == 0 {
            break;
        }
        let key_len = u32_at(d, at + 1)? as usize;
        let key = d.get(at + 5..at + 5 + key_len).ok_or_else(short)?;
        let value_len = u32_at(d, at + 5 + key_len)? as usize;
        let start = at + 9 + key_len;
        let value = d.get(start..start + value_len).ok_or_else(short)?;
        match key {
            b"$UUID" => uuid = Some(value),
            b"R" => rounds = u64_le(value),
            b"M" => memory = u64_le(value),
            b"I" => iterations = u64_le(value),
            b"P" => parallelism = u64_le(value),
            _ => {}
        }
        at = start + value_len;
    }
    if uuid.is_some_and(|u| AES_KDF_UUIDS.iter().any(|a| a.as_slice() == u)) {
        return check_rounds(rounds.unwrap_or(0));
    }
    check_argon2(memory.unwrap_or(0), iterations.unwrap_or(0), parallelism.unwrap_or(0))
}

fn check_argon2(memory: u64, iterations: u64, parallelism: u64) -> Result<()> {
    if memory > MAX_ARGON2_MEMORY {
        return Err(too_costly("Argon2 memory"));
    }
    if iterations > MAX_ARGON2_ITERATIONS {
        return Err(too_costly("Argon2 iterations"));
    }
    if parallelism > MAX_ARGON2_PARALLELISM {
        return Err(too_costly("Argon2 parallelism"));
    }
    if (memory / (1024 * 1024)).saturating_mul(iterations) > MAX_ARGON2_MIB_PASSES {
        return Err(too_costly("Argon2 memory × iterations"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdbx3(rounds: u64) -> Vec<u8> {
        let mut b = SIG1.to_vec();
        b.extend(KDBX.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(3u16.to_le_bytes());
        b.extend([2u8, 16, 0]);
        b.extend([0u8; 16]);
        b.extend([KDBX3_TRANSFORM_ROUNDS, 8, 0]);
        b.extend(rounds.to_le_bytes());
        b.extend([0u8, 0, 0]);
        b
    }

    fn entry(d: &mut Vec<u8>, kind: u8, key: &[u8], value: &[u8]) {
        d.push(kind);
        d.extend((key.len() as u32).to_le_bytes());
        d.extend(key);
        d.extend((value.len() as u32).to_le_bytes());
        d.extend(value);
    }

    fn kdbx4(dict: &[(u8, &[u8], Vec<u8>)]) -> Vec<u8> {
        let mut d = vec![0x00, 0x01];
        for (kind, key, value) in dict {
            entry(&mut d, *kind, key, value);
        }
        d.push(0);
        let mut b = SIG1.to_vec();
        b.extend(KDBX.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(4u16.to_le_bytes());
        b.push(KDBX4_KDF_PARAMETERS);
        b.extend((d.len() as u32).to_le_bytes());
        b.extend(d);
        b.extend([0u8, 0, 0, 0, 0]);
        b
    }

    fn argon2(m: u64, i: u64, p: u32) -> Vec<u8> {
        kdbx4(&[(0x42, b"$UUID", vec![0xef; 16]), (0x05, b"M", m.to_le_bytes().to_vec()), (0x05, b"I", i.to_le_bytes().to_vec()), (0x04, b"P", p.to_le_bytes().to_vec())])
    }

    #[test]
    fn default_settings_pass() {
        check_header(&kdbx3(60_000)).unwrap();
        check_header(&argon2(64 << 20, 10, 2)).unwrap();
        check_header(&kdbx4(&[(0x42, b"$UUID", AES_KDF_UUIDS[0].to_vec()), (0x05, b"R", 60_000u64.to_le_bytes().to_vec())])).unwrap();
        check_header(b"not a keepass file").unwrap();
    }

    #[test]
    fn costly_kdf_settings_are_refused() {
        assert!(matches!(check_header(&kdbx3(MAX_AES_ROUNDS + 1)), Err(CoreError::Invalid(_))));
        let aes = kdbx4(&[(0x42, b"$UUID", AES_KDF_UUIDS[1].to_vec()), (0x05, b"R", u64::MAX.to_le_bytes().to_vec())]);
        assert!(matches!(check_header(&aes), Err(CoreError::Invalid(_))));
        for bad in [argon2(MAX_ARGON2_MEMORY + 1, 1, 1), argon2(1 << 20, MAX_ARGON2_ITERATIONS + 1, 1), argon2(1 << 20, 1, 65), argon2(1 << 30, 5, 1)] {
            assert!(matches!(check_header(&bad), Err(CoreError::Invalid(_))));
        }
    }

    #[test]
    fn a_cut_header_is_corrupt_not_a_panic() {
        let full = argon2(64 << 20, 10, 2);
        for len in 12..full.len() - 1 {
            let _ = check_header(&full[..len]);
        }
        assert!(matches!(check_header(&full[..20]), Err(CoreError::Corrupt(_))));
    }
}
