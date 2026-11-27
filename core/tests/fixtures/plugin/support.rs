//! Shared builders for the plugin tests: a zip writer that can also write archives no honest tool
//! would (lying sizes, links, hidden bytes), a signer, and release-record and index payloads.
//! Every fixture is built at run time; keys are generated per test and never stored.
#![allow(dead_code)]
use std::io::Write;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bastion_core::plugin::{key_id, signed_message, Purpose};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const NOW: u64 = 1_800_000_000;
pub const MIB: usize = 1024 * 1024;

// ---- zip ----

#[derive(Clone)]
pub struct Entry {
    pub name: Vec<u8>,
    /// The bytes as they sit in the archive (stored or deflated).
    pub raw: Vec<u8>,
    pub method: u16,
    pub crc: u32,
    /// The uncompressed size the headers claim.
    pub declared: u32,
    pub flags: u16,
    pub made_by: u16,
    pub external: u32,
    pub extra: Vec<u8>,
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

impl Entry {
    fn new(name: &[u8], raw: Vec<u8>, method: u16, data: &[u8]) -> Self {
        // Made by Unix (3), a regular file with mode 0644.
        Entry { name: name.to_vec(), raw, method, crc: crc32(data), declared: data.len() as u32, flags: 0, made_by: (3 << 8) | 20, external: 0o100644 << 16, extra: Vec::new() }
    }
    pub fn stored(name: &str, data: &[u8]) -> Self {
        Self::new(name.as_bytes(), data.to_vec(), 0, data)
    }
    pub fn deflated(name: &str, data: &[u8]) -> Self {
        Self::new(name.as_bytes(), deflate(data), 8, data)
    }
}

fn local_header(out: &mut Vec<u8>, e: &Entry) {
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&e.flags.to_le_bytes());
    out.extend_from_slice(&e.method.to_le_bytes());
    out.extend_from_slice(&[0; 4]); // time, date
    out.extend_from_slice(&e.crc.to_le_bytes());
    out.extend_from_slice(&(e.raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&e.declared.to_le_bytes());
    out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(e.extra.len() as u16).to_le_bytes());
    out.extend_from_slice(&e.name);
    out.extend_from_slice(&e.extra);
}

/// A canonical archive: entries back to back from offset 0, then the directory, then the end
/// record, with nothing after it.
pub fn zip(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for e in entries {
        offsets.push(out.len() as u32);
        local_header(&mut out, e);
        out.extend_from_slice(&e.raw);
    }
    let cd_offset = out.len() as u32;
    for (e, offset) in entries.iter().zip(&offsets) {
        out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        out.extend_from_slice(&e.made_by.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&e.flags.to_le_bytes());
        out.extend_from_slice(&e.method.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&e.crc.to_le_bytes());
        out.extend_from_slice(&(e.raw.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.declared.to_le_bytes());
        out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(e.extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 2]); // comment length
        out.extend_from_slice(&[0; 2]); // disk
        out.extend_from_slice(&[0; 2]); // internal attributes
        out.extend_from_slice(&e.external.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&e.name);
        out.extend_from_slice(&e.extra);
    }
    let cd_size = out.len() as u32 - cd_offset;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]); // disk numbers
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&[0; 2]); // comment length
    out
}

/// The smallest file the reader accepts as a PNG: signature, IHDR (1 x 1, 8-bit RGBA), IEND.
pub fn png() -> Vec<u8> {
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut ihdr = b"IHDR".to_vec();
    ihdr.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
    out.extend_from_slice(&13u32.to_be_bytes());
    out.extend_from_slice(&ihdr);
    out.extend_from_slice(&crc32(&ihdr).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(b"IEND");
    out.extend_from_slice(&crc32(b"IEND").to_be_bytes());
    out
}

pub const EXTERNAL_ID: &str = "com.example.tool";
pub const OFFICIAL_ID: &str = "dev.bastion.postgres";

/// The manifest of section 6, with the id and version filled in. Only an Official id may name
/// "Bastion" as its publisher (A1-C11), so other ids get another publisher.
pub fn manifest(id: &str, version: &str) -> String {
    let publisher = if id.starts_with("dev.bastion") { "Bastion" } else { "Example Tools" };
    format!(
        r#"schema = 1
id = "{id}"
name = "PostgreSQL"
version = "{version}"
api = "1.0"
publisher = "{publisher}"
description = "Query PostgreSQL databases through Bastion connections, gateways and tunnels."
license = "Apache-2.0"
repository = "https://github.com/example/bastion/tree/main/plugins/official/postgres"

[permissions]
network = "entry"
credentials = "entry"
storage = true
clipboard = "write"
files = ["save"]

[[connection_types]]
id = "postgres"
name = "PostgreSQL"
default_port = 5432

[[connection_types.fields]]
key = "database"
label = "Database"
kind = "text"

[[commands]]
id = "new-query"
title = "New Query"
on = "connection:postgres"
"#
    )
}

/// A component header and one import section: the API interfaces the default permissions allow
/// and one WASI clock (PLUG-04b reads this list at install). No code: it is never run here.
pub const WASM: &[u8] = b"\x00asm\x0d\x00\x01\x00\x0a\x83\x02\x08\x00\x1abastion:plugin/types@1.0.0\x05\x00\x00\x1bbastion:plugin/events@1.0.0\x05\x00\x00\x18bastion:plugin/net@1.0.0\x05\x00\x00 bastion:plugin/credentials@1.0.0\x05\x00\x00\x1cbastion:plugin/storage@1.0.0\x05\x00\x00\x1ebastion:plugin/clipboard@1.0.0\x05\x00\x00\x1abastion:plugin/files@1.0.0\x05\x00\x00!wasi:clocks/monotonic-clock@0.2.0\x05\x00";

/// The six required files and the optional changelog, for the given manifest text.
pub fn entries_for(manifest: &str) -> Vec<Entry> {
    vec![
        Entry::deflated("plugin.toml", manifest.as_bytes()),
        Entry::stored("plugin.wasm", WASM),
        Entry::stored("icon.png", &png()),
        Entry::deflated("README.md", b"# PostgreSQL\n\nA plugin.\n"),
        Entry::stored("LICENSE", b"Apache License 2.0\n"),
        Entry::stored("THIRD_PARTY_NOTICES.txt", b"none\n"),
        Entry::stored("CHANGELOG.md", b"1.0.0: first release\n"),
    ]
}

pub fn good_entries() -> Vec<Entry> {
    entries_for(&manifest(EXTERNAL_ID, "1.0.0"))
}

pub fn good_package() -> Vec<u8> {
    zip(&good_entries())
}

pub fn package_for(id: &str, version: &str) -> Vec<u8> {
    zip(&entries_for(&manifest(id, version)))
}

/// Data that deflates, but well under 100 to 1: 32 pseudo-random bytes, then zeros, per KiB.
pub fn compressible(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for block in out.chunks_mut(1024) {
        for byte in block.iter_mut().take(32) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
    }
    out
}

// ---- signatures ----

/// A fresh key for one test. No private key is stored anywhere.
pub fn new_key() -> SigningKey {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

pub fn public(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

pub struct Sig<'a> {
    pub key: &'a SigningKey,
    /// The purpose the signature is really made for.
    pub signed_for: Purpose,
    /// The purpose the envelope says it has.
    pub label: &'a str,
}

pub fn sig(key: &SigningKey, purpose: Purpose) -> Sig<'_> {
    Sig { key, signed_for: purpose, label: purpose.label() }
}

pub fn envelope_value(payload: &[u8], sigs: &[Sig]) -> serde_json::Value {
    let signatures: Vec<serde_json::Value> = sigs
        .iter()
        .map(|s| {
            let signature = s.key.sign(&signed_message(s.signed_for, payload));
            serde_json::json!({ "keyid": key_id(&public(s.key)), "purpose": s.label, "sig": B64.encode(signature.to_bytes()) })
        })
        .collect();
    serde_json::json!({ "payload": B64.encode(payload), "signatures": signatures })
}

pub fn envelope(payload: &[u8], sigs: &[Sig]) -> Vec<u8> {
    serde_json::to_vec(&envelope_value(payload, sigs)).unwrap()
}

pub fn default_permissions() -> serde_json::Value {
    serde_json::json!({ "network": "entry", "credentials": "entry", "storage": true, "clipboard": "write", "files": ["save"] })
}

pub fn record_value(id: &str, version: &str, tier: &str, package: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "schema": 1,
        "id": id,
        "version": version,
        "tier": tier,
        "sha256": hex::encode(Sha256::digest(package)),
        "size": package.len(),
        "api": { "min": "1.0", "max": "1.0" },
        "permissions": default_permissions(),
        "source": { "repository": "https://github.com/example/tool", "commit": "0123456789abcdef0123456789abcdef01234567" },
    })
}

pub fn to_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

/// A correctly signed External record for `package`.
pub fn external_record(index_key: &SigningKey, id: &str, version: &str, package: &[u8]) -> Vec<u8> {
    envelope(&to_bytes(&record_value(id, version, "external", package)), &[sig(index_key, Purpose::ReleaseRecord)])
}

/// A correctly signed Official record for `package`.
pub fn official_record(index_key: &SigningKey, official_key: &SigningKey, id: &str, version: &str, package: &[u8]) -> Vec<u8> {
    envelope(&to_bytes(&record_value(id, version, "official", package)), &[sig(index_key, Purpose::ReleaseRecord), sig(official_key, Purpose::Official)])
}

pub fn index_value(sequence: u64, issued: u64, expires: u64, records: &[Vec<u8>]) -> serde_json::Value {
    let records: Vec<serde_json::Value> = records.iter().map(|r| serde_json::from_slice(r).unwrap()).collect();
    serde_json::json!({ "schema": 1, "sequence": sequence, "issued": issued, "expires": expires, "records": records, "revocations": [], "revoked_keys": [] })
}

pub fn signed_index(key: &SigningKey, value: &serde_json::Value) -> Vec<u8> {
    envelope(&to_bytes(value), &[sig(key, Purpose::Index)])
}

/// A small deterministic generator for the mutation loops.
pub struct Mutator(pub u64);

impl Mutator {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// One of: flip bits in a few bytes, cut the end off, insert bytes, or copy a run elsewhere.
    pub fn mutate(&mut self, good: &[u8]) -> Vec<u8> {
        let mut out = good.to_vec();
        if out.is_empty() {
            return out;
        }
        match self.next() % 4 {
            0 => {
                for _ in 0..1 + self.next() % 4 {
                    let at = (self.next() as usize) % out.len();
                    out[at] ^= 1 << (self.next() % 8);
                }
            }
            1 => out.truncate((self.next() as usize) % out.len()),
            2 => {
                let at = (self.next() as usize) % out.len();
                let byte = self.next() as u8;
                let count = 1 + (self.next() as usize) % 64;
                out.splice(at..at, std::iter::repeat(byte).take(count));
            }
            _ => {
                let from = (self.next() as usize) % out.len();
                let to = (self.next() as usize) % out.len();
                let len = ((self.next() as usize) % 32).min(out.len() - from).min(out.len() - to);
                let run = out[from..from + len].to_vec();
                out[to..to + len].copy_from_slice(&run);
            }
        }
        out
    }
}
