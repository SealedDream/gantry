//! Maintainer tool for the plugin catalogue keys and signatures (PLUG-15; `docs/specs/plugins.md`,
//! section 9; runbook `docs/plugins/OPERATIONS.md`). Used through `scripts/plugin-sign.sh`.
//!
//!   keygen <index|official> <key-file>        new Ed25519 key, encrypted with a passphrase
//!   pubkey <key-file>                         public key (hex) and key id; no passphrase needed
//!   envelope <payload.json>                   an unsigned envelope for a payload file
//!   sign <purpose> <key-file> <envelope>      the envelope with one more signature
//!   verify-record <envelope> <index-keys> <official-keys> [revoked-index-keys]
//!   verify-index  <envelope> <index-keys> <official-keys> [revoked-index-keys]
//!   pinned <index-keys> <official-keys>       the Rust lines for `catalogue::pinned_keys`
//!
//! Purposes: `index`, `release-record` (index keys), `official` (official keys). A key file
//! records its role and refuses the other role's purposes. Keys are comma-separated hex lists.
//!
//! The passphrase is read from the first line of standard input (the script prompts without
//! echo). A key file holds the secret only encrypted: Argon2id (64 MiB, 3 passes) and
//! XChaCha20-Poly1305, with the role and public key bound in. The secret never reaches standard
//! output, an argument or the environment.
use std::io::{BufRead, Write};

use argon2::{Algorithm, Argon2, Params, Version as ArgonVersion};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bastion_core::plugin::{key_id, signed_message, verify_index, verify_release_record, IndexOutcome, Purpose, TrustedKeys};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use zeroize::Zeroizing;

const MIN_PASSPHRASE_CHARS: usize = 16;
const KDF: &str = "argon2id-m65536-t3-p1";

fn fail(message: &str) -> ! {
    eprintln!("plugin_sign: {message}");
    std::process::exit(1);
}

fn read_passphrase() -> Zeroizing<String> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line).unwrap_or_else(|_| fail("could not read the passphrase"));
    let text = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string());
    if text.chars().count() < MIN_PASSPHRASE_CHARS {
        fail("the passphrase must have at least 16 characters");
    }
    text
}

fn kdf(passphrase: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("argon2 parameters");
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, ArgonVersion::V0x13, params).hash_password_into(passphrase.as_bytes(), salt, out.as_mut()).expect("argon2");
    out
}

fn aad(role: &str, public: &[u8; 32]) -> String {
    format!("bastion-plugin-key-v1\0{role}\0{}", hex::encode(public))
}

fn role_allows(role: &str, purpose: Purpose) -> bool {
    matches!((role, purpose), ("index", Purpose::Index | Purpose::ReleaseRecord) | ("official", Purpose::Official))
}

fn parse_purpose(label: &str) -> Purpose {
    match label {
        "index" => Purpose::Index,
        "release-record" => Purpose::ReleaseRecord,
        "official" => Purpose::Official,
        _ => fail("purpose must be index, release-record or official"),
    }
}

fn read_json(path: &str) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|_| fail(&format!("cannot read {path}")));
    serde_json::from_slice(&bytes).unwrap_or_else(|_| fail(&format!("{path} is not JSON")))
}

fn hex32(text: &str) -> [u8; 32] {
    hex::decode(text.trim()).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()).unwrap_or_else(|| fail("a key is not 32 bytes of hex"))
}

fn key_list(text: &str) -> Vec<[u8; 32]> {
    text.split(',').map(str::trim).filter(|s| !s.is_empty() && *s != "-").map(hex32).collect()
}

fn keygen(role: &str, path: &str) {
    if role != "index" && role != "official" {
        fail("role must be index or official");
    }
    if std::path::Path::new(path).exists() {
        fail("the key file already exists; a key is never overwritten");
    }
    let passphrase = read_passphrase();
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let (mut salt, mut nonce) = ([0u8; 16], [0u8; 24]);
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let wrap = kdf(&passphrase, &salt);
    let ct = XChaCha20Poly1305::new(wrap.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: seed.as_ref(), aad: aad(role, &public).as_bytes() })
        .unwrap_or_else(|_| fail("encryption failed"));
    let file = serde_json::json!({
        "schema": 1, "role": role, "public": hex::encode(public), "kdf": KDF,
        "salt": hex::encode(salt), "nonce": hex::encode(nonce), "ciphertext": hex::encode(ct),
    });
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path).unwrap_or_else(|_| fail("cannot create the key file"));
    f.write_all(serde_json::to_string_pretty(&file).unwrap().as_bytes()).unwrap_or_else(|_| fail("cannot write the key file"));
    print_pubkey(role, &public);
}

struct KeyFile {
    role: String,
    public: [u8; 32],
    file: serde_json::Value,
}

fn open_key_file(path: &str) -> KeyFile {
    let file = read_json(path);
    if file["schema"] != 1 || file["kdf"] != KDF {
        fail("unknown key file format");
    }
    let role = file["role"].as_str().unwrap_or_default().to_string();
    if role != "index" && role != "official" {
        fail("the key file has no valid role");
    }
    let public = hex32(file["public"].as_str().unwrap_or_default());
    KeyFile { role, public, file }
}

fn unlock(key: &KeyFile) -> SigningKey {
    let field = |name: &str| hex::decode(key.file[name].as_str().unwrap_or_default()).unwrap_or_else(|_| fail("damaged key file"));
    let nonce = field("nonce");
    if nonce.len() != 24 {
        fail("damaged key file");
    }
    let passphrase = read_passphrase();
    let wrap = kdf(&passphrase, &field("salt"));
    let seed = Zeroizing::new(
        XChaCha20Poly1305::new(wrap.as_ref().into())
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &field("ciphertext"), aad: aad(&key.role, &key.public).as_bytes() })
            .unwrap_or_else(|_| fail("wrong passphrase or damaged key file")),
    );
    let seed = Zeroizing::new(<[u8; 32]>::try_from(seed.as_slice()).unwrap_or_else(|_| fail("damaged key file")));
    let signing = SigningKey::from_bytes(&seed);
    if signing.verifying_key().to_bytes() != key.public {
        fail("the key file's public key does not match its secret");
    }
    signing
}

fn print_pubkey(role: &str, public: &[u8; 32]) {
    println!("role       {role}\npublic key {}\nkey id     {}", hex::encode(public), key_id(public));
}

fn sign(purpose: &str, key_path: &str, envelope_path: &str) {
    let purpose = parse_purpose(purpose);
    let key = open_key_file(key_path);
    if !role_allows(&key.role, purpose) {
        fail(&format!("an {} key may not sign for purpose {}", key.role, purpose.label()));
    }
    let mut envelope = read_json(envelope_path);
    let payload = B64.decode(envelope["payload"].as_str().unwrap_or_default()).unwrap_or_else(|_| fail("the envelope payload is not base64"));
    let id = key_id(&key.public);
    let signatures = envelope["signatures"].as_array_mut().unwrap_or_else(|| fail("the envelope has no signatures list"));
    if signatures.iter().any(|s| s["keyid"] == id.as_str() && s["purpose"] == purpose.label()) {
        fail("this key has already signed this envelope for this purpose");
    }
    if purpose == Purpose::Index && signatures.iter().any(|s| s["purpose"] == "index") {
        fail("an index carries exactly one index-key signature");
    }
    let signing = unlock(&key);
    let message = signed_message(purpose, &payload);
    let signature = signing.sign(&message);
    signing.verifying_key().verify_strict(&message, &signature).unwrap_or_else(|_| fail("self-check failed"));
    signatures.push(serde_json::json!({ "keyid": id, "purpose": purpose.label(), "sig": B64.encode(signature.to_bytes()) }));
    println!("{}", serde_json::to_string(&envelope).unwrap());
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn read_bytes(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|_| fail(&format!("cannot read {path}")))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen", role, path] => keygen(role, path),
        ["pubkey", path] => {
            let key = open_key_file(path);
            print_pubkey(&key.role, &key.public);
        }
        ["envelope", payload] => {
            let bytes = read_bytes(payload);
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_else(|_| fail("the payload is not JSON"));
            println!("{}", serde_json::json!({ "payload": B64.encode(&bytes), "signatures": [] }));
        }
        ["sign", purpose, key, envelope] => sign(purpose, key, envelope),
        ["verify-record", envelope, index, official, rest @ ..] if rest.len() <= 1 => {
            let (index, official) = (key_list(index), key_list(official));
            let revoked = rest.first().map(|r| key_list(r)).unwrap_or_default();
            let record = verify_release_record(&read_bytes(envelope), &TrustedKeys { index: &index, official: &official }, &revoked).unwrap_or_else(|e| fail(&format!("refused: {e}")));
            println!("ok {} {} {:?}", record.id, record.version, record.tier);
        }
        ["verify-index", envelope, index, official, rest @ ..] if rest.len() <= 1 => {
            let (index, official) = (key_list(index), key_list(official));
            let revoked = rest.first().map(|r| key_list(r)).unwrap_or_default();
            match verify_index(&read_bytes(envelope), &TrustedKeys { index: &index, official: &official }, &revoked, 0, now()) {
                Ok(IndexOutcome::Usable(i)) => println!(
                    "ok sequence {} expires {} records {} revocations {} revoked-keys {} signer {}",
                    i.sequence,
                    i.expires,
                    i.records.len(),
                    i.revocations.len(),
                    i.revoked_index_keys.len(),
                    key_id(&i.signer)
                ),
                Ok(other) => fail(&format!("refused: {other:?}")),
                Err(e) => fail(&format!("refused: {e}")),
            }
        }
        ["pinned", index, official] => {
            let line = |keys: Vec<[u8; 32]>| keys.iter().map(|k| format!("hex!(\"{}\")", hex::encode(k))).collect::<Vec<_>>().join(", ");
            println!("// index keys: active first, then the offline spare\nindex: &[{}],\nofficial: &[{}],", line(key_list(index)), line(key_list(official)));
        }
        _ => {
            eprintln!("usage: see the top of core/examples/plugin_sign.rs or scripts/plugin-sign.sh");
            std::process::exit(2);
        }
    }
}
