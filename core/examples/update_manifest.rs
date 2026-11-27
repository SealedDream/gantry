//! Release tool for signed update manifests (see `bastion_core::update`).
//!
//!   keygen <secret-key-file>          new Ed25519 key; the file (hex, mode 0600) must stay offline
//!   pubkey <secret-key-file>          print the public key (hex) and key id for the app's trust list
//!   sign <secret-key-file> <payload>  print the signed envelope for a payload JSON file
//!
//! The signer re-verifies its own output with the core verifier before printing it.
use std::io::Write;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bastion_core::update::{key_id, verify_manifest};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use zeroize::Zeroizing;

fn load(path: &str) -> SigningKey {
    let text = Zeroizing::new(std::fs::read_to_string(path).expect("read secret key"));
    let bytes = Zeroizing::new(hex::decode(text.trim()).expect("secret key is hex"));
    SigningKey::from_bytes(&<[u8; 32]>::try_from(bytes.as_slice()).expect("secret key is 32 bytes"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen", path] => {
            let mut raw = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(raw.as_mut());
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            let mut f = opts.open(path).expect("create key file (refuses to overwrite)");
            f.write_all(hex::encode(raw.as_ref()).as_bytes()).expect("write key");
            print_pubkey(&SigningKey::from_bytes(&raw));
        }
        ["pubkey", path] => print_pubkey(&load(path)),
        ["sign", path, payload] => {
            let key = load(path);
            let bytes = std::fs::read(payload).expect("read payload");
            let m: serde_json::Value = serde_json::from_slice(&bytes).expect("payload is JSON");
            let pk = key.verifying_key().to_bytes();
            let env = serde_json::to_vec_pretty(&serde_json::json!({
                "payload": B64.encode(&bytes),
                "signatures": [{ "keyid": key_id(&pk), "sig": B64.encode(key.sign(&bytes).to_bytes()) }],
            }))
            .unwrap();
            // Self-check with the core verifier (installed-version floor 0.0.0, current time).
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let channel = m["channel"].as_str().unwrap_or_default();
            verify_manifest(&env, &[pk], channel, "0.0.0", now).expect("the signed manifest must verify");
            std::io::stdout().write_all(&env).unwrap();
            println!();
        }
        _ => {
            eprintln!("usage: update_manifest keygen|pubkey <secret-key-file> | sign <secret-key-file> <payload.json>");
            std::process::exit(2);
        }
    }
}

fn print_pubkey(key: &SigningKey) {
    let pk = key.verifying_key().to_bytes();
    println!("public key {}\nkey id     {}", hex::encode(pk), key_id(&pk));
}
