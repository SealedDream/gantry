//! Test seed for the one-time Personal migration (NW-OF-A, PR #720): writes an OLD-style Personal
//! (`<data dir>\library.json` + `credentials.vault`, vault key in DPAPI as before) with folder
//! "Seed", connections "seed-ssh" and "seed-rdp", and one saved password assigned to both.
//! Usage: cargo run -p bastion-ffi --example seed_legacy_personal -- <data dir> <test password>
//! Throwaway test data only; refuses a data dir that already has a library.json.
use bastion_ffi::{CredentialVault, Library};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(args.next().ok_or("usage: seed_legacy_personal <data dir> <test password>")?);
    let password = args.next().ok_or("usage: seed_legacy_personal <data dir> <test password>")?;
    let lib_path = dir.join("library.json");
    if lib_path.exists() {
        return Err(format!("{} already exists: back it up and remove it first", lib_path.display()).into());
    }
    std::fs::create_dir_all(&dir)?;
    let lib = Library::open(lib_path.display().to_string())?;
    let folder = lib.add_folder(None, "Seed".into())?;
    let ssh = lib.add_connection(Some(folder.clone()), "seed-ssh".into(), "ssh".into(), "127.0.0.1".into(), Some(2222), Some("bastiontest".into()))?;
    let rdp = lib.add_connection(Some(folder), "seed-rdp".into(), "rdp".into(), std::env::var("LAB_VM_TEST1_HOST").unwrap_or_else(|_| "rdp-target.example".into()), None, Some("test".into()))?;
    let vault = CredentialVault::open(dir.join("credentials.vault").display().to_string())?;
    let cred = vault.save_password(None, "seed login".into(), None, "bastiontest".into(), password)?;
    vault.save()?;
    lib.set_credential(ssh, Some(cred.clone()))?;
    lib.set_credential(rdp, Some(cred))?;
    lib.save()?;
    println!("seeded {}: folder Seed, seed-ssh, seed-rdp, 1 credential (seed login)", dir.display());
    Ok(())
}
