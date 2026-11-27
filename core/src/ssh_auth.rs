//! SSH user authentication: passwords (falling back to keyboard-interactive when the server only
//! offers that), private keys with their OpenSSH certificates, the system SSH agent (which also
//! signs for FIDO2 `sk-` keys), and keyboard-interactive prompts for multi-factor logins.
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use russh::MethodKind;
use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse, Prompt};
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::agent::AgentIdentity;
use russh::keys::{self, Certificate, PrivateKeyWithHashAlg};

use crate::error::{CoreError, Result};
use crate::ssh::{SshAuth, Verifier};
use crate::vault::Secret;

/// The most info-request rounds one keyboard-interactive login may take.
const MAX_ROUNDS: usize = 8;

/// One question a server asks during keyboard-interactive login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KbdPrompt {
    pub text: String,
    /// Whether the answer may be shown while typed (false for passwords and codes).
    pub echo: bool,
}

/// A round of keyboard-interactive questions, as the server worded them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KbdChallenge {
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<KbdPrompt>,
}

pub type PromptFuture<'a> = Pin<Box<dyn Future<Output = Option<Vec<Secret>>> + Send + 'a>>;

/// Asks the person at the keyboard. `None` cancels the login. Answers are in prompt order.
pub trait KbdPrompter: Send + Sync {
    fn answer<'a>(&'a self, challenge: &'a KbdChallenge) -> PromptFuture<'a>;
}

pub(crate) async fn authenticate(handle: &mut Handle<Verifier>, user: &str, auth: SshAuth, prompter: Option<Arc<dyn KbdPrompter>>, allow_sha1: bool) -> Result<()> {
    let prompter = prompter.as_deref();
    let first = match auth {
        SshAuth::Password(pw) => password(handle, user, &pw, prompter).await?,
        SshAuth::KeyFile { path, passphrase } => {
            let key = keys::load_secret_key(&path, passphrase.as_ref().map(Secret::expose))
                .map_err(|e| CoreError::Invalid(format!("cannot load key {}: {e}", path.display())))?;
            // russh signs RSA certificates only with SHA-1, so without consent the key itself is used.
            match certificate_for(&path) {
                Some(cert) if allow_sha1 || !is_rsa(&key) => handle.authenticate_openssh_cert(user, Arc::new(key), cert).await.map_err(ssh_err)?,
                _ => publickey(handle, user, key, allow_sha1).await?,
            }
        }
        SshAuth::KeyPem { pem, passphrase } => {
            let key = keys::decode_secret_key(pem.expose(), passphrase.as_ref().map(Secret::expose))
                .map_err(|e| CoreError::Invalid(format!("cannot decode key: {e}")))?;
            publickey(handle, user, key, allow_sha1).await?
        }
        SshAuth::Agent { .. } => agent(handle, user, allow_sha1).await?,
        SshAuth::PasswordAndCode { password: pw, .. } => self::password(handle, user, &pw, prompter).await?,
    };
    match first {
        AuthResult::Success => Ok(()),
        // A first factor was accepted and the server wants more (for example a one-time code).
        AuthResult::Failure { partial_success: true, remaining_methods } if remaining_methods.contains(&MethodKind::KeyboardInteractive) => {
            match keyboard_interactive(handle, user, None, prompter).await? {
                AuthResult::Success => Ok(()),
                AuthResult::Failure { .. } => Err(CoreError::AuthFailed),
            }
        }
        AuthResult::Failure { .. } => Err(CoreError::AuthFailed),
    }
}

/// `<key>-cert.pub` next to a private key, as `ssh` looks for it.
fn certificate_path(key: &Path) -> PathBuf {
    let mut name = key.as_os_str().to_owned();
    name.push("-cert.pub");
    PathBuf::from(name)
}

fn certificate_for(key: &Path) -> Option<Certificate> {
    let path = certificate_path(key);
    path.is_file().then(|| keys::load_openssh_certificate(&path).ok()).flatten()
}

/// The hash for RSA user signatures: the strongest SHA-2 one the server lists; SHA-2 as well
/// when the server lists none or sends no `server-sig-algs`; legacy SHA-1 (`None`) only with
/// explicit weak-algorithm consent for this host (never under the policy veto).
pub(crate) async fn rsa_hash(handle: &Handle<Verifier>, allow_sha1: bool) -> std::result::Result<Option<keys::HashAlg>, russh::Error> {
    Ok(match handle.best_supported_rsa_hash().await? {
        Some(Some(hash)) => Some(hash),
        _ if allow_sha1 => None,
        _ => Some(keys::HashAlg::Sha512),
    })
}

fn is_rsa(key: &keys::PrivateKey) -> bool {
    matches!(key.algorithm(), keys::Algorithm::Rsa { .. })
}

async fn publickey(handle: &mut Handle<Verifier>, user: &str, key: keys::PrivateKey, allow_sha1: bool) -> Result<AuthResult> {
    let hash = rsa_hash(handle, allow_sha1).await.map_err(ssh_err)?;
    handle.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await.map_err(ssh_err)
}

/// Password authentication; servers that only take keyboard-interactive (PAM) get the password
/// as the answer to their single hidden prompt, and any later prompts go to the person.
async fn password(handle: &mut Handle<Verifier>, user: &str, pw: &Secret, prompter: Option<&dyn KbdPrompter>) -> Result<AuthResult> {
    let result = handle.authenticate_password(user, pw.expose()).await.map_err(ssh_err)?;
    match &result {
        AuthResult::Failure { partial_success: false, remaining_methods } if remaining_methods.contains(&MethodKind::KeyboardInteractive) => {
            keyboard_interactive(handle, user, Some(pw), prompter).await
        }
        _ => Ok(result),
    }
}

/// Answers the server's rounds of questions until it accepts or refuses.
async fn keyboard_interactive(handle: &mut Handle<Verifier>, user: &str, password: Option<&Secret>, prompter: Option<&dyn KbdPrompter>) -> Result<AuthResult> {
    let mut reply = handle.authenticate_keyboard_interactive_start(user, None).await.map_err(ssh_err)?;
    let mut password = password;
    for _ in 0..MAX_ROUNDS {
        let (name, instructions, prompts) = match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
            KeyboardInteractiveAuthResponse::Failure { remaining_methods, partial_success } => {
                return Ok(AuthResult::Failure { remaining_methods, partial_success });
            }
            KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => (name, instructions, prompts),
        };
        let answers = match auto_answer(&prompts, password.take()) {
            Some(a) => a,
            None => {
                let challenge = challenge(name, instructions, &prompts);
                // No one to ask, or the person cancelled: the login fails.
                let Some(p) = prompter else { return Err(CoreError::AuthFailed) };
                let answers = p.answer(&challenge).await.ok_or(CoreError::AuthFailed)?;
                if answers.len() != prompts.len() {
                    return Err(CoreError::Invalid("keyboard-interactive: wrong number of answers".into()));
                }
                answers.iter().map(|s| s.expose().to_string()).collect()
            }
        };
        reply = handle.authenticate_keyboard_interactive_respond(answers).await.map_err(ssh_err)?;
    }
    Err(CoreError::Ssh("keyboard-interactive: too many rounds".into()))
}

/// Rounds that need no person: an empty round (servers send these between steps), or a single
/// hidden prompt while the connection's password has not been used yet.
fn auto_answer(prompts: &[Prompt], password: Option<&Secret>) -> Option<Vec<String>> {
    if prompts.is_empty() {
        return Some(Vec::new());
    }
    match (prompts, password) {
        ([only], Some(pw)) if !only.echo => Some(vec![pw.expose().to_string()]),
        _ => None,
    }
}

fn challenge(name: String, instructions: String, prompts: &[Prompt]) -> KbdChallenge {
    KbdChallenge { name, instructions, prompts: prompts.iter().map(|p| KbdPrompt { text: p.prompt.clone(), echo: p.echo }).collect() }
}

type DynAgent = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

#[cfg(unix)]
pub(crate) async fn agent_client() -> Result<DynAgent> {
    AgentClient::connect_env()
        .await
        .map(AgentClient::dynamic)
        .map_err(|e| CoreError::Invalid(format!("no SSH agent is available (SSH_AUTH_SOCK): {e}")))
}

#[cfg(windows)]
pub(crate) async fn agent_client() -> Result<DynAgent> {
    // The Windows OpenSSH agent first, then Pageant.
    if let Ok(a) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
        return Ok(a.dynamic());
    }
    AgentClient::connect_pageant()
        .await
        .map(AgentClient::dynamic)
        .map_err(|e| CoreError::Invalid(format!("no SSH agent is available (OpenSSH agent or Pageant): {e}")))
}

/// Offers the agent's identities, certificates first, until the server accepts one.
async fn agent(handle: &mut Handle<Verifier>, user: &str, allow_sha1: bool) -> Result<AuthResult> {
    let mut agent = agent_client().await?;
    let mut identities = agent.request_identities().await.map_err(|e| CoreError::Ssh(format!("SSH agent: {e}")))?;
    if identities.is_empty() {
        return Err(CoreError::Invalid("the SSH agent holds no keys".into()));
    }
    identities.sort_by_key(|i| !matches!(i, AgentIdentity::Certificate { .. }));
    let hash = rsa_hash(handle, allow_sha1).await.map_err(ssh_err)?;
    let mut last = AuthResult::Failure { remaining_methods: (&[][..]).into(), partial_success: false };
    for identity in identities {
        let attempt = match identity {
            AgentIdentity::Certificate { certificate, .. } => handle.authenticate_certificate_with(user, certificate, hash, &mut agent).await,
            AgentIdentity::PublicKey { key, .. } => handle.authenticate_publickey_with(user, key, hash, &mut agent).await,
        };
        // An identity the agent declines to sign with (or a hardware key not touched) is skipped.
        match attempt {
            Ok(AuthResult::Success) => return Ok(AuthResult::Success),
            Ok(r @ AuthResult::Failure { partial_success: true, .. }) => return Ok(r),
            Ok(r) => last = r,
            Err(_) => continue,
        }
    }
    Ok(last)
}

fn ssh_err(e: russh::Error) -> CoreError {
    CoreError::Ssh(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(text: &str, echo: bool) -> Prompt {
        Prompt { prompt: text.into(), echo }
    }

    #[test]
    fn empty_rounds_are_answered_without_asking() {
        assert_eq!(auto_answer(&[], None), Some(vec![]));
    }

    #[test]
    fn a_single_hidden_prompt_takes_the_saved_password_once() {
        let pw = Secret::new("hunter2".to_string());
        assert_eq!(auto_answer(&[prompt("Password: ", false)], Some(&pw)), Some(vec!["hunter2".into()]));
        assert_eq!(auto_answer(&[prompt("Password: ", false)], None), None, "a second round goes to the person");
    }

    #[test]
    fn codes_and_visible_prompts_go_to_the_person() {
        let pw = Secret::new("x".to_string());
        assert_eq!(auto_answer(&[prompt("Username: ", true)], Some(&pw)), None);
        assert_eq!(auto_answer(&[prompt("Password: ", false), prompt("Code: ", false)], Some(&pw)), None);
    }

    #[test]
    fn certificate_sits_next_to_the_key() {
        assert_eq!(certificate_path(Path::new("/home/u/.ssh/id_ed25519")), PathBuf::from("/home/u/.ssh/id_ed25519-cert.pub"));
        assert!(certificate_for(Path::new("/no/such/key")).is_none());
    }

    #[test]
    fn challenge_keeps_prompt_order_and_echo() {
        let c = challenge("n".into(), "i".into(), &[prompt("a", true), prompt("b", false)]);
        assert_eq!(c.prompts, vec![KbdPrompt { text: "a".into(), echo: true }, KbdPrompt { text: "b".into(), echo: false }]);
    }
}

/// Check a pasted or loaded private key and, when it is encrypted, decrypt it with `passphrase`,
/// returning it in OpenSSH form without a passphrase. Used before the key is stored in the
/// (itself encrypted) vault, so connects need no second secret.
pub fn unlock_private_key(pem: &str, passphrase: Option<&str>) -> Result<crate::vault::Secret> {
    let key = keys::decode_secret_key(pem, passphrase.filter(|p| !p.is_empty())).map_err(|e| {
        let why = e.to_string();
        if pem.contains("ENCRYPTED") && passphrase.is_none_or(str::is_empty) {
            CoreError::Invalid("This key is protected by a passphrase: enter it to store the key.".into())
        } else {
            CoreError::Invalid(format!("Not a usable private key: {why}"))
        }
    })?;
    let text = key.to_openssh(keys::ssh_key::LineEnding::LF).map_err(|e| CoreError::Invalid(format!("cannot re-encode the key: {e}")))?;
    Ok(crate::vault::Secret::new(text.as_str()))
}
