//! Local IPC between the running app and the companion CLI (`bastion`).
//!
//! Transport: one JSON request line and one JSON response line per connection.
//! - Unix: a domain socket at `<data dir>/bastion.sock`, created mode 0600; every peer's uid is
//!   checked against ours.
//! - Windows: a named pipe `\\.\pipe\bastion[-tauri]-<user SID>-<data dir hash>` (see [`endpoint`]).
//!   It is created with a DACL that grants only the current user (no Everyone, SYSTEM or
//!   Administrators entry), as the first instance of that name (so a pipe someone else created
//!   first is never joined), and with remote clients rejected. The server also checks that each
//!   client process runs as the same user, and the client checks the server the same way before
//!   it sends anything, so a pipe squatted by another user is refused from both sides.
//!
//! On top of that every request carries the per-launch token the app writes to
//! `<data dir>/bastion.ipc-token` (owner-only, replaced at each start), so a stale or copied
//! token stops working with the next launch. Requests carry names and ids only; responses never
//! contain secrets. Lines are capped at 64 KiB and must parse as the closed [`Request`] enum.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::{CoreError, Result};

/// Bumped on incompatible changes; the CLI refuses to talk to a different major.
pub const PROTOCOL_VERSION: u32 = 3;
const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    Ping,
    /// Open a session for the connection named `name` (or with that id). With `protocol`, only a
    /// connection of that type matches (`sshp` asks for `ssh`).
    Open {
        name: String,
        files: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
    },
    /// Start the saved tunnel named `name` (Tunnel Manager); the app asks for the SSH login.
    OpenTunnel { name: String },
    /// Names of the saved connections (names only: no hosts, users or ids).
    List,
}

/// What goes over the wire: the token and the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub token: String,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Response {
    Pong { version: u32 },
    Names { names: Vec<String> },
    Ok,
    Error { message: String },
}

pub type Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

/// Which app is listening. Both apps can run at once (also on one data folder, as on the test
/// VM), so each gets its own endpoint and token file. Native keeps the original names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    Native,
    Tauri,
}

impl Flavour {
    pub const ALL: [Flavour; 2] = [Flavour::Native, Flavour::Tauri];

    /// File-name suffix: empty for Native (unchanged names), `-tauri` for Tauri.
    fn suffix(self) -> &'static str {
        match self {
            Flavour::Native => "",
            Flavour::Tauri => "-tauri",
        }
    }
}

/// The Native app's endpoint for `data_dir` (see [`endpoint`]).
pub fn socket_path(data_dir: &Path) -> PathBuf {
    endpoint(data_dir, Flavour::Native)
}

/// Where `flavour` listens for `data_dir`: a socket file on Unix
/// (`bastion.sock`, `bastion-tauri.sock`).
#[cfg(unix)]
pub fn endpoint(data_dir: &Path, flavour: Flavour) -> PathBuf {
    data_dir.join(format!("bastion{}.sock", flavour.suffix()))
}

/// Where `flavour` listens for `data_dir`: a pipe name on Windows.
///
/// The pipe name holds the flavour, the user's SID (pipe names are machine-wide, so two users
/// never meet on one) and a hash of the data directory (so a test library and the real one do
/// not collide).
#[cfg(windows)]
pub fn endpoint(data_dir: &Path, flavour: Flavour) -> PathBuf {
    let sid = crate::winacl::current_user_sid().unwrap_or_else(|_| "unknown".into());
    // FNV-1a over the lower-cased path: stable across runs, unlike std's hasher.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data_dir.to_string_lossy().to_lowercase().bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }
    PathBuf::from(format!(r"\\.\pipe\bastion{}-{sid}-{h:016x}", flavour.suffix()))
}

/// The Native app's token file.
pub fn token_path(data_dir: &Path) -> PathBuf {
    token_path_for(data_dir, Flavour::Native)
}

pub fn token_path_for(data_dir: &Path, flavour: Flavour) -> PathBuf {
    data_dir.join(format!("bastion{}.ipc-token", flavour.suffix()))
}

/// Create a fresh random token for this launch of the Native app (see [`issue_token_for`]).
pub fn issue_token(data_dir: &Path) -> Result<String> {
    issue_token_for(data_dir, Flavour::Native)
}

/// Create a fresh random token for this launch and write it owner-only (atomically replacing
/// the previous launch's token). Returns the token for `serve`.
pub fn issue_token_for(data_dir: &Path, flavour: Flavour) -> Result<String> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    crate::store::write_atomic(&token_path_for(data_dir, flavour), token.as_bytes())?;
    Ok(token)
}

/// The token of the running Native app, for clients.
pub fn read_token(data_dir: &Path) -> Result<String> {
    read_token_for(data_dir, Flavour::Native)
}

/// The token of the running `flavour` app, for clients.
pub fn read_token_for(data_dir: &Path, flavour: Flavour) -> Result<String> {
    let path = token_path_for(data_dir, flavour);
    let raw = std::fs::read_to_string(&path).map_err(|_| CoreError::NotFound("Gantry is not running (no IPC token)".into()))?;
    Ok(raw.trim().to_string())
}

/// The running app for `data_dir`, if any: the first flavour with a token file, Native first.
pub fn running_flavour(data_dir: &Path) -> Option<Flavour> {
    Flavour::ALL.into_iter().find(|f| token_path_for(data_dir, *f).exists())
}

/// Constant-time comparison so the token cannot be probed byte by byte.
fn token_matches(given: &str, expected: &str) -> bool {
    given.len() == expected.len() && given.bytes().zip(expected.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

async fn read_line(read: impl AsyncRead + Unpin) -> Result<String> {
    let mut line = String::new();
    let mut reader = BufReader::new(read).take(MAX_LINE as u64);
    reader.read_line(&mut line).await?;
    if !line.ends_with('\n') {
        return Err(CoreError::Invalid("IPC message too long or truncated".into()));
    }
    Ok(line)
}

async fn write_line(write: &mut (impl AsyncWrite + Unpin), value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| CoreError::Corrupt(e.to_string()))?;
    bytes.push(b'\n');
    write.write_all(&bytes).await?;
    write.flush().await?;
    Ok(())
}

/// Read one request, check its token, answer it, write one response.
async fn answer(read: impl AsyncRead + Unpin, mut write: impl AsyncWrite + Unpin, token: &str, handler: &(dyn Fn(Request) -> Response + Send + Sync)) -> Result<()> {
    let response = match read_line(read).await.map(|line| serde_json::from_str::<Envelope>(&line)) {
        Ok(Ok(env)) if token_matches(&env.token, token) => handler(env.request),
        Ok(Ok(_)) => Response::Error { message: "not authorised: wrong or stale IPC token".into() },
        Ok(Err(e)) => Response::Error { message: format!("bad request: {e}") },
        // Too long or cut short: answer with the reason rather than dropping the connection.
        Err(e) => Response::Error { message: e.to_string() },
    };
    write_line(&mut write, &response).await
}

async fn exchange(read: impl AsyncRead + Unpin, mut write: impl AsyncWrite + Unpin, token: &str, req: &Request) -> Result<Response> {
    write_line(&mut write, &Envelope { token: token.to_string(), request: req.clone() }).await?;
    let line = read_line(read).await?;
    serde_json::from_str(&line).map_err(|e| CoreError::Corrupt(format!("bad response: {e}")))
}

/// Accept requests until the listener fails.
pub async fn serve(path: &Path, token: String, handler: Handler) -> Result<()> {
    serve_ready(path, token, handler, || {}).await
}

/// Accept requests until the listener fails, calling `ready` once the endpoint exists.
pub async fn serve_ready(path: &Path, token: String, handler: Handler, ready: impl FnOnce()) -> Result<()> {
    let listener = platform::bind(path).await?;
    ready();
    platform::accept_loop(listener, path, token, handler).await
}

/// One listener's whole lifecycle, the way apps start it (audit WR-01): take the exclusive
/// startup lock for `flavour` in `data_dir`, bind the endpoint, and only then issue the token
/// clients read. A starter that loses (another instance holds the lock or answers on the
/// endpoint) fails without touching the token file, so the running listener's token stays
/// valid. The lock is held until this future ends. `ready` receives the issued token.
pub async fn serve_issuing(data_dir: &Path, flavour: Flavour, path: &Path, handler: Handler, ready: impl FnOnce(&str)) -> Result<()> {
    let _owner = startup_lock(data_dir, flavour)?;
    let listener = platform::bind(path).await?;
    let token = issue_token_for(data_dir, flavour)?;
    ready(&token);
    platform::accept_loop(listener, path, token, handler).await
}

/// The listener ownership lock: an advisory exclusive lock on `<token file>.lock`, held for
/// the listener's lifetime and released by the OS if the process dies.
fn startup_lock(data_dir: &Path, flavour: Flavour) -> Result<std::fs::File> {
    let mut name = token_path_for(data_dir, flavour).into_os_string();
    name.push(".lock");
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let f = opts.open(PathBuf::from(name))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(CoreError::Invalid("another Gantry instance is already listening".into())),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

#[cfg(unix)]
use unix as platform;
#[cfg(unix)]
pub use unix::request;
#[cfg(windows)]
use windows as platform;
#[cfg(windows)]
pub use windows::request;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::{UnixListener, UnixStream};

    /// sockaddr_un has room for 104 bytes on macOS (108 on Linux), terminator included.
    const MAX_SOCKET_PATH: usize = 103;

    /// Bind and restrict the socket. A stale socket file from a crashed run is replaced; a live
    /// one (another instance answering) is an error.
    pub(super) async fn bind(path: &Path) -> Result<UnixListener> {
        if path.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(CoreError::Invalid(format!("IPC socket path is too long for a Unix socket: {}", path.display())));
        }
        if path.exists() {
            if UnixStream::connect(path).await.is_ok() {
                return Err(CoreError::Invalid("another Gantry instance is already listening".into()));
            }
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    pub(super) async fn accept_loop(listener: UnixListener, _path: &Path, token: String, handler: Handler) -> Result<()> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        loop {
            let (stream, _) = listener.accept().await?;
            if stream.peer_cred().map(|c| c.uid()).ok() != Some(me) {
                continue;
            }
            let (handler, token) = (handler.clone(), token.clone());
            tokio::spawn(async move {
                let (read, write) = stream.into_split();
                let _ = answer(read, write, &token, handler.as_ref()).await;
            });
        }
    }

    pub async fn request(path: &Path, token: &str, req: &Request) -> Result<Response> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|_| CoreError::NotFound("Gantry is not running (no IPC socket)".into()))?;
        let (read, write) = stream.into_split();
        exchange(read, write, token, req).await
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

    /// ERROR_ACCESS_DENIED: with `first_pipe_instance`, the name is already taken.
    const ACCESS_DENIED: i32 = 5;
    /// ERROR_PIPE_BUSY: every instance is serving someone; try again shortly.
    const PIPE_BUSY: i32 = 231;
    /// ERROR_FILE_NOT_FOUND: no pipe of that name, so no app is listening.
    const FILE_NOT_FOUND: i32 = 2;
    const BUSY_RETRIES: u32 = 50;
    const BUSY_WAIT: Duration = Duration::from_millis(20);

    fn create(name: &Path, first: bool) -> Result<NamedPipeServer> {
        let made = crate::winacl::with_owner_only_attributes(|sa| {
            // SAFETY: `sa` is a valid SECURITY_ATTRIBUTES that outlives the call.
            unsafe { ServerOptions::new().first_pipe_instance(first).reject_remote_clients(true).create_with_security_attributes_raw(name, sa) }
        })?;
        made.map_err(|e| {
            if first && e.raw_os_error() == Some(ACCESS_DENIED) {
                CoreError::Invalid("another Gantry instance is already listening (or another program holds the pipe name)".into())
            } else {
                e.into()
            }
        })
    }

    /// Create the first pipe instance. A pipe name already in use (another instance, or anyone
    /// else) is an error rather than something to share.
    pub(super) async fn bind(path: &Path) -> Result<NamedPipeServer> {
        create(path, true)
    }

    pub(super) async fn accept_loop(mut server: NamedPipeServer, path: &Path, token: String, handler: Handler) -> Result<()> {
        loop {
            server.connect().await?;
            let connected = server;
            // The next instance exists before this client is served, so callers are not refused.
            server = create(path, false)?;
            let same_user = crate::winacl::pipe_peer_is_current_user(connected.as_raw_handle() as _, true).unwrap_or(false);
            if !same_user {
                let _ = connected.disconnect();
                continue;
            }
            let (handler, token) = (handler.clone(), token.clone());
            tokio::spawn(async move {
                let (read, write) = tokio::io::split(connected);
                let _ = answer(read, write, &token, handler.as_ref()).await;
            });
        }
    }

    pub async fn request(path: &Path, token: &str, req: &Request) -> Result<Response> {
        let mut tries = 0;
        let client = loop {
            match ClientOptions::new().open(path) {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(PIPE_BUSY) && tries < BUSY_RETRIES => {
                    tries += 1;
                    tokio::time::sleep(BUSY_WAIT).await;
                }
                Err(e) if e.raw_os_error() == Some(FILE_NOT_FOUND) => return Err(CoreError::NotFound("Gantry is not running (no IPC pipe)".into())),
                // The pipe exists but cannot be opened (access denied, wrong session...): say so,
                // rather than claiming Bastion is not running.
                Err(e) => return Err(CoreError::Invalid(format!("cannot open the Gantry IPC pipe: {e}"))),
            }
        };
        // Never talk to a pipe served by another user, even one that got the name first.
        if !crate::winacl::pipe_peer_is_current_user(client.as_raw_handle() as _, false)? {
            return Err(CoreError::Invalid("the IPC pipe is served by another user; refusing to use it".into()));
        }
        let (read, write) = tokio::io::split(client);
        exchange(read, write, token, req).await
    }
}
