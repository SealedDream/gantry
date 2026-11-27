//! Activity store: a history of every session of every protocol (who, where, when, how long,
//! why it ended), with the events inside a session. It holds metadata only: no secrets, no
//! keystrokes, no terminal output, no clipboard or file content.
//!
//! Storage is JSON Lines in monthly files `activity/YYYY-MM.jsonl` beside the library (a month
//! continues in `YYYY-MM.2.jsonl`, … once a file is full), owner-only, each line appended under
//! an exclusive OS file lock as in `audit.rs`. There is no hash chain: the security audit log
//! stays the tamper-evident record.
//!
//! A session is a `session_start` line and, later, a `session_end` line with the same id. An
//! end is always appended after its start, so reading the log backwards (newest first) meets
//! the end before the start and joins the two without loading the history.
//!
//! Hosts: a URL given as a host is cut down to its host and port, and text of the shape
//! `user:password` is not stored where it can be told from a host and a port (`name:22` is
//! kept, `name:word` is not). A password of digits only cannot be told from a port, so **a
//! caller must never pass a bare `user:password` as the host**: pass a host name, an address
//! or a URL.
use std::time::Duration;


/// Directory inside the app data directory.
pub const DIR_NAME: &str = "activity";
/// A monthly file this long is full; the month continues in the next part.
pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Longest stored line. A longer one is refused on write and skipped on read.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Names, host, username, app version, device name: characters kept.
pub const MAX_TEXT_CHARS: usize = 256;
pub const MAX_PATH_CHARS: usize = 1024;
pub const MAX_FOLDER_DEPTH: usize = 32;
pub const MAX_ROUTE: usize = 16;
pub const MAX_DETAILS: usize = 24;
pub const MAX_KEY_CHARS: usize = 48;
pub const MAX_VALUE_CHARS: usize = 256;
/// Events recorded for one session; later ones are dropped.
pub const MAX_EVENTS_PER_SESSION: u32 = 5000;
/// Largest page a query returns.
pub const MAX_PAGE: usize = 500;

pub(super) const MAX_PROTOCOL_CHARS: usize = 32;
pub(super) const READ_BLOCK: usize = 64 * 1024;
/// The gate file: held exclusively while a run creates its lock and while a sweep tests the
/// locks of other runs. Never deleted. Neither a run lock (`run-<id>.lock`) nor a monthly file.
pub(super) const GATE_NAME: &str = "runs.lock";
/// Longest a first write or a sweep waits for the gate. It is normally held for well under a
/// millisecond; an instance that is stopped or hung while holding it must not freeze the others.
pub(super) const GATE_WAIT: Duration = Duration::from_secs(2);
/// Pause between two tries at the gate while another instance holds it.
pub(super) const GATE_POLL: Duration = Duration::from_millis(10);
/// Tries at the run lock. One is enough under the gate; more are only needed when the gate was
/// not free in time and a sweep that had stopped comes back at that instant.
pub(super) const RUN_LOCK_TRIES: u32 = 50;
pub(super) const DAY_MS: u64 = 86_400_000;
/// 9999-12-31: the last time the monthly file name can express.
pub(super) const MAX_MS: u64 = 253_402_300_799_999;
/// Detail keys whose value is error text and goes through `short_error`.
pub(super) const ERROR_KEYS: &[&str] = &["error", "reason", "message"];
/// The tunnel detail that is a host and is stored by the host rule (`clean_host`).
pub(super) const TUNNEL_HOST_KEY: &str = "remote_host";
pub(super) const MASK: &str = "***";
/// Stored in place of a value (or host) that may hold a secret.
pub(super) const HIDDEN: &str = "(hidden)";
/// The same for error text; what `short_error` itself answers for a secret-looking error.
pub(super) const ERROR_HIDDEN: &str = "Failed (details hidden)";
/// A detail value containing one of these is not stored, whatever its key.
pub(super) const SECRET_VALUE_WORDS: &[&str] = &["password", "passwd", "passphrase", "secret", "token", "apikey", "api_key", "api-key", "private key", "authorization", "bearer"];
/// Characters a host name, an address or a port may contain besides letters and digits.
pub(super) const HOST_PUNCTUATION: &str = ".-_:[]%";
pub(super) const START_PREFIX: &[u8] = br#"{"type":"session_start""#;
pub(super) const END_PREFIX: &[u8] = br#"{"type":"session_end""#;
pub(super) const EVENT_PREFIX: &[u8] = br#"{"type":"event""#;

mod reader;
mod records;
mod store;

pub use records::*;
pub use store::ActivityLog;
