//! Safe, `async` wrappers around the imports.

/// What the helper was started for.
pub mod host {
    use crate::{sys, Entry};

    /// The entry this helper serves; none for a helper with no entry (the settings page).
    pub fn entry() -> Option<Entry> {
        sys::entry()
    }

    /// The plugin's settings, read-only.
    pub fn settings() -> Vec<(String, String)> {
        sys::settings()
    }

    /// One setting by key.
    pub fn setting(key: &str) -> Option<String> {
        settings().into_iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

/// Log lines. Rate-limited by the core; a line that holds a released password is dropped.
pub mod log {
    pub use crate::bindings::bastion::plugin::log::Level;
    use crate::sys;

    pub fn line(level: Level, text: &str) {
        sys::log(level, text)
    }
    pub fn debug(text: &str) {
        line(Level::Debug, text)
    }
    pub fn info(text: &str) {
        line(Level::Info, text)
    }
    pub fn warn(text: &str) {
        line(Level::Warn, text)
    }
    pub fn error(text: &str) {
        line(Level::Error, text)
    }
}

/// Permission `network = "entry"`: streams to the entry's host.
pub mod net {
    use crate::bindings::bastion::plugin::events::ReplyValue;
    use crate::runtime::{pending, unexpected};
    use crate::{sys, Failure};

    /// The most the core moves in one read or write.
    pub const CHUNK: usize = 1024 * 1024;
    /// The most abort bytes one stream may register.
    pub const MAX_ABORT: usize = 512;

    /// A byte stream to the entry's host through the entry's route. Closed when dropped.
    #[derive(Debug)]
    pub struct Stream {
        id: u32,
    }

    impl Stream {
        /// Opens a stream on the entry's port, or on `port` if the manifest lists it.
        pub async fn connect(port: Option<u16>) -> Result<Stream, Failure> {
            match pending(sys::connect(port)).await? {
                ReplyValue::Opened(id) => Ok(Stream { id }),
                other => Err(unexpected("connect", other)),
            }
        }

        /// The core's number for this stream.
        pub fn id(&self) -> u32 {
            self.id
        }

        /// Reads at most `max` bytes (capped at 1 MiB). An empty result means the server
        /// closed the stream.
        pub async fn read(&self, max: usize) -> Result<Vec<u8>, Failure> {
            let max = max.clamp(1, CHUNK) as u32;
            match pending(sys::read(self.id, max)).await? {
                ReplyValue::Data(data) => Ok(data),
                other => Err(unexpected("read", other)),
            }
        }

        /// Reads exactly `len` bytes, or fails with `io` if the stream ends first.
        pub async fn read_exact(&self, len: usize) -> Result<Vec<u8>, Failure> {
            let mut out = Vec::with_capacity(len.min(CHUNK));
            while out.len() < len {
                let chunk = self.read(len - out.len()).await?;
                if chunk.is_empty() {
                    return Err(Failure::Io("the server closed the stream".into()));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(out)
        }

        /// Writes all of `data`, in pieces of at most 1 MiB.
        pub async fn write(&self, data: &[u8]) -> Result<(), Failure> {
            for piece in data.chunks(CHUNK) {
                match pending(sys::write(self.id, piece)).await? {
                    ReplyValue::None => {}
                    other => return Err(unexpected("write", other)),
                }
            }
            Ok(())
        }

        /// Starts TLS on this stream. The core runs it with the entry's TLS mode.
        pub async fn start_tls(&self) -> Result<(), Failure> {
            match pending(sys::start_tls(self.id)).await? {
                ReplyValue::None => Ok(()),
                other => Err(unexpected("start-tls", other)),
            }
        }

        /// Registers bytes the core sends on a new stream to the same server if the helper
        /// stops, such as a cancel request. At most 512 bytes; a longer registration is refused
        /// here, whole, without asking the core. A new registration replaces the old one; after
        /// the core sends `stop` it is refused.
        pub async fn register_abort(&self, data: &[u8]) -> Result<(), Failure> {
            if data.len() > MAX_ABORT {
                return Err(Failure::Invalid(format!(
                    "abort bytes: {} bytes, the most is {MAX_ABORT}",
                    data.len()
                )));
            }
            match pending(sys::register_abort(self.id, data)).await? {
                ReplyValue::None => Ok(()),
                other => Err(unexpected("register-abort", other)),
            }
        }

        /// Clears this stream's abort bytes.
        pub fn clear_abort(&self) {
            sys::clear_abort(self.id)
        }
    }

    impl Drop for Stream {
        fn drop(&mut self) {
            sys::close(self.id)
        }
    }
}

/// Permission `credentials = "entry"`.
pub mod credentials {
    use crate::bindings::bastion::plugin::events::ReplyValue;
    use crate::runtime::{pending, unexpected};
    use crate::{sys, Failure, Login};

    /// The entry's own login, released once per helper by the core. Keep it only as long as
    /// you need it, and never log it, store it or show it: the core refuses those.
    pub async fn entry_login() -> Result<Login, Failure> {
        match pending(sys::entry_login()).await? {
            ReplyValue::Login(login) => Ok(login),
            other => Err(unexpected("entry-login", other)),
        }
    }
}

/// Permission `http = "entry"` (API 1.1): HTTP/1.1 requests to the entry's host. The core
/// opens the connection, runs TLS, writes the request and reads the answer; see the `http`
/// interface in `plugins/wit/plugin.wit` for the checks it makes on every request.
pub mod http {
    use crate::bindings::bastion::plugin::events::ReplyValue;
    pub use crate::bindings::bastion::plugin::http::{HttpRequest, Method};
    pub use crate::bindings::bastion::plugin::types::HttpResponse;
    use crate::runtime::{pending, unexpected};
    use crate::{sys, Failure};

    /// A request with no headers, no body, no login, on the entry's port.
    pub fn request(method: Method, target: &str) -> HttpRequest {
        HttpRequest { method, port: None, target: target.into(), headers: Vec::new(), body: Vec::new(), with_login: false, timeout_ms: None }
    }

    /// Sends `req` and waits for the answer. A 3xx is an answer like any other: the core never
    /// follows redirects.
    pub async fn send(req: &HttpRequest) -> Result<HttpResponse, Failure> {
        match pending(sys::http_send(req)).await? {
            ReplyValue::Http(resp) => Ok(resp),
            other => Err(unexpected("http.send", other)),
        }
    }

    /// `GET target` with the entry's login in the manifest's `http.auth` header.
    pub async fn get_with_login(target: &str) -> Result<HttpResponse, Failure> {
        let mut req = request(Method::Get, target);
        req.with_login = true;
        send(&req).await
    }

    impl HttpResponse {
        /// The first header named `name`, ignoring case.
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
        }
    }
}

/// Permission `open` (API 1.2): ask the app to open SSH, RDP or VNC. The core checks the
/// request and the user confirms it in a sheet; the plugin learns only yes or no. Call it right
/// after a user action in the view (a command, a button, a menu item): at any other time the
/// core refuses it.
pub mod open {
    use crate::bindings::bastion::plugin::events::ReplyValue;
    pub use crate::bindings::bastion::plugin::open::{OpenRequest, Protocol};
    use crate::runtime::{pending, unexpected};
    use crate::{sys, Failure};

    /// A request on the protocol's default port, through the plugin entry's route.
    pub fn request(protocol: Protocol, host: &str, label: &str) -> OpenRequest {
        OpenRequest { protocol, host: host.into(), port: None, label: label.into(), via_entry_route: true }
    }

    /// Asks the app. `Ok(true)` when the user confirmed and the app opened it, `Ok(false)` when
    /// the user declined.
    pub async fn connection(req: &OpenRequest) -> Result<bool, Failure> {
        match pending(sys::open_connection(req)).await? {
            ReplyValue::Connection(opened) => Ok(opened),
            other => Err(unexpected("open.connection", other)),
        }
    }
}

/// Permission `exec = "entry"` (API 1.5): run a command the manifest declares in `[[exec]]` on
/// the entry's host over the entry's SSH login and route. Name the template and give its
/// arguments; the core checks each against its kind and builds the command. A template with
/// `changes = true` needs the entry's "Allow changes" and a user action or a confirmed
/// `ui::confirm` just before.
pub mod exec {
    use crate::bindings::bastion::plugin::events::ReplyValue;
    pub use crate::bindings::bastion::plugin::types::ExecOutput;
    use crate::runtime::{pending, unexpected};
    use crate::{sys, Failure};

    /// Runs `template` and waits for it. `timeout_ms` 0 is the core's 30 s; at most 120 s.
    pub async fn run(template: &str, args: &[(&str, &str)], timeout_ms: u32) -> Result<ExecOutput, Failure> {
        let args: Vec<(String, String)> = args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        match pending(sys::exec_run(template, &args, timeout_ms)).await? {
            ReplyValue::Exec(out) => Ok(out),
            other => Err(unexpected("exec.run", other)),
        }
    }

    /// Like [`run`], but returns the request number first, for [`cancel`], with the answer.
    pub fn start(template: &str, args: &[(&str, &str)], timeout_ms: u32) -> (u32, impl core::future::Future<Output = Result<ExecOutput, Failure>>) {
        let args: Vec<(String, String)> = args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let request = sys::exec_run(template, &args, timeout_ms);
        let wait = pending(request);
        (request, async move {
            match wait.await? {
                ReplyValue::Exec(out) => Ok(out),
                other => Err(unexpected("exec.run", other)),
            }
        })
    }

    /// Opens a terminal tab running an `interactive = true` template. `Ok(true)` when it opened.
    pub async fn terminal(template: &str, args: &[(&str, &str)], label: &str) -> Result<bool, Failure> {
        let args: Vec<(String, String)> = args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        match pending(sys::exec_terminal(template, &args, label)).await? {
            ReplyValue::Connection(opened) => Ok(opened),
            other => Err(unexpected("exec.terminal", other)),
        }
    }

    /// Stops a running command by its request number.
    pub fn cancel(request: u32) {
        sys::exec_cancel(request)
    }
}

/// Permission `library = "propose"` (API 1.6): propose connections for the user's library. The
/// user picks the folder, protocol, host and credential in the app's sheet; the plugin learns
/// only how many were saved. Call it right after a user action in the view.
pub mod library {
    use crate::bindings::bastion::plugin::events::ReplyValue;
    pub use crate::bindings::bastion::plugin::library::{Proposal, Protocol};
    use crate::runtime::{pending, unexpected};
    use crate::{sys, Failure};

    /// A proposal without an OS hint.
    pub fn proposal(label: &str, host: Option<&str>, protocol: Protocol) -> Proposal {
        Proposal { label: label.into(), host: host.map(str::to_string), protocol, os_hint: None }
    }

    /// Shows the sheet. `Ok(n)`: the user saved `n` connections; `Err(Failure::Cancelled)`
    /// when the user closed the sheet.
    pub async fn propose(proposals: &[Proposal]) -> Result<u32, Failure> {
        match pending(sys::library_propose(proposals)).await? {
            ReplyValue::Created(n) => Ok(n),
            other => Err(unexpected("library.propose", other)),
        }
    }
}

/// Permission `storage`: a key-value store for this entry. Not encrypted.
pub mod storage {
    use crate::bindings::bastion::plugin::events::ReplyValue;
    use crate::runtime::{pending, unexpected};
    use crate::{sys, Failure};

    pub async fn get(key: &str) -> Result<Option<Vec<u8>>, Failure> {
        match pending(sys::storage_get(key)).await? {
            ReplyValue::Value(value) => Ok(value),
            other => Err(unexpected("storage get", other)),
        }
    }

    pub async fn set(key: &str, value: &[u8]) -> Result<(), Failure> {
        match pending(sys::storage_set(key, value)).await? {
            ReplyValue::None => Ok(()),
            other => Err(unexpected("storage set", other)),
        }
    }

    pub async fn delete(key: &str) -> Result<(), Failure> {
        match pending(sys::storage_delete(key)).await? {
            ReplyValue::None => Ok(()),
            other => Err(unexpected("storage delete", other)),
        }
    }

    /// The keys that start with `prefix`.
    pub async fn keys(prefix: &str) -> Result<Vec<String>, Failure> {
        match pending(sys::storage_keys(prefix)).await? {
            ReplyValue::Keys(keys) => Ok(keys),
            other => Err(unexpected("storage keys", other)),
        }
    }
}

/// Permission `clipboard = "write"`.
pub mod clipboard {
    use crate::bindings::bastion::plugin::events::ReplyValue;
    use crate::runtime::{pending, unexpected};
    use crate::{sys, Failure};

    /// Copies text the user asked to copy. Allowed only right after a user action.
    pub async fn write_text(text: &str) -> Result<(), Failure> {
        match pending(sys::clipboard_write(text)).await? {
            ReplyValue::None => Ok(()),
            other => Err(unexpected("clipboard write", other)),
        }
    }
}

/// Permission `files`: one file the user picks in the app's own dialog.
pub mod files {
    use crate::bindings::bastion::plugin::events::ReplyValue;
    use crate::runtime::{pending, unexpected};
    use crate::{sys, Failure};

    /// Asks the user where to save `data`. `Err(Failure::Cancelled)` if they closed the dialog.
    pub async fn save(suggested_name: &str, data: &[u8]) -> Result<(), Failure> {
        match pending(sys::files_save(suggested_name, data)).await? {
            ReplyValue::None => Ok(()),
            other => Err(unexpected("files save", other)),
        }
    }

    /// Asks the user for a file to open: its name (no path) and bytes.
    pub async fn open() -> Result<(String, Vec<u8>), Failure> {
        match pending(sys::files_open()).await? {
            ReplyValue::File(file) => Ok(file),
            other => Err(unexpected("files open", other)),
        }
    }
}
