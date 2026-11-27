//! The app side of local IPC over the C ABI (ABI v9): serve `ping`, `list` and `open <name>` for
//! the `bastion` CLI on the owner-only endpoint from `core::ipc` (named pipe on Windows).
//!
//! The listener answers `ping` and `list` itself, from the library. `open` is resolved here to an
//! existing saved connection (exact id, or exact name when exactly one connection has it); the
//! connection id is then queued for the host, which polls [`bastion_ipc_next_open`] on its UI
//! thread and runs its normal Connect flow (login dialog, host-key check). A request can therefore
//! only name a saved connection: it never carries a host, a user or a secret, and nothing is
//! connected without the host's own UI. `list` returns names only.
use std::collections::VecDeque;
use std::ffi::c_char;
use std::sync::{Arc, Mutex};

use bastion_core::ipc::{self, Request, Response, PROTOCOL_VERSION};
use bastion_ffi::{FolderView, Library};

use crate::supervisor::RUNTIME;
use crate::{guarded, library, required, to_c, BastionLibrary};

/// Longest queue of unopened requests kept; older ones are dropped (a script cannot pile up tabs).
const MAX_PENDING: usize = 16;

/// Opaque handle for a running listener.
pub struct BastionIpcListener {
    task: tokio::task::JoinHandle<()>,
    pending: Arc<Mutex<VecDeque<String>>>,
    error: Arc<Mutex<Option<String>>>,
}

fn walk<'a>(f: &'a FolderView, out: &mut Vec<(&'a str, &'a str)>) {
    walk_typed(f, None, out)
}

/// Like `walk`, keeping only connections of `protocol` when one is given.
fn walk_typed<'a>(f: &'a FolderView, protocol: Option<&str>, out: &mut Vec<(&'a str, &'a str)>) {
    out.extend(f.connections.iter().filter(|c| protocol.map_or(true, |p| c.protocol == p)).map(|c| (c.id.as_str(), c.name.as_str())));
    for sub in &f.folders {
        walk_typed(sub, protocol, out);
    }
}

/// Resolve `name` to one saved connection id: an exact id, else the only connection with that name.
fn resolve(lib: &Library, name: &str, protocol: Option<&str>) -> Result<String, String> {
    let tree = lib.tree();
    let mut all = Vec::new();
    walk_typed(&tree, protocol, &mut all);
    if let Some((id, _)) = all.iter().find(|(id, _)| *id == name) {
        return Ok(id.to_string());
    }
    let hits: Vec<_> = all.iter().filter(|(_, n)| *n == name).collect();
    match hits.as_slice() {
        [(id, _)] => Ok(id.to_string()),
        [] => Err(format!("no saved connection named {name}")),
        _ => Err(format!("{} connections are named {name}; use its id", hits.len())),
    }
}

fn handle(lib: &Library, pending: &Mutex<VecDeque<String>>, req: Request) -> Response {
    match req {
        Request::Ping => Response::Pong { version: PROTOCOL_VERSION },
        Request::List => {
            let tree = lib.tree();
            let mut all = Vec::new();
            walk(&tree, &mut all);
            Response::Names { names: all.into_iter().map(|(_, n)| n.to_string()).collect() }
        }
        Request::OpenTunnel { .. } => Response::Error { message: "the Tunnel Manager is not available in the Windows app yet".into() },
        Request::Open { name, files, protocol } => {
            if files {
                return Response::Error { message: "the file browser is not available in the Windows app yet".into() };
            }
            match resolve(lib, &name, protocol.as_deref()) {
                Ok(id) => {
                    let mut q = pending.lock().unwrap_or_else(|p| p.into_inner());
                    if q.len() >= MAX_PENDING {
                        q.pop_front();
                    }
                    q.push_back(id);
                    Response::Ok
                }
                Err(message) => Response::Error { message },
            }
        }
    }
}

/// Start listening for `data_dir` (the folder that holds the library; the CLI derives the same
/// endpoint from `BASTION_LIBRARY` or the default library path). Returns NULL and sets `*err` when
/// the endpoint cannot be created, for example because another instance is already listening.
///
/// # Safety
/// `lib` live (and kept alive until the listener is freed); `data_dir` valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ipc_listen(lib: *const BastionLibrary, data_dir: *const c_char, err: *mut *mut c_char) -> *mut BastionIpcListener {
    guarded(err, std::ptr::null_mut(), || {
        let lib = library(lib)?;
        let dir = required(data_dir, "data_dir")?;
        let path = ipc::socket_path(std::path::Path::new(&dir));
        let pending = Arc::new(Mutex::new(VecDeque::new()));
        let error = Arc::new(Mutex::new(None));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let q = pending.clone();
        let e = error.clone();
        let task = RUNTIME.spawn(async move {
            let q2 = q.clone();
            let handler: ipc::Handler = Arc::new(move |req| handle(&lib, &q2, req));
            // `serve_issuing` only returns on failure and reports readiness once the endpoint is
            // ours; only then is a fresh owner-only token written next to the library, so a
            // refused second listener never replaces the running one's token (WR-01).
            let ready = ready_tx.clone();
            let result = ipc::serve_issuing(std::path::Path::new(&dir), ipc::Flavour::Native, &path, handler, move |_| {
                let _ = ready.send(Ok(()));
            })
            .await;
            let message = result.err().map(|e| e.to_string()).unwrap_or_else(|| "the listener stopped".into());
            // Before readiness this is the start error; afterwards the receiver is gone and it is kept for `bastion_ipc_error`.
            let _ = ready_tx.send(Err(message.clone()));
            *e.lock().unwrap_or_else(|p| p.into_inner()) = Some(message);
        });
        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Box::into_raw(Box::new(BastionIpcListener { task, pending, error }))),
            Ok(Err(m)) => Err(m),
            Err(_) => {
                task.abort();
                Err("the IPC listener did not start".into())
            }
        }
    })
}

/// The next connection id a CLI asked to open, or NULL when none is waiting. Free it with
/// `bastion_string_free`.
///
/// # Safety
/// `l` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_ipc_next_open(l: *const BastionIpcListener) -> *mut c_char {
    let Some(l) = l.as_ref() else { return std::ptr::null_mut() };
    match l.pending.lock().unwrap_or_else(|p| p.into_inner()).pop_front() {
        Some(id) => to_c(id),
        None => std::ptr::null_mut(),
    }
}

/// Why the listener stopped, or NULL while it is running. Free it with `bastion_string_free`.
///
/// # Safety
/// `l` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_ipc_error(l: *const BastionIpcListener) -> *mut c_char {
    let Some(l) = l.as_ref() else { return std::ptr::null_mut() };
    l.error.lock().unwrap_or_else(|p| p.into_inner()).clone().map(to_c).unwrap_or(std::ptr::null_mut())
}

/// Stop listening and release the handle. NULL is ignored.
///
/// # Safety
/// `l` NULL or a live handle; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_ipc_free(l: *mut BastionIpcListener) {
    if !l.is_null() {
        let l = Box::from_raw(l);
        l.task.abort();
    }
}

/// The endpoint (pipe name or socket path) the listener uses for `data_dir`, for diagnostics and
/// for test clients. Free it with `bastion_string_free`.
///
/// # Safety
/// `data_dir` valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ipc_endpoint(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let dir = required(data_dir, "data_dir")?;
        Ok(to_c(ipc::socket_path(std::path::Path::new(&dir)).to_string_lossy().into_owned()))
    })
}
