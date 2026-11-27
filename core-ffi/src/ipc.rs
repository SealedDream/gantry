//! The app side of the companion CLI's local IPC (`core::ipc`): the app starts one server per
//! launch; requests are answered by a handler the app implements. Only names, ids and short
//! messages cross; the handler must never put a secret in a reply.
use std::path::PathBuf;
use std::sync::Arc;

use bastion_core::ipc::{self, Request, Response, PROTOCOL_VERSION};

use crate::terminal::RUNTIME;
use crate::{FfiError, FfiResult};

/// Implemented by the app. Called on a background thread; hop to the UI thread as needed.
#[uniffi::export(with_foreign)]
pub trait IpcHandler: Send + Sync {
    /// Open the connection named (or with the id) `name`; `files` asks for the SFTP browser;
    /// `protocol` limits the match to one type. Return `None` on success or a short error message.
    fn open_connection(&self, name: String, files: bool, protocol: Option<String>) -> Option<String>;
    /// Start the saved tunnel `name` (the app asks for the SSH login as usual).
    fn open_tunnel(&self, name: String) -> Option<String>;
}

#[derive(uniffi::Object)]
pub struct IpcServer {
    socket: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

#[uniffi::export]
impl IpcServer {
    /// Issue this launch's token, bind `<data_dir>/bastion.sock` (0600, same-uid peers only) and
    /// serve until `stop` or drop. Fails if another instance is listening.
    #[uniffi::constructor]
    pub fn start(data_dir: String, handler: Arc<dyn IpcHandler>) -> FfiResult<Arc<Self>> {
        let dir = PathBuf::from(data_dir);
        let socket = ipc::socket_path(&dir);
        // Never replace the token of an instance that is still answering.
        #[cfg(unix)]
        let serving = std::os::unix::net::UnixStream::connect(&socket).is_ok();
        // Windows: the endpoint is a named pipe; opening it as a file succeeds only if a server
        // instance exists (the server just sees an empty request).
        #[cfg(windows)]
        let serving = std::fs::OpenOptions::new().read(true).write(true).open(&socket).is_ok();
        if serving {
            return Err(FfiError::failed("another Gantry instance is already serving the CLI".into()));
        }
        let serve = Arc::new(move |req: Request| match req {
            Request::Ping => Response::Pong { version: PROTOCOL_VERSION },
            Request::Open { name, files, protocol } => match handler.open_connection(name, files, protocol) {
                None => Response::Ok,
                Some(message) => Response::Error { message },
            },
            Request::OpenTunnel { name } => match handler.open_tunnel(name) {
                None => Response::Ok,
                Some(message) => Response::Error { message },
            },
            // The connection picker (`bastion` with no name) is served by the Windows app only so far.
            Request::List => Response::Error { message: "listing connections is not supported by this app yet".into() },
        });
        // Bind synchronously so a failure is reported to the caller, then serve in the background.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let path = socket.clone();
        let task = RUNTIME.spawn(async move {
            let ok = ready_tx.clone();
            // The token is issued only once the endpoint is ours (WR-01).
            let result = ipc::serve_issuing(&dir, ipc::Flavour::Native, &path, serve, move |_| {
                let _ = ok.send(Ok(()));
            })
            .await;
            if let Err(e) = result {
                // Before `ready` this is the bind failure the caller is waiting for; after, nobody listens.
                let _ = ready_tx.send(Err(e.to_string()));
                eprintln!("bastion: IPC server stopped: {e}");
            }
        });
        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Arc::new(IpcServer { socket, task })),
            Ok(Err(message)) => Err(FfiError::failed(message)),
            Err(_) => {
                task.abort();
                Err(FfiError::failed("the CLI socket did not open in time".into()))
            }
        }
    }

    pub fn socket_path(&self) -> String {
        self.socket.display().to_string()
    }

    /// Stop serving and remove the socket and this launch's token.
    pub fn stop(&self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket);
        if let Some(dir) = self.socket.parent() {
            let _ = std::fs::remove_file(ipc::token_path(dir));
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop();
    }
}
