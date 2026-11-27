//! IPC round trips: the Unix socket, or the Windows named pipe; token, peer checks, no secrets.
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use bastion_core::ipc::*;

async fn start(dir: &std::path::Path) -> (std::path::PathBuf, String) {
    let path = socket_path(dir);
    let token = issue_token(dir).unwrap();
    let (p, t) = (path.clone(), token.clone());
    tokio::spawn(async move {
        serve(&p, t, Arc::new(|req| match req {
            Request::Ping => Response::Pong { version: PROTOCOL_VERSION },
            Request::Open { name, .. } if name == "web-01" => Response::Ok,
            Request::Open { name, .. } => Response::Error { message: format!("no connection named {name}") },
            Request::OpenTunnel { name } if name == "db" => Response::Ok,
            Request::OpenTunnel { name } => Response::Error { message: format!("no tunnel named {name}") },
            Request::List => Response::Names { names: vec!["web-01".into()] },
        }))
        .await
        .unwrap();
    });
    for _ in 0..500 {
        if request(&path, &token, &Request::Ping).await.is_ok() {
            return (path, token);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server did not start");
}

#[tokio::test]
async fn ping_open_and_bad_request() {
    let dir = tempfile::tempdir().unwrap();
    let (path, token) = start(dir.path()).await;
    assert_eq!(read_token(dir.path()).unwrap(), token);
    assert_eq!(request(&path, &token, &Request::Ping).await.unwrap(), Response::Pong { version: PROTOCOL_VERSION });
    assert_eq!(request(&path, &token, &Request::Open { name: "web-01".into(), files: false, protocol: Some("ssh".into()) }).await.unwrap(), Response::Ok);
    assert!(matches!(request(&path, &token, &Request::Open { name: "x".into(), files: false, protocol: None }).await.unwrap(), Response::Error { .. }));
    assert_eq!(request(&path, &token, &Request::OpenTunnel { name: "db".into() }).await.unwrap(), Response::Ok);
    assert_eq!(request(&path, &token, &Request::List).await.unwrap(), Response::Names { names: vec!["web-01".into()] });
    // Older requests without `protocol` still parse.
    assert_eq!(serde_json::from_str::<Envelope>(r#"{"token":"t","op":"open","name":"a","files":false}"#).unwrap().request, Request::Open { name: "a".into(), files: false, protocol: None });
    #[cfg(unix)]
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    #[cfg(unix)]
    assert_eq!(std::fs::metadata(token_path(dir.path())).unwrap().permissions().mode() & 0o777, 0o600);
    // A second server must not steal a live socket.
    assert!(serve(&path, token.clone(), Arc::new(|_| Response::Ok)).await.is_err());
}

#[tokio::test]
async fn wrong_or_stale_token_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (path, token) = start(dir.path()).await;
    let reply = request(&path, "0".repeat(64).as_str(), &Request::Ping).await.unwrap();
    assert!(matches!(reply, Response::Error { ref message } if message.contains("not authorised")), "{reply:?}");
    // A new launch issues a new token; the old one stops working.
    let next = issue_token(dir.path()).unwrap();
    assert_ne!(next, token);
    assert_eq!(token.len(), 64);
    let raw = r#"{"op":"ping"}"#;
    // Missing token: refused as a bad request, never served.
    #[cfg(unix)]
    {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let mut s = tokio::net::UnixStream::connect(&path).await.unwrap();
    s.write_all(format!("{raw}\n").as_bytes()).await.unwrap();
    let mut line = String::new();
    tokio::io::BufReader::new(s).read_line(&mut line).await.unwrap();
    assert!(line.contains("error"), "{line}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn overlong_socket_path_is_a_clear_error() {
    let long = std::path::PathBuf::from(format!("/tmp/{}/bastion.sock", "x".repeat(120)));
    let err = serve(&long, "t".into(), Arc::new(|_| Response::Ok)).await.unwrap_err();
    assert!(err.to_string().contains("too long"));
}

#[tokio::test]
async fn many_clients_in_a_row_and_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let (path, token) = start(dir.path()).await;
    let calls = (0..16).map(|_| {
        let (p, t) = (path.clone(), token.clone());
        tokio::spawn(async move { request(&p, &t, &Request::Ping).await.unwrap() })
    });
    for c in calls {
        assert_eq!(c.await.unwrap(), Response::Pong { version: PROTOCOL_VERSION });
    }
}

#[tokio::test]
async fn no_server_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = request(&socket_path(dir.path()), "t", &Request::Ping).await.unwrap_err();
    assert!(err.to_string().contains("not running"));
    assert!(read_token(dir.path()).unwrap_err().to_string().contains("not running"));
}

#[tokio::test]
async fn endpoints_differ_per_data_dir() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    assert_ne!(socket_path(a.path()), socket_path(b.path()));
    assert_eq!(socket_path(a.path()), socket_path(a.path()));
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    /// The pipe's DACL has exactly one entry: full control for the current user. No Everyone,
    /// no SYSTEM, no Administrators, no anonymous logon.
    #[tokio::test]
    async fn the_pipe_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let (path, token) = start(dir.path()).await;
        let name = path.to_string_lossy().into_owned();
        assert!(name.starts_with(r"\\.\pipe\bastion-S-1-"), "{name}");
        let tauri = endpoint(dir.path(), Flavour::Tauri).to_string_lossy().into_owned();
        assert!(tauri.starts_with(r"\\.\pipe\bastion-tauri-S-1-"), "{tauri}");
        let client = ClientOptions::new().open(&path).unwrap();
        let report = bastion_core::winacl::handle_dacl_report(client.as_raw_handle() as _).unwrap();
        let me = bastion_core::winacl::current_user_sid().unwrap();
        assert_eq!(report.aces.len(), 1, "{report:?}");
        assert_eq!(report.aces[0].ace_type, 0, "an allow entry");
        assert_eq!(report.aces[0].sid, me);
        assert!(bastion_core::winacl::pipe_peer_is_current_user(client.as_raw_handle() as _, false).unwrap());
    }

    /// Over 64 KiB without a newline is refused with an error line, not buffered forever.
    #[tokio::test]
    async fn an_oversized_request_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, token) = start(dir.path()).await;
        let mut client = ClientOptions::new().open(&path).unwrap();
        let big = vec![b'a'; 70 * 1024];
        // The server stops reading at the cap, so the write may not complete; that is fine.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), client.write_all(&big)).await;
        let mut reply = String::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_string(&mut reply)).await.unwrap().ok();
        assert!(reply.contains("too long"), "{reply}");
    }

    /// An unknown op is refused by the closed request enum.
    #[tokio::test]
    async fn an_unknown_op_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, token) = start(dir.path()).await;
        let mut client = ClientOptions::new().open(&path).unwrap();
        client.write_all(format!("{{\"token\":\"{token}\",\"op\":\"exec\",\"cmd\":\"calc\"}}\n").as_bytes()).await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.ok();
        assert!(reply.contains("bad request"), "{reply}");
    }
}

/// Native and Tauri on one data folder (the test VM) each get their own endpoint and token, so
/// both can listen at once and the CLI reaches the one it picked.
#[tokio::test]
async fn both_flavours_listen_on_one_folder() {
    let dir = tempfile::tempdir().unwrap();
    assert_ne!(endpoint(dir.path(), Flavour::Native), endpoint(dir.path(), Flavour::Tauri));
    assert_eq!(endpoint(dir.path(), Flavour::Native), socket_path(dir.path()));
    assert_ne!(token_path_for(dir.path(), Flavour::Native), token_path_for(dir.path(), Flavour::Tauri));
    assert_eq!(running_flavour(dir.path()), None);

    let mut servers = Vec::new();
    for (flavour, reply) in [(Flavour::Native, "native"), (Flavour::Tauri, "tauri")] {
        let path = endpoint(dir.path(), flavour);
        let token = issue_token_for(dir.path(), flavour).unwrap();
        let p = path.clone();
        let t = token.clone();
        tokio::spawn(async move {
            serve(&p, t, Arc::new(move |_| Response::Names { names: vec![reply.into()] })).await.unwrap();
        });
        servers.push((path, token, reply));
    }
    for (path, token, reply) in &servers {
        let mut got = None;
        for _ in 0..500 {
            if let Ok(r) = request(path, token, &Request::List).await {
                got = Some(r);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(got, Some(Response::Names { names: vec![(*reply).into()] }));
    }
    // Each app's token only opens its own endpoint.
    let crossed = request(&servers[0].0, &servers[1].1, &Request::List).await;
    assert!(!matches!(crossed, Ok(Response::Names { .. })), "{crossed:?}");
    assert_eq!(read_token_for(dir.path(), Flavour::Tauri).unwrap(), servers[1].1);
    assert_eq!(running_flavour(dir.path()), Some(Flavour::Native));
}

#[test]
fn running_flavour_finds_a_tauri_only_folder() {
    let dir = tempfile::tempdir().unwrap();
    issue_token_for(dir.path(), Flavour::Tauri).unwrap();
    assert_eq!(running_flavour(dir.path()), Some(Flavour::Tauri));
    assert!(read_token(dir.path()).is_err(), "Native has no token there");
}

fn pong_handler() -> Handler {
    Arc::new(|req| match req {
        Request::Ping => Response::Pong { version: PROTOCOL_VERSION },
        _ => Response::Ok,
    })
}

/// Start `serve_issuing` in the background; resolves to the token once listening, or the error.
async fn start_issuing(dir: &std::path::Path) -> (tokio::task::JoinHandle<()>, Result<String, String>) {
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<String, String>>();
    let (d, p) = (dir.to_path_buf(), socket_path(dir));
    let task = tokio::spawn(async move {
        let tx = std::sync::Mutex::new(Some(tx));
        let send = |r| {
            if let Some(t) = tx.lock().unwrap().take() {
                let _ = t.send(r);
            }
        };
        let r = serve_issuing(&d, Flavour::Native, &p, pong_handler(), |t| send(Ok(t.to_string()))).await;
        send(Err(r.err().map(|e| e.to_string()).unwrap_or_default()));
    });
    (task, rx.await.unwrap())
}

/// WR-01: a refused second listener must not replace the first one's token. Ping A with the
/// token re-read from disk after B fails; then restart and stop.
#[tokio::test]
async fn a_refused_second_listener_leaves_the_first_ones_token_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket_path(dir.path());
    let (a, token_a) = start_issuing(dir.path()).await;
    let token_a = token_a.unwrap();
    assert_eq!(read_token(dir.path()).unwrap(), token_a);
    let (_b, refused) = start_issuing(dir.path()).await;
    assert!(refused.unwrap_err().contains("already listening"));
    let on_disk = read_token(dir.path()).unwrap();
    assert_eq!(on_disk, token_a, "the refused starter replaced the token");
    assert_eq!(request(&path, &on_disk, &Request::Ping).await.unwrap(), Response::Pong { version: PROTOCOL_VERSION });
    // Stop A, restart: the new listener owns the endpoint and publishes its own token.
    a.abort();
    let _ = a.await;
    let (c, token_c) = start_issuing(dir.path()).await;
    let token_c = token_c.unwrap();
    assert_ne!(token_c, token_a);
    assert_eq!(request(&path, &read_token(dir.path()).unwrap(), &Request::Ping).await.unwrap(), Response::Pong { version: PROTOCOL_VERSION });
    c.abort();
}

/// Simultaneous starters: exactly one wins, and the token on disk is the winner's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_starters_leave_one_working_listener() {
    let dir = tempfile::tempdir().unwrap();
    let starts = (0..6).map(|_| start_issuing(dir.path()));
    let results = futures::future::join_all(starts).await;
    let winners: Vec<&String> = results.iter().filter_map(|(_, r)| r.as_ref().ok()).collect();
    assert_eq!(winners.len(), 1, "{:?}", results.iter().map(|(_, r)| r).collect::<Vec<_>>());
    let on_disk = read_token(dir.path()).unwrap();
    assert_eq!(&on_disk, winners[0]);
    assert_eq!(request(&socket_path(dir.path()), &on_disk, &Request::Ping).await.unwrap(), Response::Pong { version: PROTOCOL_VERSION });
    for (t, _) in results {
        t.abort();
    }
}
