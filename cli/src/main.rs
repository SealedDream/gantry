//! `bastion`: companion CLI. `list` reads the library file directly (works with the app
//! closed); `ping`, `open` and `tunnel` ask the running app over local IPC (`core::ipc`); the app
//! then connects through its normal connect sheet. Opt-in aliases (`sshp`, `rdpp`, `vncp`, `tun`)
//! are symlinks to this binary that open the picker or a named host of one type.
mod aliases;
mod picker;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aliases::Role;
use bastion_core::ipc::{self, Request, Response, PROTOCOL_VERSION};
use bastion_core::store::Store;
use bastion_core::tunnel_registry::TunnelRegistry;

const USAGE: &str = "usage: bastion <command>
  list [--json]                     list connections in the library
  pick [--protocol ssh|rdp|vnc]     choose a connection interactively and open it
  ping                              check that the Bastion app is running
  open <name> [--files] [--protocol P]   open a session (or SFTP browser) in the running app
  tunnel [<name>]                   start a saved tunnel (picker without a name)
  aliases list | install [--dir DIR] [name=role ...] | uninstall
                                    opt-in shortcuts; roles: ssh rdp vnc tunnel
                                    (default sshp=ssh rdpp=rdp vncp=vnc tun=tunnel in ~/.local/bin)";

/// Same location rules as the apps: `BASTION_LIBRARY`, else the per-user app data folder.
/// Bastion Native keeps its data in `Bastion`, Bastion Tauri in `Bastion Tauri`; the CLI ships
/// with both, so it uses the folder of the app that is running (an IPC token is present), else
/// the one that has a library, else Native's.
fn library_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BASTION_LIBRARY") {
        return Some(PathBuf::from(p));
    }
    let base = if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
    } else if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    };
    base.map(|b| pick_data_dir(&b).join("library.json"))
}

const DATA_DIR_NAMES: [&str; 2] = ["Bastion", "Bastion Tauri"];

fn pick_data_dir(base: &Path) -> PathBuf {
    let dirs = DATA_DIR_NAMES.map(|n| base.join(n));
    // A token alone can be stale (an app that was killed leaves it), so a folder whose app
    // answers a ping wins over one that only has a token file.
    let answering = dirs.iter().find(|d| answers(d));
    let running = answering.or_else(|| dirs.iter().find(|d| ipc::running_flavour(d).is_some()));
    let has_library = dirs.iter().find(|d| d.join("library.json").exists());
    running.or(has_library).unwrap_or(&dirs[0]).clone()
}

/// True when an app with a token on `dir` answers a ping.
fn answers(dir: &Path) -> bool {
    if ipc::running_flavour(dir).is_none() {
        return false;
    }
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return false };
    ipc::Flavour::ALL.into_iter().any(|f| {
        ipc::read_token_for(dir, f).is_ok_and(|t| matches!(rt.block_on(ipc::request(&ipc::endpoint(dir, f), &t, &Request::Ping)), Ok(Response::Pong { .. })))
    })
}

fn protocol_name(p: bastion_core::model::Protocol) -> String {
    p.as_str().to_string()
}

fn list(json: bool, path: &Path) -> Result<(), String> {
    let doc = Store::new(path).load().map_err(|e| format!("{}: {e}", path.display()))?;
    let rows = doc.connections();
    if json {
        let items: Vec<_> = rows
            .iter()
            .map(|r| serde_json::json!({ "id": r.connection.id, "name": r.connection.name, "protocol": r.connection.protocol, "host": r.connection.host, "path": r.path }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items).map_err(|e| e.to_string())?);
    } else {
        for r in rows {
            println!("{:<32} {:<6} {:<28} {}", r.connection.name, protocol_name(r.connection.protocol), r.connection.host, r.path.join("/"));
        }
    }
    Ok(())
}

fn send(path: &Path, req: Request) -> Result<Response, String> {
    let dir = path.parent().ok_or("library path has no parent")?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    // Each app with a token on this folder, Native first; a token left by a crashed app falls
    // through to the next one. With no token at all, the error names the missing token.
    let mut last = None;
    for flavour in ipc::Flavour::ALL {
        let Ok(token) = ipc::read_token_for(dir, flavour) else { continue };
        match rt.block_on(ipc::request(&ipc::endpoint(dir, flavour), &token, &req)) {
            Ok(r) => return Ok(r),
            Err(e) => last = Some(e.to_string()),
        }
    }
    Err(last.unwrap_or_else(|| ipc::read_token(dir).err().map(|e| e.to_string()).unwrap_or_default()))
}

fn expect_ok(r: Response) -> Result<(), String> {
    match r {
        Response::Ok => Ok(()),
        Response::Error { message } => Err(message),
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

fn open(path: &Path, name: String, files: bool, protocol: Option<String>) -> Result<(), String> {
    expect_ok(send(path, Request::Open { name, files, protocol })?)
}

/// The connection to open: `name` if given, else the picker over connections of `protocol`.
fn pick_connection(path: &Path, protocol: Option<&str>) -> Result<Option<String>, String> {
    let doc = Store::new(path).load().map_err(|e| format!("{}: {e}", path.display()))?;
    let rows: Vec<_> = doc.connections().into_iter().filter(|r| protocol.is_none_or(|p| protocol_name(r.connection.protocol) == p)).collect();
    let items: Vec<picker::Item> = rows.iter().map(|r| picker::Item { title: r.connection.name.clone(), detail: format!("{} · {}", r.connection.host, r.path.join("/")) }).collect();
    Ok(picker::pick(protocol.unwrap_or("connection"), &items)?.map(|i| rows[i].connection.id.to_string()))
}

fn tunnel(path: &Path, name: Option<String>) -> Result<(), String> {
    let name = match name {
        Some(n) => n,
        None => {
            let doc = Store::new(path).load().map_err(|e| format!("{}: {e}", path.display()))?;
            // Native keeps saved tunnels in the library; Bastion Tauri in `tunnels.json` beside it.
            let mut rows: Vec<(String, String, String)> = doc.tunnels.iter().map(|t| (t.id.to_string(), t.name.clone(), t.summary())).collect();
            let registry = path.with_file_name("tunnels.json");
            if registry.exists() {
                let reg = TunnelRegistry::open(&registry).map_err(|e| format!("{}: {e}", registry.display()))?;
                rows.extend(reg.list().iter().filter(|t| !rows.iter().any(|r| r.0 == t.id.to_string())).map(|t| (t.id.to_string(), t.name.clone(), t.summary())).collect::<Vec<_>>());
            }
            let items: Vec<picker::Item> = rows.iter().map(|r| picker::Item { title: r.1.clone(), detail: r.2.clone() }).collect();
            match picker::pick("tunnel", &items)? {
                Some(i) => rows[i].0.clone(),
                None => return Ok(()),
            }
        }
    };
    expect_ok(send(path, Request::OpenTunnel { name })?)
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

fn aliases_cmd(args: &[String], path: &Path) -> Result<(), String> {
    let data = path.parent().ok_or("library path has no parent")?;
    match args.first().map(String::as_str) {
        Some("list") | None => {
            let m = aliases::load(data)?;
            if m.aliases.is_empty() {
                println!("no aliases installed (bastion aliases install)");
            }
            for a in m.aliases {
                println!("{:<10} {:<7} {}", a.name, serde_json::to_value(a.role).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(), a.path.display());
            }
            Ok(())
        }
        Some("install") => {
            let dir = flag_value(args, "--dir").map(PathBuf::from).or_else(default_alias_dir).ok_or("no --dir, and no home folder to default to")?;
            let mut wanted: Vec<(String, Role)> = Vec::new();
            for a in args.iter().skip(1).filter(|a| a.contains('=')) {
                let (n, r) = a.split_once('=').unwrap_or_default();
                wanted.push((n.to_string(), Role::parse(r).ok_or_else(|| format!("unknown role `{r}` (ssh, rdp, vnc, tunnel)"))?));
            }
            if wanted.is_empty() {
                wanted = aliases::DEFAULTS.iter().map(|(n, r)| (n.to_string(), *r)).collect();
            }
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let made = aliases::install(data, &dir, &exe, &wanted, &std::env::var("PATH").unwrap_or_default())?;
            for a in &made {
                println!("installed {}", a.path.display());
            }
            if !std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).any(|p| p == dir) {
                println!("note: {} is not on your PATH; add it yourself (Bastion does not edit shell files)", dir.display());
            }
            Ok(())
        }
        Some("uninstall") => {
            let (removed, kept) = aliases::uninstall(data)?;
            for p in removed {
                println!("removed {}", p.display());
            }
            for p in kept {
                println!("left {} (it is no longer Bastion's)", p.display());
            }
            Ok(())
        }
        Some(other) => Err(format!("unknown aliases command `{other}`\n{USAGE}")),
    }
}

/// `sshp [name]`, `rdpp [name]`, `vncp [name]`, `tun [name]`.
fn run_alias(role: Role, args: &[String], path: &Path) -> Result<(), String> {
    let name = args.first().filter(|a| !a.starts_with('-')).cloned();
    match role {
        Role::Tunnel => tunnel(path, name),
        _ => {
            let protocol = role.protocol().map(str::to_string);
            let target = match name {
                Some(n) => Some(n),
                None => pick_connection(path, protocol.as_deref())?,
            };
            match target {
                Some(t) => open(path, t, args.iter().any(|a| a == "--files"), protocol),
                None => Ok(()),
            }
        }
    }
}

fn run(argv0: &str, args: &[String]) -> Result<(), String> {
    let path = library_path().ok_or("cannot find the library location; set BASTION_LIBRARY")?;
    if let Some(role) = path.parent().and_then(|d| aliases::role_for(d, argv0)) {
        return run_alias(role, args, &path);
    }
    match args.first().map(String::as_str) {
        Some("list") => list(args.iter().any(|a| a == "--json"), &path),
        Some("ping") => match send(&path, Request::Ping)? {
            Response::Pong { version } if version == PROTOCOL_VERSION => Ok(println!("Bastion is running")),
            Response::Pong { version } => Err(format!("app speaks IPC v{version}, CLI v{PROTOCOL_VERSION}")),
            other => Err(format!("unexpected reply: {other:?}")),
        },
        Some("open") => {
            let name = args.get(1).filter(|n| !n.starts_with("--")).ok_or(USAGE)?;
            open(&path, name.clone(), args.iter().any(|a| a == "--files"), flag_value(args, "--protocol"))
        }
        Some("pick") => {
            let protocol = flag_value(args, "--protocol");
            match pick_connection(&path, protocol.as_deref())? {
                Some(id) => open(&path, id, false, protocol),
                None => Ok(()),
            }
        }
        Some("tunnel") => tunnel(&path, args.get(1).cloned()),
        Some("aliases") => aliases_cmd(&args[1..], &path),
        _ => Err(USAGE.into()),
    }
}

/// Where `aliases install` puts the alias files without `--dir`: `%LOCALAPPDATA%\Bastion\bin` on
/// Windows (no HOME there), `~/.local/bin` elsewhere.
fn default_alias_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Bastion").join("bin"))
    } else {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/bin"))
    }
}

fn main() -> ExitCode {
    let mut argv = std::env::args();
    let argv0 = argv.next().unwrap_or_default();
    let args: Vec<String> = argv.collect();
    match run(&argv0, &args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod data_dir_tests {
    use super::pick_data_dir;

    #[test]
    fn prefers_the_running_app_then_a_library_then_native() {
        let t = tempfile::tempdir().unwrap();
        let (native, tauri) = (t.path().join("Bastion"), t.path().join("Bastion Tauri"));
        assert_eq!(pick_data_dir(t.path()), native);
        std::fs::create_dir_all(&tauri).unwrap();
        std::fs::write(tauri.join("library.json"), "{}").unwrap();
        assert_eq!(pick_data_dir(t.path()), tauri);
        std::fs::create_dir_all(&native).unwrap();
        std::fs::write(native.join("library.json"), "{}").unwrap();
        assert_eq!(pick_data_dir(t.path()), native);
        bastion_core::ipc::issue_token_for(&tauri, bastion_core::ipc::Flavour::Tauri).unwrap();
        assert_eq!(pick_data_dir(t.path()), tauri);
    }
}
