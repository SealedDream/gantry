//! A hostile plugin (PLUG-09). `open_view`'s name chooses the behaviour; every behaviour that
//! survives reports what the core answered as one label: `set_view([stack, label(report)])`.

use std::rc::Rc;

use bastion_plugin_sdk::net::Stream;
use bastion_plugin_sdk::ui::{self, Component, ViewBuilder};
use bastion_plugin_sdk::{credentials, export_plugin, host, log, open, storage, task, Failure, Plugin, Task, View};

pub struct Hostile;

fn report(view: View, text: &str) {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    b.add(root, ui::label(text));
    let _ = view.set(b.finish());
}

fn failure(f: &Failure) -> String {
    match f {
        Failure::Denied(_) => "denied".into(),
        Failure::Invalid(_) => "invalid".into(),
        Failure::Io(_) => "io".into(),
        Failure::TimedOut => "timed-out".into(),
        Failure::Cancelled => "cancelled".into(),
    }
}

/// `open.connection`'s answer, with the core's words on a refusal.
fn opened(r: &Result<bool, Failure>) -> String {
    match r {
        Ok(true) => "opened".into(),
        Ok(false) => "declined".into(),
        Err(Failure::Denied(m)) => format!("denied({})", m.split(':').next().unwrap_or_default()),
        Err(f) => failure(f),
    }
}

/// `open|<protocol>|<host>|<entry or direct>|<label>` (API 1.2).
fn open_request(spec: &str) -> Option<open::OpenRequest> {
    let mut parts = spec.split('|').skip(1);
    let protocol = match parts.next()? {
        "ssh" => open::Protocol::Ssh,
        "rdp" => open::Protocol::Rdp,
        _ => open::Protocol::Vnc,
    };
    let host = parts.next()?;
    let via = parts.next()? == "entry";
    let label = parts.next().unwrap_or("guest");
    let mut req = open::request(protocol, host, label);
    req.via_entry_route = via;
    Some(req)
}

fn outcome<T>(r: &Result<T, Failure>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(f) => failure(f),
    }
}

fn node(id: u32, parent: Option<u32>, component: Component) -> ui::Node {
    ui::Node { id, parent, component }
}

#[inline(never)]
fn spin(seed: u64) -> u64 {
    let mut x = seed;
    loop {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        if x == 0 {
            return x; // never: keeps the loop from being optimised away
        }
    }
}

impl Plugin for Hostile {
    fn start() -> Self {
        Hostile
    }

    fn open_view(self: Rc<Self>, view: View, name: String) -> Task {
        task(async move {
            match name.as_str() {
                // Conformance: every call a well-behaved plugin makes, with the answers.
                // API 1.2: asks to open a connection with no user action.
                "open-unprompted" => {
                    let r = open::connection(&open::request(open::Protocol::Ssh, "10.0.0.5", "guest")).await;
                    report(view, &format!("open={}", opened(&r)));
                }
                "conform" => {
                    let entry = host::entry().map(|e| format!("{}:{}", e.host, e.port)).unwrap_or_else(|| "none".into());
                    let settings = host::settings().len();
                    log::info("conformance run");
                    let set = storage::set("k", b"v1").await;
                    let get = storage::get("k").await;
                    let keys = storage::keys("").await;
                    let del = storage::delete("k").await;
                    let gone = storage::get("k").await;
                    let got = match &get {
                        Ok(Some(v)) => String::from_utf8_lossy(v).into_owned(),
                        other => outcome(other),
                    };
                    let keys = match &keys {
                        Ok(k) => k.join(","),
                        other => outcome(other),
                    };
                    let gone = matches!(gone, Ok(None));
                    report(view, &format!("entry={entry} settings={settings} set={} get={got} keys={keys} delete={} gone={gone}", outcome(&set), outcome(&del)));
                }
                // Resource abuse.
                "spin" => {
                    let _ = spin(name.len() as u64);
                }
                "grow" => {
                    let mut hoard: Vec<Vec<u8>> = Vec::new();
                    loop {
                        hoard.push(vec![0x5a; 8 << 20]);
                        log::debug(&format!("{}", hoard.len()));
                    }
                }
                "trap" => {
                    #[allow(unconditional_panic)]
                    let v: Vec<u8> = Vec::new();
                    let _ = v[name.len()];
                }
                // Capabilities the view does not have.
                "no-entry" => {
                    let s = storage::set("k", b"v").await;
                    let n = Stream::connect(None).await.map(|_| ());
                    let c = credentials::entry_login().await.map(|_| ());
                    report(view, &format!("storage={} net={} credentials={}", outcome(&s), outcome(&n), outcome(&c)));
                }
                "net-other-host" => {
                    // The API cannot name a host at all; a port other than the entry's goes to the entry host.
                    let n = Stream::connect(Some(1)).await.map(|_| ());
                    report(view, &format!("net={}", outcome(&n)));
                }
                // Malformed data, sent past the SDK's own checks with `patch`.
                "malformed" => {
                    let cycle = view.patch(vec![node(1, Some(2), ui::stack()), node(2, Some(1), ui::stack())], vec![]);
                    let orphan = view.patch(vec![node(5, Some(99), ui::label("x"))], vec![]);
                    let duplicate = view.patch(vec![node(3, Some(0), ui::label("a")), node(3, Some(0), ui::label("b"))], vec![]);
                    let deep: Vec<ui::Node> = (1..=200u32).map(|i| node(i, Some(i - 1), ui::stack())).collect();
                    let deep = view.patch(deep, vec![]);
                    let many: Vec<ui::Node> = (1..=20_000u32).map(|i| node(i, Some(0), ui::label("n"))).collect();
                    let many = view.patch(many, vec![]);
                    let huge = view.patch(vec![node(1, Some(0), ui::label(&"x".repeat(4 << 20)))], vec![]);
                    report(
                        view,
                        &format!(
                            "cycle={} orphan={} duplicate={} deep={} many={} huge={}",
                            outcome(&cycle),
                            outcome(&orphan),
                            outcome(&duplicate),
                            outcome(&deep),
                            outcome(&many),
                            outcome(&huge)
                        ),
                    );
                }
                probe if probe.starts_with("storage-size:") => {
                    let kib: usize = probe["storage-size:".len()..].parse().unwrap_or(1);
                    let r = storage::set("probe", &vec![0u8; kib << 10]).await;
                    report(view, &format!("size={}", outcome(&r)));
                }
                // One abuse per view, so one that ends the plugin does not hide the others.
                "storage-big" => {
                    // 2 MiB values until the 50 MiB per-plugin cap refuses one.
                    let chunk = vec![0u8; 2 << 20];
                    let mut big = Ok(());
                    for i in 0..60 {
                        big = storage::set(&format!("big{i}"), &chunk).await;
                        if big.is_err() {
                            break;
                        }
                    }
                    report(view, &format!("big={}", outcome(&big)));
                }
                "storage-long-key" => report(view, &format!("long-key={}", outcome(&storage::set(&"k".repeat(100_000), b"v").await))),
                "storage-traversal" => report(view, &format!("traversal={}", outcome(&storage::set("../../escape", b"v").await))),
                "log-flood" => {
                    for i in 0..20_000u32 {
                        log::info(&format!("line {i} {}", "y".repeat(1_000)));
                    }
                    report(view, "flooded");
                }
                "update-flood" => {
                    let mut accepted = 0;
                    for i in 0..300u32 {
                        if view.patch(vec![node(0, None, ui::stack()), node(1, Some(0), ui::label(&i.to_string()))], vec![]).is_ok() {
                            accepted += 1;
                        }
                    }
                    report(view, &format!("accepted={accepted}"));
                }
                other => report(view, &format!("unknown view {other}")),
            }
        })
    }

    fn close_view(self: Rc<Self>, _view: View) -> Task {
        bastion_plugin_sdk::done()
    }

    /// `open|…` asks to open once; `open2|…` asks twice for one user action (API 1.2).
    fn command(self: Rc<Self>, id: String, view: Option<View>) -> Task {
        task(async move {
            let (Some(view), Some(req)) = (view, open_request(&id)) else { return };
            let first = opened(&open::connection(&req).await);
            if id.starts_with("open2|") {
                let second = opened(&open::connection(&req).await);
                report(view, &format!("open={first} second={second}"));
            } else {
                report(view, &format!("open={first}"));
            }
        })
    }

    fn input(self: Rc<Self>, _view: View, _node: bastion_plugin_sdk::NodeId, _input: bastion_plugin_sdk::Input) -> Task {
        bastion_plugin_sdk::done()
    }
}

export_plugin!(Hostile);
