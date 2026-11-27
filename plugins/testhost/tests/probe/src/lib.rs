//! Commands that probe the test host: `spin`, `grow`, `print`, `env`, `time`, `everything`,
//! `leak-login`, `abort`, `open`.

use std::rc::Rc;

use bastion_plugin_sdk::net::Stream;
use bastion_plugin_sdk::ui::{self, ConfirmKind, ViewBuilder};
use bastion_plugin_sdk::{
    clipboard, credentials, export_plugin, files, log, open, storage, task, Plugin, RowsAsk, Task, View,
};

struct Probe;

impl Plugin for Probe {
    fn start() -> Self {
        Probe
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        task(async move {
            let mut b = ViewBuilder::new(ui::stack());
            b.add(b.root(), ui::table(&["n", "square"]));
            let _ = view.set(b.finish());
        })
    }

    fn rows(self: Rc<Self>, ask: RowsAsk) -> Task {
        let rows: Vec<ui::Row> = (ask.offset..ask.offset + u64::from(ask.count))
            .map(|n| ui::Row {
                key: n.to_string(),
                cells: vec![ui::Cell::Number(n as f64), ui::Cell::Number((n * n) as f64)],
            })
            .collect();
        let _ = ui::provide_rows(ask.ask, &rows, Some(10_000));
        bastion_plugin_sdk::done()
    }

    fn command(self: Rc<Self>, id: String, _view: Option<View>) -> Task {
        task(async move {
            match id.as_str() {
                "spin" => {
                    let mut x = 0u64;
                    loop {
                        x = std::hint::black_box(x.wrapping_add(1));
                    }
                }
                "grow" => {
                    let mut blocks: Vec<Vec<u8>> = Vec::new();
                    for _ in 0..200 {
                        blocks.push(vec![1u8; 1024 * 1024]);
                    }
                    log::info(&format!("grew {}", blocks.len()));
                }
                "print" => println!("standard output is a stub"),
                "env" => log::info(&format!("{:?}", std::env::var("HOME"))),
                "time" => {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
                    log::info(&format!("time ok {}", now.as_secs() > 1_700_000_000));
                }
                "everything" => {
                    let login = credentials::entry_login().await.unwrap();
                    log::info(&format!("user {}", login.user));
                    storage::set("k", b"v").await.unwrap();
                    log::info(&format!("keys {:?}", storage::keys("").await.unwrap()));
                    clipboard::write_text("copied").await.unwrap();
                    files::save("out.txt", b"data").await.unwrap();
                    log::info(&format!("open {:?}", files::open().await.map(|f| f.0)));
                    log::info(&format!("confirm {:?}", ui::confirm(ConfirmKind::Drop, "drop table t").await));
                }
                "leak-login" => {
                    let login = credentials::entry_login().await.unwrap();
                    log::info(&format!("the password is {}", login.secret));
                    let stored = storage::set("p", login.secret.as_bytes()).await;
                    let copied = clipboard::write_text(&login.secret).await;
                    log::info(&format!("store {stored:?} copy {copied:?}"));
                }
                "abort" => {
                    let s = Stream::connect(None).await.unwrap();
                    s.register_abort(b"CANCEL 42\n").await.unwrap();
                    log::info("abort registered");
                    // Wait for an answer that never comes; the test then stops the helper.
                    let _ = s.read(1).await;
                }
                "open" => {
                    let first = open::connection(&open::request(open::Protocol::Ssh, "10.0.0.5", "lab-web")).await;
                    // The same user action does not allow a second request.
                    let second = open::connection(&open::request(open::Protocol::Rdp, "10.0.0.6", "lab-win")).await;
                    log::info(&format!("open {first:?} then {}", if second.is_err() { "refused" } else { "allowed" }));
                }
                _ => log::warn("unknown command"),
            }
        })
    }
}

export_plugin!(Probe);
