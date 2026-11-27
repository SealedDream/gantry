//! `bastion-plugin-testhost`: run a plugin component from the command line.
//!
//! ```text
//! bastion-plugin-testhost <plugin.wasm> --manifest <plugin.toml> [--imports]
//!     [--entry-port <port>] [--echo-server]
//!     [--open <view>] [--type <label>=<text>]... [--press <label>]... [--command <id>]...
//! ```
//!
//! Steps run in the order given; after each one the host waits until the plugin is quiet and
//! prints the open view as text. No password is ever taken on the command line: the fake
//! login is a fixed test user with a generated password.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use bastion_plugin_testhost::bindings::bastion::plugin::types::{Entry, Login};
use bastion_plugin_testhost::{Config, LineEcho, NoServer, TestHost};

enum Step {
    Open(String),
    Type(String, String),
    Press(String),
    Command(String),
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: bastion-plugin-testhost <plugin.wasm> --manifest <plugin.toml> [--imports] \
         [--entry-port <port>] [--echo-server] [--open <view>] [--type <label>=<text>]... \
         [--press <label>]... [--command <id>]..."
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(wasm) = args.next().map(PathBuf::from) else { return usage() };
    let mut manifest = None;
    let mut list_imports = false;
    let mut echo = false;
    let mut port = 7u16;
    let mut steps = Vec::new();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(());
        let parsed: Result<(), ()> = (|| {
            match arg.as_str() {
                "--manifest" => manifest = Some(PathBuf::from(value()?)),
                "--imports" => list_imports = true,
                "--echo-server" => echo = true,
                "--entry-port" => port = value()?.parse().map_err(|_| ())?,
                "--open" => steps.push(Step::Open(value()?)),
                "--press" => steps.push(Step::Press(value()?)),
                "--command" => steps.push(Step::Command(value()?)),
                "--type" => {
                    let v = value()?;
                    let (label, text) = v.split_once('=').ok_or(())?;
                    steps.push(Step::Type(label.into(), text.into()));
                }
                _ => return Err(()),
            }
            Ok(())
        })();
        if parsed.is_err() {
            return usage();
        }
    }
    let Some(manifest) = manifest else { return usage() };

    let (host, permissions) = match TestHost::load_files(&wasm, &manifest) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("refused: {e}");
            return ExitCode::from(1);
        }
    };
    if list_imports {
        for name in host.import_names() {
            println!("import {name}");
        }
    }
    let secret: String = (0..4).map(|_| format!("{:08x}", rand_u32())).collect();
    let config = Config {
        permissions,
        entry: Some(Entry {
            id: "test-entry".into(),
            name: "Test entry".into(),
            host: "127.0.0.1".into(),
            port,
            fields: Vec::new(),
        }),
        login: Some(Login { user: "test".into(), secret }),
        ..Config::default()
    };
    let server: Box<dyn bastion_plugin_testhost::FakeServer> = if echo { Box::new(LineEcho) } else { Box::new(NoServer) };
    let mut session = match host.start(config, server) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("refused: {e}");
            return ExitCode::from(1);
        }
    };
    let quiet = Duration::from_millis(200);
    let limit = Duration::from_secs(10);
    let mut view = None;
    for step in steps {
        let done = match step {
            Step::Open(name) => {
                view = Some(session.open_view(&name));
                Ok(())
            }
            Step::Press(label) => view.ok_or("no view open".to_string()).and_then(|v| session.press(v, &label)),
            Step::Type(label, text) => {
                view.ok_or("no view open".to_string()).and_then(|v| session.type_text(v, &label, &text))
            }
            Step::Command(id) => {
                session.command(&id, view);
                Ok(())
            }
        };
        if let Err(e) = done {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
        session.settle(quiet, limit);
        if let Some(v) = view {
            println!("--- view {v}");
            print!("{}", session.render(v));
        }
    }
    session.with_outputs(|o| {
        for (level, line) in &o.logs {
            println!("log {level:?}: {line}");
        }
    });
    match session.stop() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("the plugin ended with an error: {e}");
            ExitCode::from(1)
        }
    }
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    u32::from_le_bytes(b)
}
