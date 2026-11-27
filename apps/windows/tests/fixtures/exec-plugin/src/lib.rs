//! Exec fixture: one view with Run, Wait, Cancel and Terminal buttons and a status label that
//! the Windows UI test reads.
use std::cell::Cell;
use std::rc::Rc;

use bastion_plugin_sdk::exec;
use bastion_plugin_sdk::ui::{self, ViewBuilder};
use bastion_plugin_sdk::{task, Failure, Input, NodeId, Plugin, Task, View};

const RUN: NodeId = 1;
const WAIT: NodeId = 2;
const CANCEL: NodeId = 3;
const TERMINAL: NodeId = 4;
const STATUS: NodeId = 5;

fn page(status: &str) -> Vec<ui::Node> {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    assert_eq!(b.add(root, ui::button("Run")), RUN);
    assert_eq!(b.add(root, ui::button("Wait")), WAIT);
    assert_eq!(b.add(root, ui::button("Cancel")), CANCEL);
    assert_eq!(b.add(root, ui::button("Terminal")), TERMINAL);
    assert_eq!(b.add(root, ui::label(status)), STATUS);
    b.finish()
}

fn show(view: View, text: &str) {
    let _ = view.patch(vec![ui::Node { id: STATUS, parent: Some(0), component: ui::label(text) }], vec![]);
}

fn failure(f: &Failure) -> String {
    match f {
        Failure::Denied(t) => format!("denied: {t}"),
        Failure::Cancelled => "cancelled".into(),
        other => format!("{other:?}"),
    }
}

#[derive(Default)]
struct Fixture {
    waiting: Cell<Option<u32>>,
}

impl Plugin for Fixture {
    fn start() -> Self {
        Fixture::default()
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        let _ = view.set(page("ready"));
        bastion_plugin_sdk::done()
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        if !matches!(input, Input::Pressed) {
            return bastion_plugin_sdk::done();
        }
        match node {
            RUN => task(async move {
                show(view, "running");
                match exec::run("hello", &[], 30_000).await {
                    Ok(o) => show(view, &format!("{} exit {}", String::from_utf8_lossy(&o.stdout).trim(), o.exit.map_or("none".into(), |e| e.to_string()))),
                    Err(f) => show(view, &failure(&f)),
                }
            }),
            WAIT => {
                let (request, wait) = exec::start("wait", &[("secs", "60")], 90_000);
                self.waiting.set(Some(request));
                show(view, "waiting");
                let me = self.clone();
                task(async move {
                    let text = match wait.await {
                        Ok(o) => format!("wait exit {:?}", o.exit),
                        Err(f) => failure(&f),
                    };
                    me.waiting.set(None);
                    show(view, &text);
                })
            }
            CANCEL => {
                if let Some(r) = self.waiting.get() {
                    exec::cancel(r);
                }
                bastion_plugin_sdk::done()
            }
            TERMINAL => task(async move {
                match exec::terminal("term", &[], "fixture top").await {
                    Ok(opened) => show(view, &format!("terminal opened {opened}")),
                    Err(f) => show(view, &failure(&f)),
                }
            }),
            _ => bastion_plugin_sdk::done(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
bastion_plugin_sdk::export_plugin!(Fixture);
