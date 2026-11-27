//! The Rust samples of `docs/plugins/AUTHORING.md`, compiled and run. Each `// doc:` block is
//! copied into the guide word for word; `scripts/check-plugin-doc-samples.py` checks that.

// doc:status-plugin
use std::rc::Rc;

use bastion_plugin_sdk::http::{self, Method};
use bastion_plugin_sdk::ui::{self, BannerLevel, ViewBuilder};
use bastion_plugin_sdk::{export_plugin, log, storage, task, Failure, Input, NodeId, Plugin, Task, View};

const REFRESH: NodeId = 1;
const RESULT: NodeId = 2;

#[derive(Default)]
pub struct Status;

fn nodes(result: ui::Component) -> Vec<ui::Node> {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    assert_eq!(b.add(root, ui::button("Refresh")), REFRESH);
    assert_eq!(b.add(root, result), RESULT);
    b.finish()
}

/// `GET /api/status` with the entry's login, as the manifest's `[http]` table allows.
async fn fetch() -> Result<String, Failure> {
    let mut req = http::request(Method::Get, "/api/status");
    req.headers.push(("Accept".into(), "text/plain".into()));
    req.with_login = true;
    let resp = http::send(&req).await?;
    if resp.status != 200 {
        return Err(Failure::Io(format!("the server answered {}", resp.status)));
    }
    Ok(String::from_utf8_lossy(&resp.body).into_owned())
}

async fn refresh(view: View) {
    let shown = match fetch().await {
        Ok(text) => {
            // Not a secret: storage is not encrypted, and the core refuses a value that holds
            // the released password.
            let _ = storage::set("last-status", text.as_bytes()).await;
            ui::label(&text)
        }
        Err(failure) => {
            log::warn("status request failed");
            ui::banner(BannerLevel::Error, &format!("{failure:?}"))
        }
    };
    let _ = view.patch(vec![ui::Node { id: RESULT, parent: Some(0), component: shown }], vec![]);
}

impl Plugin for Status {
    fn start() -> Self {
        Status
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        task(async move {
            let last = storage::get("last-status").await.ok().flatten();
            let text = last.map(|b| String::from_utf8_lossy(&b).into_owned());
            let _ = view.set(nodes(ui::label(text.as_deref().unwrap_or("Press Refresh."))));
        })
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        match (node, input) {
            (REFRESH, Input::Pressed) => task(refresh(view)),
            _ => bastion_plugin_sdk::done(),
        }
    }
}

export_plugin!(Status);
// end

// doc:status-test
use bastion_plugin_sdk::bindings::bastion::plugin::events::{Event, OpenView, ReplyValue, UiEvent};
use bastion_plugin_sdk::http::HttpResponse;
use bastion_plugin_sdk::testing::{reply, run_plugin, Call, FakeCore};

#[test]
fn refresh_shows_the_status_and_keeps_it() {
    let core = FakeCore::new()
        .respond(|id, call| match call {
            Call::StorageGet(_) => vec![reply(id, Ok(ReplyValue::Value(None)))],
            Call::StorageSet(..) => vec![reply(id, Ok(ReplyValue::None))],
            Call::HttpSend(req) if req.with_login && req.target == "/api/status" => {
                let resp = HttpResponse { status: 200, headers: vec![], body: b"all good".to_vec() };
                vec![reply(id, Ok(ReplyValue::Http(resp)))]
            }
            _ => vec![],
        })
        .with(Event::OpenView(OpenView { view: 1, name: "status".into() }))
        .with(Event::Ui(UiEvent { view: 1, node: REFRESH, input: Input::Pressed }));
    let core = run_plugin::<Status>(core);
    let calls = core.plain_calls();
    assert!(calls.iter().any(|c| matches!(c, Call::StorageSet(k, v) if k == "last-status" && v == b"all good")));
    assert!(calls.iter().any(|c| matches!(c, Call::PatchView(1, nodes, _)
        if matches!(&nodes[0].component, ui::Component::Label(t) if t == "all good"))));
}
// end

#[test]
fn the_view_passes_the_core_checks() {
    // doc:view-check
    assert_eq!(ui::check(&nodes(ui::label("Press Refresh."))), Ok(()));
    // end
}
