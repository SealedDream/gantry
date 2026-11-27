//! A starter plugin: one view with a text field and a button. Pressing the button sends the
//! text as a line to the entry's server and shows the answer. The `send` command does the same
//! with the entry's `greeting` field.
//!
//! Permissions (`plugin.toml`): `network = "entry"` only. The component therefore imports
//! `bastion:plugin/net` and none of `credentials`, `storage`, `clipboard` or `files`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use bastion_plugin_sdk::net::Stream;
use bastion_plugin_sdk::ui::{self, BannerLevel, Component, ViewBuilder};
use bastion_plugin_sdk::{export_plugin, host, log, task, Failure, Input, NodeId, Plugin, Task, View};

/// Node ids of the main view, which `view()` builds in this order.
const TEXT: NodeId = 1;
const SEND: NodeId = 2;
const ANSWER: NodeId = 3;

#[derive(Default)]
pub struct Echo {
    /// The text in each view's field, as the user typed it.
    text: RefCell<HashMap<View, String>>,
}

fn view(text: &str, answer: Component) -> Vec<ui::Node> {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    assert_eq!(b.add(root, ui::text_field("Line to send", text)), TEXT);
    assert_eq!(b.add(root, ui::button("Send")), SEND);
    assert_eq!(b.add(root, answer), ANSWER);
    b.finish()
}

/// One line out, one line back.
async fn exchange(line: &str) -> Result<String, Failure> {
    let stream = Stream::connect(None).await?;
    stream.write(format!("{line}\n").as_bytes()).await?;
    let mut answer = Vec::new();
    while !answer.ends_with(b"\n") && answer.len() < 4096 {
        let chunk = stream.read(4096 - answer.len()).await?;
        if chunk.is_empty() {
            break;
        }
        answer.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&answer).trim_end().to_string())
}

impl Echo {
    async fn send(self: Rc<Self>, view: View) {
        let text = self.text.borrow().get(&view).cloned().unwrap_or_default();
        let _ = view.patch(
            vec![ui::Node { id: ANSWER, parent: Some(0), component: Component::Progress(None) }],
            vec![],
        );
        let answer = match exchange(&text).await {
            Ok(answer) => ui::label(&answer),
            Err(failure) => {
                log::warn("the exchange failed");
                ui::banner(BannerLevel::Error, &describe(&failure))
            }
        };
        let _ = view.patch(vec![ui::Node { id: ANSWER, parent: Some(0), component: answer }], vec![]);
    }
}

fn describe(failure: &Failure) -> String {
    match failure {
        Failure::Denied(why) | Failure::Invalid(why) | Failure::Io(why) => why.clone(),
        Failure::TimedOut => "The server did not answer in time.".into(),
        Failure::Cancelled => "Cancelled.".into(),
    }
}

impl Plugin for Echo {
    fn start() -> Self {
        Echo::default()
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        let greeting = host::entry()
            .and_then(|e| e.fields.into_iter().find(|(k, _)| k == "greeting").map(|(_, v)| v))
            .unwrap_or_else(|| "hello".into());
        self.text.borrow_mut().insert(view, greeting.clone());
        task(async move {
            if let Err(e) = view.set(view_nodes(&greeting)) {
                log::error(&format!("view refused: {e:?}"));
            }
        })
    }

    fn close_view(self: Rc<Self>, view: View) -> Task {
        self.text.borrow_mut().remove(&view);
        bastion_plugin_sdk::done()
    }

    fn command(self: Rc<Self>, id: String, view: Option<View>) -> Task {
        match (id.as_str(), view) {
            ("send", Some(view)) => task(self.send(view)),
            _ => bastion_plugin_sdk::done(),
        }
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        match (node, input) {
            (TEXT, Input::Text(text)) => {
                self.text.borrow_mut().insert(view, text);
                bastion_plugin_sdk::done()
            }
            (SEND, Input::Pressed) => task(self.send(view)),
            _ => bastion_plugin_sdk::done(),
        }
    }
}

fn view_nodes(text: &str) -> Vec<ui::Node> {
    view(text, ui::label("Press Send."))
}

export_plugin!(Echo);

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_plugin_sdk::bindings::bastion::plugin::events::{Event, OpenView, ReplyValue, UiEvent};
    use bastion_plugin_sdk::testing::{reply, run_plugin, Call, FakeCore};

    #[test]
    fn the_view_passes_the_checks() {
        assert_eq!(ui::check(&view_nodes("hello")), Ok(()));
    }

    #[test]
    fn send_shows_the_answer() {
        let core = FakeCore::new()
            .respond(|id, call| match call {
                Call::Connect(_) => vec![reply(id, Ok(ReplyValue::Opened(1)))],
                Call::Write(..) => vec![reply(id, Ok(ReplyValue::None))],
                Call::Read(..) => vec![reply(id, Ok(ReplyValue::Data(b"HELLO\n".to_vec())))],
                _ => vec![],
            })
            .with(Event::OpenView(OpenView { view: 1, name: "echo".into() }))
            .with(Event::Ui(UiEvent { view: 1, node: SEND, input: Input::Pressed }));
        let core = run_plugin::<Echo>(core);
        let last = core.plain_calls().into_iter().rev().find_map(|c| match c {
            Call::PatchView(_, nodes, _) => Some(nodes[0].component.clone()),
            _ => None,
        });
        assert!(matches!(last, Some(Component::Label(ref t)) if t == "HELLO"), "{last:?}");
    }
}
