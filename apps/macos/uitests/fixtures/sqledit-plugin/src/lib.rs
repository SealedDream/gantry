//! Test fixture (PLUG-06c, Native Mac): a SQL code editor with fixed completions.
use std::rc::Rc;

use bastion_plugin_sdk::ui::{self, Completion, ViewBuilder};
use bastion_plugin_sdk::{done, export_plugin, task, CompletionsAsk, Input, NodeId, Plugin, Task, View};

const EDITOR: NodeId = 1;
const RESULT: NodeId = 2;

pub struct SqlEdit;

fn item(label: &str, detail: &str) -> Completion {
    Completion { label: label.into(), insert: label.into(), detail: detail.into() }
}

impl Plugin for SqlEdit {
    fn start() -> Self {
        SqlEdit
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        task(async move {
            let mut b = ViewBuilder::new(ui::stack());
            let root = b.root();
            b.add(root, ui::code_editor("postgresql", "-- fixture\nSELECT id, name FROM users WHERE id = $1;\n"));
            b.add(root, ui::label("Not run yet."));
            let _ = view.set(b.finish());
        })
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        match (node, input) {
            (EDITOR, Input::Run(text)) => task(async move {
                let ran = ui::label(&format!("Ran {} chars", text.chars().count()));
                // The root goes along: the core checks a patch's parents inside the patch.
                let root = ui::Node { id: 0, parent: None, component: ui::stack() };
                let _ = view.patch(vec![root, ui::Node { id: RESULT, parent: Some(0), component: ran }], vec![]);
            }),
            _ => done(),
        }
    }

    fn completions(self: Rc<Self>, ask: CompletionsAsk) -> Task {
        let items = [item("users", "table"), item("user_roles", "table"), item("username", "column users"), item("orders", "table")];
        let _ = ui::provide_completions(ask.ask, &items);
        done()
    }
}

export_plugin!(SqlEdit);
