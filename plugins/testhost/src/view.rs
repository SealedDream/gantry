//! Views in the test host: the SDK's checks on the host's copy of the node type, and drawing
//! a view as indented text.

use std::collections::BTreeMap;

use bastion_plugin_sdk::ui as sdk;

use crate::bindings::bastion::plugin::ui::{Axis, BannerLevel, Component, Node};

/// Converts the host's node to the SDK's, so the one set of rules in the SDK applies.
pub fn to_sdk(node: &Node) -> sdk::Node {
    sdk::Node { id: node.id, parent: node.parent, component: component_to_sdk(&node.component) }
}

fn axis(a: Axis) -> sdk::Axis {
    match a {
        Axis::Vertical => sdk::Axis::Vertical,
        Axis::Horizontal => sdk::Axis::Horizontal,
    }
}

fn columns(cols: &[crate::bindings::bastion::plugin::ui::Column]) -> Vec<sdk::Column> {
    cols.iter()
        .map(|c| sdk::Column { title: c.title.clone(), sortable: c.sortable, editable: c.editable })
        .collect()
}

fn component_to_sdk(c: &Component) -> sdk::Component {
    match c {
        Component::Stack(a) => sdk::Component::Stack(axis(*a)),
        Component::Split(a) => sdk::Component::Split(axis(*a)),
        Component::Tabs => sdk::Component::Tabs,
        Component::Tab(t) => sdk::Component::Tab(t.clone()),
        Component::Toolbar => sdk::Component::Toolbar,
        Component::Label(t) => sdk::Component::Label(t.clone()),
        Component::Banner(b) => sdk::Component::Banner(sdk::Banner {
            level: match b.level {
                BannerLevel::Info => sdk::BannerLevel::Info,
                BannerLevel::Warning => sdk::BannerLevel::Warning,
                BannerLevel::Error => sdk::BannerLevel::Error,
            },
            text: b.text.clone(),
        }),
        Component::Progress(p) => sdk::Component::Progress(*p),
        Component::EmptyState(e) => {
            sdk::Component::EmptyState(sdk::EmptyState { title: e.title.clone(), text: e.text.clone() })
        }
        Component::Button(b) => sdk::Component::Button(sdk::Button {
            label: b.label.clone(),
            icon: b.icon.clone(),
            enabled: b.enabled,
        }),
        Component::TextField(t) => sdk::Component::TextField(sdk::TextField {
            label: t.label.clone(),
            value: t.value.clone(),
            placeholder: t.placeholder.clone(),
            multi_line: t.multi_line,
        }),
        Component::NumberField(n) => sdk::Component::NumberField(sdk::NumberField {
            label: n.label.clone(),
            value: n.value,
            min: n.min,
            max: n.max,
        }),
        Component::Choice(c) => sdk::Component::Choice(sdk::ChoiceField {
            label: c.label.clone(),
            options: c.options.clone(),
            selected: c.selected,
        }),
        Component::Toggle(t) => sdk::Component::Toggle(sdk::ToggleField { label: t.label.clone(), value: t.value }),
        Component::CodeEditor(e) => sdk::Component::CodeEditor(sdk::CodeEditor {
            language: e.language.clone(),
            text: e.text.clone(),
            read_only: e.read_only,
        }),
        Component::Table(t) => {
            sdk::Component::Table(sdk::Table { columns: columns(&t.columns), total_rows: t.total_rows })
        }
        Component::Tree(t) => sdk::Component::Tree(sdk::Tree { columns: columns(&t.columns) }),
        Component::Stat(t) => sdk::Component::Stat(sdk::Stat {
            title: t.title.clone(),
            value: t.value.clone(),
            detail: t.detail.clone(),
            fraction: t.fraction,
        }),
    }
}

/// The SDK's view check on the host's nodes.
pub fn check(nodes: &[Node]) -> Result<(), String> {
    let converted: Vec<sdk::Node> = nodes.iter().map(to_sdk).collect();
    sdk::check(&converted).map_err(|e| e.to_string())
}

/// Applies a patch: replaces or adds `upsert`, removes `remove` with all their descendants.
pub fn patch(nodes: &[Node], upsert: Vec<Node>, remove: &[u32]) -> Vec<Node> {
    let mut gone: std::collections::HashSet<u32> = remove.iter().copied().collect();
    // Descendants of removed nodes go too; repeat until nothing changes (lists are small).
    loop {
        let before = gone.len();
        for n in nodes {
            if n.parent.is_some_and(|p| gone.contains(&p)) {
                gone.insert(n.id);
            }
        }
        if gone.len() == before {
            break;
        }
    }
    let mut out: Vec<Node> = nodes.iter().filter(|n| !gone.contains(&n.id)).cloned().collect();
    for node in upsert {
        match out.iter_mut().find(|n| n.id == node.id) {
            Some(slot) => *slot = node,
            None => out.push(node),
        }
    }
    out
}

fn quote(text: &str) -> String {
    // Plain text: control characters other than tab and new line are shown escaped.
    let mut s = String::with_capacity(text.len() + 2);
    s.push('"');
    for c in text.chars() {
        match c {
            '\n' => s.push_str("\\n"),
            '\t' => s.push_str("\\t"),
            '"' => s.push_str("\\\""),
            c if c.is_control() => s.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

fn describe(c: &Component) -> String {
    match c {
        Component::Stack(Axis::Vertical) => "stack".into(),
        Component::Stack(Axis::Horizontal) => "row".into(),
        Component::Split(Axis::Vertical) => "split vertical".into(),
        Component::Split(Axis::Horizontal) => "split horizontal".into(),
        Component::Tabs => "tabs".into(),
        Component::Tab(t) => format!("tab {}", quote(t)),
        Component::Toolbar => "toolbar".into(),
        Component::Label(t) => format!("label {}", quote(t)),
        Component::Banner(b) => {
            let level = match b.level {
                BannerLevel::Info => "info",
                BannerLevel::Warning => "warning",
                BannerLevel::Error => "error",
            };
            format!("banner {level} {}", quote(&b.text))
        }
        Component::Progress(Some(p)) => format!("progress {:.0}%", p * 100.0),
        Component::Progress(None) => "progress busy".into(),
        Component::EmptyState(e) => format!("empty-state {} {}", quote(&e.title), quote(&e.text)),
        Component::Button(b) => {
            format!("button {}{}", quote(&b.label), if b.enabled { "" } else { " (disabled)" })
        }
        Component::TextField(t) => format!("text-field {} = {}", quote(&t.label), quote(&t.value)),
        Component::NumberField(n) => format!("number {} = {}", quote(&n.label), n.value),
        Component::Choice(c) => format!(
            "choice {} = {}",
            quote(&c.label),
            c.selected.and_then(|i| c.options.get(i as usize)).map_or("(none)".into(), |o| quote(o))
        ),
        Component::Toggle(t) => format!("toggle {} = {}", quote(&t.label), if t.value { "on" } else { "off" }),
        Component::CodeEditor(e) => format!("code-editor {} {}", e.language, quote(&e.text)),
        Component::Table(t) => format!(
            "table [{}]{}",
            t.columns.iter().map(|c| quote(&c.title)).collect::<Vec<_>>().join(", "),
            t.total_rows.map_or(String::new(), |n| format!(" {n} rows"))
        ),
        Component::Tree(t) => format!(
            "tree [{}]",
            t.columns.iter().map(|c| quote(&c.title)).collect::<Vec<_>>().join(", ")
        ),
        Component::Stat(t) => format!(
            "stat {} {} {}{}",
            quote(&t.title),
            quote(&t.value),
            quote(&t.detail),
            t.fraction.map_or(String::new(), |f| format!(" {:.0}%", f * 100.0))
        ),
    }
}

/// Draws a view as indented text, one node per line, with each node's id. Children appear in
/// list order. The view must have passed [`check`].
pub fn render(nodes: &[Node]) -> String {
    let mut children: BTreeMap<Option<u32>, Vec<&Node>> = BTreeMap::new();
    for n in nodes {
        children.entry(n.parent).or_default().push(n);
    }
    let mut out = String::new();
    // An explicit stack, not recursion: the depth is bounded by the check, but a renderer
    // should not depend on that.
    let mut stack: Vec<(&Node, usize)> =
        children.get(&None).into_iter().flatten().rev().map(|n| (*n, 0)).collect();
    while let Some((node, depth)) = stack.pop() {
        out.push_str(&"  ".repeat(depth));
        out.push_str(&format!("#{} {}\n", node.id, describe(&node.component)));
        if let Some(kids) = children.get(&Some(node.id)) {
            stack.extend(kids.iter().rev().map(|k| (*k, depth + 1)));
        }
    }
    out
}

/// Finds the first node whose component has this label or title.
pub fn find_by_label(nodes: &[Node], label: &str) -> Option<u32> {
    nodes
        .iter()
        .find(|n| match &n.component {
            Component::Button(b) => b.label == label,
            Component::TextField(t) => t.label == label,
            Component::NumberField(t) => t.label == label,
            Component::Choice(t) => t.label == label,
            Component::Toggle(t) => t.label == label,
            Component::Tab(t) | Component::Label(t) => t == label,
            _ => false,
        })
        .map(|n| n.id)
}
