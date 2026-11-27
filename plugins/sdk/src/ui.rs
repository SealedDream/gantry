//! Views: building node lists, checking them, and answering the core's asks.
//!
//! [`check`] applies the rules of `bastion:plugin/ui` (spec section 5, "UI components"). The
//! core runs the same rules before any renderer sees a list; checking here first turns a
//! mistake into an error the author sees in a unit test. [`check_shapes`] works on plain data,
//! so the core and the test host can use it on their own copies of the node type.

pub use crate::bindings::bastion::plugin::ui::{
    Axis, Banner, BannerLevel, Button, Cell, CodeEditor, Column, Completion, Component,
    ChoiceField, ConfirmKind, EmptyState, ErrorMark, MenuItem, MeterCell, Node, NumberField, Row, Stat,
    StatusCell, Table, TextField, ToggleField, Tone, Tree, TreeItem,
};

use crate::bindings::bastion::plugin::events::ReplyValue;
use crate::runtime::{pending, unexpected};
use crate::{sys, Failure, NodeId};

/// Most nodes in one view.
pub const MAX_NODES: usize = 2_000;
/// Most bytes in one view, as [`node_size`] counts them.
pub const MAX_BYTES: usize = 256 * 1024;
/// Deepest nesting: the root is depth 1.
pub const MAX_DEPTH: usize = 32;
/// Longest label, title or tab name, in characters.
pub const MAX_LABEL: usize = 32;
/// Most rows in one answer to a `rows` ask.
pub const MAX_ROWS: usize = 1_000;

/// A view the core opened. Copy it freely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct View(pub u32);

impl View {
    /// Replaces the whole view, after [`check`].
    pub fn set(self, nodes: Vec<Node>) -> Result<(), Failure> {
        check(&nodes).map_err(|e| Failure::Invalid(e.to_string()))?;
        sys::set_view(self.0, &nodes)
    }

    /// Adds or replaces `upsert` and removes `remove` (with their children). The core checks
    /// the resulting view.
    pub fn patch(self, upsert: Vec<Node>, remove: Vec<NodeId>) -> Result<(), Failure> {
        sys::patch_view(self.0, &upsert, &remove)
    }

    /// Opens a modal dialog over this view. Its events carry the returned view.
    pub fn open_dialog(self, title: &str, nodes: Vec<Node>) -> Result<View, Failure> {
        if title.chars().count() > MAX_LABEL {
            return Err(Failure::Invalid(format!("dialog title longer than {MAX_LABEL} characters")));
        }
        check(&nodes).map_err(|e| Failure::Invalid(e.to_string()))?;
        sys::open_dialog(self.0, title, &nodes).map(View)
    }

    /// Closes a dialog this view opened.
    pub fn close_dialog(dialog: View) {
        sys::close_dialog(dialog.0)
    }

    /// Error marks in a code editor; an empty list clears them.
    pub fn mark_errors(self, editor: NodeId, marks: &[ErrorMark]) -> Result<(), Failure> {
        sys::mark_errors(self.0, editor, marks)
    }
}

/// Answers a `rows` ask. At most 1,000 rows.
pub fn provide_rows(ask: u32, rows: &[Row], total: Option<u64>) -> Result<(), Failure> {
    if rows.len() > MAX_ROWS {
        return Err(Failure::Invalid(format!("{} rows in one page, the most is {MAX_ROWS}", rows.len())));
    }
    sys::provide_rows(ask, rows, total)
}

/// Answers a `children` ask.
pub fn provide_children(ask: u32, items: &[TreeItem]) -> Result<(), Failure> {
    sys::provide_children(ask, items)
}

/// Answers a `completions` ask.
pub fn provide_completions(ask: u32, items: &[Completion]) -> Result<(), Failure> {
    sys::provide_completions(ask, items)
}

/// Answers any ask with an error the core shows in its own frame.
pub fn refuse(ask: u32, message: &str) {
    sys::refuse(ask, message)
}

/// Asks the user to confirm a risky action. The core draws the prompt in its own words.
pub async fn confirm(kind: ConfirmKind, text: &str) -> Result<bool, Failure> {
    match pending(sys::confirm(kind, text)).await? {
        ReplyValue::Confirmed(yes) => Ok(yes),
        other => Err(unexpected("confirm", other)),
    }
}

// ---- Building ------------------------------------------------------------------------------

/// Builds a node list with one root and ids handed out in order.
#[derive(Debug, Clone)]
pub struct ViewBuilder {
    nodes: Vec<Node>,
}

impl ViewBuilder {
    /// Starts a view whose root is `root` (id 0).
    pub fn new(root: Component) -> ViewBuilder {
        ViewBuilder { nodes: vec![Node { id: 0, parent: None, component: root }] }
    }

    /// The root's id.
    pub fn root(&self) -> NodeId {
        0
    }

    /// Adds a child of `parent` and returns its id.
    pub fn add(&mut self, parent: NodeId, component: Component) -> NodeId {
        let id = self.nodes.len() as NodeId;
        self.nodes.push(Node { id, parent: Some(parent), component });
        id
    }

    /// The node list, ready for [`View::set`].
    pub fn finish(self) -> Vec<Node> {
        self.nodes
    }
}

pub fn stack() -> Component {
    Component::Stack(Axis::Vertical)
}
pub fn row() -> Component {
    Component::Stack(Axis::Horizontal)
}
pub fn label(text: &str) -> Component {
    Component::Label(text.into())
}
pub fn banner(level: BannerLevel, text: &str) -> Component {
    Component::Banner(Banner { level, text: text.into() })
}
pub fn button(label: &str) -> Component {
    Component::Button(Button { label: label.into(), icon: None, enabled: true })
}
/// A button with a name from the app's icon set (for example `refresh`, `ssh`, `rdp`, `vnc`).
/// In a toolbar the app draws it as an icon button with the label as its tooltip; a run of
/// connection-type icons becomes one Connect button with a menu.
pub fn icon_button(label: &str, icon: &str, enabled: bool) -> Component {
    Component::Button(Button { label: label.into(), icon: Some(icon.into()), enabled })
}
pub fn text_field(label: &str, value: &str) -> Component {
    Component::TextField(TextField {
        label: label.into(),
        value: value.into(),
        placeholder: String::new(),
        multi_line: false,
    })
}
pub fn code_editor(language: &str, text: &str) -> Component {
    Component::CodeEditor(CodeEditor { language: language.into(), text: text.into(), read_only: false })
}
pub fn table(columns: &[&str]) -> Component {
    Component::Table(Table {
        columns: columns
            .iter()
            .map(|t| Column { title: (*t).into(), sortable: false, editable: false })
            .collect(),
        total_rows: None,
    })
}

/// A summary tile (API 1.6): title, value, detail and, with `fraction`, a thin bar.
pub fn stat(title: &str, value: &str, detail: &str, fraction: Option<f32>) -> Component {
    Component::Stat(Stat { title: title.into(), value: value.into(), detail: detail.into(), fraction: fraction.map(|f| f.clamp(0.0, 1.0)) })
}

/// A state cell (API 1.6): a dot in the tone's colour and the text. `Tone::Off` dims the row.
pub fn status_cell(tone: Tone, text: &str) -> Cell {
    Cell::Status(StatusCell { tone, text: text.into() })
}

/// A small bar cell (API 1.6), `fraction` from 0.0 to 1.0, with its text.
pub fn meter_cell(fraction: f32, text: &str) -> Cell {
    Cell::Meter(MeterCell { fraction: if fraction.is_nan() { 0.0 } else { fraction.clamp(0.0, 1.0) }, text: text.into() })
}

// ---- Checking ------------------------------------------------------------------------------

/// What a component may hold, for [`check_shapes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// No children.
    Leaf,
    /// Any number of children (`stack`, `toolbar`, `tab`).
    Container,
    /// At most two children.
    Split,
    /// Only `tab` children.
    Tabs,
    /// Must sit in a `tabs`.
    Tab,
}

/// One node, reduced to what the rules look at.
#[derive(Clone, Debug)]
pub struct ShapeNode<'a> {
    pub id: u32,
    pub parent: Option<u32>,
    pub shape: Shape,
    /// Labels and titles that must fit in [`MAX_LABEL`] characters.
    pub labels: Vec<&'a str>,
    /// The node's size as [`node_size`] counts it.
    pub bytes: usize,
}

/// Why a view was refused. The message is safe to show and echoes no plugin text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewError {
    Empty,
    TooManyNodes(usize),
    TooLarge(usize),
    DuplicateId(u32),
    NoRoot,
    SeveralRoots,
    UnknownParent { node: u32, parent: u32 },
    Unreachable(u32),
    TooDeep(u32),
    LeafWithChildren(u32),
    SplitWithMoreThanTwo(u32),
    NotATabInTabs(u32),
    TabOutsideTabs(u32),
    LabelTooLong(u32),
}

impl std::fmt::Display for ViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViewError::Empty => write!(f, "view: no nodes"),
            ViewError::TooManyNodes(n) => write!(f, "view: {n} nodes, the most is {MAX_NODES}"),
            ViewError::TooLarge(n) => write!(f, "view: {n} bytes, the most is {MAX_BYTES}"),
            ViewError::DuplicateId(id) => write!(f, "view: node id {id} is used twice"),
            ViewError::NoRoot => write!(f, "view: no root node"),
            ViewError::SeveralRoots => write!(f, "view: more than one root node"),
            ViewError::UnknownParent { node, parent } => {
                write!(f, "view: node {node} names parent {parent}, which does not exist")
            }
            ViewError::Unreachable(id) => write!(f, "view: node {id} is in a cycle"),
            ViewError::TooDeep(id) => write!(f, "view: node {id} is nested deeper than {MAX_DEPTH}"),
            ViewError::LeafWithChildren(id) => write!(f, "view: node {id} cannot hold children"),
            ViewError::SplitWithMoreThanTwo(id) => write!(f, "view: split {id} has more than two children"),
            ViewError::NotATabInTabs(id) => write!(f, "view: node {id} sits in tabs but is not a tab"),
            ViewError::TabOutsideTabs(id) => write!(f, "view: tab {id} is not inside tabs"),
            ViewError::LabelTooLong(id) => {
                write!(f, "view: a label of node {id} is longer than {MAX_LABEL} characters")
            }
        }
    }
}

impl std::error::Error for ViewError {}

/// Checks a node list against every rule. Runs in time linear in the number of nodes and
/// without recursion.
pub fn check(nodes: &[Node]) -> Result<(), ViewError> {
    let shapes: Vec<ShapeNode<'_>> = nodes
        .iter()
        .map(|n| ShapeNode {
            id: n.id,
            parent: n.parent,
            shape: shape_of(&n.component),
            labels: labels_of(&n.component),
            bytes: node_size(n),
        })
        .collect();
    check_shapes(&shapes)
}

/// The rules of [`check`] on plain data.
pub fn check_shapes(nodes: &[ShapeNode<'_>]) -> Result<(), ViewError> {
    use std::collections::HashMap;

    if nodes.is_empty() {
        return Err(ViewError::Empty);
    }
    if nodes.len() > MAX_NODES {
        return Err(ViewError::TooManyNodes(nodes.len()));
    }
    let bytes: usize = nodes.iter().map(|n| n.bytes).sum();
    if bytes > MAX_BYTES {
        return Err(ViewError::TooLarge(bytes));
    }

    let mut index: HashMap<u32, usize> = HashMap::with_capacity(nodes.len());
    for (i, n) in nodes.iter().enumerate() {
        if index.insert(n.id, i).is_some() {
            return Err(ViewError::DuplicateId(n.id));
        }
        if n.labels.iter().any(|l| l.chars().count() > MAX_LABEL) {
            return Err(ViewError::LabelTooLong(n.id));
        }
    }

    let mut root = None;
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (i, n) in nodes.iter().enumerate() {
        match n.parent {
            None if root.is_some() => return Err(ViewError::SeveralRoots),
            None => root = Some(i),
            Some(p) => {
                let Some(&pi) = index.get(&p) else {
                    return Err(ViewError::UnknownParent { node: n.id, parent: p });
                };
                children[pi].push(i);
            }
        }
    }
    let root = root.ok_or(ViewError::NoRoot)?;
    if nodes[root].shape == Shape::Tab {
        return Err(ViewError::TabOutsideTabs(nodes[root].id));
    }

    // Walk down from the root, level by level. A node not reached is in a cycle.
    let mut seen = vec![false; nodes.len()];
    let mut level = vec![root];
    seen[root] = true;
    let mut depth = 1;
    while !level.is_empty() {
        if depth > MAX_DEPTH {
            return Err(ViewError::TooDeep(nodes[level[0]].id));
        }
        let mut next = Vec::new();
        for &i in &level {
            let parent = &nodes[i];
            let kids = &children[i];
            match parent.shape {
                Shape::Leaf if !kids.is_empty() => return Err(ViewError::LeafWithChildren(parent.id)),
                Shape::Split if kids.len() > 2 => return Err(ViewError::SplitWithMoreThanTwo(parent.id)),
                _ => {}
            }
            for &k in kids {
                let child = &nodes[k];
                match (parent.shape, child.shape) {
                    (Shape::Tabs, Shape::Tab) => {}
                    (Shape::Tabs, _) => return Err(ViewError::NotATabInTabs(child.id)),
                    (_, Shape::Tab) => return Err(ViewError::TabOutsideTabs(child.id)),
                    _ => {}
                }
                seen[k] = true;
                next.push(k);
            }
        }
        level = next;
        depth += 1;
    }
    if let Some(i) = seen.iter().position(|s| !s) {
        return Err(ViewError::Unreachable(nodes[i].id));
    }
    Ok(())
}

/// What a component may hold.
pub fn shape_of(component: &Component) -> Shape {
    match component {
        Component::Stack(_) | Component::Toolbar => Shape::Container,
        Component::Tab(_) => Shape::Tab,
        Component::Split(_) => Shape::Split,
        Component::Tabs => Shape::Tabs,
        _ => Shape::Leaf,
    }
}

/// The labels and titles of a component that must fit in [`MAX_LABEL`] characters.
pub fn labels_of(component: &Component) -> Vec<&str> {
    match component {
        Component::Tab(title) => vec![title.as_str()],
        Component::Button(b) => vec![b.label.as_str()],
        Component::TextField(t) => vec![t.label.as_str()],
        Component::NumberField(n) => vec![n.label.as_str()],
        Component::Choice(c) => vec![c.label.as_str()],
        Component::Toggle(t) => vec![t.label.as_str()],
        Component::EmptyState(e) => vec![e.title.as_str()],
        Component::Stat(t) => vec![t.title.as_str(), t.value.as_str()],
        Component::Table(t) => t.columns.iter().map(|c| c.title.as_str()).collect(),
        Component::Tree(t) => t.columns.iter().map(|c| c.title.as_str()).collect(),
        _ => Vec::new(),
    }
}

/// The size of a view for the 256 KiB limit: the sum of [`node_size`]. This is the one
/// definition of "256 KiB per view"; the core's broker calls the same function, so a view the
/// SDK accepts is never refused by the core for its size.
pub fn view_bytes(nodes: &[Node]) -> usize {
    nodes.iter().map(node_size).sum()
}

/// The size of one node for the 256 KiB limit: 16 bytes for the node, plus the bytes of every
/// string and 8 bytes for every number or list item it holds. It over-counts the encoded size of
/// small values, so it stays on the safe side.
pub fn node_size(node: &Node) -> usize {
    16 + match &node.component {
        Component::Stack(_) | Component::Split(_) | Component::Tabs | Component::Toolbar => 0,
        Component::Tab(s) | Component::Label(s) => s.len(),
        Component::Banner(b) => b.text.len(),
        Component::Progress(_) => 8,
        Component::EmptyState(e) => e.title.len() + e.text.len(),
        Component::Button(b) => b.label.len() + b.icon.as_ref().map_or(0, String::len),
        Component::TextField(t) => t.label.len() + t.value.len() + t.placeholder.len(),
        Component::NumberField(n) => n.label.len() + 24,
        Component::Choice(c) => c.label.len() + c.options.iter().map(|o| o.len() + 8).sum::<usize>() + 8,
        Component::Toggle(t) => t.label.len(),
        Component::CodeEditor(c) => c.language.len() + c.text.len(),
        Component::Table(t) => t.columns.iter().map(|c| c.title.len() + 8).sum::<usize>() + 8,
        Component::Tree(t) => t.columns.iter().map(|c| c.title.len() + 8).sum::<usize>(),
        Component::Stat(t) => t.title.len() + t.value.len() + t.detail.len() + 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u32, parent: Option<u32>, component: Component) -> Node {
        Node { id, parent, component }
    }

    #[test]
    fn stat_tiles_and_cells_clamp_and_count() {
        let Component::Stat(t) = stat("CPU", "12%", "8 cores", Some(1.7)) else { panic!() };
        assert_eq!(t.fraction, Some(1.0), "a bar never runs past full");
        assert!(matches!(meter_cell(f32::NAN, "x"), Cell::Meter(m) if m.fraction == 0.0));
        assert!(matches!(meter_cell(-1.0, "x"), Cell::Meter(m) if m.fraction == 0.0));
        assert!(matches!(status_cell(Tone::Off, "db"), Cell::Status(s) if s.tone == Tone::Off && s.text == "db"));
        let mut b = ViewBuilder::new(stack());
        let root = b.root();
        b.add(root, stat("Memory", "4.0 / 16.0 GiB", "25% used", Some(0.25)));
        assert_eq!(check(&b.finish()), Ok(()));
        let mut b = ViewBuilder::new(stack());
        let root = b.root();
        b.add(root, stat("Memory", &"9".repeat(40), "", None));
        assert!(matches!(check(&b.finish()), Err(ViewError::LabelTooLong(_))), "a tile's value fits one line");
    }

    #[test]
    fn a_built_view_passes() {
        let mut b = ViewBuilder::new(stack());
        let tabs = b.add(b.root(), Component::Tabs);
        let tab = b.add(tabs, Component::Tab("Query".into()));
        b.add(tab, code_editor("sql", "select 1"));
        let split = b.add(b.root(), Component::Split(Axis::Horizontal));
        b.add(split, table(&["a", "b"]));
        b.add(split, label("x"));
        assert_eq!(check(&b.finish()), Ok(()));
    }

    #[test]
    fn empty_is_refused() {
        assert_eq!(check(&[]), Err(ViewError::Empty));
    }

    #[test]
    fn too_many_nodes() {
        let mut nodes = vec![node(0, None, stack())];
        nodes.extend((1..=MAX_NODES as u32).map(|i| node(i, Some(0), label(""))));
        assert_eq!(check(&nodes), Err(ViewError::TooManyNodes(MAX_NODES + 1)));
        nodes.pop();
        assert_eq!(check(&nodes), Ok(()));
    }

    #[test]
    fn too_large() {
        let nodes = vec![node(0, None, stack()), node(1, Some(0), label(&"x".repeat(MAX_BYTES)))];
        assert!(matches!(check(&nodes), Err(ViewError::TooLarge(_))));
        let fits = MAX_BYTES - 32;
        let nodes = vec![node(0, None, stack()), node(1, Some(0), label(&"x".repeat(fits)))];
        assert_eq!(check(&nodes), Ok(()));
    }

    #[test]
    fn view_bytes_is_the_sum_the_check_uses() {
        let nodes = vec![node(0, None, stack()), node(1, Some(0), label("abc")), node(2, Some(0), button("ok"))];
        assert_eq!(view_bytes(&nodes), 16 + (16 + 3) + (16 + 2));
        let big = vec![node(0, None, stack()), node(1, Some(0), label(&"x".repeat(MAX_BYTES - 32)))];
        assert_eq!(view_bytes(&big), MAX_BYTES);
        assert_eq!(check(&big), Ok(()));
        let over = vec![node(0, None, stack()), node(1, Some(0), label(&"x".repeat(MAX_BYTES - 31)))];
        assert_eq!(check(&over), Err(ViewError::TooLarge(MAX_BYTES + 1)));
    }

    #[test]
    fn duplicate_id() {
        let nodes = vec![node(0, None, stack()), node(1, Some(0), label("a")), node(1, Some(0), label("b"))];
        assert_eq!(check(&nodes), Err(ViewError::DuplicateId(1)));
    }

    #[test]
    fn roots() {
        assert_eq!(check(&[node(0, Some(1), stack()), node(1, Some(0), stack())]), Err(ViewError::NoRoot));
        assert_eq!(check(&[node(0, None, stack()), node(1, None, stack())]), Err(ViewError::SeveralRoots));
    }

    #[test]
    fn unknown_parent() {
        let nodes = vec![node(0, None, stack()), node(1, Some(7), label("a"))];
        assert_eq!(check(&nodes), Err(ViewError::UnknownParent { node: 1, parent: 7 }));
    }

    #[test]
    fn cycle_beside_a_root() {
        let nodes = vec![node(0, None, stack()), node(1, Some(2), stack()), node(2, Some(1), stack())];
        assert!(matches!(check(&nodes), Err(ViewError::Unreachable(1 | 2))));
    }

    #[test]
    fn depth_limit() {
        let chain = |len: u32| -> Vec<Node> {
            (0..len).map(|i| node(i, i.checked_sub(1), stack())).collect()
        };
        assert_eq!(check(&chain(MAX_DEPTH as u32)), Ok(()));
        assert_eq!(check(&chain(MAX_DEPTH as u32 + 1)), Err(ViewError::TooDeep(MAX_DEPTH as u32)));
    }

    #[test]
    fn leaf_with_children() {
        let nodes = vec![node(0, None, stack()), node(1, Some(0), label("a")), node(2, Some(1), label("b"))];
        assert_eq!(check(&nodes), Err(ViewError::LeafWithChildren(1)));
    }

    #[test]
    fn split_takes_two() {
        let mut nodes = vec![node(0, None, Component::Split(Axis::Vertical))];
        nodes.extend((1..=3).map(|i| node(i, Some(0), label(""))));
        assert_eq!(check(&nodes), Err(ViewError::SplitWithMoreThanTwo(0)));
    }

    #[test]
    fn tabs_hold_only_tabs_and_tabs_live_only_in_tabs() {
        let nodes = vec![node(0, None, Component::Tabs), node(1, Some(0), label("a"))];
        assert_eq!(check(&nodes), Err(ViewError::NotATabInTabs(1)));
        let nodes = vec![node(0, None, stack()), node(1, Some(0), Component::Tab("t".into()))];
        assert_eq!(check(&nodes), Err(ViewError::TabOutsideTabs(1)));
        assert_eq!(check(&[node(0, None, Component::Tab("t".into()))]), Err(ViewError::TabOutsideTabs(0)));
    }

    #[test]
    fn label_length_counts_characters() {
        let ok = "é".repeat(MAX_LABEL);
        assert_eq!(check(&[node(0, None, stack()), node(1, Some(0), button(&ok))]), Ok(()));
        let long = "é".repeat(MAX_LABEL + 1);
        assert_eq!(check(&[node(0, None, stack()), node(1, Some(0), button(&long))]), Err(ViewError::LabelTooLong(1)));
        assert_eq!(
            check(&[node(0, None, table(&["ok", &long]))]),
            Err(ViewError::LabelTooLong(0))
        );
    }

    #[test]
    fn errors_echo_no_plugin_text() {
        let long = "SECRET-LOOKING-TEXT".repeat(4);
        let e = check(&[node(0, None, button(&long))]).unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
    }
}
