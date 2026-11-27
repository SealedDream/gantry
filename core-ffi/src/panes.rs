//! Split panes and broadcast input bridge (`bastion_core::panes`, `bastion_core::broadcast`).
//! Trees, operations and broadcast sets cross as JSON, the same shapes the C ABI takes.
use bastion_core::broadcast::{self, InputKind, Target};
use bastion_core::panes::{PaneOp, PaneTree};

use crate::{FfiError, FfiResult};

fn parse<T: serde::de::DeserializeOwned>(what: &str, json: &str) -> FfiResult<T> {
    serde_json::from_str(json).map_err(|e| FfiError::failed(format!("invalid {what}: {e}")))
}

fn to_json<T: serde::Serialize>(v: &T) -> FfiResult<String> {
    serde_json::to_string(v).map_err(|e| FfiError::failed(e.to_string()))
}

/// Apply one pane operation (`{"op":"split","pane","axis","newPane"}`, `close {pane}`,
/// `resize {pane,axis,delta}`, `equalize`, `focus {pane,direction}`) to `tree_json`
/// (`{"kind":"leaf","id"}` or `{"kind":"split","axis","ratio","first","second"}`).
/// Returns `{"tree":…|null,"focus":id|null}`; a null tree means the last pane closed.
#[uniffi::export]
pub fn panes_apply(tree_json: String, op_json: String) -> FfiResult<String> {
    let tree: PaneTree = parse("pane tree", &tree_json)?;
    let op: PaneOp = parse("pane operation", &op_json)?;
    to_json(&tree.apply(&op)?)
}

/// The saved layout (`workspace` `layout`) for a live tree.
#[uniffi::export]
pub fn panes_to_layout(tree_json: String) -> FfiResult<String> {
    let tree: PaneTree = parse("pane tree", &tree_json)?;
    to_json(&tree.to_layout())
}

/// A live tree for a saved layout, with a fresh id per pane in reading order.
#[uniffi::export]
pub fn panes_from_layout(layout_json: String) -> FfiResult<String> {
    let layout = parse("pane layout", &layout_json)?;
    to_json(&PaneTree::from_layout(&layout, uuid::Uuid::new_v4)?)
}

/// Who receives broadcast input. `kind` is `keys` or `paste`; `targets_json` =
/// `[{"pane","name","connected","sensitive"}]`. Returns
/// `{"sendTo":[ids],"skipped":[ids],"sensitive":[names],"needsConfirm":bool}`.
#[uniffi::export]
pub fn broadcast_review(kind: String, input: String, targets_json: String, acknowledged: bool) -> FfiResult<String> {
    let kind = match kind.as_str() {
        "keys" => InputKind::Keys,
        "paste" => InputKind::Paste,
        other => return Err(FfiError::failed(format!("invalid input kind: {other}"))),
    };
    let targets: Vec<Target> = parse("broadcast targets", &targets_json)?;
    to_json(&broadcast::review(kind, &input, &targets, acknowledged)?)
}
