//! Broadcast input: what the user types or pastes in one pane goes to every pane in the
//! broadcast set. This module decides who receives it and when the app must ask first;
//! the apps write the bytes. Disconnected panes are skipped, never queued.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};

/// Most panes one broadcast may reach (16 panes in each of 16 tabs).
pub const MAX_TARGETS: usize = 256;
/// Largest single keystroke chunk or paste.
pub const MAX_INPUT: usize = 64 * 1024;
/// Ends bracketed paste early, so a paste holding it could run the rest as typed commands.
const PASTE_END: &str = "\x1b[201~";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InputKind {
    /// Typed keys, sent as they come.
    Keys,
    /// A paste (or snippet) sent in one go.
    Paste,
}

/// One pane in the broadcast set as the app sees it right now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub pane: Uuid,
    /// Host name shown in a confirmation.
    pub name: String,
    pub connected: bool,
    /// Production, customer-sensitive or privileged (`Classification::is_sensitive`).
    #[serde(default)]
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    pub send_to: Vec<Uuid>,
    /// Disconnected panes that will not get this input.
    pub skipped: Vec<Uuid>,
    /// Sensitive hosts in `send_to`.
    pub sensitive: Vec<String>,
    /// Ask before sending: a multi-line paste to several panes, or sensitive hosts the user has
    /// not yet acknowledged for this broadcast set.
    pub needs_confirm: bool,
}

/// Decide who receives `input`. `acknowledged` is true once the user confirmed this set's
/// sensitive hosts (the app resets it when the set changes).
pub fn review(kind: InputKind, input: &str, targets: &[Target], acknowledged: bool) -> Result<Review> {
    if input.is_empty() || input.len() > MAX_INPUT {
        return Err(CoreError::Invalid(format!("Input must be 1 to {MAX_INPUT} bytes.")));
    }
    if input.contains('\0') {
        return Err(CoreError::Invalid("Input must not contain NUL.".into()));
    }
    if kind == InputKind::Paste && input.contains(PASTE_END) {
        return Err(CoreError::Invalid("The paste contains a bracketed-paste end sequence and was refused.".into()));
    }
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err(CoreError::Invalid(format!("Broadcast to 1 to {MAX_TARGETS} panes.")));
    }
    let mut seen = std::collections::HashSet::new();
    if let Some(dup) = targets.iter().find(|t| !seen.insert(t.pane)) {
        return Err(CoreError::Invalid(format!("{} is listed twice.", dup.name)));
    }
    let (live, dead): (Vec<&Target>, Vec<&Target>) = targets.iter().partition(|t| t.connected);
    let sensitive: Vec<String> = live.iter().filter(|t| t.sensitive).map(|t| t.name.clone()).collect();
    let multi_line_paste = kind == InputKind::Paste && live.len() > 1 && input.trim_end_matches(['\r', '\n']).contains(['\r', '\n']);
    Ok(Review {
        send_to: live.iter().map(|t| t.pane).collect(),
        skipped: dead.iter().map(|t| t.pane).collect(),
        needs_confirm: multi_line_paste || (!sensitive.is_empty() && !acknowledged),
        sensitive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: u8, connected: bool, sensitive: bool) -> Target {
        Target { pane: Uuid::from_bytes([n; 16]), name: format!("host{n}"), connected, sensitive }
    }

    #[test]
    fn keys_go_to_connected_panes_only() {
        let r = review(InputKind::Keys, "l", &[t(1, true, false), t(2, false, false), t(3, true, false)], false).unwrap();
        assert_eq!(r.send_to, vec![t(1, true, false).pane, t(3, true, false).pane]);
        assert_eq!(r.skipped, vec![t(2, false, false).pane]);
        assert!(!r.needs_confirm);
    }

    #[test]
    fn sensitive_hosts_need_one_acknowledgement() {
        let set = [t(1, true, true), t(2, true, false)];
        let r = review(InputKind::Keys, "x", &set, false).unwrap();
        assert!(r.needs_confirm);
        assert_eq!(r.sensitive, vec!["host1".to_string()]);
        assert!(!review(InputKind::Keys, "x", &set, true).unwrap().needs_confirm);
        let offline = [t(1, false, true), t(2, true, false)];
        assert!(!review(InputKind::Keys, "x", &offline, false).unwrap().needs_confirm, "a disconnected sensitive host gets nothing");
    }

    #[test]
    fn multi_line_paste_to_several_panes_asks() {
        let two = [t(1, true, false), t(2, true, false)];
        assert!(review(InputKind::Paste, "a\nb\n", &two, true).unwrap().needs_confirm);
        assert!(!review(InputKind::Paste, "one line\n", &two, true).unwrap().needs_confirm);
        assert!(!review(InputKind::Paste, "a\nb", &two[..1], true).unwrap().needs_confirm);
    }

    #[test]
    fn refuses_bad_input_and_sets() {
        let one = [t(1, true, false)];
        assert!(review(InputKind::Keys, "", &one, false).is_err());
        assert!(review(InputKind::Keys, "a\0", &one, false).is_err());
        assert!(review(InputKind::Keys, &"a".repeat(MAX_INPUT + 1), &one, false).is_err());
        assert!(review(InputKind::Paste, "ok\x1b[201~rm -rf ~\n", &one, false).is_err());
        assert!(review(InputKind::Keys, "\x1b[201~", &one, false).is_ok(), "typed escape keys pass through");
        assert!(review(InputKind::Keys, "a", &[], false).is_err());
        assert!(review(InputKind::Keys, "a", &[t(1, true, false), t(1, true, false)], false).is_err());
        let many: Vec<Target> = (0..=MAX_TARGETS).map(|i| Target { pane: Uuid::from_u128(i as u128), name: i.to_string(), connected: true, sensitive: false }).collect();
        assert!(review(InputKind::Keys, "a", &many, false).is_err());
    }

    #[test]
    fn json_shape() {
        let r = review(InputKind::Keys, "a", &[t(1, true, false)], false).unwrap();
        let v = serde_json::to_value(&r).unwrap();
        assert!(v["sendTo"].is_array() && v["needsConfirm"] == false);
        let k: InputKind = serde_json::from_str("\"paste\"").unwrap();
        assert_eq!(k, InputKind::Paste);
    }
}
