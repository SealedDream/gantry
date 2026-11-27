//! The guest → snapshot tree (PVE-SNAP), like the VMware plugin's: node → guest → snapshot.
//!
//! Take, Rollback and Delete are offered only when the entry's "Allow changes" field is on,
//! and each one is confirmed with `ui.confirm` before it is sent. Names are checked with
//! [`check_snapshot`] before they go into a path.

use bastion_plugin_sdk::bindings::bastion::plugin::ui::{Cell, Column, MenuItem, Tree, TreeItem};
use bastion_plugin_sdk::ui::Component;

use crate::api::{check_node, check_snapshot, check_vmid};
use crate::model::{Guest, GuestKind, PowerState, Snapshot};

/// The entry field that allows snapshot changes (manifest `connection_types.fields`).
pub const ALLOW_CHANGES: &str = "allow-changes";
/// Names of snapshots taken from the tree: `gantry-1`, `gantry-2`, …
pub const NAME_PREFIX: &str = "gantry-";
pub const TREE_COLUMNS: [&str; 3] = ["Name", "State", "Taken"];

pub const TAKE: &str = "snapshot-take";
pub const ROLLBACK: &str = "snapshot-rollback";
pub const DELETE: &str = "snapshot-delete";

pub fn tree() -> Component {
    Component::Tree(Tree {
        columns: TREE_COLUMNS.iter().map(|t| Column { title: (*t).into(), sortable: false, editable: false }).collect(),
    })
}

fn item(id: &str, title: &str) -> MenuItem {
    MenuItem { id: id.into(), title: title.into() }
}

/// What a tree key names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    /// `node:pve1`
    Node(String),
    /// `pve1/201`
    Guest(String, u64),
    /// `pve1/201/before-patch`
    Snapshot(String, u64, String),
}

/// Parses and checks a key; anything that does not pass the name checks is `None`.
pub fn parse(key: &str) -> Option<Key> {
    if let Some(n) = key.strip_prefix("node:") {
        return Some(Key::Node(check_node(n).ok()?.to_string()));
    }
    let mut parts = key.splitn(3, '/');
    let node = check_node(parts.next()?).ok()?.to_string();
    let vmid = check_vmid(parts.next()?.parse().ok()?).ok()?;
    match parts.next() {
        None => Some(Key::Guest(node, vmid)),
        Some(s) => Some(Key::Snapshot(node, vmid, check_snapshot(s).ok()?.to_string())),
    }
}

pub fn guest_name(g: &Guest) -> String {
    if g.name.is_empty() { format!("Guest {}", g.vmid) } else { g.name.clone() }
}

fn state(g: &Guest) -> &'static str {
    match g.power() {
        PowerState::Running => "running",
        PowerState::Stopped => "stopped",
        PowerState::Paused => "paused",
        PowerState::Unknown => "unknown",
    }
}

/// One item per node that has guests, by name.
pub fn node_items(guests: &[Guest]) -> Vec<TreeItem> {
    let mut nodes: Vec<&str> = guests.iter().map(|g| g.node.as_str()).collect();
    nodes.sort_unstable();
    nodes.dedup();
    nodes
        .into_iter()
        .map(|n| TreeItem { key: format!("node:{n}"), label: n.into(), icon: None, has_children: true, cells: vec![Cell::Null, Cell::Null], menu: vec![] })
        .collect()
}

/// A guest's menu: Take Snapshot when changes are allowed.
pub fn guest_menu(may_change: bool) -> Vec<MenuItem> {
    if may_change { vec![item(TAKE, "Take Snapshot")] } else { vec![] }
}

/// The guests on one node, by ID; templates are left out. Each expands to its snapshots.
pub fn guest_items(guests: &[Guest], node: &str, may_change: bool) -> Vec<TreeItem> {
    let mut list: Vec<&Guest> = guests.iter().filter(|g| g.node == node && !g.is_template() && g.kind.is_some()).collect();
    list.sort_by_key(|g| g.vmid);
    list.into_iter()
        .map(|g| TreeItem {
            key: format!("{}/{}", g.node, g.vmid),
            label: format!("{} {}", g.vmid, guest_name(g)),
            icon: None,
            has_children: true,
            cells: vec![Cell::Text(state(g).into()), Cell::Null],
            menu: guest_menu(may_change),
        })
        .collect()
}

/// A snapshot's menu: Rollback and Delete when changes are allowed.
pub fn snapshot_menu(may_change: bool) -> Vec<MenuItem> {
    if may_change { vec![item(ROLLBACK, "Rollback"), item(DELETE, "Delete Snapshot")] } else { vec![] }
}

/// `snaptime` as UTC `YYYY-MM-DD HH:MM`, or empty when unknown.
pub fn taken(secs: u64) -> String {
    if secs == 0 {
        return String::new();
    }
    let days = (secs / 86_400) as i64;
    let (h, m) = (secs / 3_600 % 24, secs / 60 % 60);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02} UTC")
}

/// The snapshots of one guest, oldest first.
pub fn snapshot_items(node: &str, vmid: u64, snaps: &[Snapshot], may_change: bool) -> Vec<TreeItem> {
    let mut list: Vec<&Snapshot> = snaps.iter().filter(|s| check_snapshot(&s.name).is_ok()).collect();
    list.sort_by_key(|s| s.snaptime);
    list.into_iter()
        .map(|s| TreeItem {
            key: format!("{node}/{vmid}/{}", s.name),
            label: s.name.clone(),
            icon: None,
            has_children: false,
            cells: vec![Cell::Text(if s.vmstate != 0 { "snapshot, with RAM" } else { "snapshot" }.into()), Cell::Text(taken(s.snaptime))],
            menu: snapshot_menu(may_change),
        })
        .collect()
}

/// The first free `gantry-N` name.
pub fn next_name(snaps: &[Snapshot]) -> String {
    let n = snaps.iter().filter_map(|s| s.name.strip_prefix(NAME_PREFIX)?.parse::<u32>().ok()).max().unwrap_or(0);
    format!("{NAME_PREFIX}{}", n.saturating_add(1))
}

pub fn take_prompt(name: &str, snap: &str, kind: GuestKind) -> String {
    let what = if kind == GuestKind::Qemu { "Disks only, without RAM." } else { "The container's volumes." };
    format!("Take snapshot {snap} of {name}? {what}")
}

pub fn rollback_prompt(name: &str, snap: &str) -> String {
    format!("Roll {name} back to snapshot {snap}? Changes since the snapshot are lost.")
}

pub fn delete_prompt(name: &str, snap: &str) -> String {
    format!("Delete snapshot {snap} of {name}? This cannot be undone.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(name: &str, t: u64) -> Snapshot {
        Snapshot { name: name.into(), description: String::new(), parent: None, snaptime: t, vmstate: 0 }
    }

    #[test]
    fn keys_are_parsed_and_checked() {
        assert_eq!(parse("node:pve1"), Some(Key::Node("pve1".into())));
        assert_eq!(parse("pve1/201"), Some(Key::Guest("pve1".into(), 201)));
        assert_eq!(parse("pve1/201/before_patch"), Some(Key::Snapshot("pve1".into(), 201, "before_patch".into())));
        for bad in ["pve1/201/../x", "pve1/201/current", "pve1/99", "../201", "node:a/b", "pve1/201/a/b", "pve1/x"] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn menus_appear_only_when_changes_are_allowed() {
        assert!(guest_menu(false).is_empty() && snapshot_menu(false).is_empty());
        assert_eq!(guest_menu(true).iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), vec![TAKE]);
        assert_eq!(snapshot_menu(true).iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), vec![ROLLBACK, DELETE]);
    }

    #[test]
    fn the_next_name_is_free_and_valid() {
        assert_eq!(next_name(&[]), "gantry-1");
        assert_eq!(next_name(&[snap("gantry-2", 1), snap("other", 2), snap("gantry-x", 3)]), "gantry-3");
        assert!(check_snapshot(&next_name(&[snap("gantry-4294967295", 1)])).is_ok());
    }

    #[test]
    fn snapshots_are_listed_oldest_first_and_bad_names_dropped() {
        let items = snapshot_items("pve1", 201, &[snap("b", 20), snap("a", 10), snap("x/../y", 5)], false);
        assert_eq!(items.iter().map(|i| i.key.as_str()).collect::<Vec<_>>(), vec!["pve1/201/a", "pve1/201/b"]);
        assert!(items.iter().all(|i| i.menu.is_empty()));
    }

    #[test]
    fn taken_reads_as_a_utc_date() {
        assert_eq!(taken(0), "");
        assert_eq!(taken(1_700_000_000), "2023-11-14 22:13 UTC");
    }
}
