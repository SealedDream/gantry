//! Tab groups (Edge-style): coloured, named, collapsible runs of tabs in the session strip, plus
//! folder auto-grouping. Built once here; every app keeps its own strip UI and passes the strip
//! through as JSON (`TabStrip`), so the rules are the same in Native Mac, Windows and Tauri.
//!
//! The strip holds tab ids and connection ids only. Every operation returns a new strip and
//! leaves the input untouched. A group's tabs are always one contiguous run, in strip order.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::Document;

pub const MAX_GROUP_NAME: usize = 60;
/// Tabs a strip may hold; well above what fits on screen, so overflow is a UI concern.
pub const MAX_STRIP_TABS: usize = 512;
/// Fewest open connections from one folder that form an automatic group.
pub const AUTO_GROUP_MIN: usize = 2;
/// Key of the inheritable folder and connection property (`properties`).
pub const TAB_GROUP_COLOR_KEY: &str = "tab_group_color";

/// The eight group colours. Apps map each id to their own tint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupColor {
    Grey,
    Blue,
    Red,
    Yellow,
    Green,
    Pink,
    Purple,
    Cyan,
}

/// `(id, label)` in menu order.
pub const GROUP_COLORS: &[(&str, &str)] = &[
    ("grey", "Grey"),
    ("blue", "Blue"),
    ("red", "Red"),
    ("yellow", "Yellow"),
    ("green", "Green"),
    ("pink", "Pink"),
    ("purple", "Purple"),
    ("cyan", "Cyan"),
];

const ALL_COLORS: [GroupColor; 8] =
    [GroupColor::Grey, GroupColor::Blue, GroupColor::Red, GroupColor::Yellow, GroupColor::Green, GroupColor::Pink, GroupColor::Purple, GroupColor::Cyan];

impl GroupColor {
    pub fn parse(id: &str) -> Option<GroupColor> {
        serde_json::from_value(serde_json::Value::String(id.to_string())).ok()
    }

    /// A stable colour for a folder that sets none, so its group keeps one colour across runs.
    pub fn for_id(id: Uuid) -> GroupColor {
        let sum: u32 = id.as_bytes().iter().map(|b| u32::from(*b)).sum();
        ALL_COLORS[(sum as usize) % ALL_COLORS.len()]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TabGroup {
    pub id: Uuid,
    pub name: String,
    pub color: GroupColor,
    #[serde(default)]
    pub collapsed: bool,
    /// Set for a group formed by folder auto-grouping: the folder it follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripTab {
    pub id: Uuid,
    /// Library connection; `None` for local shells and tasks, which never auto-group.
    #[serde(default)]
    pub connection: Option<Uuid>,
    #[serde(default)]
    pub group: Option<Uuid>,
    /// Dragged out of an automatic group: auto-grouping leaves it alone from then on.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub detached: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TabStrip {
    pub tabs: Vec<StripTab>,
    #[serde(default)]
    pub groups: Vec<TabGroup>,
}

/// One user action on the strip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum StripOp {
    /// Add to new group: the tabs join a new group placed where the first of them is.
    NewGroup { tabs: Vec<Uuid>, name: Option<String>, color: Option<GroupColor> },
    Rename { group: Uuid, name: String },
    Recolor { group: Uuid, color: GroupColor },
    SetCollapsed { group: Uuid, collapsed: bool },
    /// Drag into a group (or Move to group): the tab moves to the end of the group's run.
    AddToGroup { tab: Uuid, group: Uuid },
    /// Drag out of a group: the tab moves just after the group's run.
    RemoveFromGroup { tab: Uuid },
    /// Move a tab to strip index `to` (counted without it); it joins a group it lands inside.
    Move { tab: Uuid, to: usize },
    /// Ungroup: the tabs stay open.
    Ungroup { group: Uuid },
    /// Close group: the group and its tabs go; the result lists the closed tab ids.
    CloseGroup { group: Uuid },
}

/// The new strip and the tabs the app must close.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StripChange {
    pub strip: TabStrip,
    pub closed: Vec<Uuid>,
}

fn valid_group_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.chars().count() > MAX_GROUP_NAME {
        return Err(CoreError::Invalid(format!("a group name is at most {MAX_GROUP_NAME} characters")));
    }
    Ok(name.to_string())
}

/// True when the tab sits in an automatic (folder) group.
fn in_auto_group(strip: &TabStrip, t: &StripTab) -> bool {
    t.group.and_then(|g| strip.group(g)).is_some_and(|g| g.folder.is_some())
}

impl TabStrip {
    pub fn group(&self, id: Uuid) -> Option<&TabGroup> {
        self.groups.iter().find(|g| g.id == id)
    }

    fn tab_index(&self, id: Uuid) -> Result<usize> {
        self.tabs.iter().position(|t| t.id == id).ok_or_else(|| CoreError::NotFound(format!("tab {id}")))
    }

    fn existing_group(&self, id: Uuid) -> Result<&TabGroup> {
        self.group(id).ok_or_else(|| CoreError::NotFound(format!("tab group {id}")))
    }

    fn with_group(&self, id: Uuid, change: impl Fn(&TabGroup) -> TabGroup) -> Result<TabStrip> {
        self.existing_group(id)?;
        let groups = self.groups.iter().map(|g| if g.id == id { change(g) } else { g.clone() }).collect();
        Ok(TabStrip { tabs: self.tabs.clone(), groups })
    }

    /// The strip without `tab`, plus that tab.
    fn without(&self, tab: Uuid) -> Result<(Vec<StripTab>, StripTab)> {
        let current = self.tabs[self.tab_index(tab)?].clone();
        Ok((self.tabs.iter().filter(|t| t.id != tab).cloned().collect(), current))
    }

    /// Tabs hidden because their group is collapsed.
    pub fn hidden(&self, tab: &StripTab) -> bool {
        tab.group.and_then(|g| self.group(g)).is_some_and(|g| g.collapsed)
    }

    /// Checks sizes, drops groups that lost all their tabs, clears references to missing
    /// groups and makes every group one contiguous run (kept where its first tab is).
    pub fn normalized(&self) -> Result<TabStrip> {
        if self.tabs.len() > MAX_STRIP_TABS {
            return Err(CoreError::Invalid(format!("a window holds at most {MAX_STRIP_TABS} tabs")));
        }
        let known = |g: Option<Uuid>| g.filter(|id| self.groups.iter().any(|x| x.id == *id));
        let tabs: Vec<StripTab> = self.tabs.iter().map(|t| StripTab { group: known(t.group), ..t.clone() }).collect();
        let mut placed = std::collections::HashSet::new();
        let mut order: Vec<StripTab> = Vec::with_capacity(tabs.len());
        for t in &tabs {
            if placed.contains(&t.id) {
                continue;
            }
            let run: Vec<&StripTab> = match t.group {
                Some(g) => tabs.iter().filter(|x| x.group == Some(g)).collect(),
                None => vec![t],
            };
            for x in run {
                if placed.insert(x.id) {
                    order.push(x.clone());
                }
            }
        }
        let groups = self.groups.iter().filter(|g| order.iter().any(|t| t.group == Some(g.id))).cloned().collect();
        Ok(TabStrip { tabs: order, groups })
    }

    pub fn apply(&self, op: &StripOp) -> Result<StripChange> {
        let strip = match op {
            StripOp::NewGroup { tabs, name, color } => {
                if tabs.is_empty() {
                    return Err(CoreError::Invalid("a group needs at least one tab".into()));
                }
                let first = tabs.iter().map(|t| self.tab_index(*t)).collect::<Result<Vec<_>>>()?.into_iter().min().unwrap_or(0);
                let name = valid_group_name(name.as_deref().unwrap_or(""))?;
                let id = Uuid::new_v4();
                let color = color.unwrap_or_else(|| self.next_color());
                let members: Vec<StripTab> =
                    self.tabs.iter().filter(|t| tabs.contains(&t.id)).map(|t| StripTab { group: Some(id), ..t.clone() }).collect();
                let mut rest: Vec<StripTab> = self.tabs.iter().filter(|t| !tabs.contains(&t.id)).cloned().collect();
                let at = self.tabs[..first].iter().filter(|t| !tabs.contains(&t.id)).count();
                // A tab inside another group's run would split it; join at the run's end instead.
                let at = match (at.checked_sub(1).and_then(|i| rest.get(i)).and_then(|t| t.group), rest.get(at).and_then(|t| t.group)) {
                    (Some(b), Some(a)) if a == b => rest.iter().rposition(|t| t.group == Some(a)).map_or(at, |i| i + 1),
                    _ => at,
                };
                rest.splice(at..at, members);
                let groups = self.groups.iter().cloned().chain([TabGroup { id, name, color, collapsed: false, folder: None }]).collect();
                TabStrip { tabs: rest, groups }
            }
            StripOp::Rename { group, name } => {
                let name = valid_group_name(name)?;
                self.with_group(*group, |g| TabGroup { name: name.clone(), ..g.clone() })?
            }
            StripOp::Recolor { group, color } => self.with_group(*group, |g| TabGroup { color: *color, ..g.clone() })?,
            StripOp::SetCollapsed { group, collapsed } => self.with_group(*group, |g| TabGroup { collapsed: *collapsed, ..g.clone() })?,
            StripOp::AddToGroup { tab, group } => {
                self.existing_group(*group)?;
                let (mut rest, current) = self.without(*tab)?;
                let at = rest.iter().rposition(|t| t.group == Some(*group)).map_or(rest.len(), |i| i + 1);
                rest.insert(at, StripTab { group: Some(*group), detached: false, ..current });
                TabStrip { tabs: rest, groups: self.groups.clone() }
            }
            StripOp::RemoveFromGroup { tab } => {
                let (mut rest, current) = self.without(*tab)?;
                let Some(group) = current.group else { return Ok(StripChange { strip: self.clone(), closed: vec![] }) };
                let detached = current.detached || in_auto_group(self, &current);
                let at = rest.iter().rposition(|t| t.group == Some(group)).map_or(rest.len(), |i| i + 1);
                rest.insert(at, StripTab { group: None, detached, ..current });
                TabStrip { tabs: rest, groups: self.groups.clone() }
            }
            StripOp::Move { tab, to } => {
                let (mut rest, current) = self.without(*tab)?;
                let to = (*to).min(rest.len());
                let before = to.checked_sub(1).and_then(|i| rest.get(i)).and_then(|t| t.group);
                let after = rest.get(to).and_then(|t| t.group);
                // Between two tabs of one group joins it; at its edge a member stays in; else no group.
                let group = if before.is_some() && before == after {
                    before
                } else if current.group.is_some() && (before == current.group || after == current.group) {
                    current.group
                } else {
                    None
                };
                let detached = current.detached || (group.is_none() && in_auto_group(self, &current));
                rest.insert(to, StripTab { group, detached, ..current });
                TabStrip { tabs: rest, groups: self.groups.clone() }
            }
            StripOp::Ungroup { group } => {
                let auto = self.existing_group(*group)?.folder.is_some();
                let tabs = self
                    .tabs
                    .iter()
                    .map(|t| if t.group == Some(*group) { StripTab { group: None, detached: t.detached || auto, ..t.clone() } } else { t.clone() })
                    .collect();
                TabStrip { tabs, groups: self.groups.iter().filter(|g| g.id != *group).cloned().collect() }
            }
            StripOp::CloseGroup { group } => {
                self.existing_group(*group)?;
                let closed = self.tabs.iter().filter(|t| t.group == Some(*group)).map(|t| t.id).collect();
                let tabs = self.tabs.iter().filter(|t| t.group != Some(*group)).cloned().collect();
                let strip = TabStrip { tabs, groups: self.groups.iter().filter(|g| g.id != *group).cloned().collect() };
                return Ok(StripChange { strip: strip.normalized()?, closed });
            }
        };
        Ok(StripChange { strip: strip.normalized()?, closed: vec![] })
    }

    /// The first colour no group uses yet, else the least used.
    fn next_color(&self) -> GroupColor {
        let used = |c: &GroupColor| self.groups.iter().filter(|g| g.color == *c).count();
        ALL_COLORS.iter().copied().min_by_key(used).unwrap_or(GroupColor::Grey)
    }

    /// Folder auto-grouping. With `enabled`, ungrouped, non-detached tabs whose connections sit
    /// in the same folder (not the library root) join that folder's group once there are
    /// `AUTO_GROUP_MIN` of them; the group is named after the folder and coloured by its
    /// inherited "Tab group colour" (else a stable colour per folder). An automatic group whose
    /// folder is gone, or that dropped below the minimum, is dissolved. Turning it off dissolves
    /// every automatic group and leaves the user's own groups alone.
    pub fn auto_grouped(&self, doc: &Document, enabled: bool) -> Result<TabStrip> {
        let base = self.normalized()?;
        if !enabled {
            let tabs = base.tabs.iter().map(|t| if in_auto_group(&base, t) { StripTab { group: None, ..t.clone() } } else { t.clone() }).collect();
            return TabStrip { tabs, groups: base.groups.iter().filter(|g| g.folder.is_none()).cloned().collect() }.normalized();
        }
        let folder_of = |t: &StripTab| t.connection.and_then(|c| doc.parent_of(c)).filter(|f| *f != doc.root.id);
        let mut members: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
        for t in &base.tabs {
            let auto = t.group.and_then(|g| base.group(g)).and_then(|g| g.folder);
            let folder = match auto {
                Some(f) => Some(f),
                None if t.group.is_none() && !t.detached => folder_of(t),
                None => None,
            };
            if let Some(f) = folder {
                members.entry(f).or_default().push(t.id);
            }
        }
        let mut strip = base;
        for (folder, tabs) in members {
            let existing = strip.groups.iter().find(|g| g.folder == Some(folder)).map(|g| g.id);
            let folder_node = doc.folder(folder).filter(|_| tabs.len() >= AUTO_GROUP_MIN);
            let Some(f) = folder_node else {
                if let Some(g) = existing {
                    // Not detached: it rejoins once the folder has enough tabs again.
                    let tabs = strip.tabs.iter().map(|t| if t.group == Some(g) { StripTab { group: None, ..t.clone() } } else { t.clone() }).collect();
                    strip = TabStrip { tabs, groups: strip.groups.iter().filter(|x| x.id != g).cloned().collect() };
                }
                continue;
            };
            strip = match existing {
                // The folder's colour and name are where a group starts: a recolour or rename
                // by the user must survive the next regroup.
                Some(g) => {
                    let mut s = strip;
                    for t in &tabs {
                        if s.tabs.iter().any(|x| x.id == *t && x.group.is_none()) {
                            s = s.apply(&StripOp::AddToGroup { tab: *t, group: g })?.strip;
                        }
                    }
                    s
                }
                None => {
                    let name: String = f.name.chars().take(MAX_GROUP_NAME).collect();
                    let color = folder_color(doc, folder);
                    let s = strip.apply(&StripOp::NewGroup { tabs: tabs.clone(), name: Some(name), color: Some(color) })?.strip;
                    let id = s.tabs.iter().find(|t| t.id == tabs[0]).and_then(|t| t.group).ok_or_else(|| CoreError::Invalid("group lost its tabs".into()))?;
                    s.with_group(id, |x| TabGroup { folder: Some(folder), ..x.clone() })?
                }
            };
        }
        strip.normalized()
    }
}

/// A folder's effective "Tab group colour" (own or inherited), else its stable default.
pub fn folder_color(doc: &Document, folder: Uuid) -> GroupColor {
    crate::properties::folder_values(doc, folder)
        .ok()
        .and_then(|vs| vs.into_iter().find(|v| v.key == TAB_GROUP_COLOR_KEY))
        .and_then(|v| v.effective)
        .and_then(|c| GroupColor::parse(&c))
        .unwrap_or_else(|| GroupColor::for_id(folder))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(n: usize) -> TabStrip {
        TabStrip { tabs: (0..n).map(|_| StripTab { id: Uuid::new_v4(), connection: None, group: None, detached: false }).collect(), groups: vec![] }
    }

    #[test]
    fn new_group_is_contiguous_where_the_first_tab_was() {
        let s = strip(5);
        let (a, c, e) = (s.tabs[1].id, s.tabs[3].id, s.tabs[4].id);
        let out = s.apply(&StripOp::NewGroup { tabs: vec![c, a, e], name: Some(" Web ".into()), color: None }).unwrap().strip;
        let ids: Vec<Uuid> = out.tabs.iter().map(|t| t.id).collect();
        assert_eq!(ids, vec![s.tabs[0].id, a, c, e, s.tabs[2].id]);
        assert_eq!(out.groups[0].name, "Web");
        assert_eq!(out.groups[0].color, GroupColor::Grey, "first unused colour");
        assert!(s.groups.is_empty(), "input untouched");
    }

    #[test]
    fn bad_ops_are_refused() {
        let s = strip(2);
        assert!(s.apply(&StripOp::NewGroup { tabs: vec![], name: None, color: None }).is_err());
        assert!(s.apply(&StripOp::NewGroup { tabs: vec![Uuid::new_v4()], name: None, color: None }).is_err());
        assert!(s.apply(&StripOp::NewGroup { tabs: vec![s.tabs[0].id], name: Some("x".repeat(MAX_GROUP_NAME + 1)), color: None }).is_err());
        assert!(s.apply(&StripOp::Rename { group: Uuid::new_v4(), name: "x".into() }).is_err());
        assert!(strip(MAX_STRIP_TABS + 1).normalized().is_err());
    }

    #[test]
    fn colour_ids_round_trip() {
        for (id, _) in GROUP_COLORS {
            let c = GroupColor::parse(id).unwrap();
            assert_eq!(serde_json::to_value(c).unwrap(), *id);
        }
        assert_eq!(GroupColor::parse("orange"), None);
    }
}
