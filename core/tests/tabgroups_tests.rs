//! Tab groups: operations, folder auto-grouping, the inherited "Tab group colour", 100+ tab
//! strips within the latency budget, and groups restored from `workspaces.json` after a restart.
use std::time::{Duration, Instant};

use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use bastion_core::properties;
use bastion_core::tabgroups::{folder_color, GroupColor, StripOp, StripTab, TabGroup, TabStrip, MAX_STRIP_TABS};
use bastion_core::workspace::{TabMode, WorkspaceStore, WorkspaceTab};
use uuid::Uuid;

/// One frame at 60 Hz: what a strip change may take, even on a 200-tab strip in a debug build.
const BUDGET: Duration = Duration::from_millis(16);

fn tab(connection: Option<Uuid>) -> StripTab {
    StripTab { id: Uuid::new_v4(), connection, group: None, detached: false }
}

fn plain(n: usize) -> TabStrip {
    TabStrip { tabs: (0..n).map(|_| tab(None)).collect(), groups: vec![] }
}

fn folder(name: &str) -> Folder {
    Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Settings::default(), children: vec![], dynamic_task_id: None, extra: Default::default() }
}

/// Library > Customers (Tab group colour red) > Acme > a1, a2, a3; Beta > b1; root r1.
struct Fixture {
    doc: Document,
    customers: Uuid,
    acme: Uuid,
    beta: Uuid,
    acme_conns: Vec<Uuid>,
    b1: Uuid,
    r1: Uuid,
}

fn fixture() -> Fixture {
    let mut doc = Document::new("t");
    let customers = folder("Customers");
    let (acme, beta) = (folder("Acme"), folder("Beta"));
    let (cid, aid, bid) = (customers.id, acme.id, beta.id);
    doc.insert(None, Node::Folder(customers)).unwrap();
    doc.insert(Some(cid), Node::Folder(acme)).unwrap();
    doc.insert(None, Node::Folder(beta)).unwrap();
    let acme_conns: Vec<Uuid> = (1..=3)
        .map(|i| {
            let c = Connection::new(format!("a{i}"), Protocol::Ssh, "h");
            let id = c.id;
            doc.insert(Some(aid), Node::Connection(c)).unwrap();
            id
        })
        .collect();
    let b1 = Connection::new("b1", Protocol::Ssh, "h");
    let r1 = Connection::new("r1", Protocol::Ssh, "h");
    let (b1id, r1id) = (b1.id, r1.id);
    doc.insert(Some(bid), Node::Connection(b1)).unwrap();
    doc.insert(None, Node::Connection(r1)).unwrap();
    properties::set_value(&mut doc, cid, "tab_group_color", Some("red")).unwrap();
    Fixture { doc, customers: cid, acme: aid, beta: bid, acme_conns, b1: b1id, r1: r1id }
}

fn group_of(s: &TabStrip, tab: Uuid) -> Option<&TabGroup> {
    s.tabs.iter().find(|t| t.id == tab).and_then(|t| t.group).and_then(|g| s.group(g))
}

#[test]
fn two_tabs_from_one_folder_form_a_group_named_and_coloured_after_it() {
    let f = fixture();
    let one = TabStrip { tabs: vec![tab(Some(f.acme_conns[0])), tab(Some(f.r1)), tab(Some(f.b1))], groups: vec![] };
    let s = one.auto_grouped(&f.doc, true).unwrap();
    assert!(s.groups.is_empty(), "one tab per folder, root tabs never group");

    let tabs: Vec<StripTab> = one.tabs.iter().cloned().chain([tab(Some(f.acme_conns[1]))]).collect();
    let s = TabStrip { tabs, groups: vec![] }.auto_grouped(&f.doc, true).unwrap();
    assert_eq!(s.groups.len(), 1);
    let g = &s.groups[0];
    assert_eq!((g.name.as_str(), g.color, g.folder), ("Acme", GroupColor::Red, Some(f.acme)), "colour inherited from Customers");
    let order: Vec<Option<Uuid>> = s.tabs.iter().map(|t| t.connection).collect();
    assert_eq!(order, vec![Some(f.acme_conns[0]), Some(f.acme_conns[1]), Some(f.r1), Some(f.b1)], "the run sits where its first tab was");
    assert_eq!(s.auto_grouped(&f.doc, true).unwrap(), s, "idempotent");
}

#[test]
fn own_colour_beats_inherited_and_unset_is_stable_per_folder() {
    let mut f = fixture();
    properties::set_value(&mut f.doc, f.acme, "tab_group_color", Some("green")).unwrap();
    assert_eq!(folder_color(&f.doc, f.acme), GroupColor::Green);
    assert_eq!(folder_color(&f.doc, f.beta), GroupColor::for_id(f.beta));
    assert!(properties::set_value(&mut f.doc, f.customers, "tab_group_color", Some("orange")).is_err());
    let values = properties::folder_values(&f.doc, f.acme).unwrap();
    let v = values.iter().find(|v| v.key == "tab_group_color").unwrap();
    assert_eq!(v.effective.as_deref(), Some("green"));
}

#[test]
fn new_tabs_join_the_existing_folder_group_and_a_dragged_out_tab_stays_out() {
    let f = fixture();
    let s = TabStrip { tabs: vec![tab(Some(f.acme_conns[0])), tab(Some(f.r1)), tab(Some(f.acme_conns[1]))], groups: vec![] }
        .auto_grouped(&f.doc, true)
        .unwrap();
    let gid = s.groups[0].id;
    let third = tab(Some(f.acme_conns[2]));
    let tabs: Vec<StripTab> = s.tabs.iter().cloned().chain([third.clone()]).collect();
    let s = TabStrip { tabs, groups: s.groups.clone() }.auto_grouped(&f.doc, true).unwrap();
    assert_eq!(group_of(&s, third.id).map(|g| g.id), Some(gid));
    assert_eq!(s.tabs[2].id, third.id, "joined at the end of the run");

    let out = s.apply(&StripOp::RemoveFromGroup { tab: third.id }).unwrap().strip;
    let again = out.auto_grouped(&f.doc, true).unwrap();
    assert!(group_of(&again, third.id).is_none(), "detached tabs are not pulled back");
    assert_eq!(again.tabs.iter().filter(|t| t.group == Some(gid)).count(), 2);
}

#[test]
fn turning_auto_grouping_off_keeps_the_users_own_groups() {
    let f = fixture();
    let s = TabStrip { tabs: vec![tab(Some(f.acme_conns[0])), tab(Some(f.acme_conns[1])), tab(Some(f.r1)), tab(None)], groups: vec![] }
        .auto_grouped(&f.doc, true)
        .unwrap();
    let mine = s.apply(&StripOp::NewGroup { tabs: vec![s.tabs[2].id, s.tabs[3].id], name: Some("Mine".into()), color: Some(GroupColor::Blue) }).unwrap().strip;
    let off = mine.auto_grouped(&f.doc, false).unwrap();
    assert_eq!(off.groups.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(), ["Mine"]);
}

#[test]
fn a_folder_group_dissolves_below_two_tabs_or_when_the_folder_is_deleted() {
    let mut f = fixture();
    let s = TabStrip { tabs: vec![tab(Some(f.acme_conns[0])), tab(Some(f.acme_conns[1]))], groups: vec![] }.auto_grouped(&f.doc, true).unwrap();
    let one = TabStrip { tabs: vec![s.tabs[0].clone()], groups: s.groups.clone() }.auto_grouped(&f.doc, true).unwrap();
    assert!(one.groups.is_empty() && one.tabs[0].group.is_none());
    f.doc.remove(f.acme).unwrap();
    assert!(s.auto_grouped(&f.doc, true).unwrap().groups.is_empty());
}

#[test]
fn rename_recolour_collapse_and_close_group() {
    let s = plain(6);
    let ids: Vec<Uuid> = s.tabs.iter().map(|t| t.id).collect();
    let s = s.apply(&StripOp::NewGroup { tabs: vec![ids[1], ids[2]], name: None, color: None }).unwrap().strip;
    let g = s.groups[0].id;
    let s = s.apply(&StripOp::Rename { group: g, name: "  Ops ".into() }).unwrap().strip;
    let s = s.apply(&StripOp::Recolor { group: g, color: GroupColor::Purple }).unwrap().strip;
    let s = s.apply(&StripOp::SetCollapsed { group: g, collapsed: true }).unwrap().strip;
    assert_eq!((s.groups[0].name.as_str(), s.groups[0].color, s.groups[0].collapsed), ("Ops", GroupColor::Purple, true));
    assert_eq!(s.tabs.iter().filter(|t| s.hidden(t)).count(), 2);
    let change = s.apply(&StripOp::CloseGroup { group: g }).unwrap();
    assert_eq!(change.closed, vec![ids[1], ids[2]]);
    assert_eq!(change.strip.tabs.len(), 4);
    assert!(change.strip.groups.is_empty());
}

#[test]
fn drag_in_out_and_move_keep_each_group_contiguous() {
    let s = plain(6);
    let ids: Vec<Uuid> = s.tabs.iter().map(|t| t.id).collect();
    let s = s.apply(&StripOp::NewGroup { tabs: vec![ids[0], ids[1]], name: Some("A".into()), color: None }).unwrap().strip;
    let g = s.groups[0].id;
    let s = s.apply(&StripOp::AddToGroup { tab: ids[5], group: g }).unwrap().strip;
    assert_eq!(s.tabs.iter().map(|t| t.id).take(3).collect::<Vec<_>>(), vec![ids[0], ids[1], ids[5]]);
    // Dropped between two members: joins.
    let s = s.apply(&StripOp::Move { tab: ids[3], to: 1 }).unwrap().strip;
    assert_eq!((s.tabs[1].id, s.tabs[1].group), (ids[3], Some(g)));
    // Dropped past the run: leaves.
    let s = s.apply(&StripOp::Move { tab: ids[0], to: 5 }).unwrap().strip;
    assert_eq!(s.tabs.last().unwrap().group, None);
    let s = s.apply(&StripOp::RemoveFromGroup { tab: ids[3] }).unwrap().strip;
    let runs: Vec<Option<Uuid>> = s.tabs.iter().map(|t| t.group).collect();
    let first = runs.iter().position(|x| *x == Some(g)).unwrap();
    let last = runs.iter().rposition(|x| *x == Some(g)).unwrap();
    assert!(runs[first..=last].iter().all(|x| *x == Some(g)), "contiguous: {runs:?}");
    let s = s.apply(&StripOp::Ungroup { group: g }).unwrap().strip;
    assert!(s.groups.is_empty() && s.tabs.iter().all(|t| t.group.is_none()));
}

#[test]
fn ops_parse_from_the_json_the_apps_send() {
    let op: StripOp = serde_json::from_str(r#"{"op":"setCollapsed","group":"00000000-0000-0000-0000-000000000001","collapsed":true}"#).unwrap();
    assert!(matches!(op, StripOp::SetCollapsed { collapsed: true, .. }));
    let op: StripOp = serde_json::from_str(r#"{"op":"newGroup","tabs":[],"name":null,"color":"cyan"}"#).unwrap();
    assert!(matches!(op, StripOp::NewGroup { color: Some(GroupColor::Cyan), .. }));
}

#[test]
fn hundreds_of_tabs_stay_within_the_latency_budget() {
    let mut f = fixture();
    // 150 connections over 30 folders, plus 50 local shells: 200 tabs.
    let mut tabs = Vec::new();
    for i in 0..30 {
        let fo = folder(&format!("F{i}"));
        let fid = fo.id;
        f.doc.insert(None, Node::Folder(fo)).unwrap();
        for j in 0..5 {
            let c = Connection::new(format!("c{i}-{j}"), Protocol::Ssh, "h");
            tabs.push(tab(Some(c.id)));
            f.doc.insert(Some(fid), Node::Connection(c)).unwrap();
        }
    }
    tabs.extend((0..50).map(|_| tab(None)));
    let strip = TabStrip { tabs, groups: vec![] };

    let t = Instant::now();
    let grouped = strip.auto_grouped(&f.doc, true).unwrap();
    assert!(t.elapsed() < BUDGET * 4, "auto-grouping 200 tabs took {:?}", t.elapsed());
    assert_eq!((grouped.groups.len(), grouped.tabs.len()), (30, 200));

    let g = grouped.groups[7].id;
    let last = grouped.tabs.last().unwrap().id;
    for op in [
        StripOp::SetCollapsed { group: g, collapsed: true },
        StripOp::Rename { group: g, name: "x".into() },
        StripOp::AddToGroup { tab: last, group: g },
        StripOp::Move { tab: last, to: 0 },
        StripOp::NewGroup { tabs: vec![last], name: None, color: None },
        StripOp::CloseGroup { group: g },
    ] {
        let t = Instant::now();
        grouped.apply(&op).unwrap();
        assert!(t.elapsed() < BUDGET, "{op:?} took {:?}", t.elapsed());
    }
    assert!(plain(MAX_STRIP_TABS).normalized().is_ok());
}

#[test]
fn groups_are_restored_with_the_workspace_after_a_restart() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspaces.json");
    let strip = TabStrip { tabs: (0..120).map(|i| tab(Some(f.acme_conns[i % 3]))).collect(), groups: vec![] }.auto_grouped(&f.doc, true).unwrap();
    let strip = strip.apply(&StripOp::SetCollapsed { group: strip.groups[0].id, collapsed: true }).unwrap().strip;
    let tabs: Vec<WorkspaceTab> =
        strip.tabs.iter().map(|t| WorkspaceTab { connection: t.connection.unwrap(), mode: TabMode::Terminal, layout: None, group: t.group }).collect();
    let saved = WorkspaceStore::open(&path).unwrap().save_grouped_layout("Big", tabs.clone(), strip.groups.clone(), 3, 1).unwrap();

    let reopened = WorkspaceStore::open(&path).unwrap();
    let w = reopened.get(&saved.id).unwrap();
    assert_eq!(w.tabs, tabs);
    assert_eq!(w.groups, strip.groups);
    assert!(w.groups[0].collapsed);

    let bad: Vec<WorkspaceTab> = tabs.iter().enumerate().map(|(i, t)| WorkspaceTab { group: if i == 0 { Some(Uuid::new_v4()) } else { t.group }, ..t.clone() }).collect();
    assert!(WorkspaceStore::open(&path).unwrap().save_grouped_layout("Bad", bad, strip.groups.clone(), 0, 1).is_err());
}

#[test]
fn a_recoloured_folder_group_keeps_its_colour_when_tabs_regroup() {
    let f = fixture();
    let strip = TabStrip { tabs: f.acme_conns[..2].iter().map(|c| tab(Some(*c))).collect(), groups: vec![] };
    let grouped = strip.auto_grouped(&f.doc, true).unwrap();
    let g = grouped.groups[0].id;
    let recoloured = grouped.apply(&StripOp::Recolor { group: g, color: GroupColor::Purple }).unwrap().strip;
    let mut more = recoloured.clone();
    more.tabs.push(tab(Some(f.acme_conns[2])));
    let again = more.auto_grouped(&f.doc, true).unwrap();
    assert_eq!(again.groups.len(), 1);
    assert_eq!(again.groups[0].color, GroupColor::Purple);
    assert_eq!(again.tabs.iter().filter(|t| t.group == Some(g)).count(), 3);
}
