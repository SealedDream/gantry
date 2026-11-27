//! Bulk edit (packet B3-BULK-EDIT): read and change one property on several selected connections.
//!
//! `properties_for_selection` lists the properties every selected connection has, with the shared
//! own value or a "mixed" mark. `apply_to_selection` sets one of them on all of them, or on none:
//! the change runs on a copy of the document, which replaces the original only when every
//! connection accepted it.
use std::collections::HashSet;

use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::Document;
use crate::properties::{self, find_connection, schema, PropertyDef};

/// Properties that identify one connection; setting one value on many makes no sense.
const PER_CONNECTION_KEYS: &[&str] = &["name", "host"];

/// Most connections one bulk edit may change; the selection is user input.
pub const MAX_SELECTION: usize = 10_000;

/// One property shared by every selected connection.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionProperty {
    pub def: PropertyDef,
    /// The own value when every connection has the same one (`None`: all inherit).
    pub value: Option<String>,
    /// The connections' own values differ.
    pub mixed: bool,
}

fn checked_ids(ids: &[Uuid]) -> Result<Vec<Uuid>> {
    if ids.is_empty() {
        return Err(CoreError::Invalid("Select at least one connection.".into()));
    }
    if ids.len() > MAX_SELECTION {
        return Err(CoreError::Invalid(format!("Select at most {MAX_SELECTION} connections.")));
    }
    let mut seen = HashSet::new();
    Ok(ids.iter().copied().filter(|id| seen.insert(*id)).collect())
}

/// Properties every selected connection has, in the first connection's schema order.
pub fn properties_for_selection(doc: &Document, ids: &[Uuid]) -> Result<Vec<SelectionProperty>> {
    let ids = checked_ids(ids)?;
    let mut per_conn = Vec::with_capacity(ids.len());
    for id in &ids {
        let c = find_connection(&doc.root, *id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
        let values = properties::connection_values(doc, *id)?;
        per_conn.push((schema(c.protocol), values));
    }
    let (first_schema, _) = &per_conn[0];
    let shared = first_schema
        .iter()
        .filter(|d| !PER_CONNECTION_KEYS.contains(&d.key))
        .filter(|d| per_conn.iter().all(|(s, _)| s.iter().any(|o| o.key == d.key)))
        .map(|d| {
            let owns: Vec<Option<String>> = per_conn
                .iter()
                .map(|(_, vals)| vals.iter().find(|v| v.key == d.key).and_then(|v| v.own.clone()))
                .collect();
            let mixed = owns.iter().any(|o| o != &owns[0]);
            SelectionProperty { def: d.clone(), value: if mixed { None } else { owns[0].clone() }, mixed }
        })
        .collect();
    Ok(shared)
}

/// Set `key` to `value` (`None` or blank: inherit) on every selected connection, or on none.
/// Returns how many connections were changed.
pub fn apply_to_selection(doc: &mut Document, ids: &[Uuid], key: &str, value: Option<&str>) -> Result<usize> {
    if PER_CONNECTION_KEYS.contains(&key) {
        return Err(CoreError::Invalid(format!("`{key}` belongs to one connection; edit it on its own.")));
    }
    let shared = properties_for_selection(doc, ids)?;
    if !shared.iter().any(|p| p.def.key == key) {
        return Err(CoreError::Invalid(format!("Not every selected connection has the property `{key}`.")));
    }
    let ids = checked_ids(ids)?;
    let mut next = doc.clone();
    for id in &ids {
        properties::set_value(&mut next, *id, key, value).map_err(|e| {
            let name = find_connection(&doc.root, *id).map(|c| c.name.clone()).unwrap_or_default();
            CoreError::Invalid(format!("{name}: {e}"))
        })?;
    }
    *doc = next;
    Ok(ids.len())
}

/// Add and remove tags on every selected connection, or on none; other tags stay. Returns how
/// many connections changed.
pub fn edit_tags(doc: &mut Document, ids: &[Uuid], add: &[String], remove: &[String]) -> Result<usize> {
    let ids = checked_ids(ids)?;
    let add = properties::normalize_tags(add.iter().map(String::as_str));
    let remove = properties::normalize_tags(remove.iter().map(String::as_str));
    let mut next = doc.clone();
    let mut changed = 0;
    for id in &ids {
        let c = find_connection(&doc.root, *id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
        let mut tags: Vec<String> = c.tags.iter().filter(|t| !remove.contains(&t.to_lowercase())).cloned().collect();
        tags.extend(add.iter().cloned());
        let tags = properties::normalize_tags(tags.iter().map(String::as_str));
        if tags == c.tags {
            continue;
        }
        properties::set_value(&mut next, *id, "tags", Some(&tags.join(","))).map_err(|e| CoreError::Invalid(format!("{}: {e}", c.name)))?;
        changed += 1;
    }
    *doc = next;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Connection, Node, Protocol};

    fn doc_with(conns: &[(&str, Protocol)]) -> (Document, Vec<Uuid>) {
        let mut doc = Document::new("t");
        let mut ids = vec![];
        for (name, p) in conns {
            let c = Connection::new(*name, *p, "10.0.0.1");
            ids.push(c.id);
            doc.root.children.push(Node::Connection(c));
        }
        (doc, ids)
    }

    fn prop<'a>(ps: &'a [SelectionProperty], key: &str) -> Option<&'a SelectionProperty> {
        ps.iter().find(|p| p.def.key == key)
    }

    #[test]
    fn lists_only_properties_every_connection_has() {
        let (doc, ids) = doc_with(&[("a", Protocol::Ssh), ("b", Protocol::Rdp)]);
        let ps = properties_for_selection(&doc, &ids).unwrap();
        assert!(prop(&ps, "port").is_some());
        assert!(prop(&ps, "terminal_font_size").is_none(), "SSH-only property must not be offered for RDP");
        assert!(prop(&ps, "name").is_none() && prop(&ps, "host").is_none());
    }

    #[test]
    fn same_values_show_the_value_and_different_values_show_mixed() {
        let (mut doc, ids) = doc_with(&[("a", Protocol::Ssh), ("b", Protocol::Ssh)]);
        properties::set_value(&mut doc, ids[0], "port", Some("2222")).unwrap();
        properties::set_value(&mut doc, ids[1], "port", Some("2222")).unwrap();
        properties::set_value(&mut doc, ids[0], "terminal_font_size", Some("14")).unwrap();
        let ps = properties_for_selection(&doc, &ids).unwrap();
        let port = prop(&ps, "port").unwrap();
        assert_eq!((port.value.as_deref(), port.mixed), (Some("2222"), false));
        let size = prop(&ps, "terminal_font_size").unwrap();
        assert_eq!((size.value.as_deref(), size.mixed), (None, true));
    }

    #[test]
    fn apply_changes_every_selected_connection() {
        let (mut doc, ids) = doc_with(&[("a", Protocol::Ssh), ("b", Protocol::Ssh), ("c", Protocol::Ssh)]);
        let n = apply_to_selection(&mut doc, &ids[..2], "terminal_font_size", Some("16")).unwrap();
        assert_eq!(n, 2);
        let ps = properties_for_selection(&doc, &ids[..2]).unwrap();
        assert_eq!(prop(&ps, "terminal_font_size").unwrap().value.as_deref(), Some("16"));
        let third = properties::connection_values(&doc, ids[2]).unwrap();
        assert_eq!(third.iter().find(|v| v.key == "terminal_font_size").unwrap().own, None);
    }

    #[test]
    fn blank_value_resets_to_inherited() {
        let (mut doc, ids) = doc_with(&[("a", Protocol::Ssh), ("b", Protocol::Ssh)]);
        apply_to_selection(&mut doc, &ids, "port", Some("2200")).unwrap();
        apply_to_selection(&mut doc, &ids, "port", Some("  ")).unwrap();
        let ps = properties_for_selection(&doc, &ids).unwrap();
        assert_eq!(prop(&ps, "port").unwrap().value, None);
    }

    #[test]
    fn invalid_value_changes_nothing() {
        let (mut doc, ids) = doc_with(&[("a", Protocol::Ssh), ("b", Protocol::Ssh)]);
        let before = doc.clone();
        assert!(apply_to_selection(&mut doc, &ids, "terminal_font_size", Some("99")).is_err());
        assert_eq!(doc, before);
    }

    #[test]
    fn refuses_identity_keys_unshared_keys_unknown_ids_and_empty_selection() {
        let (mut doc, ids) = doc_with(&[("a", Protocol::Ssh), ("b", Protocol::Rdp)]);
        assert!(apply_to_selection(&mut doc, &ids, "host", Some("x")).is_err());
        assert!(apply_to_selection(&mut doc, &ids, "terminal_font_size", Some("12")).is_err());
        assert!(apply_to_selection(&mut doc, &[Uuid::new_v4()], "port", Some("22")).is_err());
        assert!(apply_to_selection(&mut doc, &[], "port", Some("22")).is_err());
        assert!(properties_for_selection(&doc, &[]).is_err());
    }

    #[test]
    fn duplicate_ids_count_once() {
        let (mut doc, ids) = doc_with(&[("a", Protocol::Ssh)]);
        assert_eq!(apply_to_selection(&mut doc, &[ids[0], ids[0]], "port", Some("2022")).unwrap(), 1);
    }

    #[test]
    fn edit_tags_adds_and_removes_without_touching_others() {
        let (mut doc, ids) = doc_with(&[("a", Protocol::Ssh), ("b", Protocol::Ssh)]);
        properties::set_value(&mut doc, ids[0], "tags", Some("Prod, web,prod")).unwrap();
        assert_eq!(find_connection(&doc.root, ids[0]).unwrap().tags, vec!["prod", "web"]);
        let n = edit_tags(&mut doc, &ids, &["DB".into()], &["Web".into()]).unwrap();
        assert_eq!(n, 2);
        assert_eq!(find_connection(&doc.root, ids[0]).unwrap().tags, vec!["prod", "db"]);
        assert_eq!(find_connection(&doc.root, ids[1]).unwrap().tags, vec!["db"]);
        assert_eq!(edit_tags(&mut doc, &ids, &["db".into()], &[]).unwrap(), 0);
        assert!(edit_tags(&mut doc, &[], &["x".into()], &[]).is_err());
    }
}
