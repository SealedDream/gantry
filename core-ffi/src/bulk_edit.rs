//! Bridge for bulk edit (`bastion_core::bulk_edit`, packet B3-BULK-EDIT).
use bastion_core::bulk_edit;

use crate::properties::{def_view, PropertyDefView};
use crate::{parse_id, FfiResult, Library};

/// One property every selected connection has.
#[derive(uniffi::Record)]
pub struct SelectionPropertyView {
    pub def: PropertyDefView,
    /// The shared own value; `None` when all inherit or the values differ.
    pub value: Option<String>,
    /// The connections' own values differ.
    pub mixed: bool,
}

fn parse_ids(raw: &[String]) -> FfiResult<Vec<uuid::Uuid>> {
    raw.iter().map(|s| parse_id(s)).collect()
}

#[uniffi::export]
impl Library {
    /// Properties shared by the selected connections, with their common value or a mixed mark.
    pub fn properties_for_selection(&self, ids: Vec<String>) -> FfiResult<Vec<SelectionPropertyView>> {
        let ids = parse_ids(&ids)?;
        let props = self.with_doc(|d| bulk_edit::properties_for_selection(d, &ids))?;
        Ok(props.into_iter().map(|p| SelectionPropertyView { def: def_view(p.def), value: p.value, mixed: p.mixed }).collect())
    }

    /// Set one property on every selected connection, or on none. Returns how many changed.
    pub fn apply_to_selection(&self, ids: Vec<String>, key: String, value: Option<String>) -> FfiResult<u32> {
        let ids = parse_ids(&ids)?;
        let n = self.with_doc(|d| bulk_edit::apply_to_selection(d, &ids, &key, value.as_deref()))?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Add and remove tags on every selected connection, or on none. Returns how many changed.
    pub fn edit_tags_on_selection(&self, ids: Vec<String>, add: Vec<String>, remove: Vec<String>) -> FfiResult<u32> {
        let ids = parse_ids(&ids)?;
        let n = self.with_doc(|d| bulk_edit::edit_tags(d, &ids, &add, &remove))?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }
}

#[cfg(test)]
mod tests {
    use crate::Library;

    #[test]
    fn bulk_edit_round_trip_and_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let lib = Library::open(dir.path().join("library.json").display().to_string()).unwrap();
        let add = |n: &str| lib.add_connection(None, n.into(), "ssh".into(), "10.0.0.1".into(), None, None).unwrap();
        let (a, b) = (add("a"), add("b"));
        assert_eq!(lib.apply_to_selection(vec![a.clone(), b.clone()], "port".into(), Some("2022".into())).unwrap(), 2);
        let ps = lib.properties_for_selection(vec![a.clone(), b.clone()]).unwrap();
        let port = ps.iter().find(|p| p.def.key == "port").unwrap();
        assert_eq!((port.value.as_deref(), port.mixed), (Some("2022"), false));
        assert!(lib.apply_to_selection(vec![a.clone(), "not-an-id".into()], "port".into(), None).is_err());
        assert_eq!(lib.edit_tags_on_selection(vec![a.clone(), b], vec!["Prod".into()], vec![]).unwrap(), 2);
        let tree = lib.tree();
        assert!(tree.connections.iter().all(|c| c.tags == vec!["prod".to_string()]));
        assert_eq!(lib.edit_tags_on_selection(vec![a], vec![], vec!["PROD".into()]).unwrap(), 1);
    }
}
