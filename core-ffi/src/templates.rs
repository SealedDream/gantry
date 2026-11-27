//! Connection templates (B9) for the native apps: list, Save as Template…, New from Template…,
//! edit and delete. Templates live outside the tree, so none of these ever connects.
use std::collections::{BTreeMap, HashMap};

use bastion_core::templates::Template;

use crate::{parse_id, FfiResult, Library};

#[derive(uniffi::Record, Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateView {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: Option<String>,
    pub username: Option<String>,
    pub notes: String,
    /// Tokens "New from Template…" asks for, once each, in order.
    pub tokens: Vec<String>,
}

fn view(t: &Template) -> TemplateView {
    let c = &t.connection;
    TemplateView {
        id: c.id.to_string(),
        name: c.name.clone(),
        protocol: c.protocol_name().to_string(),
        host: c.host.clone(),
        port: t.port.clone(),
        username: c.settings.username.clone(),
        notes: c.notes.clone(),
        tokens: t.tokens().unwrap_or_default(),
    }
}

#[uniffi::export]
impl Library {
    /// Every template, in the order saved.
    pub fn templates(&self) -> Vec<TemplateView> {
        self.lock().templates().iter().map(view).collect()
    }

    /// "Save as Template…": copy connection `connection_id` (credential reference only).
    pub fn save_as_template(&self, connection_id: String, name: String) -> FfiResult<String> {
        let id = parse_id(&connection_id)?;
        self.with_doc(|d| d.save_as_template(id, &name)).map(|u| u.to_string())
    }

    /// "New from Template…": the new connection's id, under `parent` (root when `None`).
    pub fn new_from_template(&self, template_id: String, values: HashMap<String, String>, parent: Option<String>) -> FfiResult<String> {
        let id = parse_id(&template_id)?;
        let parent = parent.as_deref().map(parse_id).transpose()?;
        let values: BTreeMap<String, String> = values.into_iter().collect();
        self.with_doc(|d| d.instantiate_template(id, &values, parent)).map(|u| u.to_string())
    }

    /// Edit a template's token fields. Checked like a save; on error nothing changes.
    pub fn update_template(&self, id: String, name: String, host: String, port: Option<String>, username: Option<String>, notes: String) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| {
            let mut t = d.template(id)?.clone();
            t.connection.name = name;
            t.connection.host = host;
            t.port = port.filter(|p| !p.trim().is_empty());
            t.connection.settings.username = username.filter(|u| !u.is_empty());
            t.connection.notes = notes;
            d.update_template(t)
        })
    }

    pub fn delete_template(&self, id: String) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| d.delete_template(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_core::model::{Connection, Node, Protocol};

    fn lib_with_connection() -> (Library, String) {
        let dir = tempfile::tempdir().unwrap();
        let lib = Library::open(dir.path().join("lib.json").to_string_lossy().into_owned()).unwrap();
        let c = Connection::new("srv", Protocol::Ssh, "srv1");
        let id = c.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
        (lib, id)
    }

    #[test]
    fn save_edit_instantiate_delete() {
        let (lib, cid) = lib_with_connection();
        let tid = lib.save_as_template(cid, "T".into()).unwrap();
        lib.update_template(tid.clone(), "$Name$".into(), "$Host$".into(), Some("22".into()), None, String::new()).unwrap();
        assert_eq!(lib.templates()[0].tokens, vec!["Name", "Host"]);
        let values = HashMap::from([("Name".to_string(), "web1".to_string()), ("Host".to_string(), "10.0.0.9".to_string())]);
        let new_id = lib.new_from_template(tid.clone(), values, None).unwrap();
        assert!(lib.notes(new_id).is_ok(), "the new connection is in the tree");
        assert!(lib.notes(tid.clone()).is_err(), "a template is never in the tree");
        lib.delete_template(tid).unwrap();
        assert!(lib.templates().is_empty());
    }

    #[test]
    fn bad_edit_changes_nothing() {
        let (lib, cid) = lib_with_connection();
        let tid = lib.save_as_template(cid, "T".into()).unwrap();
        assert!(lib.update_template(tid, "T".into(), "bad host".into(), None, None, String::new()).is_err());
        assert_eq!(lib.templates()[0].host, "srv1");
    }
}
