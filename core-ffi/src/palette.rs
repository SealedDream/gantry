//! Command palette bridge: the frontend hands over its entries once per opening and asks for
//! the ranked indices on every keystroke.
use bastion_core::palette::{Entry, EntryKind, Index};

use crate::{FfiError, FfiResult, Library};

#[derive(uniffi::Record, Debug, Clone)]
pub struct PaletteEntryInput {
    /// `command`, `action`, `workspace`, `tab`, `connection` or `setting`.
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub keywords: String,
}

#[derive(uniffi::Object)]
pub struct PaletteIndex {
    index: Index,
}

#[uniffi::export]
impl PaletteIndex {
    #[uniffi::constructor]
    pub fn new(entries: Vec<PaletteEntryInput>) -> FfiResult<Self> {
        let entries = entries
            .into_iter()
            .map(|e| {
                let kind = EntryKind::parse(&e.kind).ok_or_else(|| FfiError::failed(format!("unknown palette entry kind `{}`", e.kind)))?;
                Ok(Entry { kind, title: e.title, detail: e.detail, keywords: e.keywords })
            })
            .collect::<FfiResult<Vec<_>>>()?;
        Ok(PaletteIndex { index: Index::new(&entries) })
    }

    /// Indices into the entries, best first, at most `limit`.
    pub fn rank(&self, query: String, limit: u32) -> Vec<u32> {
        self.index.rank(&query, limit as usize).into_iter().map(|i| i as u32).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: &str, title: &str) -> PaletteEntryInput {
        PaletteEntryInput { kind: kind.into(), title: title.into(), detail: String::new(), keywords: String::new() }
    }

    #[test]
    fn ranks_by_index_and_refuses_unknown_kinds() {
        let idx = PaletteIndex::new(vec![entry("connection", "docker-sshd"), entry("command", "Quick Connect…")]).unwrap();
        assert_eq!(idx.rank("qc".into(), 10), vec![1]);
        assert_eq!(idx.rank("".into(), 10), vec![1]);
        assert!(PaletteIndex::new(vec![entry("vm", "x")]).is_err());
    }
}

/// A library connection as a palette row (core `palette::library_entries`).
#[derive(uniffi::Record, Debug, Clone)]
pub struct PaletteConnectionView {
    pub id: String,
    pub protocol: String,
    pub title: String,
    pub detail: String,
    pub keywords: String,
}

#[uniffi::export]
impl Library {
    /// Every connection as a `connection` palette entry, in library order, so all apps search
    /// the library the same way.
    pub fn palette_connections(&self) -> FfiResult<Vec<PaletteConnectionView>> {
        self.with_doc(|d| {
            Ok(bastion_core::palette::library_entries(d)
                .into_iter()
                .map(|l| PaletteConnectionView { id: l.id, protocol: l.protocol, title: l.entry.title, detail: l.entry.detail, keywords: l.entry.keywords })
                .collect())
        })
    }
}
