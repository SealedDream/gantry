//! Unified search across connection names, hosts, tags, notes, folder paths and protocol.
use crate::model::{Document, ResolvedConnection};

/// Every whitespace-separated term must match somewhere (case-insensitive AND search).
/// Rows are matched on their raw fields; only matches are cloned and resolved (H06).
pub fn search(doc: &Document, query: &str) -> Vec<ResolvedConnection> {
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    let mut hay = String::new();
    doc.resolve_where(|c, path| {
        use std::fmt::Write;
        hay.clear();
        // Same text as before: name host tags notes path protocol (terms never contain spaces).
        let _ = write!(hay, "{} {} {} {} {} {:?}", c.name, c.host, c.tags.join(" "), c.notes, path.join("/"), c.protocol);
        let lower = hay.to_lowercase();
        terms.iter().all(|t| lower.contains(t.as_str()))
    })
}
