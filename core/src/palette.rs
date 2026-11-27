//! Command palette ranking shared by both frontends. A frontend lists what it can do right now
//! (commands, selection actions, workspaces, open tabs, connections, settings) and the core
//! filters and orders them for a query, so both platforms rank the same way.
//!
//! Every word of the query must match: as a substring of the title, detail or keywords, or (two
//! letters or more) as the initials of the title (`qc` → Quick Connect). Order: how the first word
//! meets the title (prefix, then word start or initials, then inside the title, then elsewhere),
//! then how many words appear in the title, then the entry kind, then the title.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryKind {
    Command,
    Action,
    Workspace,
    Tab,
    Connection,
    Setting,
}

impl EntryKind {
    pub fn parse(s: &str) -> Option<EntryKind> {
        Some(match s {
            "command" => EntryKind::Command,
            "action" => EntryKind::Action,
            "workspace" => EntryKind::Workspace,
            "tab" => EntryKind::Tab,
            "connection" => EntryKind::Connection,
            "setting" => EntryKind::Setting,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    pub title: String,
    /// Right-hand text (shortcut, section, host); searched but ranked below the title.
    pub detail: String,
    pub keywords: String,
}

/// A library connection as a palette entry, with the id to connect. Ported from the macOS palette:
/// title the name, detail the host, keywords the folder path and the protocol label; tags are
/// added so a tag finds its hosts in the palette as it does in the library search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryEntry {
    pub id: String,
    pub protocol: String,
    pub entry: Entry,
}

/// Every connection in `doc`, in library order.
pub fn library_entries(doc: &crate::model::Document) -> Vec<LibraryEntry> {
    doc.connections()
        .into_iter()
        .map(|r| {
            let c = r.connection;
            let label = crate::icons::for_protocol(c.protocol).label;
            let keywords = r.path.iter().chain(std::iter::once(&label.to_string())).chain(c.tags.iter()).cloned().collect::<Vec<_>>().join(" ");
            let protocol = c.protocol.as_str().to_string();
            LibraryEntry { id: c.id.to_string(), protocol, entry: Entry { kind: EntryKind::Connection, title: c.name, detail: c.host, keywords } }
        })
        .collect()
}

/// An entry prepared for repeated queries (lower-cased once).
struct Indexed {
    kind: EntryKind,
    title: String,
    words: Vec<String>,
    initials: String,
    haystack: String,
}

impl Indexed {
    fn new(e: &Entry) -> Indexed {
        let title = e.title.to_lowercase();
        let words: Vec<String> = title.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_string).collect();
        let initials = words.iter().filter_map(|w| w.chars().next()).collect();
        let haystack = format!("{title} {} {}", e.detail.to_lowercase(), e.keywords.to_lowercase());
        Indexed { kind: e.kind, title, words, initials, haystack }
    }

    fn by_initials(&self, term: &str) -> bool {
        term.chars().count() >= 2 && self.initials.starts_with(term)
    }

    fn matches(&self, term: &str) -> bool {
        self.haystack.contains(term) || self.by_initials(term)
    }

    /// 0 title prefix, 1 word start or initials, 2 inside the title, 3 elsewhere.
    fn score(&self, first: &str) -> u8 {
        if self.title.starts_with(first) {
            0
        } else if self.words.iter().any(|w| w.starts_with(first)) || self.by_initials(first) {
            1
        } else if self.title.contains(first) {
            2
        } else {
            3
        }
    }
}

/// The palette's entries for one opening; `rank` runs per keystroke.
pub struct Index {
    entries: Vec<Indexed>,
}

impl Index {
    pub fn new(entries: &[Entry]) -> Index {
        Index { entries: entries.iter().map(Indexed::new).collect() }
    }

    /// Indices of the entries to show for `query`, best first, at most `limit`. An empty query
    /// lists commands and selection actions in the order given.
    pub fn rank(&self, query: &str, limit: usize) -> Vec<usize> {
        let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        let Some(first) = terms.first() else {
            return self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| matches!(e.kind, EntryKind::Command | EntryKind::Action))
                .map(|(i, _)| i)
                .take(limit)
                .collect();
        };
        let mut hits: Vec<(u8, usize, EntryKind, &str, usize)> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| terms.iter().all(|t| e.matches(t)))
            .map(|(i, e)| {
                let outside_title = terms.iter().filter(|t| !e.title.contains(t.as_str()) && !e.by_initials(t)).count();
                (e.score(first), outside_title, e.kind, e.title.as_str(), i)
            })
            .collect();
        hits.sort();
        hits.into_iter().take(limit).map(|h| h.4).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use EntryKind::*;

    fn e(kind: EntryKind, title: &str, detail: &str, keywords: &str) -> Entry {
        Entry { kind, title: title.into(), detail: detail.into(), keywords: keywords.into() }
    }

    fn titles(entries: &[Entry], query: &str) -> Vec<String> {
        Index::new(entries).rank(query, 100).into_iter().map(|i| entries[i].title.clone()).collect()
    }

    fn sample() -> Vec<Entry> {
        vec![
            e(Command, "Quick Connect…", "", "open host address"),
            e(Command, "Split Right", "", "pane terminal"),
            e(Command, "Split Down", "", "pane terminal"),
            e(Action, "Connect — docker-sshd", "Selection", ""),
            e(Workspace, "Open Workspace “Ops”", "2 sessions", ""),
            e(Connection, "docker-sshd", "127.0.0.1", "Lab SSH"),
            e(Connection, "prod-split-db", "10.0.0.5", "Customers SSH"),
            e(Setting, "Font size", "Settings › Terminal", "Text size of terminal sessions"),
        ]
    }

    #[test]
    fn empty_query_lists_commands_and_actions_in_given_order() {
        assert_eq!(titles(&sample(), "  "), ["Quick Connect…", "Split Right", "Split Down", "Connect — docker-sshd"]);
    }

    #[test]
    fn every_word_must_match_somewhere() {
        assert_eq!(titles(&sample(), "split pane"), ["Split Down", "Split Right"]);
        assert!(titles(&sample(), "split nothing").is_empty());
        assert_eq!(titles(&sample(), "127.0"), ["docker-sshd"], "detail is searched");
        assert_eq!(titles(&sample(), "customers"), ["prod-split-db"], "keywords are searched");
    }

    #[test]
    fn title_prefix_beats_word_start_beats_inside_beats_elsewhere() {
        let entries = vec![
            e(Connection, "lab-terminal-01", "", ""),
            e(Setting, "Font size", "", "terminal text"),
            e(Command, "New Local Shell", "", "terminal"),
            e(Command, "Terminal Theme", "", ""),
            e(Connection, "myterminalhost", "", ""),
        ];
        assert_eq!(titles(&entries, "term"), ["Terminal Theme", "lab-terminal-01", "myterminalhost", "New Local Shell", "Font size"]);
    }

    #[test]
    fn initials_match_and_rank_as_a_word_start() {
        assert_eq!(titles(&sample(), "qc"), ["Quick Connect…"]);
        assert_eq!(titles(&sample(), "sr"), ["Split Right"]);
    }

    #[test]
    fn more_words_in_the_title_rank_higher_then_kind_then_title() {
        let entries = vec![
            e(Connection, "Split box", "", "right"),
            e(Command, "Split Right", "", ""),
        ];
        assert_eq!(titles(&entries, "split right"), ["Split Right", "Split box"]);
        let same = vec![e(Connection, "docker", "", ""), e(Workspace, "docker", "", ""), e(Command, "Docker", "", "")];
        let order: Vec<EntryKind> = Index::new(&same).rank("dock", 10).into_iter().map(|i| same[i].kind).collect();
        assert_eq!(order, [Command, Workspace, Connection]);
    }

    #[test]
    fn limit_caps_the_result() {
        let many: Vec<Entry> = (0..500).map(|n| e(Connection, &format!("host-{n:03}"), "", "")).collect();
        let idx = Index::new(&many);
        assert_eq!(idx.rank("host", 60).len(), 60);
        assert_eq!(idx.rank("host", 60)[0], 0, "ties keep title order");
    }

    #[test]
    fn library_entries_carry_path_protocol_label_and_tags() {
        use crate::model::{Connection, Document, Folder, Node, Protocol, Settings};
        let mut doc = Document::new("t");
        let mut c = Connection::new("db-01", Protocol::Ssh, "10.0.0.5");
        c.tags = vec!["postgres".into()];
        let id = c.id.to_string();
        let sub = Folder { id: uuid::Uuid::new_v4(), name: "Customers".into(), color: None, defaults: Settings::default(), children: vec![Node::Connection(c)], dynamic_task_id: None, extra: Default::default() };
        doc.root.children.push(Node::Folder(sub));
        doc.root.children.push(Node::Connection(Connection::new("lab", Protocol::Rdp, "lab.local")));
        let lib = library_entries(&doc);
        assert_eq!(lib.len(), 2);
        assert_eq!(lib[0].id, id);
        assert_eq!(lib[0].protocol, "ssh");
        assert_eq!((lib[0].entry.title.as_str(), lib[0].entry.detail.as_str()), ("db-01", "10.0.0.5"));
        let entries: Vec<Entry> = lib.iter().map(|l| l.entry.clone()).collect();
        assert_eq!(titles(&entries, "customers"), ["db-01"], "folder path");
        assert_eq!(titles(&entries, "postgres"), ["db-01"], "tag");
        let label = crate::icons::for_protocol(Protocol::Rdp).label.to_lowercase();
        assert_eq!(titles(&entries, label.split(' ').next().unwrap()), ["lab"], "protocol label");
    }

    #[test]
    fn kinds_parse_from_wire_names() {
        assert_eq!(EntryKind::parse("connection"), Some(Connection));
        assert_eq!(EntryKind::parse("vm"), None);
    }
}
