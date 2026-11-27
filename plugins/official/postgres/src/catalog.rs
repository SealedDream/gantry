//! The object browser: tree keys, the catalog queries behind each level, and the CREATE
//! statement of an object.
//!
//! Names come from the server and go back into catalog queries only as quoted literals
//! ([`literal`]), never pasted raw. [`ident`] quotes names in SQL the user sees (CREATE
//! statements). Both are tested with hostile names.

/// Separates the parts of a tree key. Names cannot hold it without being refused.
const SEP: char = '\u{1f}';

/// A tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Top level folders.
    Databases,
    Schemas,
    Extensions,
    Roles,
    /// A schema and its folders.
    Schema(String),
    Folder(Folder, String),
    /// `(schema, name)`
    Table(String, String),
    View(String, String),
    MatView(String, String),
    Sequence(String, String),
    /// `(schema, name, oid)`: functions are overloaded, so the oid picks one.
    Function(String, String, u32),
    /// Indexes and triggers of a table: `(schema, table)`.
    Indexes(String, String),
    Triggers(String, String),
    /// `(schema, table, name)`
    Index(String, String, String),
    Trigger(String, String, String),
    Database(String),
    Extension(String),
    Role(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Folder {
    Tables,
    Views,
    MatViews,
    Functions,
    Sequences,
}

impl Folder {
    fn tag(self) -> &'static str {
        match self {
            Folder::Tables => "tables",
            Folder::Views => "views",
            Folder::MatViews => "matviews",
            Folder::Functions => "functions",
            Folder::Sequences => "sequences",
        }
    }
    fn from_tag(t: &str) -> Option<Folder> {
        Some(match t {
            "tables" => Folder::Tables,
            "views" => Folder::Views,
            "matviews" => Folder::MatViews,
            "functions" => Folder::Functions,
            "sequences" => Folder::Sequences,
            _ => return None,
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Folder::Tables => "Tables",
            Folder::Views => "Views",
            Folder::MatViews => "Materialized views",
            Folder::Functions => "Functions",
            Folder::Sequences => "Sequences",
        }
    }
    pub const ALL: [Folder; 5] = [Folder::Tables, Folder::Views, Folder::MatViews, Folder::Functions, Folder::Sequences];
}

fn join(parts: &[&str]) -> Option<String> {
    if parts.iter().any(|p| p.contains(SEP)) {
        return None;
    }
    Some(parts.join(&SEP.to_string()))
}

impl Node {
    /// The tree key. `None` when a name holds the separator (such an object is not listed).
    pub fn key(&self) -> Option<String> {
        let oid;
        let parts: Vec<&str> = match self {
            Node::Databases => vec!["databases"],
            Node::Schemas => vec!["schemas"],
            Node::Extensions => vec!["extensions"],
            Node::Roles => vec!["roles"],
            Node::Schema(s) => vec!["schema", s],
            Node::Folder(f, s) => vec![f.tag(), s],
            Node::Table(s, n) => vec!["table", s, n],
            Node::View(s, n) => vec!["view", s, n],
            Node::MatView(s, n) => vec!["matview", s, n],
            Node::Sequence(s, n) => vec!["sequence", s, n],
            Node::Function(s, n, o) => {
                oid = o.to_string();
                vec!["function", s, n, &oid]
            }
            Node::Indexes(s, t) => vec!["indexes", s, t],
            Node::Triggers(s, t) => vec!["triggers", s, t],
            Node::Index(s, t, n) => vec!["index", s, t, n],
            Node::Trigger(s, t, n) => vec!["trigger", s, t, n],
            Node::Database(n) => vec!["database", n],
            Node::Extension(n) => vec!["extension", n],
            Node::Role(n) => vec!["role", n],
        };
        join(&parts)
    }

    /// Reads a key back. Anything else is `None`.
    pub fn parse(key: &str) -> Option<Node> {
        let p: Vec<&str> = key.split(SEP).collect();
        let s = |i: usize| p[i].to_string();
        Some(match (p[0], p.len()) {
            ("databases", 1) => Node::Databases,
            ("schemas", 1) => Node::Schemas,
            ("extensions", 1) => Node::Extensions,
            ("roles", 1) => Node::Roles,
            ("schema", 2) => Node::Schema(s(1)),
            ("table", 3) => Node::Table(s(1), s(2)),
            ("view", 3) => Node::View(s(1), s(2)),
            ("matview", 3) => Node::MatView(s(1), s(2)),
            ("sequence", 3) => Node::Sequence(s(1), s(2)),
            ("function", 4) => Node::Function(s(1), s(2), p[3].parse().ok()?),
            ("indexes", 3) => Node::Indexes(s(1), s(2)),
            ("triggers", 3) => Node::Triggers(s(1), s(2)),
            ("index", 4) => Node::Index(s(1), s(2), s(3)),
            ("trigger", 4) => Node::Trigger(s(1), s(2), s(3)),
            ("database", 2) => Node::Database(s(1)),
            ("extension", 2) => Node::Extension(s(1)),
            ("role", 2) => Node::Role(s(1)),
            (tag, 2) => Node::Folder(Folder::from_tag(tag)?, s(1)),
            _ => return None,
        })
    }

    /// What the tree shows.
    pub fn label(&self) -> String {
        match self {
            Node::Databases => "Databases".into(),
            Node::Schemas => "Schemas".into(),
            Node::Extensions => "Extensions".into(),
            Node::Roles => "Roles".into(),
            Node::Folder(f, _) => f.label().into(),
            Node::Indexes(..) => "Indexes".into(),
            Node::Triggers(..) => "Triggers".into(),
            Node::Schema(n) | Node::Database(n) | Node::Extension(n) | Node::Role(n) => n.clone(),
            Node::Table(_, n) | Node::View(_, n) | Node::MatView(_, n) | Node::Sequence(_, n) | Node::Function(_, n, _) => n.clone(),
            Node::Index(_, _, n) | Node::Trigger(_, _, n) => n.clone(),
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Node::Databases | Node::Schemas | Node::Extensions | Node::Roles | Node::Folder(..) | Node::Indexes(..) | Node::Triggers(..) => "folder",
            Node::Schema(_) => "schema",
            Node::Table(..) => "table",
            Node::View(..) | Node::MatView(..) => "view",
            Node::Function(..) => "function",
            Node::Sequence(..) => "sequence",
            Node::Index(..) => "index",
            Node::Trigger(..) => "trigger",
            Node::Database(_) => "database",
            Node::Extension(_) => "extension",
            Node::Role(_) => "user",
        }
    }

    pub fn has_children(&self) -> bool {
        matches!(self, Node::Databases | Node::Schemas | Node::Extensions | Node::Roles | Node::Schema(_) | Node::Folder(..) | Node::Table(..) | Node::Indexes(..) | Node::Triggers(..))
    }

    /// Children with no query (fixed folders), or `None` when a query lists them.
    pub fn fixed_children(&self) -> Option<Vec<Node>> {
        match self {
            Node::Schema(s) => Some(Folder::ALL.iter().map(|f| Node::Folder(*f, s.clone())).collect()),
            Node::Table(s, t) => Some(vec![Node::Indexes(s.clone(), t.clone()), Node::Triggers(s.clone(), t.clone())]),
            _ => None,
        }
    }

    /// The catalog query listing the children. Every row is `(name)` or `(name, oid)`.
    pub fn children_sql(&self) -> Option<Result<String, QuoteError>> {
        let q = |sql: String| Some(Ok(sql));
        let lit = |s: &str| literal(s);
        match self {
            Node::Databases => q("SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1".into()),
            Node::Schemas => q("SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema' ORDER BY 1".into()),
            Node::Extensions => q("SELECT extname FROM pg_extension ORDER BY 1".into()),
            Node::Roles => q("SELECT rolname FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ORDER BY 1".into()),
            Node::Folder(f, s) => Some(lit(s).map(|s| match f {
                Folder::Tables => format!("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = {s} AND c.relkind IN ('r', 'p') ORDER BY 1"),
                Folder::Views => format!("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = {s} AND c.relkind = 'v' ORDER BY 1"),
                Folder::MatViews => format!("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = {s} AND c.relkind = 'm' ORDER BY 1"),
                Folder::Sequences => format!("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = {s} AND c.relkind = 'S' ORDER BY 1"),
                Folder::Functions => format!("SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = {s} ORDER BY 1"),
            })),
            Node::Indexes(s, t) => Some(lit(s).and_then(|s| lit(t).map(|t| format!("SELECT i.relname FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_class c ON c.oid = x.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = {s} AND c.relname = {t} ORDER BY 1")))),
            Node::Triggers(s, t) => Some(lit(s).and_then(|s| lit(t).map(|t| format!("SELECT g.tgname FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = {s} AND c.relname = {t} AND NOT g.tgisinternal ORDER BY 1")))),
            _ => None,
        }
    }

    /// One query counting the children of each of `nodes` that has a catalog query: one row, one
    /// column per such node, in order. `None` when none has one.
    pub fn count_sql(nodes: &[Node]) -> Option<String> {
        let parts: Vec<String> = nodes.iter().filter_map(|n| n.children_sql()?.ok()).map(|sql| format!("(SELECT count(*) FROM ({sql}) q)")).collect();
        (!parts.is_empty()).then(|| format!("SELECT {}", parts.join(", ")))
    }

    /// The label with the number of children, as "Tables (3)" (navigator counts).
    pub fn label_with_count(&self, count: Option<&str>) -> String {
        match count {
            Some(n) if self.children_sql().is_some() => format!("{} ({n})", self.label()),
            _ => self.label(),
        }
    }

    /// The child for one row of [`Node::children_sql`].
    pub fn child(&self, name: String, oid: Option<u32>) -> Option<Node> {
        Some(match self {
            Node::Databases => Node::Database(name),
            Node::Schemas => Node::Schema(name),
            Node::Extensions => Node::Extension(name),
            Node::Roles => Node::Role(name),
            Node::Folder(Folder::Tables, s) => Node::Table(s.clone(), name),
            Node::Folder(Folder::Views, s) => Node::View(s.clone(), name),
            Node::Folder(Folder::MatViews, s) => Node::MatView(s.clone(), name),
            Node::Folder(Folder::Sequences, s) => Node::Sequence(s.clone(), name),
            Node::Folder(Folder::Functions, s) => Node::Function(s.clone(), name, oid?),
            Node::Indexes(s, t) => Node::Index(s.clone(), t.clone(), name),
            Node::Triggers(s, t) => Node::Trigger(s.clone(), t.clone(), name),
            _ => return None,
        })
    }

    /// A query whose rows are `(property, value)` for the details pane.
    pub fn properties_sql(&self) -> Option<Result<String, QuoteError>> {
        let rel = |s: &str, n: &str| -> Result<String, QuoteError> { Ok(format!("{}.{}", ident(s)?, ident(n)?)) };
        let regclass = |s: &str, n: &str| -> Result<String, QuoteError> { literal(&rel(s, n)?).map(|l| format!("{l}::regclass")) };
        Some(match self {
            Node::Table(s, n) | Node::View(s, n) | Node::MatView(s, n) => regclass(s, n).map(|c| {
                format!(
                    "SELECT 'Owner', pg_get_userbyid(c.relowner)::text FROM pg_class c WHERE c.oid = {c} \
                     UNION ALL SELECT 'Rows (estimate)', c.reltuples::bigint::text FROM pg_class c WHERE c.oid = {c} \
                     UNION ALL SELECT 'Size', pg_size_pretty(pg_total_relation_size({c})) \
                     UNION ALL SELECT 'Comment', obj_description({c}, 'pg_class')"
                )
            }),
            Node::Sequence(s, n) => regclass(s, n).map(|c| format!("SELECT 'Owner', pg_get_userbyid(c.relowner)::text FROM pg_class c WHERE c.oid = {c} UNION ALL SELECT 'Last value', last_value::text FROM pg_sequences WHERE schemaname || '.' || sequencename = {}", literal(&format!("{s}.{n}")).unwrap_or_default())),
            Node::Function(_, _, oid) => Ok(format!("SELECT 'Returns', pg_get_function_result({oid}) UNION ALL SELECT 'Language', l.lanname::text FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang WHERE p.oid = {oid} UNION ALL SELECT 'Owner', pg_get_userbyid(proowner)::text FROM pg_proc WHERE oid = {oid}")),
            Node::Database(n) => literal(n).map(|n| format!("SELECT 'Owner', pg_get_userbyid(datdba)::text FROM pg_database WHERE datname = {n} UNION ALL SELECT 'Encoding', pg_encoding_to_char(encoding)::text FROM pg_database WHERE datname = {n} UNION ALL SELECT 'Size', pg_size_pretty(pg_database_size({n}))")),
            Node::Role(n) => literal(n).map(|n| format!("SELECT 'Superuser', rolsuper::text FROM pg_roles WHERE rolname = {n} UNION ALL SELECT 'Can log in', rolcanlogin::text FROM pg_roles WHERE rolname = {n} UNION ALL SELECT 'Connection limit', rolconnlimit::text FROM pg_roles WHERE rolname = {n}")),
            Node::Extension(n) => literal(n).map(|n| format!("SELECT 'Version', extversion::text FROM pg_extension WHERE extname = {n} UNION ALL SELECT 'Schema', extnamespace::regnamespace::text FROM pg_extension WHERE extname = {n}")),
            Node::Schema(n) => literal(n).map(|n| format!("SELECT 'Owner', pg_get_userbyid(nspowner)::text FROM pg_namespace WHERE nspname = {n}")),
            _ => return None,
        })
    }

    /// A query whose single row and column is the object's CREATE statement.
    pub fn ddl_sql(&self) -> Option<Result<String, QuoteError>> {
        let regclass = |s: &str, n: &str| -> Result<String, QuoteError> { literal(&format!("{}.{}", ident(s)?, ident(n)?)).map(|l| format!("{l}::regclass")) };
        Some(match self {
            Node::View(s, n) => regclass(s, n).and_then(|c| Ok(format!("SELECT 'CREATE VIEW ' || {} || ' AS' || chr(10) || pg_get_viewdef({c}, true)", literal(&format!("{}.{}", ident(s)?, ident(n)?))?))),
            Node::MatView(s, n) => regclass(s, n).and_then(|c| Ok(format!("SELECT 'CREATE MATERIALIZED VIEW ' || {} || ' AS' || chr(10) || pg_get_viewdef({c}, true)", literal(&format!("{}.{}", ident(s)?, ident(n)?))?))),
            Node::Function(_, _, oid) => Ok(format!("SELECT pg_get_functiondef({oid})")),
            Node::Index(s, _, n) => regclass(s, n).map(|c| format!("SELECT pg_get_indexdef({c}) || ';'")),
            Node::Trigger(s, t, n) => regclass(s, t).and_then(|c| literal(n).map(|n| format!("SELECT pg_get_triggerdef(oid, true) || ';' FROM pg_trigger WHERE tgrelid = {c} AND tgname = {n}"))),
            Node::Table(s, n) => regclass(s, n).and_then(|c| {
                Ok(format!(
                    "SELECT 'CREATE TABLE ' || {name} || ' (' || chr(10) || string_agg(line, ',' || chr(10) ORDER BY ord) || chr(10) || ');' FROM ( \
                     SELECT a.attnum AS ord, '    ' || quote_ident(a.attname) || ' ' || format_type(a.atttypid, a.atttypmod) \
                       || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END \
                       || COALESCE(' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid), '') AS line \
                     FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
                     WHERE a.attrelid = {c} AND a.attnum > 0 AND NOT a.attisdropped \
                     UNION ALL SELECT 100000 + row_number() OVER (ORDER BY conname), '    CONSTRAINT ' || quote_ident(conname) || ' ' || pg_get_constraintdef(oid, true) \
                     FROM pg_constraint WHERE conrelid = {c} ) parts",
                    name = literal(&format!("{}.{}", ident(s)?, ident(n)?))?
                ))
            }),
            Node::Sequence(s, n) => regclass(s, n).and_then(|_| {
                let lit = literal(&format!("{s}.{n}"))?;
                let name = literal(&format!("{}.{}", ident(s)?, ident(n)?))?;
                Ok(format!("SELECT 'CREATE SEQUENCE ' || {name} || ' AS ' || data_type::text || ' INCREMENT BY ' || increment_by || ' MINVALUE ' || min_value || ' MAXVALUE ' || max_value || ' START WITH ' || start_value || ';' FROM pg_sequences WHERE schemaname || '.' || sequencename = {lit}"))
            }),
            Node::Schema(n) => ident(n).and_then(|i| literal(&format!("CREATE SCHEMA {i};")).map(|l| format!("SELECT {l}"))),
            Node::Extension(n) => ident(n).and_then(|i| literal(&format!("CREATE EXTENSION {i};")).map(|l| format!("SELECT {l}"))),
            _ => return None,
        })
    }

    /// The query for the table data viewer: `filter` is a WHERE clause the user typed (the
    /// plugin does not parse it; read only still applies), `order` a column index.
    pub fn data_sql(&self, filter: &str, order: Option<(&str, bool)>, limit: usize) -> Option<Result<String, QuoteError>> {
        self.data_page_sql(filter, order, limit, 0)
    }

    /// One page of a table's or view's rows (PLUG-08b). The filter is the user's own
    /// expression; it must pass [`crate::sqllex::safe_filter`] so it cannot end the `WHERE`.
    pub fn data_page_sql(&self, filter: &str, order: Option<(&str, bool)>, limit: usize, offset: u64) -> Option<Result<String, QuoteError>> {
        let (Node::Table(s, n) | Node::View(s, n) | Node::MatView(s, n)) = self else { return None };
        Some((|| {
            let mut sql = format!("SELECT * FROM {}.{}", ident(s)?, ident(n)?);
            let filter = filter.trim();
            if !filter.is_empty() {
                if !crate::sqllex::safe_filter(filter) {
                    return Err(QuoteError);
                }
                sql.push_str(&format!(" WHERE ({filter})"));
            }
            if let Some((col, asc)) = order {
                sql.push_str(&format!(" ORDER BY {} {}", ident(col)?, if asc { "ASC" } else { "DESC" }));
            }
            sql.push_str(&format!(" LIMIT {limit}"));
            if offset > 0 {
                sql.push_str(&format!(" OFFSET {offset}"));
            }
            Ok(sql)
        })())
    }
}

/// A name or value that cannot be quoted (it holds a NUL byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteError;

/// An identifier, always quoted: `"my ""odd"" name"`.
pub fn ident(name: &str) -> Result<String, QuoteError> {
    if name.contains('\0') {
        return Err(QuoteError);
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

/// A string literal that means the same whatever `standard_conforming_strings` is:
/// `E'...'` with backslashes and quotes doubled.
pub fn literal(value: &str) -> Result<String, QuoteError> {
    if value.contains('\0') {
        return Err(QuoteError);
    }
    Ok(format!("E'{}'", value.replace('\\', "\\\\").replace('\'', "''")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTILE: [&str; 7] = ["a'b", "a\"b", "x'); DROP TABLE t; --", "back\\slash'", "\\'", "with space", "Ünïcödé"];

    /// What PostgreSQL makes of an `E'...'` literal: the original string.
    fn unquote_literal(l: &str) -> String {
        let inner = l.strip_prefix("E'").unwrap().strip_suffix('\'').unwrap();
        let mut out = String::new();
        let mut it = inner.chars().peekable();
        while let Some(c) = it.next() {
            match c {
                '\\' => out.push(it.next().expect("escaped char")),
                '\'' => {
                    assert_eq!(it.next(), Some('\''), "a lone quote would end the literal: {l}");
                    out.push('\'');
                }
                c => out.push(c),
            }
        }
        out
    }

    fn unquote_ident(i: &str) -> String {
        let inner = i.strip_prefix('"').unwrap().strip_suffix('"').unwrap();
        assert!(!inner.replace("\"\"", "").contains('"'), "a lone quote would end the name: {i}");
        inner.replace("\"\"", "\"")
    }

    #[test]
    fn hostile_names_round_trip_through_quoting() {
        for h in HOSTILE {
            assert_eq!(unquote_literal(&literal(h).unwrap()), h);
            assert_eq!(unquote_ident(&ident(h).unwrap()), h);
        }
        assert_eq!(literal("a\0b"), Err(QuoteError));
        assert_eq!(ident("a\0b"), Err(QuoteError));
    }

    #[test]
    fn counts_cover_every_level_with_a_query() {
        let folders = Node::Schema("shop".into()).fixed_children().unwrap();
        let sql = Node::count_sql(&folders).unwrap();
        assert_eq!(sql.matches("SELECT count(*)").count(), 5);
        assert!(Node::count_sql(&[Node::Table("s".into(), "t".into())]).is_none());
        assert_eq!(Node::Roles.label_with_count(Some("4")), "Roles (4)");
        assert_eq!(Node::Table("s".into(), "t".into()).label_with_count(Some("4")), "t");
        assert_eq!(Node::Roles.label_with_count(None), "Roles");
    }

    #[test]
    fn keys_round_trip_and_reject_the_separator() {
        let nodes = [
            Node::Databases,
            Node::Schema("pub'lic".into()),
            Node::Folder(Folder::MatViews, "s".into()),
            Node::Table("s".into(), "x\"y".into()),
            Node::Function("s".into(), "f(integer)".into(), 16384),
            Node::Index("s".into(), "t".into(), "t_pkey".into()),
            Node::Trigger("s".into(), "t".into(), "audit".into()),
            Node::Role("admin".into()),
        ];
        for n in nodes {
            assert_eq!(Node::parse(&n.key().unwrap()), Some(n));
        }
        assert_eq!(Node::Schema("a\u{1f}b".into()).key(), None);
        for bad in ["", "nothing", "table\u{1f}only-one", "function\u{1f}s\u{1f}f\u{1f}not-a-number"] {
            assert_eq!(Node::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn hostile_names_only_reach_queries_quoted() {
        for h in HOSTILE {
            let sql = Node::Folder(Folder::Tables, h.into()).children_sql().unwrap().unwrap();
            assert!(sql.contains(&literal(h).unwrap()), "{sql}");
            let sql = Node::Table(h.into(), h.into()).ddl_sql().unwrap().unwrap();
            assert!(!sql.contains(&format!("'{h}'")) || h == "with space" || h == "Ünïcödé", "{sql}");
            let sql = Node::Table(h.into(), h.into()).data_sql("", Some((h, false)), 10).unwrap().unwrap();
            assert!(sql.starts_with(&format!("SELECT * FROM {}.{}", ident(h).unwrap(), ident(h).unwrap())), "{sql}");
            assert!(sql.ends_with(&format!("ORDER BY {} DESC LIMIT 10", ident(h).unwrap())), "{sql}");
        }
        assert!(Node::Schema("a\0".into()).ddl_sql().unwrap().is_err());
    }

    #[test]
    fn every_level_has_a_query_or_fixed_children() {
        for n in [Node::Databases, Node::Schemas, Node::Extensions, Node::Roles, Node::Indexes("s".into(), "t".into()), Node::Triggers("s".into(), "t".into())] {
            assert!(n.has_children() && n.children_sql().is_some(), "{n:?}");
        }
        for f in Folder::ALL {
            assert!(Node::Folder(f, "s".into()).children_sql().is_some());
        }
        assert_eq!(Node::Schema("s".into()).fixed_children().unwrap().len(), 5);
        assert!(Node::Function("s".into(), "f".into(), 1).ddl_sql().is_some());
    }
}
