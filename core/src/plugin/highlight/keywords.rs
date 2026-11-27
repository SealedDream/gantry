//! Word lists for the SQL tokenizer.
//!
//! [`KEYWORDS`] is the PostgreSQL 14 key word list: every `PG_KEYWORD` entry of
//! `src/include/parser/kwlist.h` as shipped with PostgreSQL 14.13, which is the source of the
//! "SQL Key Words" appendix of the PostgreSQL 14 documentation (all four categories: reserved,
//! non-reserved, column name, type or function name). It is lower-case and sorted by byte value,
//! so a binary search finds a word; a unit test holds it to that.

/// The longest word in [`KEYWORDS`] and [`TYPE_NAMES`], in bytes. A longer identifier is never
/// looked up.
pub(super) const MAX_WORD_BYTES: usize = 17;

/// PostgreSQL 14 key words, lower-case, sorted.
pub(super) const KEYWORDS: &[&str] = &[
    "abort", "absolute", "access", "action", "add", "admin", "after", "aggregate", "all", "also", "alter", "always", "analyse", "analyze", "and", "any",
    "array", "as", "asc", "asensitive", "assertion", "assignment", "asymmetric", "at", "atomic", "attach", "attribute", "authorization", "backward",
    "before", "begin", "between", "bigint", "binary", "bit", "boolean", "both", "breadth", "by", "cache", "call", "called", "cascade", "cascaded",
    "case", "cast", "catalog", "chain", "char", "character", "characteristics", "check", "checkpoint", "class", "close", "cluster", "coalesce",
    "collate", "collation", "column", "columns", "comment", "comments", "commit", "committed", "compression", "concurrently", "configuration",
    "conflict", "connection", "constraint", "constraints", "content", "continue", "conversion", "copy", "cost", "create", "cross", "csv", "cube",
    "current", "current_catalog", "current_date", "current_role", "current_schema", "current_time", "current_timestamp", "current_user", "cursor",
    "cycle", "data", "database", "day", "deallocate", "dec", "decimal", "declare", "default", "defaults", "deferrable", "deferred", "definer", "delete",
    "delimiter", "delimiters", "depends", "depth", "desc", "detach", "dictionary", "disable", "discard", "distinct", "do", "document", "domain",
    "double", "drop", "each", "else", "enable", "encoding", "encrypted", "end", "enum", "escape", "event", "except", "exclude", "excluding", "exclusive",
    "execute", "exists", "explain", "expression", "extension", "external", "extract", "false", "family", "fetch", "filter", "finalize", "first", "float",
    "following", "for", "force", "foreign", "forward", "freeze", "from", "full", "function", "functions", "generated", "global", "grant", "granted",
    "greatest", "group", "grouping", "groups", "handler", "having", "header", "hold", "hour", "identity", "if", "ilike", "immediate", "immutable",
    "implicit", "import", "in", "include", "including", "increment", "index", "indexes", "inherit", "inherits", "initially", "inline", "inner", "inout",
    "input", "insensitive", "insert", "instead", "int", "integer", "intersect", "interval", "into", "invoker", "is", "isnull", "isolation", "join",
    "key", "label", "language", "large", "last", "lateral", "leading", "leakproof", "least", "left", "level", "like", "limit", "listen", "load", "local",
    "localtime", "localtimestamp", "location", "lock", "locked", "logged", "mapping", "match", "materialized", "maxvalue", "method", "minute",
    "minvalue", "mode", "month", "move", "name", "names", "national", "natural", "nchar", "new", "next", "nfc", "nfd", "nfkc", "nfkd", "no", "none",
    "normalize", "normalized", "not", "nothing", "notify", "notnull", "nowait", "null", "nullif", "nulls", "numeric", "object", "of", "off", "offset",
    "oids", "old", "on", "only", "operator", "option", "options", "or", "order", "ordinality", "others", "out", "outer", "over", "overlaps", "overlay",
    "overriding", "owned", "owner", "parallel", "parser", "partial", "partition", "passing", "password", "placing", "plans", "policy", "position",
    "preceding", "precision", "prepare", "prepared", "preserve", "primary", "prior", "privileges", "procedural", "procedure", "procedures", "program",
    "publication", "quote", "range", "read", "real", "reassign", "recheck", "recursive", "ref", "references", "referencing", "refresh", "reindex",
    "relative", "release", "rename", "repeatable", "replace", "replica", "reset", "restart", "restrict", "return", "returning", "returns", "revoke",
    "right", "role", "rollback", "rollup", "routine", "routines", "row", "rows", "rule", "savepoint", "schema", "schemas", "scroll", "search", "second",
    "security", "select", "sequence", "sequences", "serializable", "server", "session", "session_user", "set", "setof", "sets", "share", "show",
    "similar", "simple", "skip", "smallint", "snapshot", "some", "sql", "stable", "standalone", "start", "statement", "statistics", "stdin", "stdout",
    "storage", "stored", "strict", "strip", "subscription", "substring", "support", "symmetric", "sysid", "system", "table", "tables", "tablesample",
    "tablespace", "temp", "template", "temporary", "text", "then", "ties", "time", "timestamp", "to", "trailing", "transaction", "transform", "treat",
    "trigger", "trim", "true", "truncate", "trusted", "type", "types", "uescape", "unbounded", "uncommitted", "unencrypted", "union", "unique",
    "unknown", "unlisten", "unlogged", "until", "update", "user", "using", "vacuum", "valid", "validate", "validator", "value", "values", "varchar",
    "variadic", "varying", "verbose", "version", "view", "views", "volatile", "when", "where", "whitespace", "window", "with", "within", "without",
    "work", "wrapper", "write", "xml", "xmlattributes", "xmlconcat", "xmlelement", "xmlexists", "xmlforest", "xmlnamespaces", "xmlparse", "xmlpi",
    "xmlroot", "xmlserialize", "xmltable", "year", "yes", "zone",
];

/// Built-in type names that are coloured as types wherever they stand. Lower-case, sorted.
///
/// The list is deliberately short: names that are also common column names (`name`, `path`,
/// `point`, `line`, `box`, `circle`) are left out, and any identifier straight after `::` is a
/// type name whether it is listed here or not.
pub(super) const TYPE_NAMES: &[&str] = &[
    "bigint", "bigserial", "bit", "bool", "boolean", "bytea", "char", "character", "cidr", "date", "decimal", "float", "float4", "float8", "inet", "int", "int2", "int4",
    "int8", "integer", "interval", "json", "jsonb", "macaddr", "money", "numeric", "oid", "real", "regclass", "serial", "smallint", "smallserial", "text", "time",
    "timestamp", "timestamptz", "timetz", "tsquery", "tsvector", "uuid", "varbit", "varchar", "xml",
];

/// Whether `word` (any case, ASCII letters only matter) is in `list`.
pub(super) fn contains(list: &[&str], word: &[u8]) -> bool {
    if word.is_empty() || word.len() > MAX_WORD_BYTES {
        return false;
    }
    let mut lower = [0u8; MAX_WORD_BYTES];
    let lower = &mut lower[..word.len()];
    for (to, from) in lower.iter_mut().zip(word) {
        *to = from.to_ascii_lowercase();
    }
    list.binary_search_by(|entry| entry.as_bytes().cmp(lower)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_sorted_lower(list: &[&str]) {
        for pair in list.windows(2) {
            assert!(pair[0].as_bytes() < pair[1].as_bytes(), "{} is not before {}", pair[0], pair[1]);
        }
        for word in list {
            assert!(word.len() <= MAX_WORD_BYTES, "{word} is longer than MAX_WORD_BYTES");
            assert!(word.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'), "{word}");
        }
    }

    #[test]
    fn the_lists_are_sorted_lower_case_and_within_the_length_cap() {
        assert_sorted_lower(KEYWORDS);
        assert_sorted_lower(TYPE_NAMES);
        assert_eq!(KEYWORDS.len(), 457, "PostgreSQL 14.13 kwlist.h has 457 key words");
        assert_eq!(KEYWORDS.iter().chain(TYPE_NAMES).map(|w| w.len()).max(), Some(MAX_WORD_BYTES));
    }

    #[test]
    fn lookup_ignores_case_and_refuses_long_or_empty_words() {
        assert!(contains(KEYWORDS, b"SeLeCt"));
        assert!(contains(KEYWORDS, b"current_timestamp"));
        assert!(contains(TYPE_NAMES, b"JSONB"));
        assert!(!contains(KEYWORDS, b""));
        assert!(!contains(KEYWORDS, b"selec"));
        assert!(!contains(KEYWORDS, b"current_timestamp_but_longer"));
        assert!(!contains(KEYWORDS, "sélect".as_bytes()));
    }
}
