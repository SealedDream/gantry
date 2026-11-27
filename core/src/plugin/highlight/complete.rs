//! Completions from plugins in the code editor (PLUG-06c; spec section 5, "Code").
//!
//! The protocol: the app asks with an `events.completions` ask (`text` and the cursor
//! `offset` in characters, see `plugin::host::view::event_from_json`); the plugin answers once
//! with `ui.provide-completions` or `ui.refuse`. This module holds the core's three parts of it,
//! all pure functions over text:
//!
//! - [`completion_context`]: at a cursor, whether to ask at all (not inside a string, comment,
//!   number or parameter), the word being typed, the UTF-16 range a choice replaces, and the
//!   character offset to send.
//! - [`clean_completions`]: the plugin's answer, checked and capped before any app sees it.
//! - [`rank_completions`]: the answer filtered and ordered against the word being typed, so all
//!   apps show the same list in the same order.

use serde_json::Value as Json;

use super::{tokenize_text, TokenKind};

/// The most completions one answer may carry; the rest are dropped.
pub const MAX_COMPLETIONS: usize = 1_000;
/// The most completions [`rank_completions`] returns, the list an editor shows.
pub const MAX_SHOWN: usize = 200;
/// The longest label, in bytes. A longer one drops the item.
pub const MAX_LABEL_BYTES: usize = 256;
/// The longest text a completion inserts, in bytes. A longer one drops the item.
pub const MAX_INSERT_BYTES: usize = 16 * 1024;
/// The longest detail, in bytes. A longer one is cut on a character boundary.
pub const MAX_DETAIL_BYTES: usize = 512;

/// One completion, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    /// What the list shows. Never empty, no control characters.
    pub label: String,
    /// What a choice puts in place of the word being typed. Never empty; may hold `\n` and `\t`.
    pub insert: String,
    /// A short note shown beside the label (a type, a schema). May be empty.
    pub detail: String,
}

/// What the editor needs to know at the cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionContext {
    /// Whether to ask the plugin. False inside a string, comment, quoted identifier, number or
    /// parameter, and for an unknown language.
    pub ask: bool,
    /// The part of the word before the cursor, to rank with. Empty after a space, `.` or `(`.
    pub prefix: String,
    /// Where the range a choice replaces starts, in UTF-16 units (the cursor minus the prefix).
    pub replace_utf16_start: usize,
    /// How long that range is, in UTF-16 units (the prefix).
    pub replace_utf16_len: usize,
    /// The cursor in characters (Unicode scalar values), as the `completions` ask carries it.
    pub char_offset: u32,
}

/// The context at `cursor_utf16` in `text`. A cursor past the end counts as the end; one inside
/// a surrogate pair counts as before the pair. Never fails and never panics.
///
/// Work is linear in the text up to the end of the cursor's line: the state at that line
/// depends on every line above it.
pub fn completion_context(language: &str, text: &str, cursor_utf16: usize) -> CompletionContext {
    // The cursor as a byte offset on a character boundary, and as a character count.
    let (mut cursor, mut units, mut chars) = (text.len(), 0usize, 0usize);
    for (at, c) in text.char_indices() {
        if units + c.len_utf16() > cursor_utf16 {
            cursor = at;
            break;
        }
        units += c.len_utf16();
        chars += 1;
    }
    if cursor == text.len() {
        units = units.min(cursor_utf16);
    }
    let none = |units| CompletionContext { ask: false, prefix: String::new(), replace_utf16_start: units, replace_utf16_len: 0, char_offset: u32::try_from(chars).unwrap_or(u32::MAX) };
    if super::sql::Dialect::named(language).is_none() {
        return none(units);
    }
    let line_end = text[cursor..].find('\n').map_or(text.len(), |n| cursor + n);
    let spans = tokenize_text(language, &text[..line_end]).spans;
    // The token that holds the character just before the cursor, if any.
    let before = spans.iter().find(|t| t.start < cursor && cursor <= t.end());
    // A cursor at the start of a token still inside an open piece (an unclosed string on this
    // line) is inside it too: the token that starts at the cursor tells.
    let at = spans.iter().find(|t| t.start == cursor);
    let quiet = |k: TokenKind| matches!(k, TokenKind::String | TokenKind::Comment | TokenKind::QuotedIdentifier | TokenKind::Number | TokenKind::Parameter | TokenKind::Error);
    if before.is_some_and(|t| quiet(t.kind) && !(t.end() == cursor && closed(t.kind, &text[t.start..t.end()]))) {
        return none(units);
    }
    if at.is_some_and(|t| t.kind == TokenKind::Error) {
        return none(units);
    }
    let mut ctx = none(units);
    ctx.ask = true;
    if let Some(t) = before.filter(|t| matches!(t.kind, TokenKind::Identifier | TokenKind::Keyword | TokenKind::TypeName | TokenKind::FunctionName)) {
        let prefix = &text[t.start..cursor];
        let len = prefix.encode_utf16().count();
        ctx.prefix = prefix.to_string();
        ctx.replace_utf16_start = units - len;
        ctx.replace_utf16_len = len;
    }
    ctx
}

/// Whether a token that ends right at the cursor is finished, so typing after it starts
/// something new: a closed string or quoted identifier (`'a'|`), or a block comment (`*/|`).
/// Numbers, parameters and line comments go on with the next character.
fn closed(kind: TokenKind, token: &str) -> bool {
    match kind {
        TokenKind::String => token.len() >= 2 && (token.ends_with('\'') || token.ends_with('$')),
        TokenKind::QuotedIdentifier => token.len() >= 2 && token.ends_with('"'),
        TokenKind::Comment => token.starts_with("/*") && token.ends_with("*/") && token.len() >= 4,
        _ => false,
    }
}

/// Text without control characters, except the ones `keep` allows.
fn strip_controls(s: &str, keep: &[char]) -> String {
    s.chars().filter(|c| !c.is_control() || keep.contains(c)).collect()
}

/// `s` cut to at most `max` bytes on a character boundary.
fn cut(s: &mut String, max: usize) {
    if s.len() > max {
        let mut at = max;
        while !s.is_char_boundary(at) {
            at -= 1;
        }
        s.truncate(at);
    }
}

/// The plugin's `provide-completions` items (a JSON array of `{label, insert, detail}`), checked:
/// at most [`MAX_COMPLETIONS`]; an item that is not an object, has no label, or whose label or
/// insert is too long is dropped; control characters go (the insert keeps `\n` and `\t`); an
/// empty insert becomes the label; a long detail is cut. Anything that is not an array gives
/// no items.
pub fn clean_completions(items: &Json) -> Vec<Completion> {
    let Some(items) = items.as_array() else { return Vec::new() };
    let field = |item: &Json, key: &str| item.get(key).and_then(Json::as_str).unwrap_or("").to_string();
    items
        .iter()
        .filter_map(|item| {
            let label = strip_controls(&field(item, "label"), &[]);
            if label.trim().is_empty() || label.len() > MAX_LABEL_BYTES {
                return None;
            }
            let raw_insert = field(item, "insert");
            if raw_insert.len() > MAX_INSERT_BYTES {
                return None;
            }
            let insert = strip_controls(&raw_insert, &['\n', '\t']);
            let insert = if insert.is_empty() { label.clone() } else { insert };
            let mut detail = field(item, "detail");
            cut(&mut detail, MAX_DETAIL_BYTES * 4);
            let mut detail = strip_controls(&detail, &[]);
            cut(&mut detail, MAX_DETAIL_BYTES);
            Some(Completion { label, insert, detail })
        })
        .take(MAX_COMPLETIONS)
        .collect()
}

/// Completions as the JSON the app gets: an array of `{label, insert, detail}`.
pub fn completions_json(items: &[Completion]) -> Json {
    Json::Array(items.iter().map(|c| serde_json::json!({ "label": c.label, "insert": c.insert, "detail": c.detail })).collect())
}

/// `items` filtered and ordered against `prefix`, at most [`MAX_SHOWN`]: labels that start with
/// the prefix in the same case, then those that start with it in any case (ASCII), then those
/// that hold it anywhere in any case. Within each group the plugin's order stands. An empty
/// prefix keeps every item in the plugin's order. Equal labels after the first are dropped.
pub fn rank_completions(items: &[Completion], prefix: &str) -> Vec<Completion> {
    let lower = prefix.to_lowercase();
    let mut groups: [Vec<&Completion>; 3] = Default::default();
    let mut seen = std::collections::HashSet::new();
    for item in items {
        if !seen.insert(item.label.as_str()) {
            continue;
        }
        let group = if item.label.starts_with(prefix) {
            0
        } else {
            let label = item.label.to_lowercase();
            if label.starts_with(&lower) {
                1
            } else if label.contains(&lower) {
                2
            } else {
                continue;
            }
        };
        groups[group].push(item);
    }
    groups.into_iter().flatten().take(MAX_SHOWN).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn c(label: &str) -> Completion {
        Completion { label: label.into(), insert: label.into(), detail: String::new() }
    }

    #[test]
    fn the_word_before_the_cursor_is_the_prefix() {
        let ctx = completion_context("postgresql", "SELECT na", 9);
        assert!(ctx.ask);
        assert_eq!(ctx.prefix, "na");
        assert_eq!((ctx.replace_utf16_start, ctx.replace_utf16_len, ctx.char_offset), (7, 2, 9));
        // A key word being typed is a prefix too.
        assert_eq!(completion_context("postgresql", "sel", 3).prefix, "sel");
        // In the middle of a word, only the part before the cursor.
        assert_eq!(completion_context("postgresql", "SELECT name", 9).prefix, "na");
    }

    #[test]
    fn after_a_space_dot_or_bracket_it_asks_with_no_prefix() {
        for (text, at) in [("SELECT ", 7), ("t.", 2), ("count(", 6), ("", 0), ("SELECT 'a' ", 11)] {
            let ctx = completion_context("postgresql", text, at);
            assert!(ctx.ask, "{text}");
            assert_eq!(ctx.prefix, "", "{text}");
            assert_eq!(ctx.replace_utf16_len, 0);
        }
    }

    #[test]
    fn no_ask_inside_strings_comments_numbers_and_parameters() {
        for (text, at) in [
            ("SELECT 'ab", 10),
            ("SELECT 'ab'", 9),
            ("-- se", 5),
            ("/* se", 5),
            ("/* a\nse", 7),
            ("SELECT $$ab\nse", 14),
            ("SELECT \"ab", 10),
            ("SELECT 12", 9),
            ("WHERE a = $1", 12),
            ("SELECT 'ab' || 'cd", 18),
        ] {
            assert!(!completion_context("postgresql", text, at).ask, "{text} at {at}");
        }
        // A finished string or comment right before the cursor does not stop it.
        assert!(completion_context("postgresql", "/* x */", 7).ask);
    }

    #[test]
    fn unknown_languages_never_ask() {
        assert!(!completion_context("text", "SELECT na", 9).ask);
    }

    #[test]
    fn offsets_count_utf16_and_characters() {
        // "é" is one unit, "😀" two units and one character.
        let text = "SELECT 😀, éna";
        let end = text.encode_utf16().count();
        let ctx = completion_context("postgresql", text, end);
        assert_eq!(ctx.prefix, "éna");
        assert_eq!(ctx.replace_utf16_start, end - 3);
        assert_eq!(ctx.char_offset as usize, text.chars().count());
        // Inside the surrogate pair counts as before it; past the end counts as the end.
        assert_eq!(completion_context("postgresql", "😀", 1).char_offset, 0);
        assert_eq!(completion_context("postgresql", "ab", 99).char_offset, 2);
        assert_eq!(completion_context("postgresql", "ab", 99).replace_utf16_start, 0);
    }

    #[test]
    fn the_cursor_line_ends_the_tokenizing() {
        // An unclosed string on a later line does not change the cursor's line.
        let ctx = completion_context("postgresql", "SELECT na\n'open", 9);
        assert!(ctx.ask);
        assert_eq!(ctx.prefix, "na");
    }

    #[test]
    fn answers_are_checked() {
        let long_label = "x".repeat(MAX_LABEL_BYTES + 1);
        let long_insert = "y".repeat(MAX_INSERT_BYTES + 1);
        let items = json!([
            {"label": "users", "insert": "", "detail": "table"},
            {"label": "a\u{1b}[31mb", "insert": "a\tb\nc\u{7}", "detail": "d\u{0}"},
            {"label": "", "insert": "x"},
            {"label": "   "},
            {"label": long_label},
            {"label": "big", "insert": long_insert},
            {"label": "long", "detail": "é".repeat(MAX_DETAIL_BYTES)},
            "not an object",
            {"insert": "no label"},
        ]);
        let out = clean_completions(&items);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], Completion { label: "users".into(), insert: "users".into(), detail: "table".into() });
        assert_eq!(out[1], Completion { label: "a[31mb".into(), insert: "a\tb\nc".into(), detail: "d".into() });
        assert!(out[2].detail.len() <= MAX_DETAIL_BYTES);
        assert!(out[2].detail.chars().all(|c| c == 'é'));
        assert!(clean_completions(&json!({"label": "x"})).is_empty());
        let many: Vec<Json> = (0..MAX_COMPLETIONS + 5).map(|n| json!({"label": format!("c{n}")})).collect();
        assert_eq!(clean_completions(&Json::Array(many)).len(), MAX_COMPLETIONS);
    }

    #[test]
    fn ranking_puts_prefix_matches_first() {
        let items = [c("user_id"), c("Users"), c("users"), c("orders_user"), c("name"), c("users")];
        let ranked: Vec<_> = rank_completions(&items, "us").into_iter().map(|c| c.label).collect();
        assert_eq!(ranked, ["user_id", "users", "Users", "orders_user"]);
        let all: Vec<_> = rank_completions(&items, "").into_iter().map(|c| c.label).collect();
        assert_eq!(all, ["user_id", "Users", "users", "orders_user", "name"]);
        let many: Vec<_> = (0..MAX_SHOWN + 10).map(|n| c(&format!("c{n}"))).collect();
        assert_eq!(rank_completions(&many, "c").len(), MAX_SHOWN);
    }
}
