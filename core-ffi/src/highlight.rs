//! PLUG-06c: the code editor's tokenizer and completions (`bastion_core::plugin::highlight`).
//!
//! An editor keeps one state string per line: it gives the line above's `end_state` with each
//! line (`""` for the first) and re-colours down from an edit until a line's `end_state` is the
//! one it already had. Offsets are UTF-16 units, as AppKit and WinUI count; byte offsets are
//! there for Rust-side callers. All pure functions: no disk, no network.
use bastion_core::plugin::highlight::{self, complete, wire, Token};

/// One coloured span. `kind`: keyword, identifier, quoted-identifier, string, number, comment,
/// operator, punctuation, parameter, type, function, text, error.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct HighlightToken {
    pub kind: String,
    pub utf16_start: u64,
    pub utf16_len: u64,
    pub start: u64,
    pub len: u64,
}

/// The spans of a line or text, and the state to give the next line.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct HighlightSpans {
    pub tokens: Vec<HighlightToken>,
    pub end_state: String,
}

/// What the editor needs at the cursor (see `complete::CompletionContext`).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct CompletionContextView {
    /// Whether to send the plugin a `completions` ask.
    pub ask: bool,
    pub prefix: String,
    pub replace_utf16_start: u64,
    pub replace_utf16_len: u64,
    /// The `offset` for the ask, in characters.
    pub char_offset: u32,
}

/// One completion, as the `provide-completions` update gives it (already checked by the core).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct CompletionItem {
    pub label: String,
    pub insert: String,
    pub detail: String,
}

pub(crate) fn token_view(t: &Token) -> HighlightToken {
    HighlightToken { kind: wire::kind_name(t.kind).into(), utf16_start: t.utf16_start as u64, utf16_len: t.utf16_len as u64, start: t.start as u64, len: t.len as u64 }
}

/// Tokenize one line (no line break) of `language` (`postgresql`, `sql`; anything else is plain
/// text) after the line whose `end_state` is `state`. Never fails.
#[uniffi::export]
pub fn highlight_line(language: String, line: String, state: String) -> HighlightSpans {
    let out = highlight::tokenize_line(&language, &line, wire::decode_state(&state));
    HighlightSpans { tokens: out.tokens.iter().map(token_view).collect(), end_state: wire::encode_state(&out.end_state) }
}

/// Tokenize a whole text; offsets from its start, `\n` not covered. For small texts.
#[uniffi::export]
pub fn highlight_text(language: String, text: String) -> HighlightSpans {
    let out = highlight::tokenize_text(&language, &text);
    HighlightSpans { tokens: out.spans.iter().map(token_view).collect(), end_state: wire::encode_state(&out.end_state) }
}

/// Whether to ask for completions at `cursor_utf16`, and what a choice replaces.
#[uniffi::export]
pub fn completion_context(language: String, text: String, cursor_utf16: u64) -> CompletionContextView {
    let c = complete::completion_context(&language, &text, usize::try_from(cursor_utf16).unwrap_or(usize::MAX));
    CompletionContextView { ask: c.ask, prefix: c.prefix, replace_utf16_start: c.replace_utf16_start as u64, replace_utf16_len: c.replace_utf16_len as u64, char_offset: c.char_offset }
}

/// The plugin's completions filtered and ordered against `prefix`, at most 200, the same way in
/// every app. Call again as the user types; ask the plugin again only when the context changes.
#[uniffi::export]
pub fn completions_rank(items: Vec<CompletionItem>, prefix: String) -> Vec<CompletionItem> {
    let items: Vec<complete::Completion> = items.into_iter().map(|i| complete::Completion { label: i.label, insert: i.insert, detail: i.detail }).collect();
    complete::rank_completions(&items, &prefix).into_iter().map(|c| CompletionItem { label: c.label, insert: c.insert, detail: c.detail }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_state_carries_to_the_next_line() {
        let first = highlight_line("postgresql".into(), "SELECT 'a".into(), String::new());
        assert_eq!(first.end_state, "s");
        assert_eq!(first.tokens[0].kind, "keyword");
        let second = highlight_line("postgresql".into(), "b' FROM t".into(), first.end_state);
        assert_eq!(second.tokens[0].kind, "string");
        assert_eq!(second.end_state, "");
        assert_eq!(highlight_line("other".into(), "x".into(), "garbage".into()).tokens[0].kind, "text");
    }

    #[test]
    fn text_offsets_are_utf16() {
        let out = highlight_text("sql".into(), "SELECT 😀\nFROM".into());
        let from = out.tokens.iter().find(|t| t.kind == "keyword" && t.start > 0).unwrap();
        assert_eq!((from.utf16_start, from.start), (10, 12));
    }

    #[test]
    fn completion_context_and_rank() {
        let c = completion_context("postgresql".into(), "SELECT us".into(), 9);
        assert!(c.ask);
        assert_eq!((c.prefix.as_str(), c.replace_utf16_start, c.replace_utf16_len, c.char_offset), ("us", 7, 2, 9));
        let item = |l: &str| CompletionItem { label: l.into(), insert: l.into(), detail: String::new() };
        let ranked = completions_rank(vec![item("name"), item("users")], c.prefix);
        assert_eq!(ranked, vec![item("users")]);
    }
}
