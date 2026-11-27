//! Code highlighting: a tokenizer in the core, so every app colours code the same way
//! (PLUG-06c1; design in `docs/specs/plugins.md`, section 5, "Highlighting").
//!
//! A plugin only names the language. The core turns a line of text into spans, each with a
//! [`TokenKind`]; an app maps a kind to a colour. Everything here is a pure function over text
//! the user typed: no state of its own, no disk, no network, no clock. The native editors (a
//! later step of PLUG-06c) reach it through the UniFFI and C ABI exports: [`wire`] gives kinds
//! and states as text for them, and [`complete`] holds the completion protocol.
//!
//! - [`tokenize_line`]: one line and the [`LineState`] the line before it left, to the line's
//!   tokens and the state after it. An editor re-colours from the edited line down and stops at
//!   the first line whose end state is the one it already had.
//! - [`tokenize_text`]: the same over a whole text, for tests and small inputs.
//!
//! Languages: `"postgresql"` (the PostgreSQL dialect) and `"sql"` (plain SQL: no nested block
//! comments, no dollar quoting, no `E''` strings; otherwise the same). Any other name gives
//! plain text. Names are matched without regard to ASCII case.
//!
//! Offsets: every token carries both its UTF-8 byte span, which is how Rust indexes the text,
//! and its UTF-16 span, which is how AppKit, WinUI and the web view index it. A span starts and
//! ends on a character boundary in both.
//!
//! Limits, so that no input can stall typing or grow the state:
//! - a line gives tokens up to [`MAX_LINE_BYTES`]; the rest of it is one plain-text token (it is
//!   still read, for the state alone, so the lines below are coloured rightly);
//! - block comments nest to [`MAX_COMMENT_DEPTH`]; an opener beyond that is not counted;
//! - a dollar-quote tag is at most [`MAX_DOLLAR_TAG_BYTES`] bytes; a longer one opens nothing.
//!
//! There is no recursion: nesting is a counter. Work and memory are linear in the input.

pub mod complete;
mod keywords;
mod sql;
pub mod wire;

/// The longest part of one line that is given as tokens, in bytes (64 KiB). What lies beyond is
/// one [`TokenKind::Text`] token, so a line cannot give more than this many tokens.
///
/// The part beyond is still read to the end of the line, without making tokens, so that the
/// line's end state is exact: a string that closes (or opens) past the limit is known to the
/// lines below. Stopping at the limit would mean guessing, and a wrong guess colours the rest
/// of the file as the inside of a string.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// The deepest nesting of PostgreSQL block comments that is counted. At this depth another
/// `/*` leaves the depth alone, so that many `*/` always get back to normal text.
pub const MAX_COMMENT_DEPTH: u8 = u8::MAX;

/// The longest dollar-quote tag, in bytes, not counting the two dollars. PostgreSQL sets no
/// limit; 63 bytes is the longest identifier it keeps. A longer tag is not a dollar quote here.
pub const MAX_DOLLAR_TAG_BYTES: usize = 63;

/// What a span of code is. An app maps each kind to a colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// A key word of the language, in any case.
    Keyword,
    /// A name that is none of the other kinds.
    Identifier,
    /// A `"quoted"` identifier, with its quotes and any `U&` prefix.
    QuotedIdentifier,
    /// A string literal of any form, with its quotes, prefix or dollar tags.
    String,
    /// A numeric literal.
    Number,
    /// A line comment or a block comment.
    Comment,
    /// One operator, such as `<=`, `::` or `||`.
    Operator,
    /// One of `,` `(` `)` `[` `]` `;` `.`
    Punctuation,
    /// A positional parameter, such as `$1`.
    Parameter,
    /// A built-in type name, or the name straight after a `::` cast.
    TypeName,
    /// A name with `(` straight after it that is not a key word or a type name.
    FunctionName,
    /// White space, or text that is nothing in the language (and all of an unknown language).
    Text,
    /// A string, quoted identifier or comment that the text never closes. Only
    /// [`tokenize_text`] gives this, because only it knows where the text ends.
    Error,
}

/// One span of a line (from [`tokenize_line`]) or of a text (from [`tokenize_text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token {
    pub kind: TokenKind,
    /// Where the span starts, in UTF-8 bytes.
    pub start: usize,
    /// How long the span is, in UTF-8 bytes. Never zero.
    pub len: usize,
    /// Where the span starts, in UTF-16 code units.
    pub utf16_start: usize,
    /// How long the span is, in UTF-16 code units.
    pub utf16_len: usize,
}

impl Token {
    /// The byte offset just past the span.
    pub fn end(&self) -> usize {
        self.start + self.len
    }

    /// The UTF-16 offset just past the span.
    pub fn utf16_end(&self) -> usize {
        self.utf16_start + self.utf16_len
    }
}

/// How a `'…'` string that is still open reads its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringMode {
    /// `'…'`, `U&'…'` and `N'…'`: `''` is a quote, a backslash is an ordinary character.
    Standard,
    /// `E'…'`: `''` is a quote, and a backslash escapes the character after it.
    Escape,
    /// `B'…'` and `X'…'`: the first quote ends it.
    Plain,
}

/// The tag of a dollar-quoted string that is still open: the text between the two dollars.
/// Bytes past the length are always zero, so two equal tags compare and hash equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DollarTag {
    len: u8,
    bytes: [u8; MAX_DOLLAR_TAG_BYTES],
}

impl DollarTag {
    /// A tag, or `None` when it is longer than [`MAX_DOLLAR_TAG_BYTES`].
    pub fn new(tag: &[u8]) -> Option<Self> {
        if tag.len() > MAX_DOLLAR_TAG_BYTES {
            return None;
        }
        let mut bytes = [0u8; MAX_DOLLAR_TAG_BYTES];
        bytes[..tag.len()].copy_from_slice(tag);
        Some(DollarTag { len: tag.len() as u8, bytes })
    }

    /// The tag, without its dollars.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// What a line leaves open for the line after it. It is all the tokenizer needs to know about
/// the lines above: small, comparable and cheap to copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LineState {
    /// Nothing is open.
    #[default]
    Normal,
    /// Inside a block comment, `depth` levels deep (1 to [`MAX_COMMENT_DEPTH`]).
    BlockComment { depth: u8 },
    /// Inside a `'…'` string.
    String { mode: StringMode },
    /// Inside a `"quoted"` identifier.
    QuotedIdentifier,
    /// Inside a dollar-quoted string that `$tag$` will close.
    DollarString { tag: DollarTag },
}

impl LineState {
    /// Whether a string, quoted identifier or comment is open. At the end of a text, this
    /// means it was never closed.
    pub fn is_open(&self) -> bool {
        *self != LineState::Normal
    }
}

/// The tokens of one line, and the state it leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineTokens {
    /// Spans with offsets from the start of the line. They cover the line with no gap and no
    /// overlap; an empty line has none.
    pub tokens: Vec<Token>,
    /// The state to give to the next line.
    pub end_state: LineState,
}

/// The tokens of a whole text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextTokens {
    /// Spans with offsets from the start of the text. They cover everything but the `\n` line
    /// breaks. A literal or comment still open at the end is [`TokenKind::Error`].
    pub spans: Vec<Token>,
    /// The state after the last line.
    pub end_state: LineState,
}

/// Tokenize one line of `language`, given the state the line before it left
/// ([`LineState::Normal`] for the first line).
///
/// `line` is the line without its line break. An unknown language gives one plain-text token
/// and [`LineState::Normal`]. This never fails and never panics, whatever the text and state.
pub fn tokenize_line(language: &str, line: &str, state: LineState) -> LineTokens {
    let mut tokens = Vec::new();
    let lexed = lex_line(sql::Dialect::named(language), line, state, Base::default(), &mut tokens);
    LineTokens { tokens, end_state: lexed.end_state }
}

/// Tokenize a whole text: [`tokenize_line`] over every line (split at `\n`), with offsets into
/// the text. For tests and small inputs; an editor keeps a state per line and calls
/// [`tokenize_line`] itself.
///
/// The one thing it adds: when the text ends inside a string, quoted identifier or comment,
/// the spans of that unclosed piece are [`TokenKind::Error`].
pub fn tokenize_text(language: &str, text: &str) -> TextTokens {
    let dialect = sql::Dialect::named(language);
    let mut spans = Vec::new();
    let mut state = LineState::Normal;
    // The index of the span that opened what is open now.
    let mut open_from = None;
    let mut base = Base::default();
    for line in text.split('\n') {
        let lexed = lex_line(dialect, line, state, base, &mut spans);
        state = lexed.end_state;
        open_from = if state.is_open() { lexed.opener.or(open_from) } else { None };
        base = Base { bytes: base.bytes + line.len() + 1, utf16: base.utf16 + lexed.utf16_len + 1 };
    }
    if let Some(from) = open_from {
        // After the opener there are only continuations of it, and the plain tails of cut lines.
        for span in spans[from..].iter_mut().filter(|span| span.kind != TokenKind::Text) {
            span.kind = TokenKind::Error;
        }
    }
    TextTokens { spans, end_state: state }
}

/// Where a line starts in the text its offsets count from.
#[derive(Clone, Copy, Default)]
struct Base {
    bytes: usize,
    utf16: usize,
}

/// What tokenizing one line gave, besides the tokens.
struct Lexed {
    end_state: LineState,
    /// The index in the output of the token that opened `end_state`, when this line opened it.
    opener: Option<usize>,
    /// The length of the line in UTF-16 code units.
    utf16_len: usize,
}

/// Tokenize `line` into `out`, with offsets counted from `base`.
fn lex_line(dialect: Option<sql::Dialect>, line: &str, state: LineState, base: Base, out: &mut Vec<Token>) -> Lexed {
    let cut = char_boundary_at_or_before(line, MAX_LINE_BYTES);
    let mut sink = Sink { bytes: line.as_bytes(), out, base, cut, at: 0, written: 0, written_utf16: 0 };
    let Some(dialect) = dialect else {
        // Nothing to cut: the whole line is one plain span.
        sink.cut = line.len();
        sink.push(TokenKind::Text, line.len());
        return Lexed { end_state: LineState::Normal, opener: None, utf16_len: sink.written_utf16 };
    };
    let (end_state, opener) = sql::lex(dialect, line.as_bytes(), state, &mut sink);
    sink.write_tail();
    Lexed { end_state, opener, utf16_len: sink.written_utf16 }
}

/// The largest character boundary of `line` that is not past `limit`.
fn char_boundary_at_or_before(line: &str, limit: usize) -> usize {
    if line.len() <= limit {
        return line.len();
    }
    // A character is at most four bytes, so this looks at four positions at most.
    (0..=limit).rev().find(|&at| line.is_char_boundary(at)).unwrap_or(0)
}

/// Collects the tokens of one line. Each token starts where the one before it ended, so the
/// spans cannot leave a gap or overlap.
///
/// Tokens are written up to `cut`. The tokenizer goes on past it, so that it knows the state
/// at the end of the line, but what it finds there is not written: a token that crosses the
/// cut is written up to it, later ones not at all, and [`Sink::write_tail`] covers the rest.
struct Sink<'a> {
    bytes: &'a [u8],
    out: &'a mut Vec<Token>,
    base: Base,
    /// Where tokens stop being written: a character boundary, at most [`MAX_LINE_BYTES`].
    cut: usize,
    /// Where the next token starts, from the start of the line.
    at: usize,
    /// How much of the line the written tokens cover, in bytes and in UTF-16 units.
    written: usize,
    written_utf16: usize,
}

impl Sink<'_> {
    /// The index the next written token will have in the output. Past the cut that is the
    /// index of the plain tail.
    fn next_index(&self) -> usize {
        self.out.len()
    }

    /// Add the token that runs from the end of the last one to `end`. Nothing is added when
    /// that is empty. `end` must be a character boundary; every caller ends a token at an
    /// ASCII byte, before one, or at the end of the line.
    fn push(&mut self, kind: TokenKind, end: usize) {
        let end = end.min(self.bytes.len());
        if end <= self.at {
            return;
        }
        self.at = end;
        self.write(kind, end.min(self.cut));
    }

    /// Cover what lies past the cut with one plain token.
    fn write_tail(&mut self) {
        self.write(TokenKind::Text, self.bytes.len());
    }

    /// Write the token from the end of the last written one to `end`, if that is not empty.
    fn write(&mut self, kind: TokenKind, end: usize) {
        if end <= self.written {
            return;
        }
        let utf16_len = utf16_units(&self.bytes[self.written..end]);
        self.out.push(Token { kind, start: self.base.bytes + self.written, len: end - self.written, utf16_start: self.base.utf16 + self.written_utf16, utf16_len });
        self.written = end;
        self.written_utf16 += utf16_len;
    }
}

/// How many UTF-16 code units the UTF-8 text in `bytes` takes: one for each character, and one
/// more for each character of four bytes.
fn utf16_units(bytes: &[u8]) -> usize {
    if bytes.is_ascii() {
        return bytes.len();
    }
    bytes.iter().filter(|&&b| (b & 0xC0) != 0x80).count() + bytes.iter().filter(|&&b| b >= 0xF0).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_units_counts_surrogate_pairs() {
        for text in ["", "abc", "é", "列", "😀", "aé列😀z", "\u{FFFD}\0"] {
            assert_eq!(utf16_units(text.as_bytes()), text.encode_utf16().count(), "{text}");
        }
    }

    #[test]
    fn the_cut_never_lands_inside_a_character() {
        assert_eq!(char_boundary_at_or_before("abc", 10), 3);
        assert_eq!(char_boundary_at_or_before("abc", 2), 2);
        for limit in 0..=8 {
            let cut = char_boundary_at_or_before("😀😀", limit);
            assert_eq!(cut, limit / 4 * 4);
        }
    }

    #[test]
    fn a_dollar_tag_keeps_its_unused_bytes_zero() {
        let short = DollarTag::new(b"ab").unwrap();
        assert_eq!(short.bytes[2..], [0u8; MAX_DOLLAR_TAG_BYTES - 2]);
        assert_eq!(short, DollarTag::new(b"ab").unwrap());
        assert!(DollarTag::new(&[b'a'; MAX_DOLLAR_TAG_BYTES]).is_some());
        assert!(DollarTag::new(&[b'a'; MAX_DOLLAR_TAG_BYTES + 1]).is_none());
    }
}
