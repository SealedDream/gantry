//! The SQL tokenizer: one line of text and the state carried into it, to tokens.
//!
//! The lexical rules are PostgreSQL's (`src/backend/parser/scan.l`; the documentation's
//! "Lexical Structure" chapter), read byte by byte:
//!
//! - identifiers start with a letter, `_` or any byte above ASCII, and go on with those,
//!   digits and `$`;
//! - `'…'`, `U&'…'` and `N'…'` strings double their quote; `E'…'` also takes backslash escapes;
//!   `B'…'` and `X'…'` end at the first quote; all of them may run over line breaks;
//! - `$tag$…$tag$` strings end at the first `$tag$` with the same tag, whatever is between;
//! - `/* … */` comments nest; `--` comments end with the line;
//! - numbers are decimal, `0x`, `0o` or `0b`, with `_` between digits, a fraction and an
//!   exponent;
//! - an operator is a run of operator characters that stops where a comment starts.
//!
//! Where colouring does not need PostgreSQL's strictness it is not copied: `1abc` is a number
//! and a name here, not an error, and a stray `$` is plain text.
//!
//! Every token ends at an ASCII byte, before one, or at the end of the line. Bytes above
//! ASCII are only ever taken in whole runs (in a name, or inside a literal or comment whose
//! delimiters are ASCII), so no token boundary can fall inside a character.

use super::keywords::{contains, KEYWORDS, TYPE_NAMES};
use super::{DollarTag, LineState, Sink, StringMode, TokenKind, MAX_COMMENT_DEPTH, MAX_DOLLAR_TAG_BYTES};

/// Which SQL the line is written in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Dialect {
    /// Plain SQL: block comments do not nest, and there are no dollar quotes or `E''` strings.
    Sql,
    PostgreSql,
}

impl Dialect {
    /// The dialect a plugin's language name stands for, if it is one of ours.
    pub(super) fn named(language: &str) -> Option<Self> {
        if language.eq_ignore_ascii_case("postgresql") {
            Some(Dialect::PostgreSql)
        } else if language.eq_ignore_ascii_case("sql") {
            Some(Dialect::Sql)
        } else {
            None
        }
    }

    fn is_postgresql(self) -> bool {
        self == Dialect::PostgreSql
    }
}

/// What a byte is at the start of a token.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Space,
    /// A letter, `_`, or a byte above ASCII: the start of a name.
    Letter,
    Digit,
    /// One of PostgreSQL's operator characters: `~ ! @ # ^ & | ` ? + - * / % < > =`.
    Operator,
    /// One of `, ( ) [ ] ;`.
    Punctuation,
    Dot,
    Colon,
    Quote,
    DoubleQuote,
    Dollar,
    /// Anything else: control characters, `\`, `{`, `}`.
    Other,
}

const fn class_of(byte: u8) -> Class {
    match byte {
        b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C => Class::Space,
        b'A'..=b'Z' | b'a'..=b'z' | b'_' | 0x80..=0xFF => Class::Letter,
        b'0'..=b'9' => Class::Digit,
        b'~' | b'!' | b'@' | b'#' | b'^' | b'&' | b'|' | b'`' | b'?' | b'+' | b'-' | b'*' | b'/' | b'%' | b'<' | b'>' | b'=' => Class::Operator,
        b',' | b'(' | b')' | b'[' | b']' | b';' => Class::Punctuation,
        b'.' => Class::Dot,
        b':' => Class::Colon,
        b'\'' => Class::Quote,
        b'"' => Class::DoubleQuote,
        b'$' => Class::Dollar,
        _ => Class::Other,
    }
}

const CLASSES: [Class; 256] = {
    let mut table = [Class::Other; 256];
    let mut byte = 0;
    while byte < 256 {
        table[byte] = class_of(byte as u8);
        byte += 1;
    }
    table
};

fn class(byte: u8) -> Class {
    CLASSES[byte as usize]
}

/// Whether a byte can go on a name: a letter, a digit or `$`.
fn continues_name(byte: u8) -> bool {
    matches!(class(byte), Class::Letter | Class::Digit) || byte == b'$'
}

/// Whether a byte can go on a dollar-quote tag: a letter or a digit, but not `$`.
fn continues_tag(byte: u8) -> bool {
    matches!(class(byte), Class::Letter | Class::Digit)
}

/// The first index at or after `from` whose byte fails `keep`, or the length of `bytes`.
fn run_end(bytes: &[u8], from: usize, keep: impl Fn(u8) -> bool) -> usize {
    bytes[from..].iter().position(|&b| !keep(b)).map_or(bytes.len(), |offset| from + offset)
}

/// A line that ends with something open: the state to carry, and the index of the token that
/// opened it when this line did.
type Open = (LineState, Option<usize>);

/// Tokenize `bytes` (one whole line) into `sink`, which writes tokens up to the line limit.
///
/// Returns the state after the line and, when the line itself opened what that state holds
/// open, the index of the token that opened it.
pub(super) fn lex(dialect: Dialect, bytes: &[u8], state: LineState, sink: &mut Sink<'_>) -> Open {
    let mut lexer = Lexer { dialect, bytes, sink, at: 0, after_cast: false };
    // First, whatever the lines above left open.
    if state.is_open() {
        if bytes.is_empty() {
            return (state, None);
        }
        let (end, after) = scan_inside(bytes, 0, state, dialect);
        lexer.take(kind_inside(state), end);
        if after.is_open() {
            return (after, None);
        }
    }
    while lexer.at < bytes.len() {
        let before = lexer.at;
        if let Some(open) = lexer.step() {
            return open;
        }
        if lexer.at <= before {
            // Every step takes at least one byte. If one ever did not, the rest of the line
            // would be plain text rather than a loop that never ends.
            lexer.take(TokenKind::Text, bytes.len());
        }
    }
    (LineState::Normal, None)
}

struct Lexer<'a, 'sink, 'line> {
    dialect: Dialect,
    bytes: &'a [u8],
    sink: &'sink mut Sink<'line>,
    /// Where the next token starts.
    at: usize,
    /// Whether the last token that was not white space was `::`.
    after_cast: bool,
}

impl Lexer<'_, '_, '_> {
    /// Take one token. Returns `Some` when it runs to the end of the line and stays open.
    fn step(&mut self) -> Option<Open> {
        let at = self.at;
        let next = self.bytes.get(at + 1).copied();
        let after_cast = std::mem::take(&mut self.after_cast);
        match class(self.bytes[at]) {
            Class::Space => {
                // White space does not come between a cast and its type.
                self.after_cast = after_cast;
                self.take(TokenKind::Text, run_end(self.bytes, at, |b| class(b) == Class::Space));
            }
            Class::Letter => return self.word(after_cast),
            Class::Digit => self.take(TokenKind::Number, number_end(self.bytes, at)),
            Class::Dot if next.is_some_and(|b| b.is_ascii_digit()) => self.take(TokenKind::Number, number_end(self.bytes, at)),
            Class::Dot if next == Some(b'.') => {
                // `..` is one lexeme in PostgreSQL, so in `1..2` the second dot is not the
                // start of `.2`. It is given as two punctuation tokens.
                self.take(TokenKind::Punctuation, at + 1);
                self.take(TokenKind::Punctuation, at + 2);
            }
            Class::Dot | Class::Punctuation => self.take(TokenKind::Punctuation, at + 1),
            Class::Colon => {
                let end = if matches!(next, Some(b':' | b'=')) { at + 2 } else { at + 1 };
                self.after_cast = next == Some(b':');
                self.take(TokenKind::Operator, end);
            }
            Class::Operator => return self.operator(next),
            Class::Quote => return self.open(at + 1, LineState::String { mode: StringMode::Standard }),
            Class::DoubleQuote => return self.open(at + 1, LineState::QuotedIdentifier),
            Class::Dollar => return self.dollar(next),
            Class::Other => self.take(TokenKind::Text, run_end(self.bytes, at, |b| class(b) == Class::Other)),
        }
        None
    }

    /// End a token at `end`.
    fn take(&mut self, kind: TokenKind, end: usize) {
        self.sink.push(kind, end);
        self.at = end;
    }

    /// Take a string, quoted identifier or comment whose opener ends at `body` and which reads
    /// as `inside` from there. Returns `Some` when the line ends before it closes.
    fn open(&mut self, body: usize, inside: LineState) -> Option<Open> {
        let (end, after) = scan_inside(self.bytes, body, inside, self.dialect);
        let index = self.sink.next_index();
        self.take(kind_inside(inside), end);
        after.is_open().then_some((after, Some(index)))
    }

    /// A token that starts with a letter: a string with a prefix, or a name.
    fn word(&mut self, after_cast: bool) -> Option<Open> {
        let (bytes, at) = (self.bytes, self.at);
        let string = |mode| LineState::String { mode };
        // A prefix counts only when the quote touches it; `at` is the start of a token, so the
        // letter is not the end of a longer name.
        match (bytes[at].to_ascii_lowercase(), bytes.get(at + 1), bytes.get(at + 2)) {
            (b'e', Some(b'\''), _) if self.dialect.is_postgresql() => return self.open(at + 2, string(StringMode::Escape)),
            (b'b' | b'x', Some(b'\''), _) => return self.open(at + 2, string(StringMode::Plain)),
            (b'n', Some(b'\''), _) => return self.open(at + 2, string(StringMode::Standard)),
            (b'u', Some(b'&'), Some(b'\'')) => return self.open(at + 3, string(StringMode::Standard)),
            (b'u', Some(b'&'), Some(b'"')) => return self.open(at + 3, LineState::QuotedIdentifier),
            _ => {}
        }
        let end = run_end(bytes, at + 1, continues_name);
        let word = &bytes[at..end];
        let kind = if after_cast || contains(TYPE_NAMES, word) {
            TokenKind::TypeName
        } else if contains(KEYWORDS, word) {
            TokenKind::Keyword
        } else if bytes.get(end) == Some(&b'(') {
            TokenKind::FunctionName
        } else {
            TokenKind::Identifier
        };
        self.take(kind, end);
        None
    }

    /// A token that starts with an operator character: a comment or an operator.
    fn operator(&mut self, next: Option<u8>) -> Option<Open> {
        let (bytes, at) = (self.bytes, self.at);
        match (bytes[at], next) {
            (b'-', Some(b'-')) => {
                self.take(TokenKind::Comment, run_end(bytes, at, |b| b != b'\n' && b != b'\r'));
                return None;
            }
            (b'/', Some(b'*')) => return self.open(at + 2, LineState::BlockComment { depth: 1 }),
            _ => {}
        }
        // The operator stops where a comment starts inside it, as in PostgreSQL.
        let starts_comment = |at: usize| matches!((bytes[at], bytes.get(at + 1)), (b'-', Some(b'-')) | (b'/', Some(b'*')));
        let mut end = at + 1;
        while end < bytes.len() && class(bytes[end]) == Class::Operator && !starts_comment(end) {
            end += 1;
        }
        self.take(TokenKind::Operator, operator_end(bytes, at, end));
        None
    }

    /// A token that starts with `$`: a parameter, a dollar-quoted string, or a stray dollar.
    fn dollar(&mut self, next: Option<u8>) -> Option<Open> {
        let (bytes, at) = (self.bytes, self.at);
        if next.is_some_and(|b| b.is_ascii_digit()) {
            self.take(TokenKind::Parameter, run_end(bytes, at + 1, |b| b.is_ascii_digit()));
            return None;
        }
        if self.dialect.is_postgresql() {
            if let Some((tag, body)) = dollar_opener(bytes, at) {
                return self.open(body, LineState::DollarString { tag });
            }
        }
        self.take(TokenKind::Text, at + 1);
        None
    }
}

/// PostgreSQL's rule for the run of operator characters from `at` to `end`: an operator of
/// more than one character cannot end in `+` or `-`, unless it also holds one of
/// `~ ! @ # % ^ & | ` ?`. So `=-` is `=` and then `-`, and `a=-1` reads as `a = -1`, while
/// `@-` and `?-` stay whole. Returns where the operator ends; never before `at + 1`.
fn operator_end(bytes: &[u8], at: usize, end: usize) -> usize {
    if bytes[at..end].iter().any(|b| b"~!@#%^&|`?".contains(b)) {
        return end;
    }
    let mut end = end;
    while end > at + 1 && matches!(bytes[end - 1], b'+' | b'-') {
        end -= 1;
    }
    end
}

/// The kind of the token that is the inside of `state`.
fn kind_inside(state: LineState) -> TokenKind {
    match state {
        LineState::Normal => TokenKind::Text,
        LineState::BlockComment { .. } => TokenKind::Comment,
        LineState::String { .. } | LineState::DollarString { .. } => TokenKind::String,
        LineState::QuotedIdentifier => TokenKind::QuotedIdentifier,
    }
}

/// Read on from `from` inside the string, quoted identifier or comment that `inside` names.
/// Returns where it ends and the state after: `Normal` when it closed, and otherwise the end
/// of the line and the state to carry.
fn scan_inside(bytes: &[u8], from: usize, inside: LineState, dialect: Dialect) -> (usize, LineState) {
    let closed_at = match inside {
        LineState::Normal => Some(from),
        LineState::BlockComment { depth } => {
            let (end, depth) = block_comment_end(bytes, from, depth, dialect.is_postgresql());
            return (end, if depth == 0 { LineState::Normal } else { LineState::BlockComment { depth } });
        }
        LineState::String { mode } => quoted_end(bytes, from, b'\'', mode),
        LineState::QuotedIdentifier => quoted_end(bytes, from, b'"', StringMode::Standard),
        LineState::DollarString { tag } => dollar_body_end(bytes, from, tag.as_bytes()),
    };
    closed_at.map_or((bytes.len(), inside), |end| (end, LineState::Normal))
}

/// Inside a block comment at `depth`, from `from`: where the comment ends and the depth there
/// (0 when it closed; otherwise the end of the line and the depth to carry).
///
/// With `nests`, `/*` goes one deeper, up to [`MAX_COMMENT_DEPTH`], and `*/` comes one back.
/// Without, the first `*/` closes the comment.
fn block_comment_end(bytes: &[u8], from: usize, depth: u8, nests: bool) -> (usize, u8) {
    let (mut at, mut depth) = (from, depth);
    while at + 1 < bytes.len() {
        match (bytes[at], bytes[at + 1]) {
            (b'*', b'/') => {
                at += 2;
                depth = if nests { depth.saturating_sub(1) } else { 0 };
                if depth == 0 {
                    return (at, 0);
                }
            }
            (b'/', b'*') if nests => {
                at += 2;
                if depth < MAX_COMMENT_DEPTH {
                    depth += 1;
                }
            }
            _ => at += 1,
        }
    }
    (bytes.len(), depth)
}

/// Inside a quoted string or identifier, from `from`: the index just past the closing quote,
/// or `None` when the line ends first.
fn quoted_end(bytes: &[u8], from: usize, quote: u8, mode: StringMode) -> Option<usize> {
    let mut at = from;
    while at < bytes.len() {
        let byte = bytes[at];
        if byte == quote {
            if mode != StringMode::Plain && bytes.get(at + 1) == Some(&quote) {
                at += 2;
                continue;
            }
            return Some(at + 1);
        }
        // A backslash takes the next byte with it. If that byte starts a longer character, the
        // bytes after it are not quotes or backslashes, so the scan cannot stop inside it. At
        // the end of the line the backslash takes the line break.
        at += if byte == b'\\' && mode == StringMode::Escape { 2 } else { 1 };
    }
    None
}

/// At the `$` at `at`: the tag and the index where the body starts, when a dollar quote opens
/// there (`$$` or `$tag$`, the tag starting with a letter and no longer than the cap).
fn dollar_opener(bytes: &[u8], at: usize) -> Option<(DollarTag, usize)> {
    let tag_start = at + 1;
    let mut tag_end = tag_start;
    if bytes.get(tag_start).is_some_and(|&b| class(b) == Class::Letter) {
        // One byte past the cap is enough to know the tag is too long.
        let limit = bytes.len().min(tag_start + MAX_DOLLAR_TAG_BYTES + 1);
        tag_end = run_end(&bytes[..limit], tag_start + 1, continues_tag);
    }
    if bytes.get(tag_end) != Some(&b'$') {
        return None;
    }
    Some((DollarTag::new(&bytes[tag_start..tag_end])?, tag_end + 1))
}

/// Inside a dollar-quoted string, from `from`: the index just past the closing `$tag$`, or
/// `None` when the line ends first. Every `$` is tried as the start of the closing tag, which
/// is what PostgreSQL's scanner comes to.
fn dollar_body_end(bytes: &[u8], from: usize, tag: &[u8]) -> Option<usize> {
    let mut at = from;
    while let Some(offset) = bytes.get(at..)?.iter().position(|&b| b == b'$') {
        let tag_start = at + offset + 1;
        let tag_end = tag_start + tag.len();
        if bytes.get(tag_start..tag_end) == Some(tag) && bytes.get(tag_end) == Some(&b'$') {
            return Some(tag_end + 1);
        }
        at = tag_start;
    }
    None
}

/// The end of the number that starts at `at` (a digit, or a `.` with a digit after it).
fn number_end(bytes: &[u8], at: usize) -> usize {
    if bytes[at] == b'0' {
        let digits: Option<fn(u8) -> bool> = match bytes.get(at + 1).map(u8::to_ascii_lowercase) {
            Some(b'x') => Some(|b| b.is_ascii_hexdigit()),
            Some(b'o') => Some(|b| matches!(b, b'0'..=b'7')),
            Some(b'b') => Some(|b| matches!(b, b'0' | b'1')),
            _ => None,
        };
        if let Some(is_digit) = digits {
            let end = digits_end(bytes, at + 2, is_digit, true);
            if end > at + 2 {
                return end;
            }
        }
    }
    let is_decimal = |b: u8| b.is_ascii_digit();
    let mut end = digits_end(bytes, at, is_decimal, false);
    // A fraction; but `1..2` is a number, two dots and a number.
    if bytes.get(end) == Some(&b'.') && bytes.get(end + 1) != Some(&b'.') {
        end = digits_end(bytes, end + 1, is_decimal, false);
    }
    // An exponent counts only with a digit in it.
    if bytes.get(end).is_some_and(|b| b.eq_ignore_ascii_case(&b'e')) {
        let sign = usize::from(matches!(bytes.get(end + 1), Some(b'+' | b'-')));
        let digits = end + 1 + sign;
        let exponent_end = digits_end(bytes, digits, is_decimal, false);
        if exponent_end > digits {
            end = exponent_end;
        }
    }
    end
}

/// The end of a run of digits from `from`, where a single `_` may stand before a digit. The
/// first digit may have one too only when `leading_underscore` (as after `0x`).
fn digits_end(bytes: &[u8], from: usize, is_digit: impl Fn(u8) -> bool, leading_underscore: bool) -> usize {
    let digit_at = |at: usize| bytes.get(at).is_some_and(|&b| is_digit(b));
    let mut at = from;
    loop {
        if digit_at(at) {
            at += 1;
        } else if bytes.get(at) == Some(&b'_') && digit_at(at + 1) && (at > from || leading_underscore) {
            at += 2;
        } else {
            return at;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_byte_has_the_class_postgresql_gives_it() {
        for byte in 0..=255u8 {
            let expected = match byte {
                b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C => Class::Space,
                b'$' => Class::Dollar,
                b'\'' => Class::Quote,
                b'"' => Class::DoubleQuote,
                b'.' => Class::Dot,
                b':' => Class::Colon,
                _ if b"~!@#^&|`?+-*/%<>=".contains(&byte) => Class::Operator,
                _ if b",()[];".contains(&byte) => Class::Punctuation,
                _ if byte.is_ascii_digit() => Class::Digit,
                _ if byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80 => Class::Letter,
                _ => Class::Other,
            };
            assert!(class(byte) == expected, "byte {byte:#04x}");
        }
    }

    #[test]
    fn the_scanners_stop_at_the_end_of_the_line() {
        assert_eq!(quoted_end(b"abc", 3, b'\'', StringMode::Standard), None);
        assert_eq!(quoted_end(b"ab\\", 0, b'\'', StringMode::Escape), None);
        assert_eq!(quoted_end(b"ab'", 0, b'\'', StringMode::Escape), Some(3));
        assert_eq!(block_comment_end(b"*", 0, 1, true), (1, 1));
        assert_eq!(block_comment_end(b"", 0, 1, true), (0, 1));
        assert_eq!(dollar_body_end(b"x$", 0, b""), None);
        assert_eq!(dollar_body_end(b"x$$", 0, b""), Some(3));
        assert_eq!(dollar_body_end(b"x$", 5, b""), None);
        assert_eq!(number_end(b"0x", 0), 1);
        assert_eq!(number_end(b"1e", 0), 1);
        assert_eq!(number_end(b".5", 0), 2);
    }

    #[test]
    fn a_dollar_opener_reads_at_most_one_byte_past_the_tag_cap() {
        let long = format!("${}$", "a".repeat(MAX_DOLLAR_TAG_BYTES + 50));
        assert!(dollar_opener(long.as_bytes(), 0).is_none());
        let longest = format!("${}$x", "a".repeat(MAX_DOLLAR_TAG_BYTES));
        let (tag, body) = dollar_opener(longest.as_bytes(), 0).unwrap();
        assert_eq!(tag.as_bytes().len(), MAX_DOLLAR_TAG_BYTES);
        assert_eq!(body, MAX_DOLLAR_TAG_BYTES + 2);
        assert!(dollar_opener(b"$1$", 0).is_none());
        assert!(dollar_opener(b"$a", 0).is_none());
        assert_eq!(dollar_opener(b"$$", 0).map(|(tag, body)| (tag.as_bytes().len(), body)), Some((0, 2)));
    }
}
