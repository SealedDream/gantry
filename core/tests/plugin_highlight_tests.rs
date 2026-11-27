//! PLUG-06c1: the SQL tokenizer for code highlighting.
//! Spec: docs/specs/plugins.md, section 5 ("Highlighting") and section 14 (the 1 MiB row).
use std::time::{Duration, Instant};

use bastion_core::plugin::highlight::{tokenize_line, tokenize_text, DollarTag, LineState, StringMode, Token, TokenKind, MAX_COMMENT_DEPTH, MAX_DOLLAR_TAG_BYTES, MAX_LINE_BYTES};
use TokenKind::*;

/// `TokenKind::String` is in scope, so the text type gets its own name here.
type Str = std::string::String;

const PG: &str = "postgresql";
const SQL: &str = "sql";
const MIB: usize = 1024 * 1024;

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// Spans must cover `text` with no gap and no overlap, never split a character, and carry
/// UTF-16 offsets that agree with the UTF-8 ones.
fn assert_covers(text: &str, tokens: &[Token]) {
    let (mut at, mut at16) = (0, 0);
    for token in tokens {
        assert!(token.len > 0, "empty token {token:?}");
        assert_eq!(token.start, at, "gap or overlap before {token:?}");
        assert_eq!(token.utf16_start, at16, "UTF-16 gap or overlap before {token:?}");
        assert!(text.is_char_boundary(token.start) && text.is_char_boundary(token.end()), "{token:?} splits a character");
        assert_eq!(token.utf16_len, text[token.start..token.end()].encode_utf16().count(), "UTF-16 length of {token:?}");
        at = token.end();
        at16 = token.utf16_end();
    }
    assert_eq!(at, text.len(), "spans stop before the end of the line");
    assert_eq!(at16, text.encode_utf16().count());
}

/// Tokenize one line from `state`, check the spans, and return them with the end state.
fn lex_from(language: &str, line: &str, state: LineState) -> (Vec<Token>, LineState) {
    let result = tokenize_line(language, line, state);
    assert_covers(line, &result.tokens);
    (result.tokens, result.end_state)
}

/// The kind and text of every token on a line that is not white space.
fn lex<'a>(language: &str, line: &'a str) -> Vec<(TokenKind, &'a str)> {
    let (tokens, _) = lex_from(language, line, LineState::Normal);
    visible(line, &tokens)
}

fn visible<'a>(line: &'a str, tokens: &[Token]) -> Vec<(TokenKind, &'a str)> {
    tokens.iter().map(|t| (t.kind, &line[t.start..t.end()])).filter(|(kind, text)| !(*kind == Text && text.trim().is_empty())).collect()
}

fn end_state(language: &str, line: &str) -> LineState {
    lex_from(language, line, LineState::Normal).1
}

/// The kind of the token that holds `needle`'s first byte.
fn kind_of(language: &str, line: &str, needle: &str) -> TokenKind {
    let at = line.find(needle).unwrap_or_else(|| panic!("{needle} is not in {line}"));
    let (tokens, _) = lex_from(language, line, LineState::Normal);
    tokens.iter().find(|t| t.start <= at && at < t.end()).unwrap().kind
}

fn tag(bytes: &[u8]) -> LineState {
    LineState::DollarString { tag: DollarTag::new(bytes).unwrap() }
}

/// What an editor does: tokenize every line with the state the line before it left.
/// Returns the tokens with offsets into the whole text, and the end state of every line.
fn by_lines(language: &str, text: &str) -> (Vec<Token>, Vec<LineState>) {
    let (mut all, mut states) = (Vec::new(), Vec::new());
    let (mut state, mut base, mut base16) = (LineState::Normal, 0, 0);
    for line in text.split('\n') {
        let (tokens, end) = lex_from(language, line, state);
        all.extend(tokens.into_iter().map(|t| Token { start: t.start + base, utf16_start: t.utf16_start + base16, ..t }));
        state = end;
        states.push(end);
        base += line.len() + 1;
        base16 += line.encode_utf16().count() + 1;
    }
    (all, states)
}

/// A small deterministic generator (xorshift64*), so a failure can be repeated.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const SAMPLE: &str = r#"-- Orders report, with every kind of token
CREATE TABLE IF NOT EXISTS "Order Lines" (
    id          bigserial PRIMARY KEY,
    order_id    integer NOT NULL REFERENCES orders (id),
    note        text DEFAULT 'it''s new',
    price       numeric(10, 2) CHECK (price >= 0.00),
    tags        jsonb DEFAULT '{}'::jsonb
);
/* a block comment
   /* nested */ that goes on
*/
CREATE OR REPLACE FUNCTION total(p_order integer) RETURNS numeric AS $fn$
DECLARE
    result numeric := 0;
BEGIN
    SELECT sum(price) INTO result FROM "Order Lines" WHERE order_id = p_order; -- $1
    RETURN coalesce(result, 0) + 1e3 * 0x1F;
END;
$fn$ LANGUAGE plpgsql;
SELECT o.id, upper(c.name) AS "Name", E'tab\there', U&'d\0061t\+000061', B'1010', X'1F'
  FROM orders o JOIN customers c ON c.id = o.customer_id
 WHERE o.created_at > now() - interval '7 days' AND o.total::numeric(12,2) <> $1
   AND c.email ~* '^[a-z]+@example\.test$' OR o.tags @> '{"vip": true}'
 ORDER BY 1 DESC LIMIT 1_000;
COPY "Order Lines" (order_id, note) FROM STDIN WITH (FORMAT csv, HEADER true);
"#;

/// About `bytes` of realistic SQL, made of whole copies of [`SAMPLE`].
fn big_sql(bytes: usize) -> Str {
    SAMPLE.repeat(bytes / SAMPLE.len() + 1)
}

// ---------------------------------------------------------------------------------------------
// Token kinds
// ---------------------------------------------------------------------------------------------

#[test]
fn each_token_kind_on_its_own() {
    assert_eq!(lex(PG, "SELECT"), [(Keyword, "SELECT")]);
    assert_eq!(lex(PG, "customers"), [(Identifier, "customers")]);
    assert_eq!(lex(PG, r#""Order Lines""#), [(QuotedIdentifier, r#""Order Lines""#)]);
    assert_eq!(lex(PG, "'text'"), [(String, "'text'")]);
    assert_eq!(lex(PG, "42"), [(Number, "42")]);
    assert_eq!(lex(PG, "-- note"), [(Comment, "-- note")]);
    assert_eq!(lex(PG, "/* note */"), [(Comment, "/* note */")]);
    assert_eq!(lex(PG, "<="), [(Operator, "<=")]);
    assert_eq!(lex(PG, ";"), [(Punctuation, ";")]);
    assert_eq!(lex(PG, "$1"), [(Parameter, "$1")]);
    assert_eq!(lex(PG, "integer"), [(TypeName, "integer")]);
    assert_eq!(lex(PG, "now()"), [(FunctionName, "now"), (Punctuation, "("), (Punctuation, ")")]);
    assert_eq!(lex(PG, "  \t "), []);
    assert_eq!(lex_from(PG, "  \t ", LineState::Normal).0.iter().map(|t| t.kind).collect::<Vec<_>>(), [Text]);
    assert_eq!(lex(PG, "\\ {"), [(Text, "\\"), (Text, "{")]);
    assert!(lex_from(PG, "", LineState::Normal).0.is_empty());
    // Error is only ever given by the whole-text helper, for what the text leaves open.
    assert_eq!(tokenize_text(PG, "'open").spans.iter().map(|t| t.kind).collect::<Vec<_>>(), [Error]);
}

#[test]
fn keywords_ignore_case_and_do_not_match_inside_a_word() {
    for word in ["select", "SELECT", "SeLeCt", "current_timestamp", "Xmlnamespaces"] {
        assert_eq!(lex(PG, word), [(Keyword, word)], "{word}");
    }
    for word in ["selects", "_select", "select1", "sélect", "current_timestamp_x"] {
        assert_eq!(lex(PG, word), [(Identifier, word)], "{word}");
    }
}

#[test]
fn identifiers_take_dollars_and_bytes_above_ascii_as_postgresql_does() {
    assert_eq!(lex(PG, "tab$1 naïve_列 _x9"), [(Identifier, "tab$1"), (Identifier, "naïve_列"), (Identifier, "_x9")]);
    // A dollar inside an identifier never opens a dollar quote.
    assert_eq!(lex(PG, "a$$b$$"), [(Identifier, "a$$b$$")]);
}

#[test]
fn quoted_identifiers_double_their_quote_and_take_a_unicode_prefix() {
    assert_eq!(lex(PG, r#""a""b" c"#), [(QuotedIdentifier, r#""a""b""#), (Identifier, "c")]);
    assert_eq!(lex(PG, r#"U&"d\0061t" u&"x""#), [(QuotedIdentifier, r#"U&"d\0061t""#), (QuotedIdentifier, r#"u&"x""#)]);
    assert_eq!(end_state(PG, r#"SELECT "open"#), LineState::QuotedIdentifier);
    let (tokens, state) = lex_from(PG, r#"still" + 1"#, LineState::QuotedIdentifier);
    assert_eq!(visible(r#"still" + 1"#, &tokens), [(QuotedIdentifier, "still\""), (Operator, "+"), (Number, "1")]);
    assert_eq!(state, LineState::Normal);
}

#[test]
fn numbers_in_every_form() {
    for number in ["0", "42", "3.14", ".5", "1.", "1e10", "1.5E-3", "2e+7", ".5e1", "0xFF", "0Xff", "0o17", "0b101", "1_000_000", "0x_ff", "0b_1_0", "1_0.2_5e1_0"] {
        assert_eq!(lex(PG, number), [(Number, number)], "{number}");
    }
    assert_eq!(lex(PG, "1..2"), [(Number, "1"), (Punctuation, "."), (Punctuation, "."), (Number, "2")]);
    assert_eq!(lex(PG, "a..5"), [(Identifier, "a"), (Punctuation, "."), (Punctuation, "."), (Number, "5")]);
    assert_eq!(lex(PG, "...5"), [(Punctuation, "."), (Punctuation, "."), (Number, ".5")]);
    assert_eq!(lex(PG, "1_"), [(Number, "1"), (Identifier, "_")]);
    assert_eq!(lex(PG, "1__0"), [(Number, "1"), (Identifier, "__0")]);
    assert_eq!(lex(PG, "1e"), [(Number, "1"), (Identifier, "e")]);
    assert_eq!(lex(PG, "1e+"), [(Number, "1"), (Identifier, "e"), (Operator, "+")]);
    assert_eq!(lex(PG, "0x"), [(Number, "0"), (Identifier, "x")]);
    assert_eq!(lex(PG, "0o8"), [(Number, "0"), (Identifier, "o8")]);
    assert_eq!(lex(PG, "0b2"), [(Number, "0"), (Identifier, "b2")]);
    assert_eq!(lex(PG, "a.5"), [(Identifier, "a"), (Number, ".5")]);
    assert_eq!(lex(PG, "a.b"), [(Identifier, "a"), (Punctuation, "."), (Identifier, "b")]);
    assert_eq!(lex(PG, "-1"), [(Operator, "-"), (Number, "1")]);
}

#[test]
fn operators_and_punctuation() {
    for operator in ["+", "-", "*", "/", "%", "^", "<>", "!=", ">=", "||", "->>", "@>", "#>>", "~*", "&&", "|/", "`", "?", "::", ":=", ":"] {
        assert_eq!(lex(PG, operator), [(Operator, operator)], "{operator}");
    }
    for mark in [",", "(", ")", "[", "]", ";", "."] {
        assert_eq!(lex(PG, mark), [(Punctuation, mark)], "{mark}");
    }
    assert_eq!(lex(PG, "a[1:2]"), [(Identifier, "a"), (Punctuation, "["), (Number, "1"), (Operator, ":"), (Number, "2"), (Punctuation, "]")]);
    assert_eq!(lex(PG, "(("), [(Punctuation, "("), (Punctuation, "(")]);
    // An operator stops where a comment starts, as in PostgreSQL.
    assert_eq!(lex(PG, "a +-- c"), [(Identifier, "a"), (Operator, "+"), (Comment, "-- c")]);
    assert_eq!(lex(PG, "a */* c */"), [(Identifier, "a"), (Operator, "*"), (Comment, "/* c */")]);
    assert_eq!(lex(PG, "a - -1"), [(Identifier, "a"), (Operator, "-"), (Operator, "-"), (Number, "1")]);
    assert_eq!(lex(PG, "*/"), [(Operator, "*/")]);
    // A multi-character operator cannot end in `+` or `-`, unless it holds one of
    // ~ ! @ # % ^ & | ` ? (PostgreSQL's rule, so that `a=-1` is `a = -1`).
    assert_eq!(lex(PG, "=-1"), [(Operator, "="), (Operator, "-"), (Number, "1")]);
    assert_eq!(lex(PG, "a=-b"), [(Identifier, "a"), (Operator, "="), (Operator, "-"), (Identifier, "b")]);
    assert_eq!(lex(PG, "a<=+b"), [(Identifier, "a"), (Operator, "<="), (Operator, "+"), (Identifier, "b")]);
    assert_eq!(lex(PG, "*-+"), [(Operator, "*"), (Operator, "-"), (Operator, "+")]);
    assert_eq!(lex(PG, "@-"), [(Operator, "@-")]);
    assert_eq!(lex(PG, "?-"), [(Operator, "?-")]);
    assert_eq!(lex(PG, "%+"), [(Operator, "%+")]);
    assert_eq!(lex(PG, "=-@"), [(Operator, "=-@")]);
    assert_eq!(lex(PG, "+-"), [(Operator, "+"), (Operator, "-")]);
    assert_eq!(lex(PG, "-"), [(Operator, "-")]);
    assert_eq!(lex(SQL, "a=-1"), lex(PG, "a=-1"));
}

#[test]
fn casts_type_names_and_function_names() {
    assert_eq!(lex(PG, "x::my_type"), [(Identifier, "x"), (Operator, "::"), (TypeName, "my_type")]);
    assert_eq!(lex(PG, "x :: \t regclass"), [(Identifier, "x"), (Operator, "::"), (TypeName, "regclass")]);
    // A key word straight after a cast is a type name there (`::name`, `::char`).
    assert_eq!(kind_of(PG, "x::name", "name"), TypeName);
    assert_eq!(kind_of(PG, "SELECT name", "name"), Keyword);
    assert_eq!(lex(PG, r#"x::"T""#), [(Identifier, "x"), (Operator, "::"), (QuotedIdentifier, r#""T""#)]);
    // Only the token straight after the cast.
    assert_eq!(lex(PG, "x::int y"), [(Identifier, "x"), (Operator, "::"), (TypeName, "int"), (Identifier, "y")]);
    assert_eq!(lex(PG, "x::1 y"), [(Identifier, "x"), (Operator, "::"), (Number, "1"), (Identifier, "y")]);
    for name in ["integer", "INT", "bigint", "text", "varchar", "timestamptz", "jsonb", "uuid", "boolean", "bytea", "numeric"] {
        assert_eq!(lex(PG, name), [(TypeName, name)], "{name}");
    }
    // Common column names are not coloured as types.
    assert_eq!(lex(PG, "path point"), [(Identifier, "path"), (Identifier, "point")]);
    assert_eq!(kind_of(PG, "my_func(1)", "my_func"), FunctionName);
    assert_eq!(kind_of(PG, "my_func (1)", "my_func"), Identifier);
    assert_eq!(kind_of(PG, "coalesce(a, b)", "coalesce"), Keyword);
    assert_eq!(kind_of(PG, "varchar(10)", "varchar"), TypeName);
}

#[test]
fn a_select_with_casts() {
    let line = "SELECT o.id::text, count(*) AS n, $1::int4 FROM \"Orders\" o WHERE o.total >= 10.5 AND note <> 'x' -- done";
    assert_eq!(
        lex(PG, line),
        [
            (Keyword, "SELECT"),
            (Identifier, "o"),
            (Punctuation, "."),
            (Identifier, "id"),
            (Operator, "::"),
            (TypeName, "text"),
            (Punctuation, ","),
            (FunctionName, "count"),
            (Punctuation, "("),
            (Operator, "*"),
            (Punctuation, ")"),
            (Keyword, "AS"),
            (Identifier, "n"),
            (Punctuation, ","),
            (Parameter, "$1"),
            (Operator, "::"),
            (TypeName, "int4"),
            (Keyword, "FROM"),
            (QuotedIdentifier, "\"Orders\""),
            (Identifier, "o"),
            (Keyword, "WHERE"),
            (Identifier, "o"),
            (Punctuation, "."),
            (Identifier, "total"),
            (Operator, ">="),
            (Number, "10.5"),
            (Keyword, "AND"),
            (Identifier, "note"),
            (Operator, "<>"),
            (String, "'x'"),
            (Comment, "-- done"),
        ]
    );
}

#[test]
fn a_create_function_with_a_dollar_quoted_body() {
    let text = "CREATE FUNCTION add_one(n integer) RETURNS integer AS $body$\nBEGIN\n  RETURN n + 1; -- 'not a string' /* not a comment\nEND;\n$body$ LANGUAGE plpgsql;";
    let lines: Vec<&str> = text.split('\n').collect();
    let (tokens, states) = by_lines(PG, text);
    let body = tag(b"body");
    assert_eq!(states, [body, body, body, body, LineState::Normal]);

    assert_eq!(
        lex(PG, lines[0]),
        [
            (Keyword, "CREATE"),
            (Keyword, "FUNCTION"),
            (FunctionName, "add_one"),
            (Punctuation, "("),
            (Identifier, "n"),
            (TypeName, "integer"),
            (Punctuation, ")"),
            (Keyword, "RETURNS"),
            (TypeName, "integer"),
            (Keyword, "AS"),
            (String, "$body$"),
        ]
    );
    // Every body line is one string token; the last line closes it and goes on.
    for line in &lines[1..4] {
        let (line_tokens, _) = lex_from(PG, line, body);
        assert_eq!(visible(line, &line_tokens), [(String, *line)]);
    }
    let (last, _) = lex_from(PG, lines[4], body);
    assert_eq!(visible(lines[4], &last), [(String, "$body$"), (Keyword, "LANGUAGE"), (Identifier, "plpgsql"), (Punctuation, ";")]);
    assert_eq!(tokenize_text(PG, text).spans, tokens);
}

#[test]
fn a_copy_statement() {
    let line = "COPY public.events (id, payload) FROM STDIN WITH (FORMAT csv, HEADER true, DELIMITER E'\\t', NULL '');";
    let tokens = lex(PG, line);
    for keyword in ["COPY", "FROM", "STDIN", "WITH", "csv", "HEADER", "true", "DELIMITER", "NULL"] {
        assert!(tokens.contains(&(Keyword, keyword)), "{keyword} in {tokens:?}");
    }
    assert!(tokens.contains(&(Identifier, "events")));
    assert!(tokens.contains(&(String, "E'\\t'")));
    assert!(tokens.contains(&(String, "''")));
    assert_eq!(tokens.last(), Some(&(Punctuation, ";")));
    assert_eq!(end_state(PG, line), LineState::Normal);
}

// ---------------------------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------------------------

/// Every string form of item 3: how it opens, how it closes, and the state it leaves when open.
fn string_forms() -> Vec<(&'static str, &'static str, LineState)> {
    let standard = LineState::String { mode: StringMode::Standard };
    let escape = LineState::String { mode: StringMode::Escape };
    let plain = LineState::String { mode: StringMode::Plain };
    vec![
        ("'", "'", standard),
        ("E'", "'", escape),
        ("e'", "'", escape),
        ("U&'", "'", standard),
        ("u&'", "'", standard),
        ("N'", "'", standard),
        ("B'", "'", plain),
        ("b'", "'", plain),
        ("X'", "'", plain),
        ("x'", "'", plain),
        ("$$", "$$", tag(b"")),
        ("$tag$", "$tag$", tag(b"tag")),
    ]
}

#[test]
fn every_string_form_terminated_on_one_line() {
    for (open, close, _) in string_forms() {
        let literal = format!("{open}01ab{close}");
        let line = format!("SELECT {literal}, 1");
        assert_eq!(lex(PG, &line), [(Keyword, "SELECT"), (String, literal.as_str()), (Punctuation, ","), (Number, "1")], "{line}");
        assert_eq!(end_state(PG, &line), LineState::Normal, "{line}");
    }
}

#[test]
fn every_string_form_unterminated() {
    for (open, _, open_state) in string_forms() {
        let line = format!("SELECT {open}01ab, 1");
        let rest = format!("{open}01ab, 1");
        assert_eq!(lex(PG, &line), [(Keyword, "SELECT"), (String, rest.as_str())], "{line}");
        assert_eq!(end_state(PG, &line), open_state, "{line}");
        assert!(open_state.is_open());

        // The whole-text helper knows the text ends there, and marks the open literal as an error.
        let whole = tokenize_text(PG, &line);
        assert_eq!(whole.end_state, open_state);
        assert_eq!(whole.spans.last().map(|t| (t.kind, &line[t.start..t.end()])), Some((Error, rest.as_str())), "{line}");
        assert_eq!(whole.spans.iter().filter(|t| t.kind == Error).count(), 1);
    }
}

#[test]
fn every_string_form_carried_across_a_line_break() {
    for (open, close, open_state) in string_forms() {
        let first = format!("SELECT {open}01ab");
        let middle = "  10 -- still /* inside";
        let last = format!("cd{close} + 1");
        assert_eq!(end_state(PG, &first), open_state, "{first}");

        let (tokens, state) = lex_from(PG, middle, open_state);
        assert_eq!(tokens.iter().map(|t| (t.kind, t.len)).collect::<Vec<_>>(), [(String, middle.len())], "{open} middle line");
        assert_eq!(state, open_state);

        let (tokens, state) = lex_from(PG, &last, open_state);
        let closing = format!("cd{close}");
        assert_eq!(visible(&last, &tokens), [(String, closing.as_str()), (Operator, "+"), (Number, "1")], "{last}");
        assert_eq!(state, LineState::Normal);

        // An empty line inside a literal has no tokens and keeps the state.
        let (tokens, state) = lex_from(PG, "", open_state);
        assert!(tokens.is_empty());
        assert_eq!(state, open_state);

        // Whole text: nothing is an error, because the literal ends.
        let text = format!("{first}\n{middle}\n\n{last}");
        let whole = tokenize_text(PG, &text);
        assert_eq!(whole.end_state, LineState::Normal);
        assert!(whole.spans.iter().all(|t| t.kind != Error), "{text}");
    }
}

#[test]
fn quote_escapes_differ_by_string_form() {
    // '' is one quote in a standard, E, U& and N string.
    for open in ["'", "E'", "U&'", "N'"] {
        let literal = format!("{open}it''s'");
        assert_eq!(lex(PG, &literal), [(String, literal.as_str())], "{literal}");
    }
    // B'' and X'' strings have no '' escape: the second quote starts a new string.
    assert_eq!(lex(PG, "B'01''10'"), [(String, "B'01'"), (String, "'10'")]);
    assert_eq!(lex(PG, "X'1F''2A'"), [(String, "X'1F'"), (String, "'2A'")]);

    // A backslash escapes only in an E string.
    assert_eq!(lex(PG, r"E'it\'s' x"), [(String, r"E'it\'s'"), (Identifier, "x")]);
    assert_eq!(lex(PG, r"E'a\\' x"), [(String, r"E'a\\'"), (Identifier, "x")]);
    assert_eq!(lex(PG, r"E'a\\\'' x"), [(String, r"E'a\\\''"), (Identifier, "x")]);
    assert_eq!(lex(PG, r"'it\' s"), [(String, r"'it\'"), (Identifier, "s")]);
    assert_eq!(lex(PG, r"U&'it\' s"), [(String, r"U&'it\'"), (Identifier, "s")]);
    assert_eq!(end_state(PG, r"'it\'s'"), LineState::String { mode: StringMode::Standard });

    // A backslash at the end of a line escapes the line break, not the next line's first quote.
    let escape = LineState::String { mode: StringMode::Escape };
    assert_eq!(end_state(PG, r"E'abc\"), escape);
    let (tokens, state) = lex_from(PG, "' x", escape);
    assert_eq!(visible("' x", &tokens), [(String, "'"), (Identifier, "x")]);
    assert_eq!(state, LineState::Normal);
    // A backslash before a character of several bytes does not split it.
    assert_eq!(lex(PG, "E'\\é\\😀' x"), [(String, "E'\\é\\😀'"), (Identifier, "x")]);
}

#[test]
fn string_prefixes_are_only_prefixes_when_they_touch_the_quote() {
    assert_eq!(lex(PG, "E 'a'"), [(Identifier, "E"), (String, "'a'")]);
    assert_eq!(lex(PG, "U & 'a'"), [(Identifier, "U"), (Operator, "&"), (String, "'a'")]);
    assert_eq!(lex(PG, "U&x"), [(Identifier, "U"), (Operator, "&"), (Identifier, "x")]);
    // `we'…'` is an identifier and a standard string, so the backslash does not escape.
    assert_eq!(lex(PG, r"we'a\' b"), [(Identifier, "we"), (String, r"'a\'"), (Identifier, "b")]);
    assert_eq!(lex(PG, "xe'a' be'b'"), [(Identifier, "xe"), (String, "'a'"), (Identifier, "be"), (String, "'b'")]);
}

// ---------------------------------------------------------------------------------------------
// Comments
// ---------------------------------------------------------------------------------------------

#[test]
fn block_comments_nest_three_deep_across_lines() {
    let lines = ["SELECT 1 /* one /* two", "/* three */ still two", "*/ in one */ SELECT 2", "*/"];
    let (_, s0) = lex_from(PG, lines[0], LineState::Normal);
    assert_eq!(s0, LineState::BlockComment { depth: 2 });
    assert_eq!(lex(PG, lines[0]), [(Keyword, "SELECT"), (Number, "1"), (Comment, "/* one /* two")]);

    let (t1, s1) = lex_from(PG, lines[1], s0);
    assert_eq!(visible(lines[1], &t1), [(Comment, lines[1])]);
    assert_eq!(s1, LineState::BlockComment { depth: 2 });

    let (t2, s2) = lex_from(PG, lines[2], s1);
    assert_eq!(visible(lines[2], &t2), [(Comment, "*/ in one */"), (Keyword, "SELECT"), (Number, "2")]);
    assert_eq!(s2, LineState::Normal);

    // Outside a comment, `*/` is two operator characters.
    let (t3, s3) = lex_from(PG, lines[3], s2);
    assert_eq!(visible(lines[3], &t3), [(Operator, "*/")]);
    assert_eq!(s3, LineState::Normal);

    // Three deep on one line, and the depth while it is open.
    assert_eq!(lex(PG, "/* a /* b /* c */ b */ a */ x"), [(Comment, "/* a /* b /* c */ b */ a */"), (Identifier, "x")]);
    assert_eq!(end_state(PG, "/* a /* b /* c"), LineState::BlockComment { depth: 3 });
    assert_eq!(end_state(PG, "/* a /* b /* c */"), LineState::BlockComment { depth: 2 });
}

#[test]
fn block_comment_edges() {
    assert_eq!(lex(PG, "/**/ x"), [(Comment, "/**/"), (Identifier, "x")]);
    assert_eq!(lex(PG, "/***/ x"), [(Comment, "/***/"), (Identifier, "x")]);
    // `/*/` opens and does not close.
    assert_eq!(end_state(PG, "/*/ x"), LineState::BlockComment { depth: 1 });
    assert_eq!(lex(PG, "/*/ */ x"), [(Comment, "/*/ */"), (Identifier, "x")]);
    // `*/*` inside a comment closes first; the `*` after it is then an operator.
    assert_eq!(lex(PG, "/* a */* 2"), [(Comment, "/* a */"), (Operator, "*"), (Number, "2")]);
    // `/*/` inside a comment: `/*` nests, and the `/` after it is comment text.
    assert_eq!(end_state(PG, "/* /*/ */"), LineState::BlockComment { depth: 1 });
    // A line comment marker inside a block comment means nothing.
    assert_eq!(lex(PG, "/* -- */ x"), [(Comment, "/* -- */"), (Identifier, "x")]);
    // A block comment marker inside a line comment means nothing.
    assert_eq!(end_state(PG, "-- /* x"), LineState::Normal);
}

#[test]
fn comment_markers_inside_strings_are_not_comments() {
    assert_eq!(lex(PG, "SELECT '-- not', 1"), [(Keyword, "SELECT"), (String, "'-- not'"), (Punctuation, ","), (Number, "1")]);
    assert_eq!(lex(PG, "SELECT '/* not', 1"), [(Keyword, "SELECT"), (String, "'/* not'"), (Punctuation, ","), (Number, "1")]);
    assert_eq!(lex(PG, "SELECT $$ /* not -- not $$, 1"), [(Keyword, "SELECT"), (String, "$$ /* not -- not $$"), (Punctuation, ","), (Number, "1")]);
    assert_eq!(lex(PG, r#"SELECT "--x", 1"#), [(Keyword, "SELECT"), (QuotedIdentifier, r#""--x""#), (Punctuation, ","), (Number, "1")]);
    // And quotes inside comments are not strings.
    assert_eq!(end_state(PG, "-- it's"), LineState::Normal);
    assert_eq!(end_state(PG, "/* it's $$ */"), LineState::Normal);
}

#[test]
fn a_line_comment_ends_at_a_line_break_inside_the_line() {
    // A caller should pass lines without their terminator; if one slips through, the comment
    // still ends there, as it does in PostgreSQL.
    assert_eq!(lex(PG, "-- a\rSELECT"), [(Comment, "-- a"), (Keyword, "SELECT")]);
    assert_eq!(lex(PG, "-- a\nSELECT"), [(Comment, "-- a"), (Keyword, "SELECT")]);
    assert_eq!(lex(PG, "SELECT 1 -- a\r"), [(Keyword, "SELECT"), (Number, "1"), (Comment, "-- a")]);
}

#[test]
fn the_comment_depth_is_capped() {
    let opens = "/*".repeat(300);
    assert_eq!(end_state(PG, &opens), LineState::BlockComment { depth: MAX_COMMENT_DEPTH });
    // From the cap, MAX_COMMENT_DEPTH closes get back to normal text.
    let closes = "*/".repeat(MAX_COMMENT_DEPTH as usize);
    let line = format!("{closes} SELECT");
    let (tokens, state) = lex_from(PG, &line, LineState::BlockComment { depth: MAX_COMMENT_DEPTH });
    assert_eq!(visible(&line, &tokens), [(Comment, closes.as_str()), (Keyword, "SELECT")]);
    assert_eq!(state, LineState::Normal);
    // A state that could not have come from the tokenizer is still safe.
    let (_, state) = lex_from(PG, "*/ x", LineState::BlockComment { depth: 0 });
    assert_eq!(state, LineState::Normal);
}

// ---------------------------------------------------------------------------------------------
// Dollar quoting and parameters
// ---------------------------------------------------------------------------------------------

#[test]
fn dollar_quoting() {
    assert_eq!(lex(PG, "$$a$$ x"), [(String, "$$a$$"), (Identifier, "x")]);
    assert_eq!(lex(PG, "$$$$ x"), [(String, "$$$$"), (Identifier, "x")]);
    assert_eq!(lex(PG, "$tag$a$tag$ x"), [(String, "$tag$a$tag$"), (Identifier, "x")]);
    assert_eq!(lex(PG, "$_t9$a$_t9$ x"), [(String, "$_t9$a$_t9$"), (Identifier, "x")]);
    assert_eq!(lex(PG, "$é$ a $é$ x"), [(String, "$é$ a $é$"), (Identifier, "x")]);
    // A body that holds another tag, an empty tag, a longer tag and a shorter one.
    assert_eq!(lex(PG, "$fn$ a $other$ b $$ c $fnx$ $f$ d $fn$ x"), [(String, "$fn$ a $other$ b $$ c $fnx$ $f$ d $fn$"), (Identifier, "x")]);
    // The closing tag may share its first dollar with the end of another tag.
    assert_eq!(lex(PG, "$a$ $ab$a$ x"), [(String, "$a$ $ab$a$"), (Identifier, "x")]);
    assert_eq!(lex(PG, "$$ $1 $ $$ x"), [(String, "$$ $1 $ $$"), (Identifier, "x")]);
    // Tags are case-sensitive.
    assert_eq!(end_state(PG, "$Tag$ a $tag$"), tag(b"Tag"));
    // Quotes and comment markers in the body mean nothing.
    assert_eq!(end_state(PG, "$$ ' \" /* -- $$"), LineState::Normal);
}

#[test]
fn a_parameter_beside_a_dollar_tag() {
    assert_eq!(lex(PG, "$1 $tag$x$tag$ $2"), [(Parameter, "$1"), (String, "$tag$x$tag$"), (Parameter, "$2")]);
    assert_eq!(lex(PG, "$1$$x$$"), [(Parameter, "$1"), (String, "$$x$$")]);
    assert_eq!(lex(PG, "$12,$3"), [(Parameter, "$12"), (Punctuation, ","), (Parameter, "$3")]);
    assert_eq!(lex(PG, "$1::int"), [(Parameter, "$1"), (Operator, "::"), (TypeName, "int")]);
    // A tag cannot start with a digit, so this is a parameter and stray text.
    assert_eq!(lex(PG, "$5$ x"), [(Parameter, "$5"), (Text, "$"), (Identifier, "x")]);
}

#[test]
fn dollars_that_open_nothing_are_plain_text() {
    assert_eq!(lex(PG, "$ x"), [(Text, "$"), (Identifier, "x")]);
    assert_eq!(lex(PG, "$ab x"), [(Text, "$"), (Identifier, "ab"), (Identifier, "x")]);
    assert_eq!(lex(PG, "$a b$ x"), [(Text, "$"), (Identifier, "a"), (Identifier, "b$"), (Identifier, "x")]);
    assert_eq!(end_state(PG, "$ab x"), LineState::Normal);
}

#[test]
fn the_dollar_tag_length_is_capped() {
    let longest = "t".repeat(MAX_DOLLAR_TAG_BYTES);
    let line = format!("${longest}$ body");
    assert_eq!(end_state(PG, &line), tag(longest.as_bytes()));
    let closed = format!("${longest}$ body ${longest}$ x");
    assert_eq!(lex(PG, &closed).last(), Some(&(Identifier, "x")));
    assert_eq!(end_state(PG, &closed), LineState::Normal);

    // One byte more: not a dollar quote, so nothing is carried.
    let too_long = "t".repeat(MAX_DOLLAR_TAG_BYTES + 1);
    let line = format!("${too_long}$ body");
    assert_eq!(end_state(PG, &line), LineState::Normal);
    assert_eq!(lex(PG, &line)[0], (Text, "$"));
    assert!(DollarTag::new(too_long.as_bytes()).is_none());
    assert_eq!(DollarTag::new(b"tag").unwrap().as_bytes(), b"tag");
}

#[test]
fn an_unterminated_dollar_body_stays_open_to_the_end() {
    let text = "SELECT $q$ one\n two $q $ q$ $Q$\n three";
    let whole = tokenize_text(PG, text);
    assert_eq!(whole.end_state, tag(b"q"));
    let errors: Vec<&str> = whole.spans.iter().filter(|t| t.kind == Error).map(|t| &text[t.start..t.end()]).collect();
    assert_eq!(errors, ["$q$ one", " two $q $ q$ $Q$", " three"]);
    assert_eq!(whole.spans[0].kind, Keyword);
}

// ---------------------------------------------------------------------------------------------
// The plain SQL dialect and unknown languages
// ---------------------------------------------------------------------------------------------

#[test]
fn plain_sql_differs_from_postgresql_where_the_dialect_does() {
    // Block comments do not nest.
    assert_eq!(lex(SQL, "/* a /* b */ c */"), [(Comment, "/* a /* b */"), (Identifier, "c"), (Operator, "*/")]);
    assert_eq!(lex(PG, "/* a /* b */ c */"), [(Comment, "/* a /* b */ c */")]);
    assert_eq!(end_state(SQL, "/* a /* b"), LineState::BlockComment { depth: 1 });
    // No dollar quoting.
    assert_eq!(lex(SQL, "$$ x $$"), [(Text, "$"), (Text, "$"), (Identifier, "x"), (Text, "$"), (Text, "$")]);
    assert_eq!(end_state(SQL, "$tag$ x"), LineState::Normal);
    // No E'' strings: E is an identifier and the backslash does not escape.
    assert_eq!(lex(SQL, r"E'a\' b"), [(Identifier, "E"), (String, r"'a\'"), (Identifier, "b")]);
    // What plain SQL shares: the rest.
    let shared = "SELECT a, 'it''s', U&'x', B'1', X'F', N'n', 1.5, $1, now() -- c";
    assert_eq!(lex(SQL, shared), lex(PG, shared));
    assert_eq!(lex(SQL, "x::int"), [(Identifier, "x"), (Operator, "::"), (TypeName, "int")]);
    // A state left by the other dialect is still read safely.
    let (tokens, state) = lex_from(SQL, "x $t$ y", tag(b"t"));
    assert_eq!(visible("x $t$ y", &tokens), [(String, "x $t$"), (Identifier, "y")]);
    assert_eq!(state, LineState::Normal);
}

#[test]
fn language_names_ignore_case() {
    for name in ["sql", "SQL", "Sql"] {
        assert_eq!(lex(name, "SELECT $$"), [(Keyword, "SELECT"), (Text, "$"), (Text, "$")], "{name}");
    }
    for name in ["postgresql", "PostgreSQL", "POSTGRESQL"] {
        assert_eq!(lex(name, "SELECT $$"), [(Keyword, "SELECT"), (String, "$$")], "{name}");
    }
}

#[test]
fn an_unknown_language_is_plain_text() {
    for name in ["", "python", "sql ", "postgres", "pgsql", "sql\0", "SQL😀"] {
        let line = "SELECT 'a' /* b";
        let (tokens, state) = lex_from(name, line, LineState::Normal);
        assert_eq!(tokens.iter().map(|t| (t.kind, t.start, t.len)).collect::<Vec<_>>(), [(Text, 0, line.len())], "{name:?}");
        assert_eq!(state, LineState::Normal);
        // A state from another language is dropped, not carried.
        assert_eq!(lex_from(name, line, LineState::BlockComment { depth: 3 }).1, LineState::Normal);
        assert!(lex_from(name, "", LineState::Normal).0.is_empty());

        let text = "one 'two\nthree é😀\n";
        let whole = tokenize_text(name, text);
        assert_eq!(whole.end_state, LineState::Normal);
        assert_eq!(whole.spans.iter().map(|t| (t.kind, &text[t.start..t.end()])).collect::<Vec<_>>(), [(Text, "one 'two"), (Text, "three é😀")]);
    }
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

#[test]
fn tokenizing_line_by_line_equals_tokenizing_whole() {
    for language in [PG, SQL] {
        for text in [SAMPLE.to_string(), SAMPLE.replace('\n', "\r\n"), Str::new(), "\n\n".to_string(), "SELECT 1".to_string(), "é😀 -- ü\n'列\n列' x".to_string()] {
            let whole = tokenize_text(language, &text);
            let (lines, states) = by_lines(language, &text);
            assert_eq!(whole.spans, lines, "{language}");
            assert_eq!(whole.end_state, *states.last().unwrap());
            assert_eq!(whole.end_state, LineState::Normal);
            assert!(whole.spans.iter().all(|t| t.kind != Error));
        }
    }
    // The sample really does carry every state across a line break.
    let (_, states) = by_lines(PG, SAMPLE);
    assert!(states.contains(&LineState::BlockComment { depth: 1 }));
    assert!(states.contains(&tag(b"fn")));
}

#[test]
fn whole_text_spans_skip_only_the_line_breaks() {
    let text = "SELECT 'é',\r\n  '😀' -- 列\n\nFROM t";
    let whole = tokenize_text(PG, text);
    let (mut at, mut at16) = (0, 0);
    for span in &whole.spans {
        // Between two spans there is nothing, or exactly the line breaks.
        assert!(text[at..span.start].bytes().all(|b| b == b'\n'), "gap {:?}", &text[at..span.start]);
        assert_eq!(span.utf16_start - at16, span.start - at);
        assert_eq!(span.utf16_start, text[..span.start].encode_utf16().count());
        assert_eq!(span.utf16_len, text[span.start..span.end()].encode_utf16().count());
        at = span.end();
        at16 = span.utf16_end();
    }
    assert_eq!(at, text.len());
    // The carriage return stays in its line as plain text.
    assert!(whole.spans.iter().any(|t| t.kind == Text && &text[t.start..t.end()] == "\r"));
}

#[test]
fn the_whole_text_helper_marks_only_the_literal_or_comment_left_open() {
    fn shown<'a>(text: &'a str, spans: &[Token]) -> Vec<(TokenKind, &'a str)> {
        spans.iter().map(|t| (t.kind, &text[t.start..t.end()])).filter(|(_, s)| !s.trim().is_empty()).collect()
    }
    // The comment on line 1 is closed; the one opened on line 2 is not.
    let text = "/* closed\n */ SELECT 1 /* open\n more\n\n /* deeper */ end";
    let whole = tokenize_text(PG, text);
    assert_eq!(whole.end_state, LineState::BlockComment { depth: 1 });
    assert_eq!(shown(text, &whole.spans), [(Comment, "/* closed"), (Comment, " */"), (Keyword, "SELECT"), (Number, "1"), (Error, "/* open"), (Error, " more"), (Error, " /* deeper */ end")]);

    // Line by line, the same spans are comments: only the helper knows where the text ends.
    let (lines, states) = by_lines(PG, text);
    assert_eq!(*states.last().unwrap(), whole.end_state);
    assert_eq!(lines.len(), whole.spans.len());
    for (line_token, span) in lines.iter().zip(&whole.spans) {
        assert_eq!((line_token.start, line_token.len, line_token.utf16_start, line_token.utf16_len), (span.start, span.len, span.utf16_start, span.utf16_len));
        assert_eq!(line_token.kind, if span.kind == Error { Comment } else { span.kind });
    }

    // A literal closed and another opened on the last line: only the second is marked.
    let text = "'a\nb' 'c";
    assert_eq!(shown(text, &tokenize_text(PG, text).spans), [(String, "'a"), (String, "b'"), (Error, "'c")]);
    // Open at the end of a line, then only empty lines.
    let text = "SELECT \"open\n\n";
    assert_eq!(shown(text, &tokenize_text(PG, text).spans), [(Keyword, "SELECT"), (Error, "\"open")]);
}

#[test]
fn the_state_is_small_comparable_and_cheap_to_copy() {
    fn is_small_value<T: Copy + Eq + std::hash::Hash + std::fmt::Debug + Default>() {}
    is_small_value::<LineState>();
    assert!(std::mem::size_of::<LineState>() <= MAX_DOLLAR_TAG_BYTES + 8, "{} bytes", std::mem::size_of::<LineState>());
    assert_eq!(LineState::default(), LineState::Normal);
    assert!(!LineState::Normal.is_open());
    // Two tags with the same text are the same state, however they were reached.
    assert_eq!(end_state(PG, "$a$ x"), end_state(PG, "SELECT 1, $a$ $b$"));
    assert_ne!(end_state(PG, "$a$ x"), end_state(PG, "$b$ x"));
    assert_ne!(end_state(PG, "/* /*"), end_state(PG, "/*"));
}

/// An editor's copy of a text: the lines, and the tokens and end state it has stored for each.
struct Editor {
    lines: Vec<Str>,
    states: Vec<LineState>,
    tokens: Vec<Vec<Token>>,
}

impl Editor {
    fn open(text: &str) -> Self {
        let lines: Vec<Str> = text.split('\n').map(str::to_string).collect();
        let mut editor = Editor { states: vec![LineState::Normal; lines.len()], tokens: vec![Vec::new(); lines.len()], lines };
        let mut state = LineState::Normal;
        for i in 0..editor.lines.len() {
            let result = tokenize_line(PG, &editor.lines[i], state);
            state = result.end_state;
            editor.states[i] = result.end_state;
            editor.tokens[i] = result.tokens;
        }
        editor
    }
    /// Replace one line, then re-colour from it down until a line's end state is the one already
    /// stored for it. Returns how many lines were tokenized.
    fn edit(&mut self, index: usize, line: &str) -> usize {
        self.lines[index] = line.to_string();
        let mut state = if index == 0 { LineState::Normal } else { self.states[index - 1] };
        let mut done = 0;
        for i in index..self.lines.len() {
            let result = tokenize_line(PG, &self.lines[i], state);
            done += 1;
            let unchanged = result.end_state == self.states[i];
            state = result.end_state;
            self.states[i] = result.end_state;
            self.tokens[i] = result.tokens;
            if unchanged {
                break;
            }
        }
        done
    }
    fn matches_a_fresh_tokenize(&self) -> bool {
        let fresh = Editor::open(&self.lines.join("\n"));
        fresh.states == self.states && fresh.tokens == self.tokens
    }
}

#[test]
fn an_edit_recolours_down_to_the_first_unchanged_end_state_and_converges() {
    let text = "SELECT 1;\nSELECT 2;\nSELECT 3; /* c */\nSELECT 4;\nSELECT 5; */ SELECT 6;\nSELECT 7;\nSELECT 8;";
    let mut editor = Editor::open(text);
    assert!(editor.states.iter().all(|s| *s == LineState::Normal));

    // An edit that leaves the line's end state alone re-colours that one line.
    assert_eq!(editor.edit(1, "SELECT 22, 'two';"), 1);
    assert!(editor.matches_a_fresh_tokenize());

    // Opening a comment on line 1: lines 1 to 3 now end inside it, the `*/` on line 4 closes
    // it, and line 4 ends in the state it had. Re-colouring stops there, not at the end.
    assert_eq!(editor.edit(1, "SELECT 22 /* opened"), 4);
    assert_eq!(editor.states[1..4], [LineState::BlockComment { depth: 1 }; 3]);
    assert_eq!(editor.states[4], LineState::Normal);
    assert!(editor.matches_a_fresh_tokenize());

    // Taking it away again converges the same way.
    assert_eq!(editor.edit(1, "SELECT 22;"), 4);
    assert!(editor.matches_a_fresh_tokenize());
    assert!(editor.states.iter().all(|s| *s == LineState::Normal));

    // An unterminated dollar quote on the first line runs to the end of the text.
    assert_eq!(editor.edit(0, "SELECT $x$"), editor.lines.len());
    assert!(editor.matches_a_fresh_tokenize());
    assert!(editor.states.iter().all(|s| s.is_open()));

    // Closing it on the last line touches only that line.
    let last = editor.lines.len() - 1;
    assert_eq!(editor.edit(last, "$x$;"), 1);
    assert!(editor.matches_a_fresh_tokenize());
}

#[test]
fn random_edits_always_converge_to_a_fresh_tokenize() {
    let fragments = ["/*", "*/", "'", "''", "\"", "$$", "$a$", "$1", "--", "E'", "\\", "SELECT", " ", "x", "1.5", "::", "é", "😀", "B'", ";"];
    let mut rng = Rng(0x5EED_06C1);
    let mut editor = Editor::open(&SAMPLE.repeat(2));
    for _ in 0..400 {
        let index = rng.below(editor.lines.len());
        let mut line = Str::new();
        for _ in 0..rng.below(6) {
            line.push_str(fragments[rng.below(fragments.len())]);
        }
        editor.edit(index, &line);
        assert!(editor.matches_a_fresh_tokenize(), "after setting line {index} to {line:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// Offsets
// ---------------------------------------------------------------------------------------------

#[test]
fn offsets_with_two_three_and_four_byte_characters() {
    // é is 2 bytes and 1 UTF-16 unit; 列 is 3 and 1; 😀 is 4 and 2.
    let line = "SELECT 'é列😀' AS \"é😀\", 列é😀 -- 😀é";
    let (tokens, _) = lex_from(PG, line, LineState::Normal);
    let found: Vec<(TokenKind, &str, usize, usize, usize, usize)> =
        tokens.iter().filter(|t| t.kind != Text).map(|t| (t.kind, &line[t.start..t.end()], t.start, t.len, t.utf16_start, t.utf16_len)).collect();
    assert_eq!(
        found,
        [
            (Keyword, "SELECT", 0, 6, 0, 6),
            (String, "'é列😀'", 7, 11, 7, 6),
            (Keyword, "AS", 19, 2, 14, 2),
            (QuotedIdentifier, "\"é😀\"", 22, 8, 17, 5),
            (Punctuation, ",", 30, 1, 22, 1),
            (Identifier, "列é😀", 32, 9, 24, 4),
            (Comment, "-- 😀é", 42, 9, 29, 6),
        ]
    );
    // UTF-16 offsets index the UTF-16 form of the line, as AppKit and WinUI do.
    let units: Vec<u16> = line.encode_utf16().collect();
    for token in &tokens {
        let slice = Str::from_utf16(&units[token.utf16_start..token.utf16_end()]).unwrap();
        assert_eq!(slice, &line[token.start..token.end()]);
    }
}

#[test]
fn no_span_splits_a_character_in_any_state() {
    let line = "é😀列 '😀' \"列\" $é$😀$é$ /*😀*/ E'\\😀' --é";
    let states = [
        LineState::Normal,
        LineState::BlockComment { depth: 2 },
        LineState::String { mode: StringMode::Standard },
        LineState::String { mode: StringMode::Escape },
        LineState::String { mode: StringMode::Plain },
        LineState::QuotedIdentifier,
        tag("é".as_bytes()),
    ];
    for language in [PG, SQL, "none"] {
        for state in states {
            // Every suffix that starts at a character, so each character meets each state.
            for (at, _) in line.char_indices() {
                lex_from(language, &line[at..], state);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Limits and robustness
// ---------------------------------------------------------------------------------------------

#[test]
fn a_line_beyond_the_limit_is_plain_text_from_there() {
    // A two-byte character sits across the limit: the cut moves back to its start.
    let line = format!("{}é SELECT 'x'", "a".repeat(MAX_LINE_BYTES - 1));
    let (tokens, state) = lex_from(PG, &line, LineState::Normal);
    assert_eq!(tokens.iter().map(|t| (t.kind, t.start, t.len)).collect::<Vec<_>>(), [(Identifier, 0, MAX_LINE_BYTES - 1), (Text, MAX_LINE_BYTES - 1, line.len() - (MAX_LINE_BYTES - 1))]);
    assert_eq!(state, LineState::Normal);

    // Exactly at the limit nothing is cut.
    let line = format!("{} SELECT", "a".repeat(MAX_LINE_BYTES - 7));
    assert_eq!(line.len(), MAX_LINE_BYTES);
    assert_eq!(lex(PG, &line).last(), Some(&(Keyword, "SELECT")));

    // A comment that the whole line leaves open is still open after it.
    let line = format!("/* {}", "x".repeat(MAX_LINE_BYTES + 100));
    let (tokens, state) = lex_from(PG, &line, LineState::Normal);
    assert_eq!(tokens.iter().map(|t| (t.kind, t.len)).collect::<Vec<_>>(), [(Comment, MAX_LINE_BYTES), (Text, 103)]);
    assert_eq!(state, LineState::BlockComment { depth: 1 });

    // An unknown language has nothing to cut: it is one plain span either way.
    let (tokens, _) = lex_from("none", &line, LineState::Normal);
    assert_eq!(tokens.len(), 1);
}

/// The tokens stop at the limit, but the line is read to its end for the state, so what the
/// part past the limit closes or opens is known to the lines below.
#[test]
fn the_state_after_a_cut_line_is_the_state_at_the_end_of_the_line() {
    let blob = "A".repeat(MAX_LINE_BYTES + 500);
    let normal = LineState::Normal;
    let standard = LineState::String { mode: StringMode::Standard };
    // (the long line, the state it must leave)
    let cases = [
        // A string open at the cut and closed past it: the usual long line, one big literal.
        (format!("INSERT INTO t VALUES ('{blob}');"), normal),
        // The same, never closed.
        (format!("INSERT INTO t VALUES ('{blob}"), standard),
        // Closed past the cut, and another opened after that.
        (format!("SELECT '{blob}', 'next"), standard),
        (format!("SELECT '{blob}' /* open"), LineState::BlockComment { depth: 1 }),
        (format!("SELECT $q${blob}$q$, $r$ open"), tag(b"r")),
        (format!("SELECT $q${blob}$q$ -- 'not open"), normal),
        // Nothing open at the cut, something opened past it.
        (format!("SELECT {blob} 'open"), standard),
        (format!("/* {blob} */ /* /* two"), LineState::BlockComment { depth: 2 }),
        (format!("SELECT E'{blob}\\\\' + 1"), normal),
    ];
    for (line, expected) in &cases {
        let (tokens, state) = lex_from(PG, line, normal);
        let shown = &line[..40];
        assert_eq!(state, *expected, "{shown}…");
        // Tokens stop at the limit; the rest is one plain span.
        let tail = tokens.last().unwrap();
        assert_eq!((tail.kind, tail.start, tail.end()), (Text, MAX_LINE_BYTES, line.len()), "{shown}…");
        assert!(tokens.iter().all(|t| t.end() <= MAX_LINE_BYTES || t.start == MAX_LINE_BYTES));

        // The lines below are coloured by what the whole line left, and line by line still
        // equals the whole text.
        let text = format!("{line}\nSELECT 1; -- it's\n' x");
        let whole = tokenize_text(PG, &text);
        let (lines, states) = by_lines(PG, &text);
        assert_eq!(states[0], *expected);
        assert_eq!(whole.end_state, *states.last().unwrap());
        assert_eq!(whole.spans.len(), lines.len());
        for (line_token, span) in lines.iter().zip(&whole.spans) {
            assert_eq!((line_token.start, line_token.len, line_token.utf16_start, line_token.utf16_len), (span.start, span.len, span.utf16_start, span.utf16_len));
            assert!(span.kind == line_token.kind || span.kind == Error);
        }
        if *expected == normal {
            let second = &whole.spans[tokens.len()];
            assert_eq!((second.kind, &text[second.start..second.end()]), (Keyword, "SELECT"), "{shown}…");
        }
    }

    // What a cut line leaves open past the limit is marked by the whole-text helper from the
    // next line on; the plain tail itself stays plain.
    let text = format!("SELECT {blob} 'open\nmore");
    let whole = tokenize_text(PG, &text);
    let kinds: Vec<TokenKind> = whole.spans.iter().rev().take(2).map(|t| t.kind).collect();
    assert_eq!(kinds, [Error, Text]);

    // A line that starts inside a literal and is cut inside it.
    let line = format!("{blob}' + 1");
    let (tokens, state) = lex_from(PG, &line, standard);
    assert_eq!(tokens.iter().map(|t| (t.kind, t.len)).collect::<Vec<_>>(), [(String, MAX_LINE_BYTES), (Text, line.len() - MAX_LINE_BYTES)]);
    assert_eq!(state, normal);
}

#[test]
fn a_one_mebibyte_single_line_is_bounded() {
    // The sample on one line, without its line comments (they would swallow the rest).
    let one_line: Str = SAMPLE.lines().map(|l| l.split("--").next().unwrap()).collect::<Vec<_>>().join(" ");
    let line = one_line.repeat(MIB / one_line.len() + 1);
    assert!(line.len() >= MIB);
    let started = Instant::now();
    let (tokens, _) = lex_from(PG, &line, LineState::Normal);
    let took = started.elapsed();
    let tail = tokens.last().unwrap();
    assert_eq!(tail.kind, Text);
    assert!(tail.start <= MAX_LINE_BYTES && tail.start > MAX_LINE_BYTES - 4);
    assert_eq!(tail.end(), line.len());
    assert!(tokens.len() > 5_000 && tokens.len() < MAX_LINE_BYTES, "{} tokens", tokens.len());
    assert!(took < Duration::from_secs(5), "took {took:?}");

    // The worst single line for each scanner: one character class, a mebibyte long.
    for fill in ["'", "\"", "$", "/*", "*/", "\\", "-", ".", "1", "_", "e", "\0", "\u{FFFD}", "😀", "$a", "E'\\", "(", " "] {
        let line = fill.repeat(MIB / fill.len());
        for state in [LineState::Normal, LineState::BlockComment { depth: 1 }, LineState::String { mode: StringMode::Escape }, tag(b"a")] {
            let started = Instant::now();
            lex_from(PG, &line, state);
            tokenize_text(PG, &line);
            assert!(started.elapsed() < Duration::from_secs(5), "{fill:?} from {state:?} took {:?}", started.elapsed());
        }
    }
}

#[test]
fn one_hundred_thousand_short_lines() {
    let text: Str = (0..100_000).map(|i| format!("INSERT INTO t (id, note) VALUES ({i}, 'row {i}'); -- {i}\n")).collect();
    let started = Instant::now();
    let whole = tokenize_text(PG, &text);
    let took = started.elapsed();
    assert_eq!(whole.end_state, LineState::Normal);
    assert_eq!(whole.spans.iter().filter(|t| t.kind == Keyword).count(), 300_000);
    assert_eq!(whole.spans.iter().filter(|t| t.kind == Comment).count(), 100_000);
    assert_eq!(whole.spans.iter().filter(|t| t.kind == String).count(), 100_000);
    assert!(took < Duration::from_secs(20), "took {took:?}");
    let (lines, _) = by_lines(PG, &text);
    assert_eq!(whole.spans, lines);
}

#[test]
fn nul_replacement_characters_and_controls_do_not_panic() {
    for line in ["\0", "SELECT\0'a\0'", "\u{FFFD}", "'\u{FFFD}", "\u{FFFD}'\u{FFFD}'", "\u{1}\u{2}\u{7f}", "\u{2028}\u{2029}\u{feff}", "$\0$ x $\0$", "\t\u{b}\u{c}\r"] {
        for language in [PG, SQL, "other"] {
            let (tokens, _) = lex_from(language, line, LineState::Normal);
            assert!(!tokens.is_empty());
            tokenize_text(language, line);
        }
    }
    // NUL is not a tag character, so `$\0$` is not a dollar quote.
    assert_eq!(end_state(PG, "$\0$ x"), LineState::Normal);
}

#[test]
fn mutated_and_random_inputs_never_panic_and_stay_bounded() {
    let mut rng = Rng(0x06C1_F00D);
    let alphabet: Vec<char> = "'\"$/*-\\.:_ \t\r\n\0eExXbBuUnN&0123456789aZ(),;[]<>=+é列😀\u{FFFD}".chars().collect();
    let states = [
        LineState::Normal,
        LineState::BlockComment { depth: 1 },
        LineState::BlockComment { depth: MAX_COMMENT_DEPTH },
        LineState::String { mode: StringMode::Standard },
        LineState::String { mode: StringMode::Escape },
        LineState::String { mode: StringMode::Plain },
        LineState::QuotedIdentifier,
        tag(b""),
        tag(b"a"),
    ];
    let sample: Vec<char> = SAMPLE.chars().collect();
    let mut slowest = Duration::ZERO;
    for round in 0..6_000 {
        let text: Str = match round % 3 {
            // Random bytes turned into text.
            0 => {
                let bytes: Vec<u8> = (0..rng.below(300)).map(|_| rng.next() as u8).collect();
                Str::from_utf8_lossy(&bytes).into_owned()
            }
            // Characters that matter to the tokenizer, in random order.
            1 => (0..rng.below(120)).map(|_| alphabet[rng.below(alphabet.len())]).collect(),
            // The sample with a few characters replaced, removed or doubled.
            _ => {
                let mut chars = sample.clone();
                for _ in 0..1 + rng.below(8) {
                    let at = rng.below(chars.len());
                    match rng.below(3) {
                        0 => chars[at] = alphabet[rng.below(alphabet.len())],
                        1 => {
                            chars.remove(at);
                        }
                        _ => chars.insert(at, chars[at]),
                    }
                }
                chars.into_iter().collect()
            }
        };
        for language in [PG, SQL] {
            let started = Instant::now();
            let whole = tokenize_text(language, &text);
            slowest = slowest.max(started.elapsed());
            // Line by line gives the same spans and end state; only the error marks differ.
            let (lines, line_states) = by_lines(language, &text);
            assert_eq!(whole.end_state, *line_states.last().unwrap());
            assert_eq!(whole.spans.len(), lines.len());
            for (line_token, span) in lines.iter().zip(&whole.spans) {
                assert_eq!((line_token.start, line_token.len), (span.start, span.len));
                assert!(span.kind == line_token.kind || span.kind == Error);
            }
            assert_eq!(whole.end_state.is_open(), whole.spans.iter().any(|t| t.kind == Error), "{text:?}");
        }
        // One line (the text with its breaks kept) from every state.
        let state = states[rng.below(states.len())];
        let started = Instant::now();
        lex_from(PG, &text, state);
        lex_from(SQL, &text, state);
        slowest = slowest.max(started.elapsed());
    }
    assert!(slowest < Duration::from_secs(1), "slowest call took {slowest:?}");
}

// ---------------------------------------------------------------------------------------------
// Speed. Release build, quiet Mac:
//   cargo test --release --test plugin_highlight_tests -- --ignored --nocapture
// ---------------------------------------------------------------------------------------------

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

/// `core` has no bench setup, so the figures for the evidence file are timed here.
#[test]
#[ignore = "speed figures; run in a release build on a quiet Mac"]
fn speed_figures() {
    const RUNS: usize = 15;
    let text = big_sql(MIB);
    let lines: Vec<&str> = text.split('\n').collect();
    println!("input: {} bytes, {} lines", text.len(), lines.len());

    // 1. The whole 1 MiB file.
    let whole = median(
        (0..RUNS)
            .map(|_| {
                let started = Instant::now();
                let result = tokenize_text(PG, &text);
                let took = started.elapsed();
                assert!(result.spans.len() > 100_000);
                took
            })
            .collect(),
    );
    println!("whole 1 MiB file: {whole:?} (median of {RUNS})");

    // 2. One 200-character line.
    let line = "SELECT o.id, upper(c.name) AS \"Name\", E'tab\\there', o.total::numeric(12,2), $1, now() - interval '7 days', 0x1F + 1_000 FROM orders o JOIN customers c ON c.id = o.customer_id /* note */ WHERE a <> 'x'";
    assert_eq!(line.chars().count(), 200);
    let rounds = 20_000;
    let one_line = median(
        (0..RUNS)
            .map(|_| {
                let started = Instant::now();
                for _ in 0..rounds {
                    std::hint::black_box(tokenize_line(PG, std::hint::black_box(line), LineState::Normal));
                }
                started.elapsed() / rounds
            })
            .collect(),
    );
    println!("one 200-character line: {one_line:?} (median of {RUNS} runs of {rounds})");

    // 3. Re-colouring after an edit at the top of the file that never converges: every line is
    //    tokenized again with the carried state, as an editor does it. Two directions: a block
    //    comment is opened (every line below becomes comment), and that opener is taken away
    //    again (every line below goes back to full SQL, the dearer direction).
    let recolour = |first: LineState| {
        median(
            (0..RUNS)
                .map(|_| {
                    let started = Instant::now();
                    let (mut state, mut tokens) = (first, 0);
                    for line in &lines {
                        let result = tokenize_line(PG, line, state);
                        state = result.end_state;
                        tokens += result.tokens.len();
                    }
                    std::hint::black_box(tokens);
                    assert_eq!(state.is_open(), first.is_open());
                    started.elapsed()
                })
                .collect(),
        )
    };
    // The sample closes its own comments, which would end an opened comment early. Starting at
    // the depth cap keeps every line inside the comment, which is the case to measure.
    let opened = recolour(LineState::BlockComment { depth: MAX_COMMENT_DEPTH });
    println!("re-colour 1 MiB after opening a block comment at the top: {opened:?} (median of {RUNS})");
    let removed = recolour(LineState::Normal);
    println!("re-colour 1 MiB after removing that opener: {removed:?} (median of {RUNS})");
}
