//! A small SQL tokenizer shared by the single-statement check (Explain) and the Data tab's
//! filter check (PLUG-08b).
//!
//! These checks give the user a clear message before anything is sent. They are not the
//! security boundary: the filter and Explain go to the server with the extended protocol
//! (`Parse`), which refuses more than one statement, and the filter runs inside
//! `BEGIN READ ONLY` ... `ROLLBACK` (see `client.rs`).
//!
//! The tokenizer is strict where PostgreSQL's lexer could read the text differently:
//! - a quote straight after a word is accepted only when the word is a string prefix
//!   PostgreSQL knows (`E`, `B`, `X`, `N`, `U&`), so `xE'\'` or `1E'...'` is refused;
//! - every run is done twice, once with backslash escapes only in `E'...'` strings
//!   (`standard_conforming_strings = on`) and once with them in every string (`off`). Both
//!   must succeed and agree, so a server or role setting cannot change what the user sees.

/// A token that matters to the checks; everything else is `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tok {
    Semi,
    Open,
    Close,
    Comment,
    Dollar,
    Other,
}

/// Bytes that continue a word (identifier, keyword or number). `$` is one inside a word.
fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c >= 0x80
}

/// The tokens of `sql`, or `None` if something is left open or ambiguous.
/// `backslash_everywhere` reads `\` as an escape in plain strings too.
pub fn tokens(sql: &str, backslash_everywhere: bool) -> Option<Vec<Tok>> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b';' => {
                out.push(Tok::Semi);
                i += 1;
            }
            b'(' => {
                out.push(Tok::Open);
                i += 1;
            }
            b')' => {
                out.push(Tok::Close);
                i += 1;
            }
            b'-' if b.get(i + 1) == Some(&b'-') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                out.push(Tok::Comment);
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 1usize;
                i += 2;
                while depth > 0 {
                    if i + 1 >= b.len() {
                        return None;
                    }
                    if b[i] == b'/' && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                out.push(Tok::Comment);
            }
            b'\'' => {
                let escapes = string_prefix(b, i)? || backslash_everywhere;
                i = skip_quoted(b, i, b'\'', escapes)?;
                out.push(Tok::Other);
            }
            b'"' => {
                // A quoted name may follow `U&` only, never a word.
                if i > 0 && is_word(b[i - 1]) {
                    return None;
                }
                i = skip_quoted(b, i, b'"', false)?;
                out.push(Tok::Other);
            }
            b'$' => {
                // Here `$` starts a token (inside a word it is eaten below). A dollar quote
                // opens with `$tag$`, the tag a name not starting with a digit; `$1` is a
                // parameter.
                let mut j = i + 1;
                while j < b.len() && is_word(b[j]) && b[j] != b'$' {
                    j += 1;
                }
                if j < b.len() && b[j] == b'$' && !b.get(i + 1).is_some_and(u8::is_ascii_digit) {
                    let tag = &b[i..=j];
                    let rest = &b[j + 1..];
                    let end = rest.windows(tag.len()).position(|w| w == tag)?;
                    i = j + 1 + end + tag.len();
                    out.push(Tok::Dollar);
                } else {
                    i += 1;
                    while i < b.len() && b[i].is_ascii_digit() {
                        i += 1;
                    }
                    out.push(Tok::Other);
                }
            }
            c if c.is_ascii_whitespace() => i += 1,
            c if is_word(c) => {
                while i < b.len() && is_word(b[i]) {
                    i += 1;
                }
                out.push(Tok::Other);
            }
            _ => {
                out.push(Tok::Other);
                i += 1;
            }
        }
    }
    Some(out)
}

/// For a `'` at `i`: `Some(true)` for an `E'...'` string, `Some(false)` for a plain one (no
/// prefix, or `B`, `X`, `N`, `U&`), `None` for any other word right before it, which
/// PostgreSQL might lex differently.
fn string_prefix(b: &[u8], i: usize) -> Option<bool> {
    if i > 0 && b[i - 1] == b'&' {
        // `U&'...'`: the `&` must follow exactly `U` at a token start.
        let u = i - 1;
        return (u > 0 && (b[u - 1] == b'U' || b[u - 1] == b'u') && (u < 2 || !is_word(b[u - 2]))).then_some(false);
    }
    let mut start = i;
    while start > 0 && is_word(b[start - 1]) {
        start -= 1;
    }
    match &b[start..i] {
        [] => Some(false),
        [b'E' | b'e'] => Some(true),
        [b'B' | b'b' | b'X' | b'x' | b'N' | b'n'] => Some(false),
        _ => None,
    }
}

/// The index after the closing quote; a doubled quote is part of the text.
fn skip_quoted(b: &[u8], start: usize, q: u8, backslash: bool) -> Option<usize> {
    let mut i = start + 1;
    loop {
        let c = *b.get(i)?;
        if backslash && c == b'\\' {
            i += 2;
        } else if c == q {
            if b.get(i + 1) == Some(&q) {
                i += 2;
            } else {
                return Some(i + 1);
            }
        } else {
            i += 1;
        }
    }
}

fn count(toks: &[Tok]) -> usize {
    let mut n = 0;
    let mut text = false;
    for t in toks {
        match t {
            Tok::Semi => {
                n += usize::from(text);
                text = false;
            }
            Tok::Comment => {}
            _ => text = true,
        }
    }
    n + usize::from(text)
}

/// The statements in `sql` with text in them (a trailing `;` or empty statements are not
/// counted). `None` if the SQL is left open or ambiguous, or the two readings of `\` disagree.
pub fn statement_count(sql: &str) -> Option<usize> {
    let a = tokens(sql, false)?;
    let b = tokens(sql, true)?;
    (a == b).then(|| count(&a))
}

/// Whether `sql` is one statement (a trailing `;` is allowed).
pub fn single_statement(sql: &str) -> bool {
    statement_count(sql) == Some(1)
}

fn filter_ok(toks: &[Tok]) -> bool {
    let mut depth = 0i32;
    for t in toks {
        match t {
            Tok::Semi | Tok::Comment | Tok::Dollar => return false,
            Tok::Open => depth += 1,
            Tok::Close => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Tok::Other => {}
        }
    }
    depth == 0
}

/// Whether a Data tab filter is one expression that cannot end the `WHERE` it goes into: no
/// `;`, comment or dollar quote, balanced parentheses, nothing left open or ambiguous, and the
/// same tokens under both readings of `\`.
pub fn safe_filter(filter: &str) -> bool {
    if filter.contains('\0') {
        return false;
    }
    match (tokens(filter, false), tokens(filter, true)) {
        (Some(a), Some(b)) => a == b && filter_ok(&a),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_statements() {
        assert_eq!(statement_count("SELECT 1"), Some(1));
        assert_eq!(statement_count("SELECT 1;"), Some(1));
        assert_eq!(statement_count("  ;; SELECT 1 ;  ; "), Some(1));
        assert_eq!(statement_count("SELECT 1; DELETE FROM t"), Some(2));
        assert_eq!(statement_count("SELECT 'a;b'"), Some(1));
        assert_eq!(statement_count("SELECT 'it''s; here'"), Some(1));
        assert_eq!(statement_count("SELECT E'\\'; DROP TABLE t; --'"), Some(1));
        // Without an E prefix the backslash is plain only when standard_conforming_strings is
        // on; the two readings disagree, so the SQL is refused.
        assert_eq!(statement_count("SELECT '\\'; DROP TABLE t"), None);
        assert_eq!(statement_count("SELECT \"a;\"\"b\" FROM t"), Some(1));
        assert_eq!(statement_count("SELECT 1 -- ; DROP\n"), Some(1));
        assert_eq!(statement_count("SELECT /* ; /* ; */ ; */ 1"), Some(1));
        assert_eq!(statement_count("SELECT $$;$$, $f$ ; $$ ; $f$"), Some(1));
        assert_eq!(statement_count("SELECT $1; SELECT 2"), Some(2));
        assert_eq!(statement_count("SELECT a$b; SELECT 2"), Some(2));
        assert_eq!(statement_count("SELECT U&'\\'; SELECT 2"), None, "U& strings are plain; the readings disagree");
        assert_eq!(statement_count("SELECT x'1F', b'01', n'a', U&'a', U&\"b\""), Some(1));
        assert_eq!(statement_count(""), Some(0));
        assert_eq!(statement_count("-- only a comment"), Some(0));
    }

    #[test]
    fn unterminated_sql_is_not_counted() {
        for s in ["SELECT 'a", "SELECT \"a", "SELECT /* a", "SELECT $$ a", "SELECT $x$ a $y$", "SELECT E'\\'"] {
            assert_eq!(statement_count(s), None, "{s}");
            assert!(!single_statement(s));
        }
    }

    #[test]
    fn a_quote_after_a_word_is_refused() {
        // Review #1346 HIGH: `xE` is an identifier, so `'\'` is a plain string in PostgreSQL.
        let hostile = "xE'\\'); SET default_transaction_read_only = off; DELETE FROM t; --'";
        assert!(!safe_filter(hostile));
        assert_eq!(statement_count(hostile), None);
        for s in ["1E'\\'); DROP TABLE t; --'", "ae'\\') OR (1=1", "a$E'\\'); x; --'", "aU&'x'", "foo'x'", "1'x'", "x\"a\""] {
            assert!(!safe_filter(s), "{s}");
            assert_eq!(statement_count(s), None, "{s}");
        }
        // A real E string at a token start is fine.
        assert!(safe_filter("note = E'it\\'s; ok'"));
        assert!(safe_filter("(note)=E'a'"));
    }

    #[test]
    fn standard_conforming_strings_off_cannot_split_differently() {
        // Review #1346 MEDIUM: with standard_conforming_strings = off, `\'` escapes the quote
        // in a plain string.
        let hostile = "a = '\\'); DELETE FROM t; --'";
        assert!(!safe_filter(hostile));
        assert_eq!(statement_count(&format!("SELECT 1 WHERE {hostile}")), None);
        // A backslash both readings agree on is fine.
        assert!(safe_filter("a = 'C:\\dir'"));
    }

    #[test]
    fn filters() {
        for ok in ["id > 3", "name = 'a;b'", "name = 'it''s'", "(a = 1) OR (b = 2)", "\"odd)\" = 1", "x IN (1, 2)"] {
            assert!(safe_filter(ok), "{ok}");
        }
        for bad in ["1 = 1; DROP TABLE t", "1 = 1) OR (1 = 1", "1 = 1 --", "a = 'x", "a /* b */", "a = $$x$$", "a)", "(a", "a\0"] {
            assert!(!safe_filter(bad), "{bad}");
        }
    }
}
