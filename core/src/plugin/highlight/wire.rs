//! Token kinds and line states as text, for the UniFFI and C ABI exports (PLUG-06c). An app
//! keeps the state string of each line and gives it back for the line below; it never reads it.
//!
//! State strings: `""` normal, `c<depth>` block comment, `s` / `se` / `sp` standard, escape and
//! plain string, `q` quoted identifier, `d<hex tag>` dollar string (`d` alone: `$$`). A string
//! that is none of these reads as normal, so a damaged state colours a line wrongly but never
//! fails.

use super::{DollarTag, LineState, StringMode, TokenKind, MAX_DOLLAR_TAG_BYTES};

/// The name an app maps to a colour.
pub fn kind_name(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Keyword => "keyword",
        TokenKind::Identifier => "identifier",
        TokenKind::QuotedIdentifier => "quoted-identifier",
        TokenKind::String => "string",
        TokenKind::Number => "number",
        TokenKind::Comment => "comment",
        TokenKind::Operator => "operator",
        TokenKind::Punctuation => "punctuation",
        TokenKind::Parameter => "parameter",
        TokenKind::TypeName => "type",
        TokenKind::FunctionName => "function",
        TokenKind::Text => "text",
        TokenKind::Error => "error",
    }
}

/// The state as a short string.
pub fn encode_state(state: &LineState) -> String {
    match state {
        LineState::Normal => String::new(),
        LineState::BlockComment { depth } => format!("c{depth}"),
        LineState::String { mode: StringMode::Standard } => "s".into(),
        LineState::String { mode: StringMode::Escape } => "se".into(),
        LineState::String { mode: StringMode::Plain } => "sp".into(),
        LineState::QuotedIdentifier => "q".into(),
        LineState::DollarString { tag } => {
            let mut s = String::from("d");
            for b in tag.as_bytes() {
                s.push_str(&format!("{b:02x}"));
            }
            s
        }
    }
}

/// A state string back; anything not made by [`encode_state`] is [`LineState::Normal`].
pub fn decode_state(s: &str) -> LineState {
    let normal = LineState::Normal;
    match s {
        "" => normal,
        "s" => LineState::String { mode: StringMode::Standard },
        "se" => LineState::String { mode: StringMode::Escape },
        "sp" => LineState::String { mode: StringMode::Plain },
        "q" => LineState::QuotedIdentifier,
        _ if s.starts_with('c') => match s[1..].parse::<u8>() {
            Ok(depth) if depth >= 1 && !s[1..].starts_with('0') && s[1..].bytes().all(|b| b.is_ascii_digit()) => LineState::BlockComment { depth },
            _ => normal,
        },
        _ if s.starts_with('d') => {
            let hex = &s[1..];
            if hex.len() % 2 != 0 || hex.len() > MAX_DOLLAR_TAG_BYTES * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return normal;
            }
            let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect();
            DollarTag::new(&bytes).map_or(normal, |tag| LineState::DollarString { tag })
        }
        _ => normal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_round_trip() {
        let states = [
            LineState::Normal,
            LineState::BlockComment { depth: 1 },
            LineState::BlockComment { depth: u8::MAX },
            LineState::String { mode: StringMode::Standard },
            LineState::String { mode: StringMode::Escape },
            LineState::String { mode: StringMode::Plain },
            LineState::QuotedIdentifier,
            LineState::DollarString { tag: DollarTag::new(b"").unwrap() },
            LineState::DollarString { tag: DollarTag::new("fn_é".as_bytes()).unwrap() },
            LineState::DollarString { tag: DollarTag::new(&[b'a'; MAX_DOLLAR_TAG_BYTES]).unwrap() },
        ];
        for state in states {
            assert_eq!(decode_state(&encode_state(&state)), state, "{state:?}");
        }
    }

    #[test]
    fn damaged_states_read_as_normal() {
        let long = format!("d{}", "61".repeat(MAX_DOLLAR_TAG_BYTES + 1));
        for s in ["x", "c", "c0", "c01", "c256", "c-1", "c+1", "d6", "dzz", long.as_str(), "S", "sq"] {
            assert_eq!(decode_state(s), LineState::Normal, "{s}");
        }
    }
}
