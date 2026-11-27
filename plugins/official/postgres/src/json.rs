//! A small JSON reader for EXPLAIN (FORMAT JSON) output (PLUG-08b). No new crate: the plugin
//! reads one document the server wrote, with bounded depth and size.

/// A JSON value. Objects keep their order.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

/// Nesting deeper than this is refused (a plan nests about three levels per plan node).
pub const MAX_DEPTH: usize = 256;
/// Documents larger than this are refused.
pub const MAX_LEN: usize = 16 * 1024 * 1024;

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }
}

pub fn parse(text: &str) -> Result<Json, String> {
    if text.len() > MAX_LEN {
        return Err("The plan is too large.".into());
    }
    let mut p = Parser { b: text.as_bytes(), i: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err());
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self) -> String {
        format!("The plan is not valid JSON (at byte {}).", self.i)
    }
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn eat(&mut self, s: &[u8]) -> bool {
        if self.b[self.i..].starts_with(s) {
            self.i += s.len();
            true
        } else {
            false
        }
    }
    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err("The plan nests too deeply.".into());
        }
        self.ws();
        match self.b.get(self.i) {
            Some(b'{') => {
                self.i += 1;
                let mut o = Vec::new();
                self.ws();
                if self.eat(b"}") {
                    return Ok(Json::Object(o));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return Err(self.err());
                    }
                    let k = self.string()?;
                    self.ws();
                    if !self.eat(b":") {
                        return Err(self.err());
                    }
                    let v = self.value(depth + 1)?;
                    o.push((k, v));
                    self.ws();
                    if self.eat(b"}") {
                        return Ok(Json::Object(o));
                    }
                    if !self.eat(b",") {
                        return Err(self.err());
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.eat(b"]") {
                    return Ok(Json::Array(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    if self.eat(b"]") {
                        return Ok(Json::Array(a));
                    }
                    if !self.eat(b",") {
                        return Err(self.err());
                    }
                }
            }
            Some(b'"') => self.string().map(Json::String),
            Some(b't') if self.eat(b"true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat(b"false") => Ok(Json::Bool(false)),
            Some(b'n') if self.eat(b"null") => Ok(Json::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                while self.i < self.b.len() && matches!(self.b[self.i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    self.i += 1;
                }
                std::str::from_utf8(&self.b[start..self.i]).ok().and_then(|s| s.parse().ok()).map(Json::Number).ok_or_else(|| self.err())
            }
            _ => Err(self.err()),
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let c = *self.b.get(self.i).ok_or_else(|| self.err())?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).map_err(|_| self.err()),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or_else(|| self.err())?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp) && self.eat(b"\\u") {
                                let lo = self.hex4()?;
                                if (0xDC00..0xE000).contains(&lo) {
                                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                }
                            }
                            let ch = char::from_u32(cp).unwrap_or('\u{FFFD}');
                            let mut buf = [0; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(self.err()),
                    }
                }
                c if c < 0x20 => return Err(self.err()),
                c => out.push(c),
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let s = self.b.get(self.i..self.i + 4).ok_or_else(|| self.err())?;
        let v = std::str::from_utf8(s).ok().and_then(|s| u32::from_str_radix(s, 16).ok()).ok_or_else(|| self.err())?;
        self.i += 4;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let v = parse(r#" [ {"a": 1.5, "b": "x\"y\u00e9\ud83d\ude00", "c": [true, false, null], "d": {}} ] "#).unwrap();
        let o = &v.as_array().unwrap()[0];
        assert_eq!(o.get("a").and_then(Json::as_f64), Some(1.5));
        assert_eq!(o.get("b").and_then(Json::as_str), Some("x\"yé😀"));
        assert_eq!(o.get("c"), Some(&Json::Array(vec![Json::Bool(true), Json::Bool(false), Json::Null])));
        assert_eq!(o.get("d"), Some(&Json::Object(vec![])));
        assert_eq!(parse("-2e3").unwrap(), Json::Number(-2000.0));
    }

    #[test]
    fn refuses_bad_input() {
        for bad in ["", "[", "[1,]", "{\"a\" 1}", "{\"a\":1,}", "\"abc", "\"a\nb\"", "tru", "[1] x", "\"\\q\"", "\"\\u12\"", "{1:2}"] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert!(parse(&deep).is_err());
        let ok = "[".repeat(100) + &"]".repeat(100);
        assert!(parse(&ok).is_ok());
    }
}
