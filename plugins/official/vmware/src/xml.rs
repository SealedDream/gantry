//! A small, bounded XML tree for SOAP answers (standalone ESXi). Only element names (without
//! the namespace prefix), the `type` attribute and text are kept. DOCTYPE is refused; entities
//! other than the five predefined ones and character references are refused.

use quick_xml::events::Event;
use quick_xml::Reader;

/// Limits on an answer: elements, depth and text.
pub const MAX_ELEMENTS: usize = 200_000;
pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    pub name: String,
    /// The `type` attribute (`<obj type="VirtualMachine">`, `<val xsi:type="ArrayOfString">`).
    pub kind: Option<String>,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Every element named `name` below this one, depth first.
    pub fn descendants<'a>(&'a self, name: &str, out: &mut Vec<&'a Element>) {
        for c in &self.children {
            if c.name == name {
                out.push(c);
            }
            c.descendants(name, out);
        }
    }

    pub fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str())
    }
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

/// Parses `body` into its root element.
pub fn parse(body: &[u8]) -> Result<Element, String> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut count = 0usize;
    loop {
        let event = reader.read_event().map_err(|e| e.to_string())?;
        match event {
            Event::Eof => break,
            Event::DocType(_) => return Err("a DOCTYPE in the answer".into()),
            Event::Start(s) | Event::Empty(s) if stack.len() > MAX_DEPTH => return Err(format!("answer deeper than {MAX_DEPTH} ({})", local(s.name().as_ref()))),
            Event::Start(s) => {
                count += 1;
                stack.push(open(&s, count)?);
            }
            Event::Empty(s) => {
                count += 1;
                let e = open(&s, count)?;
                stack.last_mut().expect("root").children.push(e);
            }
            Event::End(_) => {
                let done = stack.pop().ok_or("unbalanced answer")?;
                stack.last_mut().ok_or("unbalanced answer")?.children.push(done);
            }
            Event::Text(t) => {
                let s: &str = t.as_ref();
                stack.last_mut().expect("root").text.push_str(s);
            }
            Event::CData(c) => {
                let s: &str = c.as_ref();
                stack.last_mut().expect("root").text.push_str(s);
            }
            Event::GeneralRef(r) => {
                let name: &str = r.as_ref();
                let text = match name {
                    "lt" => "<".to_string(),
                    "gt" => ">".to_string(),
                    "amp" => "&".to_string(),
                    "quot" => "\"".to_string(),
                    "apos" => "'".to_string(),
                    _ => match r.resolve_char_ref() {
                        Ok(Some(c)) => c.to_string(),
                        _ => return Err("an entity in the answer".into()),
                    },
                };
                stack.last_mut().expect("root").text.push_str(&text);
            }
            _ => {}
        }
    }
    if stack.len() != 1 {
        return Err("unbalanced answer".into());
    }
    stack.pop().expect("root").children.into_iter().next().ok_or_else(|| "an empty answer".into())
}

fn open(s: &quick_xml::events::BytesStart<'_>, count: usize) -> Result<Element, String> {
    if count > MAX_ELEMENTS {
        return Err("answer too large".into());
    }
    let kind = s.attributes().flatten().find(|a| local(a.key.as_ref()) == "type").and_then(|a| a.normalized_value(quick_xml::XmlVersion::Implicit1_0).ok().map(|v| v.into_owned()));
    Ok(Element { name: local(s.name().as_ref()), kind, ..Default::default() })
}

/// XML text escaping for values the plugin writes (snapshot names).
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names_types_and_text() {
        let e = parse(br#"<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="s" xmlns:xsi="x"><soapenv:Body><obj type="VirtualMachine">12</obj><val xsi:type="xsd:string">a &amp; b &#65;</val></soapenv:Body></soapenv:Envelope>"#).unwrap();
        assert_eq!(e.name, "Envelope");
        let body = e.child("Body").unwrap();
        assert_eq!((body.child("obj").unwrap().kind.as_deref(), body.text_of("obj")), (Some("VirtualMachine"), Some("12")));
        assert_eq!(body.text_of("val"), Some("a & b A"));
    }

    #[test]
    fn refuses_hostile_answers() {
        assert!(parse(br#"<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>"#).is_err());
        assert!(parse(b"<a>&x;</a>").is_err());
        assert!(parse(b"<a><b></a>").is_err());
        assert!(parse(b"").is_err());
        let deep = "<a>".repeat(MAX_DEPTH + 2) + &"</a>".repeat(MAX_DEPTH + 2);
        assert!(parse(deep.as_bytes()).is_err());
    }

    #[test]
    fn escapes() {
        assert_eq!(escape("a<b>&\"'\u{1}"), "a&lt;b&gt;&amp;&quot;&apos;");
    }
}
