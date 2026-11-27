//! How connections and tree nodes are read and written (split from `model.rs`).
//!
//! A connection's type is read as a name, so one this app does not know is kept and not an
//! error; fields no struct names are kept beside the known ones (PLUG-03a, see `unknown.rs`).
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Connection, Extra, Folder, Node, Protocol, Settings};


/// A connection as it is read: the type is still a name, so one this app does not know is not
/// an error. Every other known field keeps its type, so damaged data still fails to parse.
#[derive(Deserialize)]
struct ConnectionIn {
    id: Uuid,
    name: String,
    protocol: ProtocolIn,
    host: String,
    #[serde(default)]
    settings: Settings,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    classification: crate::policy::Classification,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

/// A connection type as read: one this app knows, or the stored name of one it does not.
enum ProtocolIn {
    Known(Protocol),
    Unknown(String),
}

impl<'de> Deserialize<'de> for ProtocolIn {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = ProtocolIn;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a connection type name")
            }
            fn visit_str<E: serde::de::Error>(self, name: &str) -> std::result::Result<ProtocolIn, E> {
                Ok(Protocol::from_wire(name).map_or_else(|| ProtocolIn::Unknown(name.to_owned()), ProtocolIn::Known))
            }
        }
        d.deserialize_str(V)
    }
}

impl<'de> Deserialize<'de> for Connection {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let mut extra = Extra::new();
        let c = ConnectionIn::deserialize(crate::unknown::Capturing::new(d, &mut extra))?;
        let (protocol, unknown_protocol) = match c.protocol {
            ProtocolIn::Known(p) => (p, None),
            ProtocolIn::Unknown(name) if name.is_empty() => return Err(D::Error::custom("a connection has an empty type")),
            ProtocolIn::Unknown(name) => (Protocol::Unsupported, Some(crate::unknown::unknown_type_name(name)?)),
        };
        Ok(Connection {
            id: c.id,
            name: c.name,
            protocol,
            host: c.host,
            settings: c.settings,
            tags: c.tags,
            notes: c.notes,
            icon: c.icon,
            favorite: c.favorite,
            classification: c.classification,
            metadata: c.metadata,
            extra,
            unknown_protocol,
        })
    }
}

/// A connection as it is written: the same fields in the same order as always, then the
/// unknown ones.
#[derive(Serialize)]
struct ConnectionOut<'a> {
    id: &'a Uuid,
    name: &'a str,
    protocol: &'a str,
    host: &'a str,
    settings: &'a Settings,
    tags: &'a [String],
    notes: &'a str,
    icon: &'a Option<String>,
    favorite: bool,
    classification: &'a crate::policy::Classification,
    metadata: &'a BTreeMap<String, String>,
    #[serde(flatten)]
    extra: &'a Extra,
}

impl Serialize for Connection {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let protocol = match (self.protocol, &self.unknown_protocol) {
            (Protocol::Unsupported, Some(name)) => name.as_str(),
            (Protocol::Unsupported, None) => return Err(serde::ser::Error::custom("a connection of an unknown type has lost its type name")),
            (known, _) => known.as_str(),
        };
        ConnectionOut {
            id: &self.id,
            name: &self.name,
            protocol,
            host: &self.host,
            settings: &self.settings,
            tags: &self.tags,
            notes: &self.notes,
            icon: &self.icon,
            favorite: self.favorite,
            classification: &self.classification,
            metadata: &self.metadata,
            extra: &self.extra,
        }
        .serialize(s)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum NodeKind {
    Folder,
    Connection,
}

impl NodeKind {
    fn read<'de, D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<Node, D::Error> {
        match self {
            NodeKind::Folder => {
                // Through the trait: `Folder::deserialize` is the derived reader, which drops
                // unknown fields.
                let _level = crate::unknown::FolderLevel::enter::<D::Error>()?;
                <Folder as Deserialize>::deserialize(d).map(Node::Folder)
            }
            NodeKind::Connection => <Connection as Deserialize>::deserialize(d).map(Node::Connection),
        }
    }
}

/// The first key of a node as read: `kind`, or anything else.
enum FirstKey {
    Kind,
    Other(String),
}

impl<'de> Deserialize<'de> for FirstKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = FirstKey;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a field name")
            }
            fn visit_str<E: serde::de::Error>(self, key: &str) -> std::result::Result<FirstKey, E> {
                Ok(if key == "kind" { FirstKey::Kind } else { FirstKey::Other(key.to_owned()) })
            }
        }
        d.deserialize_str(V)
    }
}

/// Reads `{"kind": "folder" | "connection", …}`. Bastion always writes `kind` first, and then
/// the rest of the object is read straight into the folder or connection, with no buffering
/// (this is what keeps a large library as fast to load as before the readers kept unknown
/// fields). Every twentieth folder level its fields are each handed to a JSON reader of their
/// own (see `unknown::fresh_reader_due`). An object with `kind` elsewhere is gathered as
/// text, with `kind` moved to the front, and read the same way: no tree is built for it, the limits apply as they do on the
/// first road, and it needs little more stack. A missing, repeated or unknown `kind` is an
/// error, as it always was.
impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::{value::MapAccessDeserializer, Error, MapAccess};
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Node;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a folder or a connection")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Node, A::Error> {
                match map.next_key::<FirstKey>()? {
                    None => Err(A::Error::missing_field("kind")),
                    Some(FirstKey::Kind) if !crate::unknown::fresh_reader_due() => {
                        let node = map.next_value::<NodeKind>()?.read(MapAccessDeserializer::new(map))?;
                        let extra = match &node {
                            Node::Folder(f) => &f.extra,
                            Node::Connection(c) => &c.extra,
                        };
                        // A second `kind` would otherwise be kept as an unknown field.
                        if extra.contains_key("kind") {
                            return Err(A::Error::duplicate_field("kind"));
                        }
                        Ok(node)
                    }
                    Some(FirstKey::Kind) => {
                        // A node written the way Bastion writes it, at a depth where the JSON
                        // reader's own level count has to start again: each of its fields is
                        // read by a reader of its own. This is not the gathered road, and
                        // nothing here counts against the gathered-text limit: whatever this
                        // app saves, it must open.
                        let kind = map.next_value::<NodeKind>()?;
                        let mut fields = Vec::new();
                        while let Some(field) = map.next_entry::<String, Box<serde_json::value::RawValue>>()? {
                            fields.push(field);
                        }
                        let node = kind.read(MapAccessDeserializer::new(crate::unknown::RawFields::new(fields))).map_err(A::Error::custom)?;
                        let extra = match &node {
                            Node::Folder(f) => &f.extra,
                            Node::Connection(c) => &c.extra,
                        };
                        if extra.contains_key("kind") {
                            return Err(A::Error::duplicate_field("kind"));
                        }
                        Ok(node)
                    }
                    Some(FirstKey::Other(first)) => {
                        // `{"kind":` and room for the longest kind, filled in once it is known.
                        const KIND_AT: std::ops::Range<usize> = 8..20;
                        let mut text = String::from(r#"{"kind":            "#);
                        let mut held = crate::unknown::Gathered::default();
                        let mut kind: Option<NodeKind> = None;
                        let mut next = Some(first);
                        loop {
                            let key = match next.take() {
                                Some(key) => key,
                                None => match map.next_key::<String>()? {
                                    Some(key) => key,
                                    None => break,
                                },
                            };
                            if key == "kind" {
                                if kind.replace(map.next_value()?).is_some() {
                                    return Err(A::Error::duplicate_field("kind"));
                                }
                                continue;
                            }
                            let value: Box<serde_json::value::RawValue> = map.next_value()?;
                            held.add::<A::Error>(key.len() + value.get().len() + 4)?;
                            text.push(',');
                            text.push_str(&serde_json::to_string(&key).map_err(A::Error::custom)?);
                            text.push(':');
                            text.push_str(value.get());
                        }
                        let kind = kind.ok_or_else(|| A::Error::missing_field("kind"))?;
                        text.replace_range(
                            KIND_AT,
                            match kind {
                                NodeKind::Folder => r#""folder"    "#,
                                NodeKind::Connection => r#""connection""#,
                            },
                        );
                        text.push('}');
                        crate::unknown::with_fresh_reader(|| serde_json::from_str::<Node>(&text)).map_err(A::Error::custom)
                    }
                }
            }
        }
        d.deserialize_map(V)
    }
}
