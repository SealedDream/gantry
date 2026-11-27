//! Data this app does not know (PLUG-03a, `docs/specs/plugins.md` section 10).
//!
//! A library may hold connection types and fields written by a newer Bastion or by a plugin.
//! The readers keep them and write them back unchanged, so one such entry no longer makes the
//! whole library "corrupt". What is kept is untrusted: it is never interpreted, never logged,
//! never handed to a connect path and never exported, and it is capped in size and depth.
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::{Deref, DerefMut};

use serde::de::{self, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Number, Value};

use crate::error::{CoreError, Result};
use crate::model::{Document, Folder, Node, Protocol, Settings};

/// What every app shows on an entry whose connection type this app does not know, and what a
/// connect attempt on it answers. One text, from the core, so the apps cannot drift.
pub const NEEDS_NEWER: &str = "Needs a newer Gantry or a plugin";

/// Fields this app does not know, by name, exactly as read.
pub type Extra = BTreeMap<String, Value>;

/// Longest unknown connection type name that is kept, in bytes. It must also be made of the
/// characters `a-z 0-9 . _ / -` only (a plugin type id is lower-case `plugin-id/type`), so a
/// stored name can never differ from a type this app knows by its case alone.
pub const MAX_PROTOCOL_NAME_BYTES: usize = 128;
/// Most unknown data kept in one place (one entry, one folder, one set of settings, one type
/// default, the document itself), measured as compact JSON.
pub const MAX_UNKNOWN_ENTRY_BYTES: usize = 256 * 1024;
/// Most unknown data kept in one library.
pub const MAX_UNKNOWN_TOTAL_BYTES: usize = 16 * 1024 * 1024;
/// Deepest nesting of arrays and objects inside one unknown value.
pub const MAX_UNKNOWN_DEPTH: usize = 32;
/// Deepest nesting of folders below the root that is read or saved: 62, the deepest the
/// reader before PLUG-03a could open (the JSON reader's own limit of 128 levels allowed no
/// more), so every library that opened before still opens. Reading a folder inside a folder
/// uses stack, and library work also runs on threads with a small one (512 KiB on macOS), so
/// the depth is bounded here, and a read runs on a thread of its own (see [`reading`]).
pub const MAX_FOLDER_DEPTH: usize = 62;
/// Folders this deep, and every so many levels below, are read by a JSON reader of their own
/// (see [`fresh_reader_due`]).
const FRESH_READER_EVERY: usize = 20;
/// Most text held at one time for folders and entries whose `kind` is not their first field
/// (Bastion writes it first; such a node is gathered as text before it can be read).
const MAX_GATHERED_BYTES: usize = crate::docfile::MAX_BYTES;

const ITEM_OVER: &str = "one item is over the size limit";
const LIBRARY_OVER: &str = "the library is over the size limit";
const TOO_DEEP: &str = "a value is nested too deeply";
const BAD_TYPE_NAME: &str = "a connection type name is too long or has characters other than a-z 0-9 . _ / -";

fn over_cap_text(what: &str) -> String {
    format!("this library holds data from a newer Gantry or a plugin that is more than this app can keep ({what}); open it with a newer Gantry")
}

fn over_cap(what: &str) -> CoreError {
    CoreError::Invalid(over_cap_text(what))
}

pub(crate) fn folders_too_deep() -> String {
    format!("folders are nested more than {MAX_FOLDER_DEPTH} deep; this app does not open or save a library like that")
}

/// Whether `name` may be kept as the stored name of a connection type this app does not know.
fn type_name_ok(name: &str) -> bool {
    name.len() <= MAX_PROTOCOL_NAME_BYTES && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'/' | b'-'))
}

fn check_type_name(name: &str) -> Result<()> {
    if !type_name_ok(name) {
        return Err(over_cap(BAD_TYPE_NAME));
    }
    Ok(())
}

// --- limits while reading --------------------------------------------------------------------
//
// The limits are enforced as the text is read, so a file that is refused never builds what it
// describes. serde gives a reader no place for state of its own, so the running numbers are
// kept per thread: a read is one call on one thread.

struct ReadState {
    /// Unknown data read so far, in the units of [`weigh`].
    total: usize,
    /// Why the read was refused, when a limit was passed (and not because the file is damaged).
    refused: Option<String>,
}

thread_local! {
    static READ: RefCell<Option<ReadState>> = const { RefCell::new(None) };
    static FOLDER_DEPTH: Cell<usize> = const { Cell::new(0) };
    static GATHERED: Cell<usize> = const { Cell::new(0) };
    /// The folder depth whose node is being read by a JSON reader of its own right now.
    static FRESH_READER_AT: Cell<usize> = const { Cell::new(usize::MAX) };
}

/// Why a library could not be read.
pub(crate) enum ReadError {
    /// It is over a limit of this app. A plain refusal: the file is not damaged.
    Refused(CoreError),
    /// It does not parse.
    Damaged(serde_json::Error),
}

impl ReadError {
    /// The error to report, with `damaged` deciding what a file that does not parse is called.
    pub(crate) fn or_else(self, damaged: impl FnOnce(serde_json::Error) -> CoreError) -> CoreError {
        match self {
            ReadError::Refused(e) => e,
            ReadError::Damaged(e) => damaged(e),
        }
    }
}

/// Stack for one read of a library. Reading a folder inside a folder uses stack (most of all
/// in a debug build), and the caller may be on a thread with very little: a macOS secondary
/// thread has 512 KiB. A read therefore runs on a thread of its own with a known stack, and
/// [`MAX_FOLDER_DEPTH`] bounds what it can use, so no file can overflow the stack.
const READ_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Run one read of a library (`parse`) with the limit for a whole library in force, and tell a
/// refusal at a limit apart from a file that does not parse.
pub(crate) fn reading<T: Send>(parse: impl FnOnce() -> serde_json::Result<T> + Send) -> std::result::Result<T, ReadError> {
    let read = move || {
        struct Scope(Option<ReadState>);
        impl Drop for Scope {
            fn drop(&mut self) {
                READ.with(|r| *r.borrow_mut() = self.0.take());
            }
        }
        let outer = Scope(READ.with(|r| r.borrow_mut().replace(ReadState { total: 0, refused: None })));
        let out = parse();
        let refused = READ.with(|r| r.borrow_mut().as_mut().and_then(|s| s.refused.take()));
        drop(outer);
        match (refused, out) {
            (Some(why), _) => Err(ReadError::Refused(CoreError::Invalid(why))),
            (None, Ok(read)) => Ok(read),
            (None, Err(e)) => Err(ReadError::Damaged(e)),
        }
    };
    std::thread::scope(|scope| match std::thread::Builder::new().name("bastion-library-read".into()).stack_size(READ_STACK_BYTES).spawn_scoped(scope, read) {
        Ok(thread) => thread.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
        Err(e) => Err(ReadError::Refused(CoreError::Io(e))),
    })
}

/// The error for passing a limit. Inside [`reading`] it is reported as a refusal, not as damage.
fn refuse<E: de::Error>(why: String) -> E {
    READ.with(|r| {
        if let Some(state) = r.borrow_mut().as_mut() {
            state.refused.get_or_insert_with(|| why.clone());
        }
    });
    E::custom(why)
}

/// Account for `n` more units of unknown data in the place whose running size is `here`.
fn spend<E: de::Error>(here: &mut usize, n: usize) -> std::result::Result<(), E> {
    *here = here.saturating_add(n);
    if *here > MAX_UNKNOWN_ENTRY_BYTES {
        return Err(refuse(over_cap_text(ITEM_OVER)));
    }
    let over = READ.with(|r| {
        r.borrow_mut().as_mut().is_some_and(|state| {
            state.total = state.total.saturating_add(n);
            state.total > MAX_UNKNOWN_TOTAL_BYTES
        })
    });
    if over {
        return Err(refuse(over_cap_text(LIBRARY_OVER)));
    }
    Ok(())
}

/// One more folder inside a folder is being read; dropped when it has been.
pub(crate) struct FolderLevel(());

impl FolderLevel {
    pub(crate) fn enter<E: de::Error>() -> std::result::Result<FolderLevel, E> {
        let depth = FOLDER_DEPTH.get();
        if depth >= MAX_FOLDER_DEPTH {
            return Err(refuse(folders_too_deep()));
        }
        FOLDER_DEPTH.set(depth + 1);
        Ok(FolderLevel(()))
    }
}

impl Drop for FolderLevel {
    fn drop(&mut self) {
        FOLDER_DEPTH.set(FOLDER_DEPTH.get().saturating_sub(1));
    }
}

/// Whether the node about to be read should get a JSON reader of its own.
///
/// The JSON reader stops at 128 nested arrays and objects, counted from where it started, and
/// each folder level takes two. Left alone, that limit would make a library within this app's
/// own limits unreadable (an entry in a folder 61 deep, an unknown value in a folder 50 deep),
/// and then this app could save a file it cannot open. So every [`FRESH_READER_EVERY`] folder
/// levels the fields of a node are each read by a new reader ([`RawFields`]); a node with
/// `kind` not first is always gathered as text and read by a new reader. What bounds depth is then this module alone: [`MAX_FOLDER_DEPTH`] for folders
/// and [`MAX_UNKNOWN_DEPTH`] for unknown values; everything else has a fixed shape.
pub(crate) fn fresh_reader_due() -> bool {
    let depth = FOLDER_DEPTH.get();
    depth > 0 && depth % FRESH_READER_EVERY == 0 && FRESH_READER_AT.get() != depth
}

/// Run `read`, which reads the node at the current folder depth with a JSON reader of its
/// own, so that the node is not gathered a second time.
pub(crate) fn with_fresh_reader<T>(read: impl FnOnce() -> T) -> T {
    let outer = FRESH_READER_AT.replace(FOLDER_DEPTH.get());
    let out = read();
    FRESH_READER_AT.set(outer);
    out
}

/// The fields of one JSON object, each still as text, served to a struct's reader with a JSON
/// reader of its own per value (so each value starts the JSON reader's level count again).
pub(crate) struct RawFields {
    fields: std::vec::IntoIter<(String, Box<serde_json::value::RawValue>)>,
    value: Option<Box<serde_json::value::RawValue>>,
}

impl RawFields {
    pub(crate) fn new(fields: Vec<(String, Box<serde_json::value::RawValue>)>) -> Self {
        RawFields { fields: fields.into_iter(), value: None }
    }
}

impl<'de> MapAccess<'de> for RawFields {
    type Error = serde_json::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> serde_json::Result<Option<K::Value>> {
        match self.fields.next() {
            None => Ok(None),
            Some((key, value)) => {
                self.value = Some(value);
                seed.deserialize(de::value::StringDeserializer::new(key)).map(Some)
            }
        }
    }
    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> serde_json::Result<T::Value> {
        let value = self.value.take().ok_or_else(|| serde_json::Error::custom("a value was asked for before its field"))?;
        // The text is dropped as soon as it has been read, so at most one copy of a node's
        // fields is held, and less and less of it as the node is read.
        // Read as a stream: the text lives only as long as this call, and the caller's
        // lifetime for borrowed data is longer, so nothing may be borrowed from it.
        seed.deserialize(&mut serde_json::Deserializer::from_reader(value.get().as_bytes()))
    }
}

/// Text held for one node that is gathered before it is read; given back when dropped.
#[derive(Default)]
pub(crate) struct Gathered(usize);

impl Gathered {
    pub(crate) fn add<E: de::Error>(&mut self, bytes: usize) -> std::result::Result<(), E> {
        self.0 = self.0.saturating_add(bytes);
        let live = GATHERED.get().saturating_add(bytes);
        GATHERED.set(live);
        if live > MAX_GATHERED_BYTES {
            return Err(refuse("this library is too large to read: its folders and entries are not written the way Gantry writes them".into()));
        }
        Ok(())
    }
}

impl Drop for Gathered {
    fn drop(&mut self) {
        GATHERED.set(GATHERED.get().saturating_sub(self.0));
    }
}

/// The stored name of a connection type this app does not know, or the refusal for a name
/// that may not be kept.
pub(crate) fn unknown_type_name<E: de::Error>(name: String) -> std::result::Result<String, E> {
    if type_name_ok(&name) {
        Ok(name)
    } else {
        Err(refuse(over_cap_text(BAD_TYPE_NAME)))
    }
}

fn number_size(n: &Number) -> usize {
    n.to_string().len()
}

/// Reads one unknown value, charging it against the limits as it goes: the same units and the
/// same depth rule as [`weigh`], so what is read here is exactly what [`check`] accepts.
struct Capped<'a> {
    here: &'a mut usize,
    depth: usize,
}

impl Capped<'_> {
    fn number<E: de::Error>(self, n: Number) -> std::result::Result<Value, E> {
        spend(self.here, number_size(&n))?;
        Ok(Value::Number(n))
    }
}

impl<'de> DeserializeSeed<'de> for Capped<'_> {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Capped<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        spend(self.here, 5)?;
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        self.number(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        self.number(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        match Number::from_f64(v) {
            Some(n) => self.number(n),
            None => self.visit_unit(),
        }
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        spend(self.here, v.len() + 2)?;
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        spend(self.here, v.len() + 2)?;
        Ok(Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        spend(self.here, 5)?;
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> std::result::Result<Value, E> {
        self.visit_unit()
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        d.deserialize_any(self)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        if self.depth > MAX_UNKNOWN_DEPTH {
            return Err(refuse(over_cap_text(TOO_DEEP)));
        }
        spend(self.here, 2)?;
        let mut items = Vec::new();
        loop {
            spend(self.here, 1)?;
            match seq.next_element_seed(Capped { here: self.here, depth: self.depth + 1 })? {
                Some(item) => items.push(item),
                None => return Ok(Value::Array(items)),
            }
        }
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        if self.depth > MAX_UNKNOWN_DEPTH {
            return Err(refuse(over_cap_text(TOO_DEEP)));
        }
        spend(self.here, 2)?;
        let mut fields = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            spend(self.here, key.len() + 4)?;
            let value = map.next_value_seed(Capped { here: self.here, depth: self.depth + 1 })?;
            if fields.insert(key, value).is_some() {
                return Err(A::Error::custom("a field is repeated"));
            }
        }
        Ok(Value::Object(fields))
    }
}

/// A reader for a struct that keeps the fields the struct does not name.
///
/// It stands in front of the real reader. The struct's derived code asks it for a struct and
/// names its fields; this passes those through untouched and reads every other field into
/// `extra`, within the limits, refusing one that is written twice. Nothing is buffered on the
/// way (serde's own `flatten` buffers every unknown field before any limit can apply).
pub(crate) struct Capturing<'a, D> {
    inner: D,
    extra: &'a mut Extra,
}

impl<'a, D> Capturing<'a, D> {
    pub(crate) fn new(inner: D, extra: &'a mut Extra) -> Self {
        Capturing { inner, extra }
    }
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Capturing<'_, D> {
    type Error = D::Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> std::result::Result<V::Value, D::Error> {
        self.inner.deserialize_any(visitor)
    }
    fn deserialize_struct<V: Visitor<'de>>(self, _name: &'static str, fields: &'static [&'static str], visitor: V) -> std::result::Result<V::Value, D::Error> {
        self.inner.deserialize_map(CapturingVisitor { fields, visitor, extra: self.extra })
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf option unit
        unit_struct newtype_struct seq tuple tuple_struct map enum identifier ignored_any
    }
}

struct CapturingVisitor<'a, V> {
    fields: &'static [&'static str],
    visitor: V,
    extra: &'a mut Extra,
}

impl<'de, V: Visitor<'de>> Visitor<'de> for CapturingVisitor<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.visitor.expecting(f)
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<V::Value, A::Error> {
        self.visitor.visit_map(KnownFields { map, fields: self.fields, extra: self.extra, next: 0, here: 0 })
    }
}

/// A field name as read: one of the struct's own (by position), or any other.
enum FieldName {
    Known(usize),
    Unknown(String),
}

/// Recognises a field name without copying it when the struct has it. Fields usually arrive
/// in the order they are declared, so the search starts after the last one found.
struct FieldNameSeed {
    fields: &'static [&'static str],
    next: usize,
}

impl<'de> DeserializeSeed<'de> for FieldNameSeed {
    type Value = FieldName;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<FieldName, D::Error> {
        d.deserialize_str(self)
    }
}

impl Visitor<'_> for FieldNameSeed {
    type Value = FieldName;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a field name")
    }
    fn visit_str<E: de::Error>(self, key: &str) -> std::result::Result<FieldName, E> {
        let from = self.next.min(self.fields.len());
        let found = (from..self.fields.len()).chain(0..from).find(|&i| self.fields[i] == key);
        Ok(found.map_or_else(|| FieldName::Unknown(key.to_owned()), FieldName::Known))
    }
}

/// The fields of a JSON object as the struct's derived reader sees them: only its own.
struct KnownFields<'a, A> {
    map: A,
    fields: &'static [&'static str],
    extra: &'a mut Extra,
    next: usize,
    /// Size of the unknown data kept in this place so far.
    here: usize,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for KnownFields<'_, A> {
    type Error = A::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> std::result::Result<Option<K::Value>, A::Error> {
        loop {
            match self.map.next_key_seed(FieldNameSeed { fields: self.fields, next: self.next })? {
                None => return Ok(None),
                Some(FieldName::Known(i)) => {
                    self.next = i + 1;
                    return seed.deserialize(de::value::StrDeserializer::new(self.fields[i])).map(Some);
                }
                Some(FieldName::Unknown(key)) => {
                    spend(&mut self.here, key.len() + 3)?;
                    let value = self.map.next_value_seed(Capped { here: &mut self.here, depth: 1 })?;
                    if self.extra.insert(key, value).is_some() {
                        return Err(A::Error::custom("a field is repeated"));
                    }
                }
            }
        }
    }
    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> std::result::Result<T::Value, A::Error> {
        self.map.next_value_seed(seed)
    }
}

/// `Serialize` and `Deserialize` for a struct that keeps unknown fields in `extra`. The struct
/// derives both with `#[serde(remote = "Self")]` and marks `extra` as
/// `#[serde(flatten, skip_deserializing)]`; this adds the reader that fills `extra`.
/// Always read such a struct through the trait (`<T as Deserialize>::deserialize`): the derived
/// function of the same name on the type itself drops unknown fields.
macro_rules! keeps_unknown_fields {
    ($t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                <$t>::serialize(self, s)
            }
        }
        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let mut extra = $crate::unknown::Extra::new();
                let mut read = <$t>::deserialize($crate::unknown::Capturing::new(d, &mut extra))?;
                read.extra = extra;
                Ok(read)
            }
        }
    };
}
pub(crate) use keeps_unknown_fields;

// --- limits on what is held (after reading, and before saving) -------------------------------

/// Running total for one library.
struct Budget {
    total: usize,
}

impl Budget {
    /// Account for the unknown values held in one place.
    fn spend<'a>(&mut self, values: impl Iterator<Item = (&'a String, &'a Value)>) -> Result<()> {
        let mut here = 0usize;
        for (key, value) in values {
            here = here.saturating_add(key.len() + 3);
            weigh(value, 1, &mut here)?;
            if here > MAX_UNKNOWN_ENTRY_BYTES {
                return Err(over_cap(ITEM_OVER));
            }
        }
        self.total = self.total.saturating_add(here);
        if self.total > MAX_UNKNOWN_TOTAL_BYTES {
            return Err(over_cap(LIBRARY_OVER));
        }
        Ok(())
    }

    /// `depth` is how many folders `f` is below the root.
    fn folder(&mut self, f: &Folder, depth: usize) -> Result<()> {
        if depth > MAX_FOLDER_DEPTH {
            return Err(CoreError::Invalid(folders_too_deep()));
        }
        self.spend(f.extra.iter())?;
        self.spend(f.defaults.extra.iter())?;
        for child in &f.children {
            match child {
                Node::Folder(sub) => self.folder(sub, depth + 1)?,
                Node::Connection(c) => {
                    if let Some(name) = &c.unknown_protocol {
                        check_type_name(name)?;
                    }
                    self.spend(c.extra.iter())?;
                    self.spend(c.settings.extra.iter())?;
                }
            }
        }
        Ok(())
    }
}

/// Add the compact-JSON size of `v` to `size`, stopping early once it is over the entry cap.
fn weigh(v: &Value, depth: usize, size: &mut usize) -> Result<()> {
    if *size > MAX_UNKNOWN_ENTRY_BYTES {
        return Ok(()); // the caller refuses; no need to walk the rest
    }
    match v {
        Value::Null | Value::Bool(_) => *size += 5,
        Value::Number(n) => *size += number_size(n),
        Value::String(s) => *size = size.saturating_add(s.len() + 2),
        Value::Array(items) => {
            if depth > MAX_UNKNOWN_DEPTH {
                return Err(over_cap(TOO_DEEP));
            }
            *size += 2;
            for item in items {
                *size += 1;
                weigh(item, depth + 1, size)?;
            }
        }
        Value::Object(fields) => {
            if depth > MAX_UNKNOWN_DEPTH {
                return Err(over_cap(TOO_DEEP));
            }
            *size += 2;
            for (key, item) in fields {
                *size = size.saturating_add(key.len() + 4);
                weigh(item, depth + 1, size)?;
            }
        }
    }
    Ok(())
}

/// Refuse a library whose unknown data is over the caps or whose folders are nested too deeply.
/// The readers enforce the same limits while they read; this is the same rule for a library
/// that is already in memory. Both writers call it before they write, so this app never saves
/// a file it would refuse to open, and both readers call it on what they loaded. The answer is
/// a plain error, never "corrupt" (which would point at a backup).
/// `outside` is unknown data kept next to the document (a document file's contents).
pub fn check(doc: &Document, outside: &Extra) -> Result<()> {
    let mut budget = Budget { total: 0 };
    budget.spend(outside.iter())?;
    budget.spend(doc.extra.iter())?;
    for settings in doc.type_defaults.values() {
        budget.spend(settings.extra.iter())?;
    }
    for (name, value) in doc.type_defaults.unknown() {
        check_type_name(name)?;
        budget.spend(std::iter::once((name, value)))?;
    }
    budget.folder(&doc.root, 0)
}

/// True when the library holds anything this app keeps without knowing it: an entry of an
/// unknown type (plugin entries included, PLUG-03b), or an unknown field anywhere, or defaults
/// for an unknown type. A document file holding any of it is written as `VERSION + 1` (spec
/// section 10, step 3), so apps older than the tolerant readers say "saved by a newer Gantry"
/// instead of calling it corrupt.
pub fn holds_unknown(doc: &Document, outside: &Extra) -> bool {
    fn settings(s: &Settings) -> bool {
        !s.extra.is_empty()
    }
    fn folder(f: &Folder) -> bool {
        !f.extra.is_empty()
            || settings(&f.defaults)
            || f.children.iter().any(|n| match n {
                Node::Connection(c) => c.protocol == Protocol::Unsupported || !c.extra.is_empty() || settings(&c.settings),
                Node::Folder(sub) => folder(sub),
            })
    }
    !outside.is_empty() || !doc.extra.is_empty() || !doc.type_defaults.unknown.is_empty() || doc.type_defaults.values().any(settings) || folder(&doc.root)
}

/// Drop every entry of an unknown type and every unknown field below `f`. Used where data
/// leaves or enters a library by another road than open and save (export, import): unknown
/// data cannot be checked for secrets or for references, so it does not travel.
pub fn strip_folder(f: &mut Folder) {
    f.extra.clear();
    f.defaults.extra.clear();
    f.children.retain(|n| !matches!(n, Node::Connection(c) if c.protocol == Protocol::Unsupported));
    for child in &mut f.children {
        match child {
            Node::Folder(sub) => strip_folder(sub),
            Node::Connection(c) => {
                c.extra.clear();
                c.settings.extra.clear();
            }
        }
    }
}

/// [`strip_folder`] for a whole document, with its document-level unknown data.
pub fn strip_document(doc: &mut Document) {
    doc.extra.clear();
    doc.type_defaults.unknown.clear();
    for settings in doc.type_defaults.values_mut() {
        settings.extra.clear();
    }
    strip_folder(&mut doc.root);
}

/// Default Settings per connection type. It behaves as the map of the types this app knows;
/// defaults stored for a type it does not know are kept beside it, untouched, and written back.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TypeDefaults {
    known: BTreeMap<Protocol, Settings>,
    unknown: BTreeMap<String, Value>,
}

impl TypeDefaults {
    /// Nothing stored at all, for known or unknown types.
    pub fn is_empty(&self) -> bool {
        self.known.is_empty() && self.unknown.is_empty()
    }

    /// Defaults kept for connection types this app does not know, by stored type name.
    pub fn unknown(&self) -> &BTreeMap<String, Value> {
        &self.unknown
    }
}

impl Deref for TypeDefaults {
    type Target = BTreeMap<Protocol, Settings>;
    fn deref(&self) -> &Self::Target {
        &self.known
    }
}

impl DerefMut for TypeDefaults {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.known
    }
}

impl From<BTreeMap<Protocol, Settings>> for TypeDefaults {
    fn from(known: BTreeMap<Protocol, Settings>) -> Self {
        TypeDefaults { known, unknown: BTreeMap::new() }
    }
}

impl FromIterator<(Protocol, Settings)> for TypeDefaults {
    fn from_iter<I: IntoIterator<Item = (Protocol, Settings)>>(iter: I) -> Self {
        TypeDefaults::from(iter.into_iter().collect::<BTreeMap<_, _>>())
    }
}

impl Serialize for TypeDefaults {
    /// Known types first, in the order they have always been written, then the unknown ones.
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(self.known.len() + self.unknown.len()))?;
        for (protocol, settings) in &self.known {
            if *protocol == Protocol::Unsupported {
                return Err(serde::ser::Error::custom("defaults cannot be stored for an unknown connection type"));
            }
            map.serialize_entry(protocol.as_str(), settings)?;
        }
        for (name, value) in &self.unknown {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for TypeDefaults {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = TypeDefaults;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map of connection type to default settings")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<TypeDefaults, A::Error> {
                let mut out = TypeDefaults::default();
                while let Some(name) = map.next_key::<String>()? {
                    let repeated = match Protocol::from_wire(&name) {
                        Some(protocol) => {
                            // A repeated known type keeps its last value, as it always did.
                            out.known.insert(protocol, map.next_value()?);
                            false
                        }
                        None => {
                            let name = unknown_type_name(name)?;
                            let mut here = 0;
                            spend(&mut here, name.len() + 3)?;
                            let value = map.next_value_seed(Capped { here: &mut here, depth: 1 })?;
                            out.unknown.insert(name, value).is_some()
                        }
                    };
                    if repeated {
                        return Err(A::Error::custom("a connection type is repeated"));
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_map(V)
    }
}
