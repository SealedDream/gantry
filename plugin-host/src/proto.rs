//! The pipe protocol between the core and `bastion-plugin-host` (spec section 5, "Messages";
//! PLUG-01 decisions 3 and 4).
//!
//! - A frame is a 4-byte little-endian length and that many bytes, at most `MAX_FRAME`. The
//!   length is checked before anything is allocated. Either side ends the conversation on a
//!   frame that is too long or does not decode.
//! - Bulk bytes (a component, compiled code) go in pieces of at most `CHUNK`.
//! - Plugin calls into the core travel as `Value` trees: the WIT world has no resources, so every
//!   import is plain data. The helper converts them to and from Wasmtime's values; the core
//!   decides what each one means. Decoding is bounded in depth and never allocates more than
//!   the frame holds.
//!
//! This module has no dependencies, so the core links it without Wasmtime.

use std::io::{self, Read, Write};

/// Bumped when a message changes shape. The helper reports it in `Hello`; the core refuses a
/// helper with another number (an app bundle with a stale helper).
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest frame in either direction (spec section 5).
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Largest value one `storage.set` may store. The helper sends a larger value's length only
/// (`[key, u64 length]` in place of `[key, bytes]`) and the core answers `invalid`, so the
/// plugin hears a refusal instead of the helper running out of memory or framing it.
pub const MAX_STORAGE_VALUE_BYTES: usize = 2 * 1024 * 1024;
/// Largest piece of a component or of compiled code in one frame.
pub const CHUNK: usize = 1024 * 1024;
/// Deepest `Value` nesting either side decodes. WIT values in API 1 are a few levels deep; a
/// view list is flat (parents by id), so 64 leaves a wide margin and keeps decoding off the
/// edge of the stack.
pub const MAX_VALUE_DEPTH: usize = 64;

/// Writes one frame. Refuses a body over `MAX_FRAME` instead of sending it.
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame over 16 MiB"));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    w.write_all(&out)?;
    w.flush()
}

/// Reads one frame. `Ok(None)` at a clean end of the pipe. A length over `MAX_FRAME` is an
/// error before any allocation.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame over 16 MiB"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Which job a helper process does. A helper does one job for its whole life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Runs one plugin's code from compiled code the core sends.
    View,
    /// Compiles one component and sends the code back; runs no plugin code.
    Compile,
}

/// The helper's OS sandbox, as it reports it. PLUG-05 adds the real sandbox and its checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sandbox {
    None,
    Applied,
}

/// A WIT value. Mirrors the component model's value kinds; `Bytes` is `list<u8>`, kept apart
/// because data and stream bytes are the bulk of the traffic.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    S8(i8),
    U8(u8),
    S16(i16),
    U16(u16),
    S32(i32),
    U32(u32),
    S64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    Char(char),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Record(Vec<(String, Value)>),
    Tuple(Vec<Value>),
    Variant(String, Option<Box<Value>>),
    Enum(String),
    Option(Option<Box<Value>>),
    Result(Result<Option<Box<Value>>, Option<Box<Value>>>),
    Flags(Vec<String>),
}

/// Core to helper.
#[derive(Debug, Clone, PartialEq)]
pub enum ToHelper {
    /// View helper: compiled code follows in `Chunk`s, then `End`. The limits apply to the
    /// plugin from the start.
    Load { memory_limit: u64, compute_ms: u32, total: u64 },
    /// Compile helper: the component follows in `Chunk`s, then `End`. `max_output` caps the
    /// compiled code (spec section 4).
    Compile { total: u64, max_output: u64 },
    Chunk(Vec<u8>),
    End,
    /// Call the plugin's `run` export.
    Run,
    /// The answer to `ToCore::Import` number `seq`: the import's results, in order.
    Reply { seq: u64, results: Vec<Value> },
    Ping(u64),
    /// Leave now. The core kills a helper that does not.
    Shutdown,
}

/// Helper to core.
#[derive(Debug, Clone, PartialEq)]
pub enum ToCore {
    /// Always the first message (spec section 5: the sandbox report).
    Hello { protocol: u32, role: Role, pid: u32, sandbox: Sandbox, engine_key: String },
    /// View helper: the code is loaded (or why not).
    Loaded { error: Option<String> },
    /// Compile helper: a piece of the compiled code.
    Compiled(Vec<u8>),
    /// Compile helper: the end of the code (or why there is none).
    CompileDone { error: Option<String> },
    /// The plugin called import `name` (`<interface>#<function>`); it waits for a `Reply`.
    Import { seq: u64, name: String, args: Vec<Value> },
    Pong(u64),
    /// `run` returned (`error: None`) or the plugin trapped. Either way the plugin is over.
    Ended { error: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed message: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

type D<T> = Result<T, DecodeError>;

// ---- encoding ----

struct Enc(Vec<u8>);

impl Enc {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn raw(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
    fn u32(&mut self, v: u32) {
        self.raw(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.raw(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.raw(v);
    }
    fn str(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }
    fn opt_str(&mut self, v: &Option<String>) {
        match v {
            None => self.u8(0),
            Some(s) => {
                self.u8(1);
                self.str(s);
            }
        }
    }
    fn opt_value(&mut self, v: &Option<Box<Value>>) {
        match v {
            None => self.u8(0),
            Some(v) => {
                self.u8(1);
                self.value(v);
            }
        }
    }
    fn values(&mut self, v: &[Value]) {
        self.u32(v.len() as u32);
        for x in v {
            self.value(x);
        }
    }
    fn value(&mut self, v: &Value) {
        match v {
            Value::Bool(b) => self.raw(&[0, *b as u8]),
            Value::S8(x) => self.raw(&[1, *x as u8]),
            Value::U8(x) => self.raw(&[2, *x]),
            Value::S16(x) => {
                self.u8(3);
                self.raw(&x.to_le_bytes());
            }
            Value::U16(x) => {
                self.u8(4);
                self.raw(&x.to_le_bytes());
            }
            Value::S32(x) => {
                self.u8(5);
                self.raw(&x.to_le_bytes());
            }
            Value::U32(x) => {
                self.u8(6);
                self.u32(*x);
            }
            Value::S64(x) => {
                self.u8(7);
                self.raw(&x.to_le_bytes());
            }
            Value::U64(x) => {
                self.u8(8);
                self.u64(*x);
            }
            Value::F32(x) => {
                self.u8(9);
                self.raw(&x.to_le_bytes());
            }
            Value::F64(x) => {
                self.u8(10);
                self.raw(&x.to_le_bytes());
            }
            Value::Char(c) => {
                self.u8(11);
                self.u32(*c as u32);
            }
            Value::String(s) => {
                self.u8(12);
                self.str(s);
            }
            Value::Bytes(b) => {
                self.u8(13);
                self.bytes(b);
            }
            Value::List(l) => {
                self.u8(14);
                self.values(l);
            }
            Value::Record(fields) => {
                self.u8(15);
                self.u32(fields.len() as u32);
                for (name, v) in fields {
                    self.str(name);
                    self.value(v);
                }
            }
            Value::Tuple(t) => {
                self.u8(16);
                self.values(t);
            }
            Value::Variant(name, payload) => {
                self.u8(17);
                self.str(name);
                self.opt_value(payload);
            }
            Value::Enum(name) => {
                self.u8(18);
                self.str(name);
            }
            Value::Option(v) => {
                self.u8(19);
                self.opt_value(v);
            }
            Value::Result(Ok(v)) => {
                self.u8(20);
                self.opt_value(v);
            }
            Value::Result(Err(v)) => {
                self.u8(21);
                self.opt_value(v);
            }
            Value::Flags(names) => {
                self.u8(22);
                self.u32(names.len() as u32);
                for n in names {
                    self.str(n);
                }
            }
        }
    }
}

// ---- decoding ----

struct Dec<'a> {
    b: &'a [u8],
}

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> D<&'a [u8]> {
        if n > self.b.len() {
            return Err(DecodeError("truncated"));
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }
    fn u8(&mut self) -> D<u8> {
        Ok(self.take(1)?[0])
    }
    fn arr<const N: usize>(&mut self) -> D<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn u32(&mut self) -> D<u32> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> D<u64> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    fn bool(&mut self) -> D<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError("bad bool")),
        }
    }
    /// A count of items that each take at least `min` bytes: refused when the rest of the
    /// frame could not hold them, so a forged count never drives an allocation.
    fn count(&mut self, min: usize) -> D<usize> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min.max(1)) > self.b.len() {
            return Err(DecodeError("count larger than the frame"));
        }
        Ok(n)
    }
    fn bytes(&mut self) -> D<Vec<u8>> {
        let n = self.count(1)?;
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> D<String> {
        String::from_utf8(self.bytes()?).map_err(|_| DecodeError("bad UTF-8"))
    }
    fn opt_str(&mut self) -> D<Option<String>> {
        Ok(if self.bool()? { Some(self.str()?) } else { None })
    }
    fn opt_value(&mut self, depth: usize) -> D<Option<Box<Value>>> {
        Ok(if self.bool()? { Some(Box::new(self.value(depth)?)) } else { None })
    }
    fn values(&mut self, depth: usize) -> D<Vec<Value>> {
        // Every value takes at least two bytes (its tag and one byte of payload).
        let n = self.count(2)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.value(depth)?);
        }
        Ok(out)
    }
    fn value(&mut self, depth: usize) -> D<Value> {
        if depth >= MAX_VALUE_DEPTH {
            return Err(DecodeError("value nested too deeply"));
        }
        let d = depth + 1;
        Ok(match self.u8()? {
            0 => Value::Bool(self.bool()?),
            1 => Value::S8(self.u8()? as i8),
            2 => Value::U8(self.u8()?),
            3 => Value::S16(i16::from_le_bytes(self.arr()?)),
            4 => Value::U16(u16::from_le_bytes(self.arr()?)),
            5 => Value::S32(i32::from_le_bytes(self.arr()?)),
            6 => Value::U32(self.u32()?),
            7 => Value::S64(i64::from_le_bytes(self.arr()?)),
            8 => Value::U64(self.u64()?),
            9 => Value::F32(f32::from_le_bytes(self.arr()?)),
            10 => Value::F64(f64::from_le_bytes(self.arr()?)),
            11 => Value::Char(char::from_u32(self.u32()?).ok_or(DecodeError("bad char"))?),
            12 => Value::String(self.str()?),
            13 => Value::Bytes(self.bytes()?),
            14 => Value::List(self.values(d)?),
            15 => {
                // A field is at least a 4-byte name length and a 2-byte value.
                let n = self.count(6)?;
                let mut fields = Vec::with_capacity(n);
                for _ in 0..n {
                    let name = self.str()?;
                    fields.push((name, self.value(d)?));
                }
                Value::Record(fields)
            }
            16 => Value::Tuple(self.values(d)?),
            17 => {
                let name = self.str()?;
                Value::Variant(name, self.opt_value(d)?)
            }
            18 => Value::Enum(self.str()?),
            19 => Value::Option(self.opt_value(d)?),
            20 => Value::Result(Ok(self.opt_value(d)?)),
            21 => Value::Result(Err(self.opt_value(d)?)),
            22 => {
                let n = self.count(4)?;
                let mut names = Vec::with_capacity(n);
                for _ in 0..n {
                    names.push(self.str()?);
                }
                Value::Flags(names)
            }
            _ => return Err(DecodeError("unknown value tag")),
        })
    }
    fn end(self) -> D<()> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(DecodeError("trailing bytes"))
        }
    }
}

impl ToHelper {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc(Vec::new());
        match self {
            ToHelper::Load { memory_limit, compute_ms, total } => {
                e.u8(1);
                e.u64(*memory_limit);
                e.u32(*compute_ms);
                e.u64(*total);
            }
            ToHelper::Compile { total, max_output } => {
                e.u8(2);
                e.u64(*total);
                e.u64(*max_output);
            }
            ToHelper::Chunk(b) => {
                e.u8(3);
                e.bytes(b);
            }
            ToHelper::End => e.u8(4),
            ToHelper::Run => e.u8(5),
            ToHelper::Reply { seq, results } => {
                e.u8(6);
                e.u64(*seq);
                e.values(results);
            }
            ToHelper::Ping(n) => {
                e.u8(7);
                e.u64(*n);
            }
            ToHelper::Shutdown => e.u8(8),
        }
        e.0
    }

    pub fn decode(body: &[u8]) -> D<Self> {
        let mut d = Dec { b: body };
        let m = match d.u8()? {
            1 => ToHelper::Load { memory_limit: d.u64()?, compute_ms: d.u32()?, total: d.u64()? },
            2 => ToHelper::Compile { total: d.u64()?, max_output: d.u64()? },
            3 => ToHelper::Chunk(d.bytes()?),
            4 => ToHelper::End,
            5 => ToHelper::Run,
            6 => ToHelper::Reply { seq: d.u64()?, results: d.values(0)? },
            7 => ToHelper::Ping(d.u64()?),
            8 => ToHelper::Shutdown,
            _ => return Err(DecodeError("unknown message")),
        };
        d.end()?;
        Ok(m)
    }
}

impl ToCore {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc(Vec::new());
        match self {
            ToCore::Hello { protocol, role, pid, sandbox, engine_key } => {
                e.u8(1);
                e.u32(*protocol);
                e.u8(match role {
                    Role::View => 0,
                    Role::Compile => 1,
                });
                e.u32(*pid);
                e.u8(match sandbox {
                    Sandbox::None => 0,
                    Sandbox::Applied => 1,
                });
                e.str(engine_key);
            }
            ToCore::Loaded { error } => {
                e.u8(2);
                e.opt_str(error);
            }
            ToCore::Compiled(b) => {
                e.u8(3);
                e.bytes(b);
            }
            ToCore::CompileDone { error } => {
                e.u8(4);
                e.opt_str(error);
            }
            ToCore::Import { seq, name, args } => {
                e.u8(5);
                e.u64(*seq);
                e.str(name);
                e.values(args);
            }
            ToCore::Pong(n) => {
                e.u8(6);
                e.u64(*n);
            }
            ToCore::Ended { error } => {
                e.u8(7);
                e.opt_str(error);
            }
        }
        e.0
    }

    pub fn decode(body: &[u8]) -> D<Self> {
        let mut d = Dec { b: body };
        let m = match d.u8()? {
            1 => ToCore::Hello {
                protocol: d.u32()?,
                role: match d.u8()? {
                    0 => Role::View,
                    1 => Role::Compile,
                    _ => return Err(DecodeError("bad role")),
                },
                pid: d.u32()?,
                sandbox: match d.u8()? {
                    0 => Sandbox::None,
                    1 => Sandbox::Applied,
                    _ => return Err(DecodeError("bad sandbox state")),
                },
                engine_key: d.str()?,
            },
            2 => ToCore::Loaded { error: d.opt_str()? },
            3 => ToCore::Compiled(d.bytes()?),
            4 => ToCore::CompileDone { error: d.opt_str()? },
            5 => ToCore::Import { seq: d.u64()?, name: d.str()?, args: d.values(0)? },
            6 => ToCore::Pong(d.u64()?),
            7 => ToCore::Ended { error: d.opt_str()? },
            _ => return Err(DecodeError("unknown message")),
        };
        d.end()?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        Value::Record(vec![
            ("id".into(), Value::U32(7)),
            ("label".into(), Value::String("Run ▶".into())),
            ("data".into(), Value::Bytes(vec![0, 1, 2, 255])),
            ("kind".into(), Value::Variant("button".into(), Some(Box::new(Value::Tuple(vec![Value::Bool(true), Value::Char('é')]))))),
            ("level".into(), Value::Enum("warn".into())),
            ("parent".into(), Value::Option(None)),
            ("res".into(), Value::Result(Err(Some(Box::new(Value::String("no".into())))))),
            ("flags".into(), Value::Flags(vec!["a".into(), "b".into()])),
            (
                "nums".into(),
                Value::List(vec![
                    Value::S8(-1),
                    Value::S16(-2),
                    Value::U16(3),
                    Value::S32(-4),
                    Value::S64(-5),
                    Value::U64(u64::MAX),
                    Value::F32(1.5),
                    Value::F64(-2.25),
                    Value::U8(9),
                ]),
            ),
        ])
    }

    #[test]
    fn every_message_round_trips() {
        let to_helper = [
            ToHelper::Load { memory_limit: 1 << 30, compute_ms: 5000, total: 42 },
            ToHelper::Compile { total: 9, max_output: 144 },
            ToHelper::Chunk(vec![1, 2, 3]),
            ToHelper::End,
            ToHelper::Run,
            ToHelper::Reply { seq: 3, results: vec![sample(), Value::Result(Ok(None))] },
            ToHelper::Ping(u64::MAX),
            ToHelper::Shutdown,
        ];
        for m in to_helper {
            assert_eq!(ToHelper::decode(&m.encode()).unwrap(), m);
        }
        let to_core = [
            ToCore::Hello { protocol: PROTOCOL_VERSION, role: Role::Compile, pid: 12, sandbox: Sandbox::None, engine_key: "k".into() },
            ToCore::Loaded { error: Some("bad".into()) },
            ToCore::Loaded { error: None },
            ToCore::Compiled(vec![9; 10]),
            ToCore::CompileDone { error: None },
            ToCore::Import { seq: 1, name: "bastion:plugin/log@1.0.0#line".into(), args: vec![sample()] },
            ToCore::Pong(4),
            ToCore::Ended { error: Some("trap".into()) },
        ];
        for m in to_core {
            assert_eq!(ToCore::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn frames_round_trip_and_end_cleanly() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"abc").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"abc");
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"");
        assert!(read_frame(&mut r).unwrap().is_none());
    }

    #[test]
    fn a_frame_at_the_limit_passes_and_one_byte_more_is_refused_before_allocating() {
        let mut at_limit = (MAX_FRAME as u32).to_le_bytes().to_vec();
        at_limit.resize(4 + MAX_FRAME, 0);
        assert_eq!(read_frame(&mut &at_limit[..]).unwrap().unwrap().len(), MAX_FRAME);
        // Only the 4-byte header exists: allocating 16 MiB + 1 first would be the bug.
        let over = ((MAX_FRAME + 1) as u32).to_le_bytes();
        assert_eq!(read_frame(&mut &over[..]).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let huge = u32::MAX.to_le_bytes();
        assert!(read_frame(&mut &huge[..]).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![0u8; MAX_FRAME + 1]).is_err());
    }

    #[test]
    fn a_truncated_header_or_body_is_an_error() {
        assert!(read_frame(&mut &[1u8, 0][..]).is_err());
        assert!(read_frame(&mut &[5u8, 0, 0, 0, 1][..]).is_err());
    }

    #[test]
    fn forged_counts_never_allocate_past_the_frame() {
        // A reply that claims 2^32 - 1 results in a 13-byte message.
        let mut m = vec![6u8];
        m.extend_from_slice(&0u64.to_le_bytes());
        m.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(ToHelper::decode(&m), Err(DecodeError("count larger than the frame")));
        let mut b = vec![3u8];
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(ToHelper::decode(&b), Err(DecodeError("count larger than the frame")));
    }

    fn nested(depth: usize) -> Value {
        let mut v = Value::Bool(true);
        for _ in 1..depth {
            v = Value::Option(Some(Box::new(v)));
        }
        v
    }

    #[test]
    fn nesting_at_the_limit_passes_and_one_more_level_is_refused() {
        let ok = ToHelper::Reply { seq: 0, results: vec![nested(MAX_VALUE_DEPTH)] };
        assert_eq!(ToHelper::decode(&ok.encode()).unwrap(), ok);
        let deep = ToHelper::Reply { seq: 0, results: vec![nested(MAX_VALUE_DEPTH + 1)] };
        assert_eq!(ToHelper::decode(&deep.encode()), Err(DecodeError("value nested too deeply")));
    }

    #[test]
    fn junk_is_refused_not_panicked_on() {
        assert!(ToCore::decode(&[]).is_err());
        assert!(ToCore::decode(&[99]).is_err());
        assert!(ToHelper::decode(&[4, 0]).is_err(), "trailing bytes");
        assert!(ToCore::decode(&[2, 2]).is_err(), "bad bool");
        let mut s = vec![5u8];
        s.extend_from_slice(&1u64.to_le_bytes());
        s.extend_from_slice(&2u32.to_le_bytes());
        s.extend_from_slice(&[0xff, 0xfe]);
        s.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(ToCore::decode(&s), Err(DecodeError("bad UTF-8")));
        // Every prefix of a valid message fails cleanly.
        let full = ToCore::Import { seq: 1, name: "x".into(), args: vec![sample()] }.encode();
        for cut in 0..full.len() {
            assert!(ToCore::decode(&full[..cut]).is_err());
        }
    }
}
