//! The `.bastionplugin` reader (section 6, "Reading rules").
//!
//! A package is a zip, read from a byte slice into memory and never unpacked to disk. The reader
//! accepts one canonical layout only: the listed files back to back from the first byte, then the
//! directory, then the end record, and nothing else anywhere. Zip64, several disks, encryption,
//! data descriptors, comments and every method but "stored" and "deflate" are refused.
//!
//! Order of work, so that no rule is checked after the bytes it guards against were allocated:
//! 1. the end record: entry count (at most 16) before the directory is looked at;
//! 2. the directory: every name rule, then every size rule (the 50 MiB total, the 100 to 1
//!    ratio, the icon and manifest limits), all from the headers, with nothing inflated;
//! 3. the local headers: they must repeat the directory, and the entries must tile the file;
//! 4. only then the data. Each entry is inflated in 32 KiB steps into a buffer that grows with
//!    the bytes that really arrive and never beyond the size its header states, so a header
//!    that lies is caught at the first step past its claim. The sizes in the headers are a
//!    ceiling, not a trusted fact: the total is bounded because every entry is.
use flate2::{Crc, Decompress, FlushDecompress, Status};
use sha2::{Digest, Sha256};

use super::error::{Excerpt, PluginError};
use super::manifest::{parse_manifest, Manifest, MAX_MANIFEST_BYTES};

/// All files of a package together, uncompressed.
pub const MAX_UNCOMPRESSED_BYTES: u64 = 50 * 1024 * 1024;
/// The package file itself. Stored (uncompressed) entries make a file slightly larger than its
/// content, so this is the content limit plus room for the zip structure.
pub const MAX_PACKAGE_FILE_BYTES: usize = 51 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 16;
/// Uncompressed size over compressed size, per entry.
pub const MAX_RATIO: u64 = 100;
pub const MAX_ICON_BYTES: u64 = 64 * 1024;
/// Extra fields are allowed (some tools write time stamps) but kept too small to hide data in.
const MAX_EXTRA_BYTES: usize = 64;
const INFLATE_STEP: usize = 32 * 1024;

const MANIFEST: &str = "plugin.toml";
const WASM: &str = "plugin.wasm";
const ICON: &str = "icon.png";
const README: &str = "README.md";
const LICENSE: &str = "LICENSE";
const NOTICES: &str = "THIRD_PARTY_NOTICES.txt";
const CHANGELOG: &str = "CHANGELOG.md";
/// The fixed list of section 6: name, and whether the file is required.
const FILES: [(&str, bool); 7] = [(MANIFEST, true), (WASM, true), (ICON, true), (README, true), (LICENSE, true), (NOTICES, true), (CHANGELOG, false)];

const END_SIGNATURE: u32 = 0x0605_4b50;
const DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const END_LEN: usize = 22;
const DIRECTORY_LEN: usize = 46;
const LOCAL_LEN: usize = 30;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
/// Bits 1 and 2 (a hint about the deflate level) and bit 11 (names are UTF-8) change nothing.
const HARMLESS_FLAGS: u16 = 0b0000_1000_0000_0110;
const FLAG_ENCRYPTED: u16 = 1;
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
const HOST_UNIX: u16 = 3;
const DOS_DIRECTORY: u32 = 0x10;
const UNIX_TYPE_MASK: u32 = 0o170000;
const UNIX_REGULAR: u32 = 0o100000;
const UNIX_DIRECTORY: u32 = 0o040000;
const UNIX_LINK: u32 = 0o120000;
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// A package whose every file passed the reading rules. It can only be built by
/// [`read_package`]. Its tier is not known here: see `check_package_against_record`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Package {
    pub manifest: Manifest,
    /// The component, unchecked beyond "not empty": the import-list check is PLUG-04b.
    pub wasm: Vec<u8>,
    /// A PNG by signature and header; not decoded.
    pub icon: Vec<u8>,
    pub readme: String,
    pub license: String,
    pub notices: String,
    pub changelog: Option<String>,
    /// SHA-256 of the whole package file.
    pub sha256: [u8; 32],
    /// Length of the whole package file.
    pub size: u64,
}

/// What the reader did, for tests and measurements: proof that it stops early.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadCount {
    /// Bytes inflated or copied out of the package so far, refused ones included.
    pub bytes_out: u64,
    /// The largest buffer allocated for one file.
    pub peak_capacity: usize,
}

struct Entry<'a> {
    name: &'a [u8],
    /// Position in [`FILES`]; set once the name is known to be on the list.
    file: usize,
    made_by: u16,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: usize,
    declared: usize,
    extra_len: usize,
    comment_len: usize,
    disk: u16,
    external: u32,
    offset: usize,
    /// The entry's bytes in the package, set once the local header has been checked.
    data: &'a [u8],
}

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

struct End {
    at: usize,
    entries: usize,
    directory_at: usize,
}

/// The end record must be the last 22 bytes of the file.
fn end_record(bytes: &[u8]) -> Result<End, PluginError> {
    let at = bytes.len().checked_sub(END_LEN).ok_or(PluginError::ZipTruncated)?;
    if le32(bytes, at) != Some(END_SIGNATURE) {
        return Err(misplaced_end(bytes));
    }
    let field16 = |offset: usize| le16(bytes, at + offset).ok_or(PluginError::ZipTruncated);
    let field32 = |offset: usize| le32(bytes, at + offset).ok_or(PluginError::ZipTruncated);
    if field16(20)? != 0 {
        return Err(PluginError::ZipTruncated); // it promises a comment that is not there
    }
    let (disk, directory_disk, entries_here, entries) = (field16(4)?, field16(6)?, field16(8)?, field16(10)?);
    let (directory_len, directory_at) = (field32(12)?, field32(16)?);
    if entries == u16::MAX || directory_len == u32::MAX || directory_at == u32::MAX {
        return Err(PluginError::ZipUnsupported("zip64"));
    }
    if disk != 0 || directory_disk != 0 || entries_here != entries {
        return Err(PluginError::ZipUnsupported("more than one disk"));
    }
    if usize::from(entries) > MAX_ENTRIES {
        return Err(PluginError::TooManyEntries);
    }
    if u64::from(directory_at) + u64::from(directory_len) != at as u64 {
        return Err(PluginError::ZipMalformed("the directory does not end where the end record begins"));
    }
    Ok(End { at, entries: usize::from(entries), directory_at: directory_at as usize })
}

/// The file does not end in an end record. Look for one further back, only to name the rule:
/// the package is refused either way.
fn misplaced_end(bytes: &[u8]) -> PluginError {
    const WINDOW: usize = 128 * 1024;
    let last = bytes.len() - END_LEN;
    for at in (last.saturating_sub(WINDOW)..last).rev() {
        if le32(bytes, at) == Some(END_SIGNATURE) {
            let comment = le16(bytes, at + 20).map_or(0, usize::from);
            return if comment != 0 && at + END_LEN + comment == bytes.len() { PluginError::ZipUnsupported("an archive comment") } else { PluginError::ZipTrailingData };
        }
    }
    PluginError::ZipTruncated
}

fn directory<'a>(bytes: &'a [u8], end: &End) -> Result<Vec<Entry<'a>>, PluginError> {
    const SHORT: PluginError = PluginError::ZipMalformed("the directory is shorter than it says");
    let table = &bytes[..end.at];
    let mut entries = Vec::with_capacity(end.entries);
    let mut at = end.directory_at;
    for _ in 0..end.entries {
        let field16 = |offset: usize| le16(table, at + offset).ok_or(SHORT);
        let field32 = |offset: usize| le32(table, at + offset).ok_or(SHORT);
        if field32(0)? != DIRECTORY_SIGNATURE {
            return Err(PluginError::ZipMalformed("a directory entry does not start with its signature"));
        }
        let (name_len, extra_len, comment_len) = (usize::from(field16(28)?), usize::from(field16(30)?), usize::from(field16(32)?));
        let name = table.get(at + DIRECTORY_LEN..at + DIRECTORY_LEN + name_len).ok_or(SHORT)?;
        entries.push(Entry {
            name,
            file: usize::MAX,
            made_by: field16(4)?,
            flags: field16(8)?,
            method: field16(10)?,
            crc: field32(16)?,
            compressed: field32(20)? as usize,
            declared: field32(24)? as usize,
            extra_len,
            comment_len,
            disk: field16(34)?,
            external: field32(38)?,
            offset: field32(42)? as usize,
            data: &[],
        });
        at += DIRECTORY_LEN + name_len + extra_len + comment_len;
        if at > end.at {
            return Err(SHORT);
        }
    }
    if at != end.at {
        return Err(PluginError::ZipMalformed("the directory is longer than its entries"));
    }
    Ok(entries)
}

/// The rules about one name on its own: ASCII, not absolute, no `..`, not a folder, not a link.
fn check_name(entry: &Entry) -> Result<(), PluginError> {
    let name = entry.name;
    if !name.is_ascii() {
        return Err(PluginError::NameNotAscii);
    }
    let shown = || Excerpt::new(name);
    let is_separator = |b: &u8| *b == b'/' || *b == b'\\';
    let has_drive = name.len() >= 2 && name[0].is_ascii_alphabetic() && name[1] == b':';
    if name.first().is_some_and(is_separator) || has_drive {
        return Err(PluginError::NameAbsolute(shown()));
    }
    if name.split(is_separator).any(|part| part == b"..") {
        return Err(PluginError::NameParent(shown()));
    }
    // The type bits are only meaningful when the entry was made on Unix.
    let unix_type = if entry.made_by >> 8 == HOST_UNIX { (entry.external >> 16) & UNIX_TYPE_MASK } else { 0 };
    if name.iter().any(is_separator) || entry.external & DOS_DIRECTORY != 0 || unix_type == UNIX_DIRECTORY {
        return Err(PluginError::EntryIsFolder(shown()));
    }
    if unix_type == UNIX_LINK {
        return Err(PluginError::EntryIsLink(shown()));
    }
    if unix_type != 0 && unix_type != UNIX_REGULAR {
        return Err(PluginError::ZipUnsupported("a device or other special file"));
    }
    Ok(())
}

/// The rules about the names together: no duplicates, exact or by case, and only listed files.
fn check_names(entries: &mut [Entry]) -> Result<(), PluginError> {
    for entry in entries.iter() {
        check_name(entry)?;
    }
    for (i, entry) in entries.iter().enumerate() {
        for earlier in &entries[..i] {
            if earlier.name == entry.name {
                return Err(PluginError::NameDuplicate(Excerpt::new(entry.name)));
            }
            if earlier.name.eq_ignore_ascii_case(entry.name) {
                return Err(PluginError::NameCaseDuplicate(Excerpt::new(entry.name)));
            }
        }
    }
    for entry in entries.iter_mut() {
        entry.file = FILES.iter().position(|(listed, _)| listed.as_bytes() == entry.name).ok_or_else(|| PluginError::EntryNotAllowed(Excerpt::new(entry.name)))?;
    }
    if let Some((missing, _)) = FILES.iter().enumerate().find(|(i, (_, required))| *required && !entries.iter().any(|e| e.file == *i)).map(|(_, file)| file) {
        return Err(PluginError::MissingFile(missing));
    }
    Ok(())
}

/// Every size rule, from the directory alone. Nothing has been inflated or allocated yet.
fn check_headers(entries: &[Entry]) -> Result<(), PluginError> {
    let mut total: u64 = 0;
    for entry in entries {
        let name = FILES[entry.file].0;
        if entry.flags & FLAG_ENCRYPTED != 0 {
            return Err(PluginError::ZipUnsupported("encryption"));
        }
        if entry.flags & FLAG_DATA_DESCRIPTOR != 0 {
            return Err(PluginError::ZipUnsupported("a data descriptor"));
        }
        if entry.flags & !HARMLESS_FLAGS != 0 {
            return Err(PluginError::ZipUnsupported("an unknown flag"));
        }
        if entry.method != METHOD_STORED && entry.method != METHOD_DEFLATE {
            return Err(PluginError::ZipUnsupported("a compression method other than deflate"));
        }
        if entry.compressed == u32::MAX as usize || entry.declared == u32::MAX as usize || entry.offset == u32::MAX as usize {
            return Err(PluginError::ZipUnsupported("zip64"));
        }
        if entry.disk != 0 {
            return Err(PluginError::ZipUnsupported("more than one disk"));
        }
        if entry.comment_len != 0 {
            return Err(PluginError::ZipUnsupported("an entry comment"));
        }
        if entry.extra_len > MAX_EXTRA_BYTES {
            return Err(PluginError::ZipUnsupported("a large extra field"));
        }
        if entry.method == METHOD_STORED && entry.compressed != entry.declared {
            return Err(PluginError::SizeMismatch(name));
        }
        let declared = entry.declared as u64;
        if name == ICON && declared > MAX_ICON_BYTES {
            return Err(PluginError::IconTooLarge);
        }
        if name == MANIFEST && declared > MAX_MANIFEST_BYTES as u64 {
            return Err(PluginError::ManifestTooLarge);
        }
        total += declared;
        if total > MAX_UNCOMPRESSED_BYTES {
            return Err(PluginError::UncompressedTooLarge);
        }
    }
    for entry in entries {
        if entry.declared as u64 > entry.compressed as u64 * MAX_RATIO {
            return Err(PluginError::RatioTooHigh(FILES[entry.file].0));
        }
    }
    Ok(())
}

/// Each local header must repeat its directory entry, and the entries must tile the file from
/// the first byte to the directory, so no byte of the package is outside a listed file.
fn locate_data<'a>(bytes: &'a [u8], end: &End, entries: &mut [Entry<'a>]) -> Result<(), PluginError> {
    const DIFFERS: PluginError = PluginError::ZipMalformed("a local header differs from the directory");
    const OUTSIDE: PluginError = PluginError::ZipMalformed("there are bytes outside the listed entries");
    let files = &bytes[..end.directory_at];
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|&i| entries[i].offset);
    let mut expected = 0;
    for i in order {
        let entry = &mut entries[i];
        let at = entry.offset;
        if at != expected {
            return Err(OUTSIDE);
        }
        let field16 = |offset: usize| le16(files, at + offset).ok_or(OUTSIDE);
        let field32 = |offset: usize| le32(files, at + offset).ok_or(OUTSIDE);
        if field32(0)? != LOCAL_SIGNATURE {
            return Err(PluginError::ZipMalformed("an entry does not start with its signature"));
        }
        let same = field16(6)? == entry.flags && field16(8)? == entry.method && field32(14)? == entry.crc && field32(18)? as usize == entry.compressed && field32(22)? as usize == entry.declared;
        let (name_len, extra_len) = (usize::from(field16(26)?), usize::from(field16(28)?));
        if !same || files.get(at + LOCAL_LEN..at + LOCAL_LEN + name_len) != Some(entry.name) {
            return Err(DIFFERS);
        }
        if extra_len > MAX_EXTRA_BYTES {
            return Err(PluginError::ZipUnsupported("a large extra field"));
        }
        let start = at + LOCAL_LEN + name_len + extra_len;
        entry.data = files.get(start..start + entry.compressed).ok_or(OUTSIDE)?;
        expected = start + entry.compressed;
    }
    if expected != end.directory_at {
        return Err(OUTSIDE);
    }
    Ok(())
}

/// Make room for `more` bytes without ever reserving past `ceiling` (the size the header
/// states) and without reserving ahead of the bytes that have really arrived.
fn reserve(out: &mut Vec<u8>, more: usize, ceiling: usize, count: &mut ReadCount) {
    if out.capacity() - out.len() < more {
        let room = ceiling - out.len();
        out.reserve_exact(out.len().max(INFLATE_STEP).min(room).max(more));
    }
    count.peak_capacity = count.peak_capacity.max(out.capacity());
}

/// Inflate one entry. The output can never grow beyond `entry.declared`: the step that would
/// pass it is refused before it is copied.
fn inflate(entry: &Entry, name: &'static str, count: &mut ReadCount) -> Result<Vec<u8>, PluginError> {
    let mut inflater = Decompress::new(false);
    let mut out = Vec::new();
    let mut step = vec![0u8; INFLATE_STEP];
    loop {
        let (consumed_before, produced_before) = (inflater.total_in(), inflater.total_out());
        let input = entry.data.get(consumed_before as usize..).unwrap_or_default();
        let status = inflater.decompress(input, &mut step, FlushDecompress::None).map_err(|_| PluginError::ZipMalformed("a compressed entry is damaged"))?;
        let produced = (inflater.total_out() - produced_before) as usize;
        let consumed = inflater.total_in() - consumed_before;
        count.bytes_out += produced as u64;
        if produced > entry.declared - out.len() {
            return Err(PluginError::SizeMismatch(name));
        }
        reserve(&mut out, produced, entry.declared, count);
        out.extend_from_slice(&step[..produced]);
        match status {
            Status::StreamEnd => break,
            _ if produced == 0 && consumed == 0 => return Err(PluginError::ZipMalformed("a compressed entry ends early")),
            _ => {}
        }
    }
    if inflater.total_in() as usize != entry.data.len() || out.len() != entry.declared {
        return Err(PluginError::SizeMismatch(name));
    }
    Ok(out)
}

fn extract(entry: &Entry, count: &mut ReadCount) -> Result<Vec<u8>, PluginError> {
    let name = FILES[entry.file].0;
    let out = if entry.method == METHOD_STORED {
        // `check_headers` made sure the two sizes agree, and the slice is exactly that long.
        count.bytes_out += entry.data.len() as u64;
        let out = entry.data.to_vec();
        count.peak_capacity = count.peak_capacity.max(out.capacity());
        out
    } else {
        inflate(entry, name, count)?
    };
    let mut crc = Crc::new();
    crc.update(&out);
    if crc.sum() != entry.crc {
        return Err(PluginError::ChecksumMismatch(name));
    }
    Ok(out)
}

/// Text files are shown as plain text: UTF-8, and no control characters but line breaks and tabs.
fn plain_text(bytes: Vec<u8>, name: &'static str) -> Result<String, PluginError> {
    let text = String::from_utf8(bytes).map_err(|_| PluginError::FileNotText(name))?;
    if text.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')) {
        return Err(PluginError::FileNotText(name));
    }
    Ok(text)
}

/// A PNG by its signature and its header chunk (IHDR: length 13, a width and a height that are
/// not zero, a matching checksum). The image itself is not decoded.
fn is_png(bytes: &[u8]) -> bool {
    let Some(header) = bytes.get(..33) else { return false };
    let be32 = |at: usize| u32::from_be_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]]);
    let mut crc = Crc::new();
    crc.update(&header[12..29]);
    header[..8] == PNG_SIGNATURE && be32(8) == 13 && &header[12..16] == b"IHDR" && be32(16) != 0 && be32(20) != 0 && be32(29) == crc.sum()
}

fn read(bytes: &[u8], count: &mut ReadCount) -> Result<Package, PluginError> {
    if bytes.len() > MAX_PACKAGE_FILE_BYTES {
        return Err(PluginError::PackageTooLarge);
    }
    let end = end_record(bytes)?;
    let mut entries = directory(bytes, &end)?;
    check_names(&mut entries)?;
    check_headers(&entries)?;
    locate_data(bytes, &end, &mut entries)?;

    let mut files: [Option<Vec<u8>>; FILES.len()] = Default::default();
    for entry in &entries {
        files[entry.file] = Some(extract(entry, count)?);
    }
    let mut take = |name: &'static str| {
        let at = FILES.iter().position(|(listed, _)| *listed == name);
        at.and_then(|at| files[at].take())
    };
    let mut required = |name: &'static str| take(name).ok_or(PluginError::MissingFile(name));

    let manifest = parse_manifest(&required(MANIFEST)?)?;
    let wasm = required(WASM)?;
    if wasm.is_empty() {
        return Err(PluginError::FileEmpty(WASM));
    }
    let icon = required(ICON)?;
    if !is_png(&icon) {
        return Err(PluginError::IconNotPng);
    }
    let readme = plain_text(required(README)?, README)?;
    let license = plain_text(required(LICENSE)?, LICENSE)?;
    let notices = plain_text(required(NOTICES)?, NOTICES)?;
    let changelog = take(CHANGELOG).map(|bytes| plain_text(bytes, CHANGELOG)).transpose()?;
    Ok(Package { manifest, wasm, icon, readme, license, notices, changelog, sha256: Sha256::digest(bytes).into(), size: bytes.len() as u64 })
}

/// Read a `.bastionplugin` from memory. Any broken rule rejects the whole package.
pub fn read_package(bytes: &[u8]) -> Result<Package, PluginError> {
    read(bytes, &mut ReadCount::default())
}

/// [`read_package`], also reporting how many bytes were read out and the largest buffer used,
/// whether or not the package was accepted.
pub fn read_package_counted(bytes: &[u8]) -> (Result<Package, PluginError>, ReadCount) {
    let mut count = ReadCount::default();
    let result = read(bytes, &mut count);
    (result, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_are_the_ones_the_spec_states() {
        assert_eq!(MAX_UNCOMPRESSED_BYTES, 52_428_800);
        assert_eq!((MAX_ENTRIES, MAX_RATIO, MAX_ICON_BYTES), (16, 100, 65_536));
        assert!(MAX_PACKAGE_FILE_BYTES as u64 > MAX_UNCOMPRESSED_BYTES);
        let required: Vec<&str> = FILES.iter().filter(|(_, required)| *required).map(|(name, _)| *name).collect();
        assert_eq!(required, ["plugin.toml", "plugin.wasm", "icon.png", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.txt"]);
        assert_eq!(FILES[6], ("CHANGELOG.md", false));
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_looked_at() {
        let (result, count) = read_package_counted(&vec![0u8; MAX_PACKAGE_FILE_BYTES + 1]);
        assert_eq!(result.unwrap_err(), PluginError::PackageTooLarge);
        assert_eq!(count, ReadCount::default());
    }

    #[test]
    fn a_buffer_never_grows_past_its_ceiling_or_far_ahead_of_its_content() {
        let mut count = ReadCount::default();
        let mut out = Vec::new();
        while out.len() + 1000 <= 30_000 {
            reserve(&mut out, 1000, 30_000, &mut count);
            out.extend_from_slice(&[0; 1000]);
        }
        assert_eq!(out.len(), 30_000);
        assert!(out.capacity() <= 30_000 && count.peak_capacity <= 30_000);
        let (mut big, mut count) = (Vec::new(), ReadCount::default());
        for _ in 0..10 {
            reserve(&mut big, INFLATE_STEP, usize::MAX / 2, &mut count);
            big.extend_from_slice(&[0; INFLATE_STEP]);
            assert!(big.capacity() <= 2 * big.len(), "capacity {} for {} bytes", big.capacity(), big.len());
        }
    }
}
