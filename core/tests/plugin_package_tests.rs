//! PLUG-04a: the package reader, the manifest, and a package checked against its release record.
//! Spec: docs/specs/plugins.md, sections 5 (limits), 6 and 7.
#[path = "fixtures/plugin/support.rs"]
mod support;

use std::time::{Duration, Instant};

use bastion_core::plugin::{
    check_package_against_record, parse_manifest, read_package, read_package_counted, verify_release_record, ApiVersion, FieldKind, PluginError, Purpose, Tier, TrustedKeys, Version,
    MAX_ICON_BYTES, MAX_UNCOMPRESSED_BYTES,
};
use support::*;

fn rejects(entries: &[Entry]) -> PluginError {
    read_package(&zip(entries)).expect_err("the package must be refused")
}

fn with_extra(entry: Entry) -> Vec<Entry> {
    let mut entries = good_entries();
    entries.push(entry);
    entries
}

fn replaced(name: &str, entry: Entry) -> Vec<Entry> {
    let mut entries = good_entries();
    let at = entries.iter().position(|e| e.name == name.as_bytes()).expect("a listed file");
    entries[at] = entry;
    entries
}

// ---- package ----

#[test]
fn a_good_package_is_read_into_memory_with_its_hash_and_size() {
    let bytes = good_package();
    let (result, count) = read_package_counted(&bytes);
    let package = result.unwrap();
    assert_eq!(package.manifest.id, EXTERNAL_ID);
    assert_eq!(package.wasm, WASM);
    assert_eq!(package.icon, png());
    assert_eq!(package.readme, "# PostgreSQL\n\nA plugin.\n");
    assert_eq!(package.license, "Apache License 2.0\n");
    assert_eq!(package.notices, "none\n");
    assert_eq!(package.changelog.as_deref(), Some("1.0.0: first release\n"));
    assert_eq!(package.size, bytes.len() as u64);
    assert_eq!(hex::encode(package.sha256), hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes)));
    let total: u64 = good_entries().iter().map(|e| u64::from(e.declared)).sum();
    assert_eq!(count.bytes_out, total, "every byte read out is counted");
}

#[test]
fn the_changelog_is_optional() {
    let entries: Vec<Entry> = good_entries().into_iter().filter(|e| e.name != b"CHANGELOG.md").collect();
    assert_eq!(read_package(&zip(&entries)).unwrap().changelog, None);
}

#[test]
fn an_entry_that_is_not_on_the_list_is_refused() {
    assert!(matches!(rejects(&with_extra(Entry::stored("extra.txt", b"x"))), PluginError::EntryNotAllowed(_)));
    assert!(matches!(rejects(&with_extra(Entry::stored("plugin.dylib", b"x"))), PluginError::EntryNotAllowed(_)));
}

#[test]
fn a_folder_is_refused() {
    assert!(matches!(rejects(&with_extra(Entry::stored("docs/", b""))), PluginError::EntryIsFolder(_)));
    assert!(matches!(rejects(&with_extra(Entry::stored("docs/README.md", b"x"))), PluginError::EntryIsFolder(_)));
    // A listed name that the directory marks as a folder (MS-DOS bit, then Unix mode).
    let mut dos = Entry::stored("LICENSE", b"x");
    dos.external = 0x10;
    assert!(matches!(rejects(&replaced("LICENSE", dos)), PluginError::EntryIsFolder(_)));
    let mut unix = Entry::stored("LICENSE", b"x");
    unix.external = 0o040755 << 16;
    assert!(matches!(rejects(&replaced("LICENSE", unix)), PluginError::EntryIsFolder(_)));
}

#[test]
fn a_link_is_refused() {
    let mut link = Entry::stored("README.md", b"/etc/passwd");
    link.external = 0o120777 << 16;
    assert!(matches!(rejects(&replaced("README.md", link)), PluginError::EntryIsLink(_)));
}

#[test]
fn an_absolute_path_is_refused() {
    assert!(matches!(rejects(&with_extra(Entry::stored("/plugin.toml", b"x"))), PluginError::NameAbsolute(_)));
    assert!(matches!(rejects(&with_extra(Entry::stored("\\plugin.toml", b"x"))), PluginError::NameAbsolute(_)));
    assert!(matches!(rejects(&with_extra(Entry::stored("C:\\plugin.toml", b"x"))), PluginError::NameAbsolute(_)));
}

#[test]
fn a_path_with_dot_dot_is_refused() {
    assert!(matches!(rejects(&with_extra(Entry::stored("../plugin.toml", b"x"))), PluginError::NameParent(_)));
    assert!(matches!(rejects(&with_extra(Entry::stored("a/../../plugin.toml", b"x"))), PluginError::NameParent(_)));
    assert!(matches!(rejects(&with_extra(Entry::stored("..", b"x"))), PluginError::NameParent(_)));
}

#[test]
fn a_non_ascii_name_is_refused() {
    assert_eq!(rejects(&with_extra(Entry::stored("ícon.png", b"x"))), PluginError::NameNotAscii);
    let mut raw = Entry::stored("icon.png", b"x");
    raw.name = vec![0xFF, b'.', b'p', b'n', b'g'];
    assert_eq!(rejects(&with_extra(raw)), PluginError::NameNotAscii);
}

#[test]
fn two_names_that_differ_only_by_case_are_refused() {
    assert!(matches!(rejects(&with_extra(Entry::stored("readme.md", b"x"))), PluginError::NameCaseDuplicate(_)));
    assert!(matches!(rejects(&with_extra(Entry::stored("README.md", b"x"))), PluginError::NameDuplicate(_)));
}

#[test]
fn seventeen_entries_are_refused_before_the_directory_is_read() {
    let entries: Vec<Entry> = (0..17).map(|i| Entry::stored(&format!("f{i}"), b"x")).collect();
    let (result, count) = read_package_counted(&zip(&entries));
    assert_eq!(result.unwrap_err(), PluginError::TooManyEntries);
    assert_eq!(count.bytes_out, 0);
}

#[test]
fn more_than_50_mib_uncompressed_is_refused_without_inflating_anything() {
    // Two files of 26 MiB that deflate at well under 100 to 1, so only the total is over a limit.
    let big = compressible(26 * MIB);
    let wasm = Entry::deflated("plugin.wasm", &big);
    let readme = Entry::deflated("README.md", &big);
    assert!(wasm.raw.len() * 100 > big.len(), "the fixture must stay under the ratio limit");
    assert!(wasm.raw.len() < big.len() / 4, "the fixture must really be compressed");
    let mut entries = replaced("plugin.wasm", wasm);
    let at = entries.iter().position(|e| e.name == b"README.md").unwrap();
    entries[at] = readme;
    let bytes = zip(&entries);
    assert!(bytes.len() < 8 * MIB, "the file itself is small");
    let (result, count) = read_package_counted(&bytes);
    assert_eq!(result.unwrap_err(), PluginError::UncompressedTooLarge);
    assert_eq!(count.bytes_out, 0, "the total is checked from the directory, before any inflating");
    assert_eq!(count.peak_capacity, 0);
}

#[test]
fn exactly_50_mib_uncompressed_is_accepted() {
    let others: u64 = good_entries().iter().filter(|e| e.name != b"plugin.wasm").map(|e| u64::from(e.declared)).sum();
    let wasm = compressible(MAX_UNCOMPRESSED_BYTES as usize - others as usize);
    let entries = replaced("plugin.wasm", Entry::deflated("plugin.wasm", &wasm));
    let (result, count) = read_package_counted(&zip(&entries));
    assert_eq!(result.unwrap().wasm.len(), wasm.len());
    assert_eq!(count.bytes_out, MAX_UNCOMPRESSED_BYTES);
    // One byte more is over the limit.
    let mut over = wasm;
    over.push(0);
    assert_eq!(rejects(&replaced("plugin.wasm", Entry::deflated("plugin.wasm", &over))), PluginError::UncompressedTooLarge);
}

#[test]
fn a_zip_bomb_over_100_to_1_is_refused_without_inflating_anything() {
    let bomb = Entry::deflated("plugin.wasm", &vec![0u8; 10 * MIB]);
    assert!(bomb.raw.len() * 100 < 10 * MIB, "zeros deflate far beyond 100 to 1");
    let (result, count) = read_package_counted(&zip(&replaced("plugin.wasm", bomb)));
    assert_eq!(result.unwrap_err(), PluginError::RatioTooHigh("plugin.wasm"));
    assert_eq!(count.bytes_out, 0);
    assert_eq!(count.peak_capacity, 0);
}

#[test]
fn a_header_that_understates_its_size_stops_the_reader_early() {
    // 10 MiB of zeros, but the headers claim exactly 100 times the compressed size, which passes
    // the ratio check. The reader must stop as soon as the stream runs past the claim.
    let mut bomb = Entry::deflated("plugin.wasm", &vec![0u8; 10 * MIB]);
    let claimed = bomb.raw.len() * 100;
    assert!(claimed < 5 * MIB, "the claim is well under the real 10 MiB");
    bomb.declared = claimed as u32;
    let (result, count) = read_package_counted(&zip(&replaced("plugin.wasm", bomb)));
    assert_eq!(result.unwrap_err(), PluginError::SizeMismatch("plugin.wasm"));
    let before: u64 = good_entries().iter().take_while(|e| e.name != b"plugin.wasm").map(|e| u64::from(e.declared)).sum();
    assert!(count.bytes_out <= before + claimed as u64 + 64 * 1024, "stopped after {} bytes for a claim of {claimed}", count.bytes_out);
    assert!(count.peak_capacity <= claimed, "allocated {} for a claim of {claimed}", count.peak_capacity);
}

#[test]
fn a_header_that_overstates_its_size_is_refused_and_nothing_is_allocated_up_front() {
    // The stream holds 64 KiB; the headers claim 100 times the compressed size, the most the
    // ratio check lets through.
    let data = compressible(64 * 1024);
    let mut liar = Entry::deflated("plugin.wasm", &data);
    liar.declared = (liar.raw.len() * 100) as u32;
    let claimed = liar.declared as usize;
    assert!(claimed > 2 * data.len(), "the claim ({claimed}) is far above the real size");
    let (result, count) = read_package_counted(&zip(&replaced("plugin.wasm", liar)));
    assert_eq!(result.unwrap_err(), PluginError::SizeMismatch("plugin.wasm"));
    assert!(count.peak_capacity <= data.len() + 32 * 1024, "allocated {} for {} real bytes (claim {claimed})", count.peak_capacity, data.len());
    assert!(count.peak_capacity < claimed / 2, "the claim was not allocated up front");
    // A stored entry whose two sizes disagree.
    let mut stored = Entry::stored("LICENSE", b"Apache License 2.0\n");
    stored.declared += 1;
    assert_eq!(rejects(&replaced("LICENSE", stored)), PluginError::SizeMismatch("LICENSE"));
}

#[test]
fn a_wrong_checksum_is_refused() {
    let mut entry = Entry::stored("LICENSE", b"Apache License 2.0\n");
    entry.crc ^= 1;
    assert_eq!(rejects(&replaced("LICENSE", entry)), PluginError::ChecksumMismatch("LICENSE"));
}

#[test]
fn each_required_file_must_be_present() {
    for name in ["plugin.toml", "plugin.wasm", "icon.png", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.txt"] {
        let entries: Vec<Entry> = good_entries().into_iter().filter(|e| e.name != name.as_bytes()).collect();
        assert_eq!(rejects(&entries), PluginError::MissingFile(name), "{name}");
    }
    assert_eq!(rejects(&[]), PluginError::MissingFile("plugin.toml"));
}

#[test]
fn a_truncated_zip_is_refused() {
    let bytes = good_package();
    for cut in [0, 1, 21, bytes.len() / 2, bytes.len() - 22, bytes.len() - 1] {
        assert_eq!(read_package(&bytes[..cut]).unwrap_err(), PluginError::ZipTruncated, "cut at {cut}");
    }
    assert_eq!(read_package(b"not a zip at all, just some text that is long enough").unwrap_err(), PluginError::ZipTruncated);
}

#[test]
fn a_zip_with_trailing_data_is_refused() {
    let mut bytes = good_package();
    bytes.extend_from_slice(b"extra");
    assert_eq!(read_package(&bytes).unwrap_err(), PluginError::ZipTrailingData);
    // An archive comment is trailing data the format allows; it is refused as well.
    let mut commented = good_package();
    let at = commented.len() - 2;
    commented[at] = 5;
    commented.extend_from_slice(b"extra");
    assert!(matches!(read_package(&commented).unwrap_err(), PluginError::ZipUnsupported(_)));
}

#[test]
fn bytes_hidden_before_or_between_entries_are_refused() {
    // Bytes prepended: every offset in the directory is now wrong.
    let mut prefixed = b"hidden".to_vec();
    prefixed.extend_from_slice(&good_package());
    assert!(matches!(read_package(&prefixed).unwrap_err(), PluginError::ZipMalformed(_)));
    // Two directory entries pointing at the same bytes.
    let mut entries = good_entries();
    entries[6] = Entry::stored("CHANGELOG.md", b"Apache License 2.0\n");
    let mut bytes = zip(&entries);
    let license = good_entries().iter().position(|e| e.name == b"LICENSE").unwrap();
    let license_offset = offset_of(&bytes, license);
    set_offset(&mut bytes, 6, license_offset);
    assert!(matches!(read_package(&bytes).unwrap_err(), PluginError::ZipMalformed(_)));
}

/// Where the directory keeps the local-header offset of entry `index`.
fn directory_field(bytes: &[u8], index: usize) -> usize {
    let cd_offset = u32::from_le_bytes(bytes[bytes.len() - 6..bytes.len() - 2].try_into().unwrap()) as usize;
    let mut at = cd_offset;
    for _ in 0..index {
        let name = u16::from_le_bytes(bytes[at + 28..at + 30].try_into().unwrap()) as usize;
        let extra = u16::from_le_bytes(bytes[at + 30..at + 32].try_into().unwrap()) as usize;
        at += 46 + name + extra;
    }
    at + 42
}

fn offset_of(bytes: &[u8], index: usize) -> u32 {
    let at = directory_field(bytes, index);
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn set_offset(bytes: &mut [u8], index: usize, offset: u32) {
    let at = directory_field(bytes, index);
    bytes[at..at + 4].copy_from_slice(&offset.to_le_bytes());
}

#[test]
fn unusual_zip_features_are_refused() {
    let mut encrypted = Entry::stored("LICENSE", b"Apache License 2.0\n");
    encrypted.flags = 1;
    assert!(matches!(rejects(&replaced("LICENSE", encrypted)), PluginError::ZipUnsupported(_)));
    let mut descriptor = Entry::stored("LICENSE", b"Apache License 2.0\n");
    descriptor.flags = 1 << 3;
    assert!(matches!(rejects(&replaced("LICENSE", descriptor)), PluginError::ZipUnsupported(_)));
    let mut method = Entry::stored("LICENSE", b"Apache License 2.0\n");
    method.method = 12; // bzip2
    assert!(matches!(rejects(&replaced("LICENSE", method)), PluginError::ZipUnsupported(_)));
    let mut extra = Entry::stored("LICENSE", b"Apache License 2.0\n");
    extra.extra = vec![0; 65];
    assert!(matches!(rejects(&replaced("LICENSE", extra)), PluginError::ZipUnsupported(_)));
}

#[test]
fn an_icon_that_is_not_a_png_or_is_too_large_is_refused() {
    assert_eq!(rejects(&replaced("icon.png", Entry::stored("icon.png", b"<svg xmlns='http://www.w3.org/2000/svg'/>"))), PluginError::IconNotPng);
    // The right signature, but no IHDR header behind it.
    let mut no_header = png();
    no_header[12..16].copy_from_slice(b"IDAT");
    assert_eq!(rejects(&replaced("icon.png", Entry::stored("icon.png", &no_header))), PluginError::IconNotPng);
    let mut zero_width = png();
    zero_width[16..20].copy_from_slice(&[0; 4]);
    assert_eq!(rejects(&replaced("icon.png", Entry::stored("icon.png", &zero_width))), PluginError::IconNotPng);
    assert_eq!(rejects(&replaced("icon.png", Entry::stored("icon.png", &png()[..20]))), PluginError::IconNotPng);
    // 64 KiB is the limit; the size is refused from the directory.
    let mut large = png();
    large.resize(MAX_ICON_BYTES as usize, 0);
    assert!(read_package(&zip(&replaced("icon.png", Entry::stored("icon.png", &large)))).is_ok());
    large.push(0);
    let (result, count) = read_package_counted(&zip(&replaced("icon.png", Entry::stored("icon.png", &large))));
    assert_eq!(result.unwrap_err(), PluginError::IconTooLarge);
    assert_eq!(count.bytes_out, 0);
}

#[test]
fn text_files_must_be_plain_text_and_the_component_must_not_be_empty() {
    assert_eq!(rejects(&replaced("README.md", Entry::stored("README.md", &[0xFF, 0xFE, 0x00]))), PluginError::FileNotText("README.md"));
    assert_eq!(rejects(&replaced("LICENSE", Entry::stored("LICENSE", b"MIT\x1b[31m"))), PluginError::FileNotText("LICENSE"));
    assert_eq!(rejects(&replaced("plugin.wasm", Entry::stored("plugin.wasm", b""))), PluginError::FileEmpty("plugin.wasm"));
}

#[test]
fn a_bad_manifest_rejects_the_whole_package() {
    let entries = entries_for(&manifest(EXTERNAL_ID, "1.0.0").replace("schema = 1", "schema = 2"));
    assert_eq!(rejects(&entries), PluginError::ManifestSchema);
}

// ---- manifest ----

fn manifest_error(text: &str) -> PluginError {
    parse_manifest(text.as_bytes()).expect_err("the manifest must be refused")
}

fn good_manifest() -> String {
    manifest(EXTERNAL_ID, "1.2.3")
}

#[test]
fn a_good_manifest_is_parsed_into_typed_values() {
    let m = parse_manifest(good_manifest().as_bytes()).unwrap();
    assert_eq!(m.id, EXTERNAL_ID);
    assert_eq!(m.name, "PostgreSQL");
    assert_eq!(m.version, Version { major: 1, minor: 2, patch: 3 });
    assert_eq!(m.api, ApiVersion { major: 1, minor: 0 });
    assert_eq!(m.publisher, "Example Tools");
    assert_eq!(m.license, "Apache-2.0");
    assert!(m.permissions.network_entry && m.permissions.credentials_entry && m.permissions.storage && m.permissions.clipboard_write);
    assert!(m.permissions.files_save && !m.permissions.files_open);
    assert_eq!(m.connection_types.len(), 1);
    assert_eq!(m.connection_types[0].id, "postgres");
    assert_eq!(m.connection_types[0].default_port, Some(5432));
    assert_eq!(m.connection_types[0].fields[0].key, "database");
    assert_eq!(m.connection_types[0].fields[0].kind, FieldKind::Text);
    assert_eq!(m.commands[0].id, "new-query");
    assert_eq!(m.commands[0].on.as_deref(), Some("postgres"));
}

#[test]
fn a_manifest_without_permissions_asks_for_nothing() {
    let text = good_manifest();
    let start = text.find("[permissions]").unwrap();
    let end = text.find("[[connection_types]]").unwrap();
    let m = parse_manifest(format!("{}{}", &text[..start], &text[end..]).as_bytes()).unwrap();
    assert_eq!(m.permissions, Default::default());
}

#[test]
fn an_unknown_key_is_refused_at_every_level() {
    assert!(matches!(manifest_error(&good_manifest().replace("schema = 1", "schema = 1\ntier = \"official\"")), PluginError::ManifestUnknownKey(_)));
    assert!(matches!(manifest_error(&good_manifest().replace("storage = true", "storage = true\nshell = true")), PluginError::ManifestUnknownKey(_)));
    assert!(matches!(manifest_error(&good_manifest().replace("default_port = 5432", "default_port = 5432\nnative = true")), PluginError::ManifestUnknownKey(_)));
    assert!(matches!(manifest_error(&good_manifest().replace("kind = \"text\"", "kind = \"text\"\nsecret = true")), PluginError::ManifestUnknownKey(_)));
    assert!(matches!(manifest_error(&good_manifest().replace("title = \"New Query\"", "title = \"New Query\"\nrun = \"sh\"")), PluginError::ManifestUnknownKey(_)));
}

#[test]
fn a_wrong_or_missing_schema_is_refused() {
    assert_eq!(manifest_error(&good_manifest().replace("schema = 1", "schema = 2")), PluginError::ManifestSchema);
    assert_eq!(manifest_error(&good_manifest().replace("schema = 1", "schema = 0")), PluginError::ManifestSchema);
    assert_eq!(manifest_error(&good_manifest().replace("schema = 1\n", "")), PluginError::ManifestMissingKey("schema"));
    assert_eq!(manifest_error(&good_manifest().replace("schema = 1", "schema = \"1\"")), PluginError::ManifestWrongType("schema"));
}

#[test]
fn a_bad_id_is_refused() {
    for id in ["Com.Example.Tool", "com.example.Tool", "tool", "com..tool", ".com.tool", "com.tool.", "com.1tool", "com.tool-", "com.to ol", "com.tøol", "com/example", ""] {
        let text = manifest(id, "1.0.0");
        assert_eq!(manifest_error(&text), PluginError::BadId("id"), "`{id}`");
    }
    let long = format!("com.{}", "a.".repeat(40));
    assert_eq!(manifest_error(&manifest(long.trim_end_matches('.'), "1.0.0")), PluginError::BadId("id"));
    assert!(parse_manifest(manifest("io.github.some-author.my-tool2", "1.0.0").as_bytes()).is_ok());
}

#[test]
fn bad_versions_are_refused() {
    for version in ["1.0", "1.0.0.0", "1.0.x", "01.0.0", "1.0.0-beta", "v1.0.0", " 1.0.0", "1.0.99999999999", ""] {
        assert_eq!(manifest_error(&manifest(EXTERNAL_ID, version)), PluginError::BadVersion("version"), "`{version}`");
    }
    for api in ["1", "1.0.0", "a.b", "1.-1"] {
        let text = good_manifest().replace("api = \"1.0\"", &format!("api = \"{api}\""));
        assert_eq!(manifest_error(&text), PluginError::BadVersion("api"), "`{api}`");
    }
}

#[test]
fn over_long_text_is_refused_at_the_limits_of_section_5() {
    let name = |n: usize| good_manifest().replacen("name = \"PostgreSQL\"", &format!("name = \"{}\"", "n".repeat(n)), 1);
    assert!(parse_manifest(name(32).as_bytes()).is_ok());
    assert_eq!(manifest_error(&name(33)), PluginError::TextTooLong { field: "name", max: 32 });
    // The limit counts characters, not bytes.
    let accented = good_manifest().replacen("name = \"PostgreSQL\"", &format!("name = \"{}\"", "é".repeat(32)), 1);
    assert!(parse_manifest(accented.as_bytes()).is_ok());

    let title = |n: usize| good_manifest().replace("title = \"New Query\"", &format!("title = \"{}\"", "t".repeat(n)));
    assert!(parse_manifest(title(40).as_bytes()).is_ok());
    assert_eq!(manifest_error(&title(41)), PluginError::TextTooLong { field: "commands.title", max: 40 });

    let label = |n: usize| good_manifest().replace("label = \"Database\"", &format!("label = \"{}\"", "l".repeat(n)));
    assert!(parse_manifest(label(32).as_bytes()).is_ok());
    assert_eq!(manifest_error(&label(33)), PluginError::TextTooLong { field: "connection_types.fields.label", max: 32 });

    let description = |n: usize| {
        let text = good_manifest();
        let start = text.find("description = ").unwrap();
        let end = start + text[start..].find('\n').unwrap();
        format!("{}description = \"{}\"{}", &text[..start], "d".repeat(n), &text[end..])
    };
    assert!(parse_manifest(description(120).as_bytes()).is_ok());
    assert_eq!(manifest_error(&description(121)), PluginError::TextTooLong { field: "description", max: 120 });

    let type_name = good_manifest().replace("id = \"postgres\"\nname = \"PostgreSQL\"", &format!("id = \"postgres\"\nname = \"{}\"", "n".repeat(33)));
    assert_eq!(manifest_error(&type_name), PluginError::TextTooLong { field: "connection_types.name", max: 32 });
}

#[test]
fn an_unknown_permission_value_is_refused() {
    let cases = [
        ("network = \"entry\"", "network = \"any\"", "network"),
        ("network = \"entry\"", "network = true", "network"),
        ("credentials = \"entry\"", "credentials = \"all\"", "credentials"),
        ("storage = true", "storage = \"yes\"", "storage"),
        ("clipboard = \"write\"", "clipboard = \"read\"", "clipboard"),
        ("files = [\"save\"]", "files = [\"save\", \"delete\"]", "files"),
        ("files = [\"save\"]", "files = [\"save\", \"save\"]", "files"),
        ("files = [\"save\"]", "files = \"save\"", "files"),
    ];
    for (from, to, key) in cases {
        assert_eq!(manifest_error(&good_manifest().replace(from, to)), PluginError::BadPermission(key), "{to}");
    }
    let both = parse_manifest(good_manifest().replace("files = [\"save\"]", "files = [\"open\", \"save\"]").as_bytes()).unwrap();
    assert!(both.permissions.files_open && both.permissions.files_save);
}

#[test]
fn control_characters_in_text_are_refused() {
    assert_eq!(manifest_error(&good_manifest().replacen("name = \"PostgreSQL\"", "name = \"Postgre\\u001bSQL\"", 1)), PluginError::TextControlChar("name"));
    assert_eq!(manifest_error(&good_manifest().replace("publisher = \"Example Tools\"", "publisher = \"Bast\\nion\"")), PluginError::TextControlChar("publisher"));
    assert_eq!(manifest_error(&good_manifest().replace("title = \"New Query\"", "title = \"New\\tQuery\"")), PluginError::TextControlChar("commands.title"));
    assert_eq!(manifest_error(&good_manifest().replace("label = \"Database\"", "label = \"Data\\u0000base\"")), PluginError::TextControlChar("connection_types.fields.label"));
    // Characters that reorder or hide text are refused with the control characters.
    assert_eq!(manifest_error(&good_manifest().replace("publisher = \"Example Tools\"", "publisher = \"Bast\\u202Eion\"")), PluginError::TextControlChar("publisher"));
    assert_eq!(manifest_error(&good_manifest().replace("publisher = \"Example Tools\"", "publisher = \"\"")), PluginError::TextEmpty("publisher"));
}

#[test]
fn connection_types_fields_and_commands_are_checked() {
    let m = good_manifest();
    assert_eq!(manifest_error(&m.replace("id = \"postgres\"", "id = \"Postgres\"")), PluginError::BadId("connection_types.id"));
    assert_eq!(manifest_error(&m.replace("key = \"database\"", "key = \"data base\"")), PluginError::BadId("connection_types.fields.key"));
    assert_eq!(manifest_error(&m.replace("id = \"new-query\"", "id = \"new query\"")), PluginError::BadId("commands.id"));
    assert_eq!(manifest_error(&m.replace("kind = \"text\"", "kind = \"password\"")), PluginError::BadValue("connection_types.fields.kind"));
    assert_eq!(manifest_error(&m.replace("default_port = 5432", "default_port = 0")), PluginError::BadValue("connection_types.default_port"));
    assert_eq!(manifest_error(&m.replace("default_port = 5432", "default_port = 65536")), PluginError::BadValue("connection_types.default_port"));
    assert_eq!(manifest_error(&m.replace("on = \"connection:postgres\"", "on = \"connection:mysql\"")), PluginError::BadValue("commands.on"));
    assert_eq!(manifest_error(&m.replace("on = \"connection:postgres\"", "on = \"everything\"")), PluginError::BadValue("commands.on"));
    assert_eq!(manifest_error(&m.replace("repository = \"https://", "repository = \"http://")), PluginError::BadValue("repository"));
    let twice = format!("{m}\n[[commands]]\nid = \"new-query\"\ntitle = \"Again\"\n");
    assert_eq!(manifest_error(&twice), PluginError::DuplicateId("commands.id"));
    let two_types = format!("{m}\n[[connection_types]]\nid = \"postgres\"\nname = \"Again\"\n");
    assert_eq!(manifest_error(&two_types), PluginError::DuplicateId("connection_types.id"));
}

#[test]
fn a_manifest_that_is_not_toml_or_is_too_large_is_refused() {
    assert!(matches!(manifest_error("schema = "), PluginError::ManifestSyntax(_)));
    assert!(matches!(manifest_error(&format!("schema = 1\n{}", good_manifest())), PluginError::ManifestSyntax(_)), "a key given twice");
    assert_eq!(parse_manifest(&[0xFF, 0xFE]).unwrap_err(), PluginError::FileNotText("plugin.toml"));
    let padded = format!("{}\n#{}\n", good_manifest(), "x".repeat(64 * 1024));
    assert_eq!(manifest_error(&padded), PluginError::ManifestTooLarge);
}

#[test]
fn errors_never_echo_more_than_64_bytes_of_untrusted_input() {
    let long_key = "k".repeat(500);
    let message = manifest_error(&good_manifest().replace("schema = 1", &format!("schema = 1\n{long_key} = 1"))).to_string();
    assert!(!message.contains(&"k".repeat(65)), "{message}");
    let long_name = format!("{}.txt", "n".repeat(500));
    let message = rejects(&with_extra(Entry::stored(&long_name, b"x"))).to_string();
    assert!(!message.contains(&"n".repeat(65)), "{message}");
    assert!(message.contains(&"n".repeat(64)), "the start of the name is shown: {message}");
    // Control characters in a name are not passed through to a terminal or a log.
    let message = rejects(&with_extra(Entry::stored("a\x1b[31m.txt", b"x"))).to_string();
    assert!(!message.contains('\x1b'), "{message:?}");
    let message = manifest_error(&format!("schema = 1\n{}", "[".repeat(900))).to_string();
    assert!(message.len() < 200, "{message}");
}

// ---- package against record ----

fn keys<'a>(index: &'a [[u8; 32]], official: &'a [[u8; 32]]) -> TrustedKeys<'a> {
    TrustedKeys { index, official }
}

#[test]
fn a_package_that_matches_its_record_gets_the_tier_of_the_record() {
    let (index_key, official_key) = (new_key(), new_key());
    let (index, official) = ([public(&index_key)], [public(&official_key)]);
    let trusted = keys(&index, &official);

    let bytes = good_package();
    let record = verify_release_record(&external_record(&index_key, EXTERNAL_ID, "1.0.0", &bytes), &trusted, &[]).unwrap();
    assert_eq!(check_package_against_record(&read_package(&bytes).unwrap(), Some(&record)).unwrap(), Tier::External);

    let bytes = package_for(OFFICIAL_ID, "1.0.0");
    let record = verify_release_record(&official_record(&index_key, &official_key, OFFICIAL_ID, "1.0.0", &bytes), &trusted, &[]).unwrap();
    assert_eq!(check_package_against_record(&read_package(&bytes).unwrap(), Some(&record)).unwrap(), Tier::Official);
}

#[test]
fn a_package_without_a_record_is_unverified_unless_its_id_is_reserved() {
    assert_eq!(check_package_against_record(&read_package(&good_package()).unwrap(), None).unwrap(), Tier::Unverified);
    let reserved = read_package(&package_for(OFFICIAL_ID, "1.0.0")).unwrap();
    assert_eq!(check_package_against_record(&reserved, None).unwrap_err(), PluginError::ReservedIdNeedsOfficial);
}

#[test]
fn a_wrong_hash_or_size_is_refused() {
    let index_key = new_key();
    let index = [public(&index_key)];
    let trusted = keys(&index, &[]);
    let bytes = good_package();
    let package = read_package(&bytes).unwrap();

    let mut value = record_value(EXTERNAL_ID, "1.0.0", "external", &bytes);
    value["sha256"] = hex::encode([7u8; 32]).into();
    let record = verify_release_record(&envelope(&to_bytes(&value), &[sig(&index_key, Purpose::ReleaseRecord)]), &trusted, &[]).unwrap();
    assert_eq!(check_package_against_record(&package, Some(&record)).unwrap_err(), PluginError::PackageHashMismatch);

    let mut value = record_value(EXTERNAL_ID, "1.0.0", "external", &bytes);
    value["size"] = (bytes.len() + 1).into();
    let record = verify_release_record(&envelope(&to_bytes(&value), &[sig(&index_key, Purpose::ReleaseRecord)]), &trusted, &[]).unwrap();
    assert_eq!(check_package_against_record(&package, Some(&record)).unwrap_err(), PluginError::PackageSizeMismatch);

    // A record made for another package (same id and version, different bytes).
    let other = zip(&replaced("README.md", Entry::stored("README.md", b"changed\n")));
    let record = verify_release_record(&external_record(&index_key, EXTERNAL_ID, "1.0.0", &other), &trusted, &[]).unwrap();
    assert!(matches!(check_package_against_record(&package, Some(&record)).unwrap_err(), PluginError::PackageSizeMismatch | PluginError::PackageHashMismatch));
}

#[test]
fn a_manifest_whose_id_version_or_permissions_differ_from_the_record_is_refused() {
    let index_key = new_key();
    let index = [public(&index_key)];
    let trusted = keys(&index, &[]);
    let bytes = good_package();
    let package = read_package(&bytes).unwrap();
    let verified = |value: &serde_json::Value| verify_release_record(&envelope(&to_bytes(value), &[sig(&index_key, Purpose::ReleaseRecord)]), &trusted, &[]).unwrap();

    let record = verified(&record_value("com.example.other", "1.0.0", "external", &bytes));
    assert_eq!(check_package_against_record(&package, Some(&record)).unwrap_err(), PluginError::ManifestRecordMismatch("id"));

    let record = verified(&record_value(EXTERNAL_ID, "1.0.1", "external", &bytes));
    assert_eq!(check_package_against_record(&package, Some(&record)).unwrap_err(), PluginError::ManifestRecordMismatch("version"));

    // The record allows less than the manifest asks for, and then more: both are refused.
    let mut fewer = record_value(EXTERNAL_ID, "1.0.0", "external", &bytes);
    fewer["permissions"] = serde_json::json!({ "network": "entry" });
    assert_eq!(check_package_against_record(&package, Some(&verified(&fewer))).unwrap_err(), PluginError::ManifestRecordMismatch("permissions"));
    let mut more = record_value(EXTERNAL_ID, "1.0.0", "external", &bytes);
    more["permissions"]["files"] = serde_json::json!(["save", "open"]);
    assert_eq!(check_package_against_record(&package, Some(&verified(&more))).unwrap_err(), PluginError::ManifestRecordMismatch("permissions"));
}

#[test]
fn a_manifest_whose_api_version_is_outside_the_range_of_the_record_is_refused() {
    let index_key = new_key();
    let index = [public(&index_key)];
    let trusted = keys(&index, &[]);
    let bytes = good_package();
    let package = read_package(&bytes).unwrap();
    assert_eq!(package.manifest.api, ApiVersion { major: 1, minor: 0 });
    let check = |min: &str, max: &str| {
        let mut value = record_value(EXTERNAL_ID, "1.0.0", "external", &bytes);
        value["api"] = serde_json::json!({ "min": min, "max": max });
        let record = verify_release_record(&envelope(&to_bytes(&value), &[sig(&index_key, Purpose::ReleaseRecord)]), &trusted, &[]).unwrap();
        check_package_against_record(&package, Some(&record))
    };
    // The manifest needs API 1.0. Below the range, and above it, are both refused.
    assert_eq!(check("1.1", "1.2").unwrap_err(), PluginError::ManifestRecordMismatch("api"));
    assert_eq!(check("2.0", "2.0").unwrap_err(), PluginError::ManifestRecordMismatch("api"));
    assert_eq!(check("0.1", "0.9").unwrap_err(), PluginError::ManifestRecordMismatch("api"));
    // Both ends of the range are inside it.
    assert_eq!(check("1.0", "1.0").unwrap(), Tier::External);
    assert_eq!(check("1.0", "1.4").unwrap(), Tier::External);
    assert_eq!(check("0.9", "1.0").unwrap(), Tier::External);
    assert_eq!(check("0.9", "1.3").unwrap(), Tier::External);
}

// ---- robustness ----

const PER_CALL: Duration = Duration::from_secs(2);

#[test]
fn mutated_packages_never_panic_and_never_take_long() {
    let good = good_package();
    let original = read_package(&good).unwrap();
    let mut mutator = Mutator(0x5EED_0001);
    let (mut accepted, mut refused) = (0, 0);
    for round in 0..4000 {
        let bytes = mutator.mutate(&good);
        let started = Instant::now();
        let (result, count) = read_package_counted(&bytes);
        assert!(started.elapsed() < PER_CALL, "round {round} took {:?}", started.elapsed());
        assert!(count.bytes_out <= MAX_UNCOMPRESSED_BYTES, "round {round}");
        match result {
            // A change to zip metadata the reader does not use (time stamps, version bytes) is
            // accepted. What matters is that it cannot change a single byte of any file. The
            // package hash differs, so such a file still fails against its release record.
            Ok(package) => {
                accepted += 1;
                let same = package.manifest == original.manifest && package.wasm == original.wasm && package.icon == original.icon && package.readme == original.readme;
                assert!(same && package.license == original.license && package.notices == original.notices && package.changelog == original.changelog, "round {round}: content changed");
            }
            Err(error) => {
                refused += 1;
                assert!(error.to_string().len() < 300, "round {round}: {error}");
            }
        }
    }
    assert!(refused > 3500 && accepted + refused == 4000, "{refused} refused, {accepted} accepted");
}

#[test]
fn mutated_manifests_never_panic_and_never_take_long() {
    let good = good_manifest().into_bytes();
    let mut mutator = Mutator(0x5EED_0002);
    for round in 0..4000 {
        let bytes = mutator.mutate(&good);
        let started = Instant::now();
        if let Err(error) = parse_manifest(&bytes) {
            assert!(error.to_string().len() < 300, "round {round}: {error}");
        }
        assert!(started.elapsed() < PER_CALL, "round {round} took {:?}", started.elapsed());
    }
}

#[test]
fn deeply_nested_manifests_do_not_overflow_the_stack() {
    for text in [format!("a = {}", "[".repeat(60_000)), format!("a = {}", "{ b = ".repeat(10_000)), format!("[{}]", "a.".repeat(30_000))] {
        let started = Instant::now();
        assert!(parse_manifest(text.as_bytes()).is_err());
        assert!(started.elapsed() < PER_CALL);
    }
}

/// The Speed section of docs/evidence/PLUG-04a.md: run with
/// `cargo test --release --test plugin_package_tests -- --ignored --nocapture speed`.
#[test]
#[ignore = "a measurement, not a check"]
fn speed_of_reading_and_checking_a_50_mib_package() {
    let index_key = new_key();
    let index = [public(&index_key)];
    let trusted = keys(&index, &[]);
    let others: u64 = good_entries().iter().filter(|e| e.name != b"plugin.wasm").map(|e| u64::from(e.declared)).sum();
    let wasm = compressible(MAX_UNCOMPRESSED_BYTES as usize - others as usize);
    for (label, entry) in [("deflated", Entry::deflated("plugin.wasm", &wasm)), ("stored", Entry::stored("plugin.wasm", &wasm))] {
        let bytes = zip(&replaced("plugin.wasm", entry));
        let record_bytes = external_record(&index_key, EXTERNAL_ID, "1.0.0", &bytes);
        let mut times = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            let package = read_package(&bytes).unwrap();
            let record = verify_release_record(&record_bytes, &trusted, &[]).unwrap();
            assert_eq!(check_package_against_record(&package, Some(&record)).unwrap(), Tier::External);
            times.push(started.elapsed());
        }
        times.sort();
        println!("50 MiB package ({label}, file {} bytes): median {:?}, slowest {:?}", bytes.len(), times[2], times[4]);
    }
}
