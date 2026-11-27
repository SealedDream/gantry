# Local patch

Copy of `ironrdp-rdpdr-native` 0.9.0 from crates.io (MIT OR Apache-2.0, licences kept), used
through `[patch.crates-io]` in `rdp-ffi/Cargo.toml`.

Change: `make_query_dir_resp` in `src/nix/backend.rs` answers `FileDirectoryInformation`,
`FileFullDirectoryInformation` and `FileNamesInformation` as well as
`FileBothDirectoryInformation`. Upstream answers only the last and replies `NOT_SUPPORTED`
otherwise, so servers that list with another class (xrdp's FUSE layer) see an empty, unreadable
drive. Drop this copy once upstream answers all four classes.

Change 2: `RelativePath::parse` in `src/nix/path.rs` reads `/` as a path separator before
validating components (xrdp opens files as `/name`). Every component is still validated, so the
upstream traversal tests keep passing; cases for `/../outside`, `/dir//file` and `/dir/` are added.

Change 3: the same `/` reading in `RelativePath::parse` in `src/windows/path.rs`, so the Windows
backend opens and creates the files xrdp names as `/name` (before, listing worked but every open
failed with STATUS_NO_SUCH_FILE). `//server` stays rooted and every component is still
validated; a test covers `/../outside`, `/dir//file`, `/dir/` and `/C:/outside`.

Change 4: `read_inner` in `src/windows/file.rs` answers a read at or past the end of a file with
an empty success instead of forwarding NtReadFile's STATUS_END_OF_FILE (xrdp reads 4 KiB at the
end of every file and turned that status into an I/O error, so no file could be read to its end).

Change 5: the FileDispositionInformation branch of `set_information_inner` in
`src/windows/file.rs`: when the request's handle lacks DELETE access (xrdp opens with only
FILE_READ_ATTRIBUTES before an unlink or rmdir), the same validated path is reopened beneath the
root with DELETE, reparse points still not followed, and marked there. Writable drives only.

Change 6: `src/nix/backend.rs` set-information no longer refuses FileDispositionInformation on a
handle without DELETE access (MS-FSA 2.1.5.15.3). xrdp unlinks and removes directories through a
handle opened with only FILE_READ_ATTRIBUTES, so before this nothing could be deleted from the
shared folder. Rename still requires DELETE; the read-only and empty-directory checks still apply.
The upstream test `a_handle_without_delete_access_can_neither_rename_nor_delete` keeps its rename case.

Change (2026-11-16): `next_file_id` in `src/nix/backend.rs` never hands out FileId 0; the root
handle of the share was 0, while the Windows backend starts at 1.
