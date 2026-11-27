//! The raw imports, one free function each.
//!
//! On `wasm32` each function calls the generated binding directly, so the linker drops every
//! import a plugin never calls, and the component imports only the interfaces (and so the
//! permissions) it really uses. On a build machine the same functions go to the fake core in
//! [`crate::testing`].

use crate::bindings::bastion::plugin::events::Event;
use crate::bindings::bastion::plugin::log::Level;
use crate::bindings::bastion::plugin::types::{Entry, Failure};
use crate::bindings::bastion::plugin::ui::{
    Completion, ConfirmKind, ErrorMark, Node, Row, TreeItem,
};

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::*;
    use crate::bindings::bastion::plugin as p;

    pub fn next() -> Event { p::events::next() }
    pub fn entry() -> Option<Entry> { p::host::entry_info() }
    pub fn settings() -> Vec<(String, String)> { p::host::settings() }
    pub fn log(level: Level, text: &str) { p::log::line(level, text) }

    pub fn set_view(view: u32, nodes: &[Node]) -> Result<(), Failure> { p::ui::set_view(view, nodes) }
    pub fn patch_view(view: u32, upsert: &[Node], remove: &[u32]) -> Result<(), Failure> {
        p::ui::patch_view(view, upsert, remove)
    }
    pub fn open_dialog(over: u32, title: &str, nodes: &[Node]) -> Result<u32, Failure> {
        p::ui::open_dialog(over, title, nodes)
    }
    pub fn close_dialog(dialog: u32) { p::ui::close_dialog(dialog) }
    pub fn mark_errors(view: u32, editor: u32, marks: &[ErrorMark]) -> Result<(), Failure> {
        p::ui::mark_errors(view, editor, marks)
    }
    pub fn provide_rows(ask: u32, rows: &[Row], total: Option<u64>) -> Result<(), Failure> {
        p::ui::provide_rows(ask, rows, total)
    }
    pub fn provide_children(ask: u32, items: &[TreeItem]) -> Result<(), Failure> {
        p::ui::provide_children(ask, items)
    }
    pub fn provide_completions(ask: u32, items: &[Completion]) -> Result<(), Failure> {
        p::ui::provide_completions(ask, items)
    }
    pub fn refuse(ask: u32, message: &str) { p::ui::refuse(ask, message) }
    pub fn confirm(kind: ConfirmKind, text: &str) -> u32 { p::ui::confirm(kind, text) }

    pub fn connect(port: Option<u16>) -> u32 { p::net::connect(port) }
    pub fn read(stream: u32, max: u32) -> u32 { p::net::read(stream, max) }
    pub fn write(stream: u32, data: &[u8]) -> u32 { p::net::write(stream, data) }
    pub fn start_tls(stream: u32) -> u32 { p::net::start_tls(stream) }
    pub fn close(stream: u32) { p::net::close(stream) }
    pub fn register_abort(stream: u32, data: &[u8]) -> u32 { p::net::register_abort(stream, data) }
    pub fn clear_abort(stream: u32) { p::net::clear_abort(stream) }

    pub fn entry_login() -> u32 { p::credentials::entry_login() }

    pub fn http_send(req: &p::http::HttpRequest) -> u32 { p::http::send(req) }

    pub fn open_connection(req: &p::open::OpenRequest) -> u32 { p::open::connection(req) }

    pub fn exec_run(template: &str, args: &[(String, String)], timeout_ms: u32) -> u32 { p::exec::run(template, args, timeout_ms) }
    pub fn exec_cancel(req: u32) { p::exec::cancel(req) }
    pub fn exec_terminal(template: &str, args: &[(String, String)], label: &str) -> u32 { p::exec::terminal(template, args, label) }
    pub fn library_propose(proposals: &[p::library::Proposal]) -> u32 { p::library::propose(proposals) }

    pub fn storage_get(key: &str) -> u32 { p::storage::get(key) }
    pub fn storage_set(key: &str, value: &[u8]) -> u32 { p::storage::set(key, value) }
    pub fn storage_delete(key: &str) -> u32 { p::storage::delete(key) }
    pub fn storage_keys(prefix: &str) -> u32 { p::storage::keys(prefix) }

    pub fn clipboard_write(text: &str) -> u32 { p::clipboard::write_text(text) }

    pub fn files_save(name: &str, data: &[u8]) -> u32 { p::files::save(name, data) }
    pub fn files_open() -> u32 { p::files::open() }
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::*;
    use crate::testing::{with_host, Call};

    pub fn next() -> Event { with_host(|h| h.next()) }
    pub fn entry() -> Option<Entry> { with_host(|h| h.entry.clone()) }
    pub fn settings() -> Vec<(String, String)> { with_host(|h| h.settings.clone()) }
    pub fn log(level: Level, text: &str) { with_host(|h| h.call(Call::Log(level, text.into()))); }

    pub fn set_view(view: u32, nodes: &[Node]) -> Result<(), Failure> {
        with_host(|h| h.call_result(Call::SetView(view, nodes.to_vec())))
    }
    pub fn patch_view(view: u32, upsert: &[Node], remove: &[u32]) -> Result<(), Failure> {
        with_host(|h| h.call_result(Call::PatchView(view, upsert.to_vec(), remove.to_vec())))
    }
    pub fn open_dialog(over: u32, title: &str, nodes: &[Node]) -> Result<u32, Failure> {
        with_host(|h| {
            h.call_result(Call::OpenDialog(over, title.into(), nodes.to_vec()))?;
            Ok(h.new_id())
        })
    }
    pub fn close_dialog(dialog: u32) { with_host(|h| h.call(Call::CloseDialog(dialog))); }
    pub fn mark_errors(view: u32, editor: u32, marks: &[ErrorMark]) -> Result<(), Failure> {
        with_host(|h| h.call_result(Call::MarkErrors(view, editor, marks.to_vec())))
    }
    pub fn provide_rows(ask: u32, rows: &[Row], total: Option<u64>) -> Result<(), Failure> {
        with_host(|h| h.call_result(Call::ProvideRows(ask, rows.to_vec(), total)))
    }
    pub fn provide_children(ask: u32, items: &[TreeItem]) -> Result<(), Failure> {
        with_host(|h| h.call_result(Call::ProvideChildren(ask, items.to_vec())))
    }
    pub fn provide_completions(ask: u32, items: &[Completion]) -> Result<(), Failure> {
        with_host(|h| h.call_result(Call::ProvideCompletions(ask, items.to_vec())))
    }
    pub fn refuse(ask: u32, message: &str) { with_host(|h| h.call(Call::Refuse(ask, message.into()))); }
    pub fn confirm(kind: ConfirmKind, text: &str) -> u32 { with_host(|h| h.call(Call::Confirm(kind, text.into()))) }

    pub fn connect(port: Option<u16>) -> u32 { with_host(|h| h.call(Call::Connect(port))) }
    pub fn read(stream: u32, max: u32) -> u32 { with_host(|h| h.call(Call::Read(stream, max))) }
    pub fn write(stream: u32, data: &[u8]) -> u32 { with_host(|h| h.call(Call::Write(stream, data.to_vec()))) }
    pub fn start_tls(stream: u32) -> u32 { with_host(|h| h.call(Call::StartTls(stream))) }
    pub fn close(stream: u32) { with_host(|h| h.call(Call::Close(stream))); }
    pub fn register_abort(stream: u32, data: &[u8]) -> u32 {
        with_host(|h| h.call(Call::RegisterAbort(stream, data.to_vec())))
    }
    pub fn clear_abort(stream: u32) { with_host(|h| h.call(Call::ClearAbort(stream))); }

    pub fn entry_login() -> u32 { with_host(|h| h.call(Call::EntryLogin)) }

    pub fn http_send(req: &crate::bindings::bastion::plugin::http::HttpRequest) -> u32 {
        with_host(|h| h.call(Call::HttpSend(req.clone())))
    }

    pub fn open_connection(req: &crate::bindings::bastion::plugin::open::OpenRequest) -> u32 {
        with_host(|h| h.call(Call::OpenConnection(req.clone())))
    }

    pub fn exec_run(template: &str, args: &[(String, String)], timeout_ms: u32) -> u32 {
        with_host(|h| h.call(Call::ExecRun(template.into(), args.to_vec(), timeout_ms)))
    }
    pub fn exec_cancel(req: u32) { with_host(|h| h.call(Call::ExecCancel(req))); }
    pub fn exec_terminal(template: &str, args: &[(String, String)], label: &str) -> u32 {
        with_host(|h| h.call(Call::ExecTerminal(template.into(), args.to_vec(), label.into())))
    }
    pub fn library_propose(proposals: &[crate::bindings::bastion::plugin::library::Proposal]) -> u32 {
        with_host(|h| h.call(Call::LibraryPropose(proposals.to_vec())))
    }

    pub fn storage_get(key: &str) -> u32 { with_host(|h| h.call(Call::StorageGet(key.into()))) }
    pub fn storage_set(key: &str, value: &[u8]) -> u32 {
        with_host(|h| h.call(Call::StorageSet(key.into(), value.to_vec())))
    }
    pub fn storage_delete(key: &str) -> u32 { with_host(|h| h.call(Call::StorageDelete(key.into()))) }
    pub fn storage_keys(prefix: &str) -> u32 { with_host(|h| h.call(Call::StorageKeys(prefix.into()))) }

    pub fn clipboard_write(text: &str) -> u32 { with_host(|h| h.call(Call::ClipboardWrite(text.into()))) }

    pub fn files_save(name: &str, data: &[u8]) -> u32 {
        with_host(|h| h.call(Call::FilesSave(name.into(), data.to_vec())))
    }
    pub fn files_open() -> u32 { with_host(|h| h.call(Call::FilesOpen)) }
}

pub use imp::*;
