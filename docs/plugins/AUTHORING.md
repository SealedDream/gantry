# Writing a Gantry plugin

A guide for plugin authors (PLUG-16a). It describes the plugin system as it is built today, on
`main`: the SDK, the manifest, permissions, the HTTP helper, views, storage, testing with the
test host, and how installing, permissions and Safe mode work for users.

The design is in `docs/specs/plugins.md` and its amendments; the API itself is
`plugins/wit/plugin.wit`. Where this guide and those files disagree, the WIT file and the core's
checks (`core/src/plugin/`) are right, and this guide has a bug.

**Publishing is not open yet.** The public registry for External plugins comes with PLUG-12.
Until then only Official plugins (in this repository, `plugins/official/`) load by default, and
a plugin you build yourself installs as **Unverified** (section 9).

## 1. What a plugin is

- A plugin is a **WebAssembly component** (`wasm32-wasip2`) plus a manifest, `plugin.toml`.
- It runs in a separate helper process, in Wasmtime, inside the OS sandbox. It can reach the
  outside world only through the calls in `plugins/wit/plugin.wit`, and each call that touches
  the network, a login, storage, the clipboard or a file needs a permission in the manifest.
- A plugin serves **one library entry** at a time (one helper per entry). It can add:
  - connection types (a new kind of library entry, opened in a tab);
  - commands (context menu of its own connection types, and the command palette);
  - views (tab content built from the core's components);
  - one settings page.
- The plugin never draws pixels. It sends a list of nodes; each app draws them with its own
  native controls.
- Only `wasi:clocks` and `wasi:random` work. Files, environment variables, standard output,
  sockets and threads are stubs that end the plugin when called. Use `log` for output.

## 2. Start from the template

```bash
cp -r plugins/template ~/my-plugin
```

Then, in the copy:

1. In `Cargo.toml`, change the package name, and point `bastion-plugin-sdk` at a git path of
   this repository (the SDK is not on crates.io).
2. In `plugin.toml`, change everything: `id`, `name`, `publisher`, `description`, `repository`.
3. Build:

```bash
rustup target add wasm32-wasip2
```

```bash
cargo build --release --target wasm32-wasip2
```

The component is `target/wasm32-wasip2/release/<crate_name>.wasm`. Keep the template's
`[profile.release]` (`opt-level = "s"`, `panic = "abort"`, `lto = true`): smaller components
start faster, and `panic = "abort"` ends a panicking plugin at once instead of unwinding.

## 3. The manifest

`plugin.toml` is TOML, at most 64 KiB. **Unknown keys are refused at every level**, so a typo is
an install error, not a silent default.

The sample plugin of this guide (section 5) reads a status page over HTTP:

```toml
schema = 1
id = "com.example.status"
name = "Status"
version = "0.1.0"
api = "1.1"
publisher = "Example"
description = "Shows a server's status page and keeps the last answer."
license = "MIT OR Apache-2.0"
repository = "https://example.com/status"

[permissions]
storage = true
http = "entry"

[http]
paths = ["/api/"]
methods = ["GET"]
auth = { header = "Authorization", format = "bearer" }

[[connection_types]]
id = "status"
name = "Status"
default_port = 8443

[[connection_types.fields]]
key = "site"
label = "Site"
kind = "text"

[[commands]]
id = "refresh"
title = "Refresh Status"
on = "connection:status"
```

### Top-level keys

| Key | Rule |
|---|---|
| `schema` | `1` |
| `id` | Reverse DNS, lower case, at most 64 bytes. `dev.gantry.*` (and the older `dev.bastion.*`) is reserved for Official plugins |
| `name` | Plain text, at most 32 characters. A name holding "Gantry" (any case) needs the official signature |
| `version` | `major.minor.patch`, digits only, no leading zeros, no suffix |
| `api` | The lowest API version you need, `major.minor`: `"1.0"`, or `"1.1"` for `http` |
| `publisher` | Plain text, at most 64 characters; the "Gantry" rule of `name` applies |
| `description` | Plain text, at most 120 characters |
| `license` | At most 64 characters, for example an SPDX expression |
| `repository` | An `https://` address, at most 256 characters, no spaces |

"Plain text" means: not empty, no control characters. The apps show it verbatim, never as
markup.

### Connection types and fields

| Key | Rule |
|---|---|
| `connection_types.id` | A short local id; the core namespaces it as `<plugin id>/<type id>` |
| `connection_types.name` | At most 32 characters |
| `connection_types.default_port` | Optional, 1 to 65535 |
| `fields.key`, `fields.label` | Local id; label at most 32 characters |
| `fields.kind` | `text`, `number` or `toggle` |

**No secrets in fields.** A field whose key or label contains (ignoring case, spaces, `_` and
`-`) `password`, `passwd`, `pwd`, `passphrase`, `secret`, `token`, `apikey`, `privatekey`,
`credential`, `dsn` or `connectionstring` is refused. Fields are stored in the library without
encryption. A plugin that needs a login asks for `credentials = "entry"` (or uses
`with_login` in the HTTP helper) and the core supplies the entry's own login.

### Commands

| Key | Rule |
|---|---|
| `id` | Local id |
| `title` | At most 40 characters |
| `on` | Optional: `connection:<type id>` of one of your own connection types |

## 4. Permissions

Ask only for what you use. **The component's import list must match the permissions**: the
core reads the imports at install and the helper checks them again at load, so a component that
imports `bastion:plugin/storage` without `storage = true` is refused even if it never calls it.
The Rust SDK imports an interface only when your code uses its module.

| Manifest | Interface | What it allows | Limits |
|---|---|---|---|
| `network = "entry"` | `net` | Byte streams to the entry's host, through the entry's route (direct, gateway, tunnel). The core runs TLS with the entry's TLS mode | Entry's port only (no extra-port list yet in the manifest); 16 streams at once; 30 new connections a minute (attempts count); 1 MiB per read or write; before `start_tls`, at most 512 bytes of preamble when TLS is required |
| `credentials = "entry"` | `credentials` | The entry's own login (user and password), once per helper, after the core's checks and prompt; audited | Passwords only, never SSH keys. Never a login of another entry on the same host |
| `storage = true` | `storage` | A key-value store for this entry | Not encrypted; 2 MiB per value; 50 MiB per plugin; a write holding the released password is refused |
| `clipboard = "write"` | `clipboard` | Copy text | Only right after a user action; never reading; never the released password |
| `files = ["save"]`, `["open"]` or both | `files` | One file the user picks in the app's own dialog | 100 MiB per file; no paths, no folders |
| `http = "entry"` | `http` | HTTP/1.1 requests to the entry's host (API 1.1; section 6) | Needs the `[http]` table and `api = "1.1"` or later |

Every plugin may log, read the clock, draw random numbers and draw views without asking.

**The secret check.** Once the core has released a password to your helper, it refuses log
lines, clipboard writes, storage writes, abort bytes and pre-TLS preambles that contain it, also
as base64, hex or percent-encoding. Do not try to store or show a password; there is no case
where that is needed.

## 5. The SDK

`bastion-plugin-sdk` (`plugins/sdk`) wraps the WIT bindings in ordinary `async` Rust. You
implement the `Plugin` trait; each event runs as its own task, so one view can wait on the
network while another handles a click. There is one plugin value per helper: keep mutable state
in a `RefCell` (or `Cell`) and never hold a borrow across an `.await`.

| `Plugin` method | Called when | Default |
|---|---|---|
| `start()` | Once, before the first event | required |
| `open_view(view, name)` | The core opened a view: a connection type's id, a command's view, or `settings` | required |
| `close_view(view)` | The tab or dialog closed. Streams are not closed for you | nothing |
| `command(id, view)` | A command ran | nothing |
| `input(view, node, input)` | A button, field, code-editor run, tree-menu item, selection or sort | nothing |
| `table_edits(edits)` | The user edited cells of an editable table | nothing |
| `rows(ask)` | A table needs rows | refuses |
| `children(ask)` | A tree node was expanded | refuses |
| `completions(ask)` | A code editor wants completions | none |
| `cancel(view)` | The user pressed Cancel | nothing |

Return a `Task`: `task(async move { ... })` for work, `bastion_plugin_sdk::done()` for nothing.
End the file with `export_plugin!(YourType);`.

The modules, one per WIT interface:

| Module | Calls |
|---|---|
| `host` | `entry()`, `settings()`, `setting(key)` |
| `log` | `debug`, `info`, `warn`, `error` |
| `net` | `Stream::connect(port)`, `read`, `read_exact`, `write`, `start_tls`, `register_abort`, `clear_abort`; the stream closes when dropped |
| `credentials` | `entry_login()` |
| `http` | `request(method, target)`, `send(&req)`, `get_with_login(target)`, `HttpResponse::header(name)` |
| `storage` | `get`, `set`, `delete`, `keys(prefix)` |
| `clipboard` | `write_text` |
| `files` | `save(name, bytes)`, `open()` |
| `ui` | `View::set`, `View::patch`, `View::open_dialog`, `View::close_dialog`, `View::mark_errors`, `provide_rows`, `provide_children`, `provide_completions`, `refuse`, `confirm`, `ViewBuilder`, component helpers, `check` |

Every call that needs the core's answer returns `Result<_, Failure>`:

| `Failure` | Meaning |
|---|---|
| `Denied(text)` | Not allowed: no permission, policy, a cap, the secret check |
| `Invalid(text)` | The request was wrong: a bad view, too large, unknown stream |
| `Io(text)` | The network or the server failed |
| `TimedOut` | The time limit passed |
| `Cancelled` | The user cancelled or closed a dialog |

The text is the core's own words and is safe to show the user.

### The sample plugin

This is the whole plugin for the manifest of section 3. It is compiled and tested in
`plugins/sdk/tests/doc_samples.rs`.

```rust
use std::rc::Rc;

use bastion_plugin_sdk::http::{self, Method};
use bastion_plugin_sdk::ui::{self, BannerLevel, ViewBuilder};
use bastion_plugin_sdk::{export_plugin, log, storage, task, Failure, Input, NodeId, Plugin, Task, View};

const REFRESH: NodeId = 1;
const RESULT: NodeId = 2;

#[derive(Default)]
pub struct Status;

fn nodes(result: ui::Component) -> Vec<ui::Node> {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    assert_eq!(b.add(root, ui::button("Refresh")), REFRESH);
    assert_eq!(b.add(root, result), RESULT);
    b.finish()
}

/// `GET /api/status` with the entry's login, as the manifest's `[http]` table allows.
async fn fetch() -> Result<String, Failure> {
    let mut req = http::request(Method::Get, "/api/status");
    req.headers.push(("Accept".into(), "text/plain".into()));
    req.with_login = true;
    let resp = http::send(&req).await?;
    if resp.status != 200 {
        return Err(Failure::Io(format!("the server answered {}", resp.status)));
    }
    Ok(String::from_utf8_lossy(&resp.body).into_owned())
}

async fn refresh(view: View) {
    let shown = match fetch().await {
        Ok(text) => {
            // Not a secret: storage is not encrypted, and the core refuses a value that holds
            // the released password.
            let _ = storage::set("last-status", text.as_bytes()).await;
            ui::label(&text)
        }
        Err(failure) => {
            log::warn("status request failed");
            ui::banner(BannerLevel::Error, &format!("{failure:?}"))
        }
    };
    let _ = view.patch(vec![ui::Node { id: RESULT, parent: Some(0), component: shown }], vec![]);
}

impl Plugin for Status {
    fn start() -> Self {
        Status
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        task(async move {
            let last = storage::get("last-status").await.ok().flatten();
            let text = last.map(|b| String::from_utf8_lossy(&b).into_owned());
            let _ = view.set(nodes(ui::label(text.as_deref().unwrap_or("Press Refresh."))));
        })
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        match (node, input) {
            (REFRESH, Input::Pressed) => task(refresh(view)),
            _ => bastion_plugin_sdk::done(),
        }
    }
}

export_plugin!(Status);
```

For a raw byte protocol (`network = "entry"`) see the template, `plugins/template/src/lib.rs`,
and the PostgreSQL plugin, `plugins/official/postgres`, which also shows `start_tls`, abort bytes
for cancelling a running query, paged tables, trees and completions.

## 6. The HTTP helper (API 1.1)

With `http = "entry"` the core makes the HTTP/1.1 request for you: it opens the connection on
the entry's route, runs TLS under the entry's TLS mode, writes the request and reads the answer.
The plugin never sees a socket or a TLS key.

The `[http]` table is required with the permission, and refused without it:

| Key | Rule |
|---|---|
| `paths` | Required; 1 to 16 path prefixes, each starting and ending with `/`, at most 256 bytes, with no `%`, `?`, `#`, `\` or `;`. Every request target must start with one of them, byte for byte |
| `ports` | Optional; up to 16 extra ports besides the entry's port |
| `methods` | Optional; any of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, upper case. Default `["GET", "HEAD"]`. Methods that change the server are named in the install prompt |
| `auth` | Optional; `{ header = "...", format = "..." }`. `format` is `basic`, `bearer`, or a template with exactly one `{secret}` and at most one `{user}`, such as `"PVEAPIToken={user}={secret}"` |

Checks the core makes on **every** request (refused with `Denied` or `Invalid`, in its words):

- The method is in `methods`; the port is the entry's or in `ports`.
- `target` is origin form (`/path?query`), printable ASCII, at most 8 KiB. The path holds no
  `#`, `\` or `;`, no `.`, `..` or empty segment, and no percent-encoded `/`, `\`, `.`, `;`, `%`
  or control character.
- At most 32 headers and 16 KiB of headers. The core sets `Host`, `Content-Length`,
  `Connection`, `User-Agent` and the login header itself, and refuses `Cookie`, `Proxy-*`,
  `Upgrade` and other framing headers.
- A body (at most 4 MiB) only with `POST`, `PUT`, `PATCH` or `DELETE`.
- Nothing in the target, headers or body may hold a password the core knows.

With `with_login = true` the core adds the entry's login in the `auth` header. **Your plugin
never sees the password**, and an answer that echoes it back is withheld. This is the preferred
way to authenticate to an HTTP API; you do not need `credentials = "entry"` for it.

Answers: at most 16 MiB. **Redirects are not followed**; a 3xx comes back as it is, with its
`Location` header. The time limit is `timeout_ms` (default and maximum 60 s). The WIT's `http.cancel` ends an
outstanding request; the SDK does not wrap it yet.

## 7. Views

A view is a **flat list of nodes**, each with an id, an optional parent id and a component. You
replace it with `View::set` or change part of it with `View::patch`. `ViewBuilder` hands out ids
in order, starting at 0 for the root.

| Kind | Components |
|---|---|
| Layout | `stack(axis)`, `split(axis)` (two children), `tabs` (children are `tab(title)`), `toolbar` |
| Display | `label`, `banner(level, text)`, `progress(fraction or none)`, `empty-state` |
| Input | `button`, `text-field` (never masked), `number-field`, `choice`, `toggle` |
| Code | `code-editor(language, text, read-only)`: the core colours it (`sql` first) and keeps its text across a helper restart |
| Data | `table` (paged; optionally editable and sortable), `tree` (lazy; per-node menus; with columns it is a tree table) |

Rules the core checks before any app draws the list. A list that breaks one is refused with
`Invalid`; the plugin keeps running:

- At most 2,000 nodes and 256 KiB per view; nesting depth at most 32.
- Ids unique; exactly one root; every parent exists; no cycles.
- Only `stack`, `split`, `tabs`, `tab` and `toolbar` hold children.
- Labels and titles at most 32 characters; longer text is cut in the app with a tooltip.
- All text is plain text: no markup, no links.
- At most 30 updates a second; extra updates are held back, not lost.

Check your views in unit tests with the same rules:

```rust
    assert_eq!(ui::check(&nodes(ui::label("Press Refresh."))), Ok(()));
```

**Tables and trees load lazily.** The core sends a `rows` ask as the user scrolls (at most 1,000
rows each) and a `children` ask when a node is expanded. Answer each ask exactly once, with
`provide_rows` / `provide_children`, or with `refuse(ask, message)`.

**Dialogs.** `View::open_dialog(title, nodes)` opens a modal form over a view. The core adds
fixed chrome with your plugin's name, which you cannot change.

**Confirmations.** Before anything destructive (drop, truncate, delete rows, ending a session,
running statements from table edits), call `ui::confirm(kind, text).await`. The core draws the
prompt in its own words, names the entry and its environment (for example Production), shows
your text in a framed region (cut at 64 KiB), and audits the answer. Edits in an editable table
come to `table_edits`; turn them into statements and confirm them with
`ConfirmKind::RunStatements` before you run them.

**There are no password fields.** Text fields are never masked, and every credential prompt is
the core's own.

## 8. Limits

| What | Limit | When it is passed |
|---|---|---|
| Compute per event | 2 s of CPU; waiting for the network or for `events.next` does not count | The plugin is stopped ("Plugin stopped", with Restart) |
| Memory | 64 MiB per helper | The allocation fails; with `panic = "abort"` the plugin ends |
| Hang | No answer to the core's ping for 10 s | The helper is killed |
| Stop | `run` must return within 2 s of `stop` (the SDK does this) | The helper is killed |
| Messages | 16 MiB per frame | A larger frame ends the helper |
| Storage | 2 MiB per value, 50 MiB per plugin | `Denied`, before the value leaves the helper |
| Result data | 256 MiB per view, 256 MiB per plugin, 512 MiB in total | `Invalid("result too large")` |
| Helpers | 8 at once, over all plugins | |

A helper that keeps crashing restarts after 1 s, 5 s, then 30 s.

**Abort bytes.** `Stream::register_abort(bytes)` (at most 512 bytes) registers a message the
core sends once, on a new stream to the same server, when the helper stops in an ordinary way:
Cancel, closing the tab, a limit, a crash. Use it for a protocol's cancel request. They are sent
in plain text, so they must not carry a login. A stop that withdraws trust (removing or turning
off the plugin, Safe mode, revocation) never sends them.

## 9. Testing

### Unit tests: `bastion_plugin_sdk::testing`

Plugin logic runs on your own machine with `cargo test`. `FakeCore` plays the core: it queues
events, records every call your plugin makes (`Call::...`) and answers them with a closure.
`run_plugin::<P>(core)` runs the plugin until the events are used up. This is the test for the
sample plugin:

```rust
use bastion_plugin_sdk::bindings::bastion::plugin::events::{Event, OpenView, ReplyValue, UiEvent};
use bastion_plugin_sdk::http::HttpResponse;
use bastion_plugin_sdk::testing::{reply, run_plugin, Call, FakeCore};

#[test]
fn refresh_shows_the_status_and_keeps_it() {
    let core = FakeCore::new()
        .respond(|id, call| match call {
            Call::StorageGet(_) => vec![reply(id, Ok(ReplyValue::Value(None)))],
            Call::StorageSet(..) => vec![reply(id, Ok(ReplyValue::None))],
            Call::HttpSend(req) if req.with_login && req.target == "/api/status" => {
                let resp = HttpResponse { status: 200, headers: vec![], body: b"all good".to_vec() };
                vec![reply(id, Ok(ReplyValue::Http(resp)))]
            }
            _ => vec![],
        })
        .with(Event::OpenView(OpenView { view: 1, name: "status".into() }))
        .with(Event::Ui(UiEvent { view: 1, node: REFRESH, input: Input::Pressed }));
    let core = run_plugin::<Status>(core);
    let calls = core.plain_calls();
    assert!(calls.iter().any(|c| matches!(c, Call::StorageSet(k, v) if k == "last-status" && v == b"all good")));
    assert!(calls.iter().any(|c| matches!(c, Call::PatchView(1, nodes, _)
        if matches!(&nodes[0].component, ui::Component::Label(t) if t == "all good"))));
}
```

`FakeCore` does not apply the core's permission or secret checks. Use the test host for those.

### The real component: the test host

`plugins/testhost` loads your `.wasm` in Wasmtime with the same import check, compute and memory
limits as the helper, fakes a server and a login, and prints views as text. From the command
line:

```bash
cd plugins/testhost && cargo run -- ~/my-plugin/target/wasm32-wasip2/release/my_plugin.wasm --manifest ~/my-plugin/plugin.toml --imports
```

`--imports` lists the component's imports and checks them against `[permissions]`. Further
steps run in order; after each one the host waits until the plugin is quiet and prints the open
view:

| Option | Step |
|---|---|
| `--open <view>` | Open a view by name (a connection type id, or `settings`) |
| `--type <label>=<text>` | Type into the text field with that label |
| `--press <label>` | Press the button with that label |
| `--command <id>` | Run a command |
| `--echo-server` | Fake server that answers each line in upper case (instead of none) |
| `--entry-port <port>` | The fake entry's port (default 7) |

The template's run:

```bash
cd plugins/testhost && cargo run -- ../template/target/wasm32-wasip2/release/bastion_plugin_template.wasm --manifest ../template/plugin.toml --open echo --press Send --echo-server
```

No password is taken on the command line: the fake login is a fixed test user with a generated
password.

For scripted tests, use the test host as a library (`bastion_plugin_testhost::TestHost`):
`TestHost::load_files`, then `start(Config { .. }, Box::new(server))`, and drive the session
with `open_view`, `type_text`, `press`, `command`, `ask_rows`, `ask_children`, `wait_for` and
`render`. Implement `FakeServer` (`connect`, and `http` for the HTTP helper) to fake your
protocol. `plugins/testhost/tests/components.rs` has worked examples, including the compute and
memory limits.

### In the app

Install the plugin from a file (section 10) on a build of the Native Mac or Native Windows app,
and open an entry of your connection type. A plugin built by you is Unverified, so the app asks
before it installs and again before it opens it.

## 10. Installing, permissions and Safe mode (for users)

What a user sees today, in the Native Mac and Native Windows apps. Tauri gets the same with
PLUG-10.

- **Plugins page**, with Installed, Catalogue and Updates tabs. Each plugin shows its tier badge,
  publisher, version, its permissions in plain words, licence and source link. Actions: install,
  update, turn off, remove (keeping or deleting its data).
- **Tiers** come only from signatures, never from the manifest:
  - **Official**: made by the Gantry team, signed by the index key and the official key; can
    ship inside the app.
  - **External**: by another publisher, built from a pinned commit and reviewed by Gantry.
    Comes with the public registry (PLUG-12).
  - **Unverified**: no valid signed record, for example your own build. A red badge; the app
    asks before installing and before opening it.
- **Install from a file** works offline. A plugin package is one `.gantryplugin` file: a zip
  holding exactly `plugin.toml`, `plugin.wasm`, `icon.png` (PNG, at most 64 KiB), `README.md`,
  `LICENSE`, `THIRD_PARTY_NOTICES.txt` and optionally `CHANGELOG.md`. It is never unpacked to
  disk. Any other entry, a folder, a link, an absolute or `..` path, a non-ASCII name, two names
  differing only by case, more than 16 entries, more than 50 MiB uncompressed or a compression
  ratio over 100:1 rejects the whole package.
- **Checks at install**, besides the manifest rules of section 3: the component's imports match
  its permissions; the app supports its `api`; a plugin with the same id already installed at a
  higher tier cannot be replaced; `dev.gantry.*` or `dev.bastion.*` ids and "Gantry" or "Bastion" names need the official
  signature.
- **Permissions** are shown in plain words before installing and in the plugin's details, and
  the core checks them on every call, not only at install. An update that asks for a new
  permission waits for the user.
- **Logins.** When a plugin asks for the entry's login and none is saved, the core asks with its
  own prompt, naming the plugin, its tier, the host, the port and the route. Each release is
  audited.
- **Safe mode** runs the app with every plugin off. The core already refuses to load any plugin in
  Safe mode, and a Safe-mode stop never sends abort bytes; the command-line flag and the
  after-crash prompt that turn it on are not in the apps yet (the apps pass Safe mode off).
- **Policy** (managed, can only tighten) can turn plugins off, allow Official plugins only,
  allow only listed ids, forbid Unverified plugins, and forbid TLS off for plugin streams.
- **Library entries** of a plugin type that is not installed show "Needs plugin <name>" and are
  saved unchanged.

## 11. Publishing

Coming with PLUG-12: the public `bastion-plugins` registry, its review policy, the build and
review tools for External plugins, and signed release records. Until then, share a plugin as
source, or as a `.gantryplugin` file that users install as Unverified.

## 12. Checklist before you share a plugin

- [ ] `plugin.toml` asks only for the permissions the code uses; `--imports` in the test host
      passes.
- [ ] No field asks for a secret; logins come from `credentials = "entry"` or `with_login`.
- [ ] Every view passes `ui::check` in a unit test.
- [ ] Every `rows`, `children` and `completions` ask is answered once.
- [ ] Destructive actions go through `ui::confirm`.
- [ ] Nothing logs, stores or shows a password.
- [ ] Long work can be cancelled (`cancel`, abort bytes for byte protocols).
- [ ] The component works offline against your fake server in the test host.
