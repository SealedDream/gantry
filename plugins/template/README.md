# Gantry plugin template

A starter plugin for Gantry (`docs/specs/plugins.md`). It draws one view with a text field
and a button; pressing the button sends the text as a line to the entry's server and shows
the answer.

## Build

```
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

The component is `target/wasm32-wasip2/release/bastion_plugin_template.wasm`.

## Test

- Plugin logic, on your machine: `cargo test` (uses `bastion_plugin_sdk::testing`).
- The real component: the test host in `plugins/testhost`, which loads the `.wasm`, draws the
  views as text and fakes a server and a login:

```
cd ../testhost
cargo run -- ../template/target/wasm32-wasip2/release/bastion_plugin_template.wasm \
  --manifest ../template/plugin.toml --open echo --press Send --echo-server
```

## Rules to keep in mind

- Only `wasi:clocks` and `wasi:random` work. Files, environment variables, standard output and
  threads end the plugin. Use `log` for output.
- Ask only for the permissions you use. The component's imports must match `[permissions]`.
- Never ask for a secret in a field; use `credentials = "entry"`.
