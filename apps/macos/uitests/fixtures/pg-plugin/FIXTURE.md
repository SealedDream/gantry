# PostgreSQL fixture

Test copy of plugins/official/postgres for PLUG-08-MAC (uitests/plug08-postgres.txt and the
core-ffi field test): the same wasm, with the test id com.example.postgres so the unsigned package
installs as Unverified (an unsigned `dev.bastion.*` id is refused until PLUG-14 signing). Pack, with
this folder as working directory, after `cargo build --offline --release --target wasm32-wasip2` in
plugins/official/postgres:
`python3 ../pack-plugin.py . ../../../../../plugins/target/wasm32-wasip2/release/bastion_plugin_postgres.wasm ../postgres.bastionplugin`
