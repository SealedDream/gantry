# PostgreSQL fixture (PLUG-08-WIN)

Test copy of `plugins/official/postgres` for `tests/plug08-win-ui-test.ps1`: the same wasm, with the test id
`com.example.postgres` so the unsigned package installs as Unverified. Pack, with this folder as working directory,
after `cd plugins && cargo build --release --target wasm32-wasip2 -p bastion-plugin-postgres`:
`python3 ../pack-plugin.py . ../../../../../plugins/target/wasm32-wasip2/release/bastion_plugin_postgres.wasm ../postgres.bastionplugin`
