# Docker fixture (PLUG-DOCKER-01, Native Windows)

Test copy of `plugins/official/docker` for `tests/docker01-win-ui-test.ps1`: the same wasm and templates, with the test id
`com.example.docker` and neutral name and publisher, so the unsigned package installs as Unverified. Keep `plugin.toml` in step
with the official manifest (only id, name, publisher and repository differ). Build and pack, with this folder as working
directory: `cd ../../../../../plugins/official/docker && cargo build --release --target wasm32-wasip2 --features plugin`, then
`python3 ../pack-plugin.py . <target>/wasm32-wasip2/release/bastion_plugin_docker.wasm ../docker.bastionplugin`
