# Exec fixture (PLUG-EXEC-01, Native Windows)

Test plugin for `tests/plugexec-win-ui-test.ps1`: id `com.example.execfixture`, unsigned, so it installs as
Unverified. Templates `hello` (`echo exec-ok`), `wait` (`sleep {secs}`) and `term` (`top`, a change, interactive).
Build and pack, with this folder as working directory:
`cargo build --release --target wasm32-wasip2`, then
`python3 ../pack-plugin.py . <target>/wasm32-wasip2/release/bastion_fixture_exec.wasm ../exec.bastionplugin`
