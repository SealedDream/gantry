# Proxmox fixture

Test copy of plugins/official/proxmox for tests/pve01-win-ui-test.ps1 (and the Mac uitests/pve01-entries.txt): the same wasm, with the
test id com.example.proxmox so the unsigned package installs as Unverified. Pack:
`python3 ../pack-plugin.py . ../../../../../plugins/official/proxmox/target/wasm32-wasip2/release/bastion_plugin_proxmox.wasm ../proxmox.bastionplugin`
(with this folder as working directory) after building the plugin with `--features plugin`.
