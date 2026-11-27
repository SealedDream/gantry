# VMware fixture

Test copy of plugins/official/vmware for uitests/vmw01-entries.txt: the same wasm, with the
test id com.example.vmware so the unsigned package installs as Unverified. Pack:
`python3 ../pack-plugin.py . ../../../../../plugins/official/vmware/target/wasm32-wasip2/release/bastion_plugin_vmware.wasm ../vmware.bastionplugin`
(with this folder as working directory) after building the plugin with `--features plugin`.
