# Kubernetes fixture

Test copy of plugins/official/kubernetes for uitests/k8s01-dashboard.txt: the same wasm, with the
test id com.example.kubernetes so the unsigned package installs as Unverified. Pack (this folder
as working directory, after building the plugin with `--features plugin`):
`python3 ../pack-plugin.py . ../../../../../plugins/official/kubernetes/target/wasm32-wasip2/release/bastion_plugin_kubernetes.wasm ../kubernetes.bastionplugin`
