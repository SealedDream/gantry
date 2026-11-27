#![no_main]
//! PLUG-09: the app's JSON events for a plugin view, checked before the plugin sees them.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(j) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = bastion_core::plugin::host::view::event_from_json(&j);
    }
});
