#![no_main]
//! PLUG-09: a message from a (compromised) helper to the core. A decoded message must encode
//! and decode back to the same bytes (bytes, not values: NaN is not equal to itself).
use bastion_core::plugin::host::proto::ToCore;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = ToCore::decode(data) {
        let bytes = m.encode();
        let again = ToCore::decode(&bytes).expect("an encoded message decodes");
        assert_eq!(again.encode(), bytes);
    }
});
