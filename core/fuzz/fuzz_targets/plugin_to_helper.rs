#![no_main]
//! PLUG-09: a message from the core to the helper, as the helper decodes it; it must encode and
//! decode back to the same bytes.
use bastion_core::plugin::host::proto::ToHelper;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = ToHelper::decode(data) {
        let bytes = m.encode();
        let again = ToHelper::decode(&bytes).expect("an encoded message decodes");
        assert_eq!(again.encode(), bytes);
    }
});
