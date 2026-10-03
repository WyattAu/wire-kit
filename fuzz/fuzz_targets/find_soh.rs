//! Fuzz target — the SOH scanner differential: SIMD path (when compiled in)
//! must agree with the scalar/SWAR oracle on arbitrary inputs, and neither
//! may panic. REQ-WIRE-006.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wire_kit::scan::{find_soh, find_soh_reference};

fuzz_target!(|data: &[u8]| {
    let swar = find_soh(data);
    let byte_loop = find_soh_reference(data);
    assert_eq!(swar, byte_loop, "SWAR and byte-loop oracles diverged");
    #[cfg(feature = "simd")]
    {
        let simd = wire_kit::scan::find_soh_simd(data);
        assert_eq!(swar, simd, "SIMD and scalar oracles diverged");
    }
});
