//! Fuzz target — the FIX 4.4 parser and every accessor it feeds
//! (fields, groups, checksum, iteration). REQ-WIRE-003: Err-not-panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wire_kit::fix::FixMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = FixMessage::parse(data) {
        let _ = m.field(35);
        let _ = m.field_str(58);
        let _ = m.message_type();
        let _ = m.verify_checksum();
        for f in m.iter() {
            let _ = f.tag;
            let _ = core::str::from_utf8(f.value);
        }
        // Declared groups: any count tag; entries must stay in bounds.
        for tag in [268u16, 9, 10, 1] {
            if let Ok(g) = m.group(tag) {
                let _ = g.len();
                for e in g.iter().flatten() {
                    let _ = e.field(269);
                    let _ = e.field_str(270);
                }
            }
        }
    }
});
