//! Fuzz target — the SBE decoders (header + typed root + group + data
//! field). REQ-WIRE-003: Err-not-panic on hostile input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wire_kit::sbe::{Endianness, MdIncrementalRefresh, SbeHeader};

fuzz_target!(|data: &[u8]| {
    for e in [Endianness::Little, Endianness::Big] {
        if let Ok(d) = SbeHeader::decode(data, e) {
            // The view must stay readable without panicking.
            let _ = d.view.block_len as usize + d.rest.len();
        }
        if let Ok(d) = MdIncrementalRefresh::root(data, e) {
            let _ = d.view.transact_time();
            let _ = d.view.security_id();
            if let Ok(entries) = d.view.md_entries() {
                for entry in entries.flatten() {
                    let _ = entry.update_action();
                    let _ = entry.entry_type();
                    let _ = entry.price();
                    let _ = entry.size();
                    let _ = entry.order_id();
                }
            }
            if let Ok(text) = d.view.text_field() {
                let _ = text.bytes();
                let _ = text.as_str();
            }
        }
    }
});
