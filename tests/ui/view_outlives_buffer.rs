//! REQ-WIRE-005 — a lifetime-bound view cannot outlive its buffer.
//!
//! The typed views hold `&'a [u8]`; dropping the buffer while a view exists
//! must fail to compile (E0597), not compile to a dangling reference.

fn main() {
    let view = {
        let buf: [u8; 64] = [0; 64];
        match wire_kit::sbe::SbeHeader::decode(&buf, wire_kit::Endianness::Little) {
            Ok(decoded) => decoded.view,
            Err(_) => return,
        }
    };
    let _ = view.block_len;
}
