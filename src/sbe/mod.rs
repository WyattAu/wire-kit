//! SBE (FIX SBE) block encoding/decoding — fixed-width headers, repeating
//! groups, and data fields as hand-rolled reader/writer over raw buffers.
//!
//! [REQ-WIRE-001] — decode produces lifetime-bound accessor structs over the
//! input buffer with zero allocation and zero copying ([REQ-WIRE-005]).
//! [REQ-WIRE-004] — endianness is explicit per message block: every generic
//! entry point takes an [`Endianness`] parameter and typed roots honor the
//! block's declared byte order. All integer conversion uses
//! `from_le_bytes`/`from_be_bytes` — byteorder-free by mandate.
//!
//! Per the spec's flagged decision 1, v1 ships generic block/group/data-field
//! primitives plus **hand-written accessor blocks** for the reference message
//! set ([`MdIncrementalRefresh`]) — no schema→Rust codegen. The reference
//! layout is documented in [`md`].
//!
//! [REQ-WIRE-001]: crate::req::WIRE_001
//! [REQ-WIRE-004]: crate::req::WIRE_004
//! [REQ-WIRE-005]: crate::req::WIRE_005

pub mod encoder;
pub mod group;
pub mod header;
pub mod md;

pub use encoder::{Encoder, GroupWriter, Template};
pub use group::{DataField, GroupBlock, GroupIter};
pub use header::{Decoded, HeaderView, SbeHeader, HEADER_LEN};
pub use md::{MdEntry, MdEntryType, MdIncrementalRefresh, UpdateAction};

/// Byte order of a message block — explicit per block, never crate-global.
///
/// [REQ-WIRE-004]: crate::req::WIRE_004
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Little-endian fields (the reference corpus's declared order).
    Little,
    /// Big-endian fields (SBE `bigEndian="true"` schemas).
    Big,
}

/// wire-kit reference schema id — `"WK"` (`0x57 0x4B`) in the header.
pub const SCHEMA_ID: u16 = 0x574B;
/// Highest SBE schema version this build decodes; frames declaring a higher
/// version are rejected with [`WireError::UnsupportedSchemaVersion`].
pub const MAX_SCHEMA_VERSION: u16 = 1;
/// Version written by [`Encoder::write_header`] (== [`MAX_SCHEMA_VERSION`]).
pub const CURRENT_SCHEMA_VERSION: u16 = MAX_SCHEMA_VERSION;

impl Endianness {
    /// Read a `u16` at `off` in this byte order. `None` when the two bytes
    /// are not in bounds — callers translate to
    /// [`WireError::InsufficientBytes`].
    pub(crate) fn u16_at(self, buf: &[u8], off: usize) -> Option<u16> {
        let mut b = [0u8; 2];
        b.copy_from_slice(buf.get(off..off.checked_add(2)?)?);
        Some(match self {
            Endianness::Little => u16::from_le_bytes(b),
            Endianness::Big => u16::from_be_bytes(b),
        })
    }

    /// Read a `u32` at `off` in this byte order.
    pub(crate) fn u32_at(self, buf: &[u8], off: usize) -> Option<u32> {
        let mut b = [0u8; 4];
        b.copy_from_slice(buf.get(off..off.checked_add(4)?)?);
        Some(match self {
            Endianness::Little => u32::from_le_bytes(b),
            Endianness::Big => u32::from_be_bytes(b),
        })
    }

    /// Read a `u64` at `off` in this byte order.
    pub(crate) fn u64_at(self, buf: &[u8], off: usize) -> Option<u64> {
        let mut b = [0u8; 8];
        b.copy_from_slice(buf.get(off..off.checked_add(8)?)?);
        Some(match self {
            Endianness::Little => u64::from_le_bytes(b),
            Endianness::Big => u64::from_be_bytes(b),
        })
    }

    /// Read an `i64` at `off` in this byte order.
    pub(crate) fn i64_at(self, buf: &[u8], off: usize) -> Option<i64> {
        let mut b = [0u8; 8];
        b.copy_from_slice(buf.get(off..off.checked_add(8)?)?);
        Some(match self {
            Endianness::Little => i64::from_le_bytes(b),
            Endianness::Big => i64::from_be_bytes(b),
        })
    }

    /// Encode a `u16` into exactly two bytes in this byte order.
    pub(crate) fn u16_bytes(self, v: u16) -> [u8; 2] {
        match self {
            Endianness::Little => v.to_le_bytes(),
            Endianness::Big => v.to_be_bytes(),
        }
    }

    /// Encode a `u32` into exactly four bytes in this byte order.
    pub(crate) fn u32_bytes(self, v: u32) -> [u8; 4] {
        match self {
            Endianness::Little => v.to_le_bytes(),
            Endianness::Big => v.to_be_bytes(),
        }
    }

    /// Encode a `u64` into exactly eight bytes in this byte order.
    pub(crate) fn u64_bytes(self, v: u64) -> [u8; 8] {
        match self {
            Endianness::Little => v.to_le_bytes(),
            Endianness::Big => v.to_be_bytes(),
        }
    }

    /// Encode an `i64` into exactly eight bytes in this byte order.
    pub(crate) fn i64_bytes(self, v: i64) -> [u8; 8] {
        match self {
            Endianness::Little => v.to_le_bytes(),
            Endianness::Big => v.to_be_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Endianness, MAX_SCHEMA_VERSION, SCHEMA_ID};

    #[test]
    fn endianness_roundtrip_all_widths() {
        // REQ-WIRE-004 — from_*/to_* agreement in both byte orders.
        let buf: [u8; 8] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) | 1);
        for e in [Endianness::Little, Endianness::Big] {
            assert_eq!(
                e.u16_at(&buf, 0).map(|v| e.u16_bytes(v)),
                Some([buf[0], buf[1]])
            );
            assert_eq!(
                e.u32_at(&buf, 0).map(|v| e.u32_bytes(v)),
                Some([buf[0], buf[1], buf[2], buf[3]])
            );
            assert_eq!(e.u64_at(&buf, 0).map(|v| e.u64_bytes(v)), Some(buf));
        }
        assert_eq!(SCHEMA_ID, 0x574B);
        assert_eq!(MAX_SCHEMA_VERSION, 1);
    }

    #[test]
    fn oob_reads_are_none() {
        let two = [1u8, 2];
        assert_eq!(Endianness::Little.u16_at(&two, 1), None);
        assert_eq!(Endianness::Little.u32_at(&two, 0), None);
        assert_eq!(Endianness::Little.u64_at(&two, 0), None);
        assert_eq!(Endianness::Big.u64_at(&two, usize::MAX - 9), None);
    }
}
