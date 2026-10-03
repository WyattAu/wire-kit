//! Bounds-checked SBE encoding into caller-owned `&mut [u8]` — the write side
//! of [REQ-WIRE-001], with explicit per-write endianness ([REQ-WIRE-004]).
//!
//! The encoder never allocates and never panics: every write is bounds-checked
//! against the remaining capacity and surfaces
//! [`WireError::InsufficientBytes`].

use crate::error::WireError;
use crate::sbe::{Endianness, CURRENT_SCHEMA_VERSION, SCHEMA_ID};

/// Width of a group dimension block (`blockLength: u16 + numInGroup: u16`).
pub const DIM_BLOCK_LEN: usize = 4;

/// The v1 message set the [`Encoder`] can frame (spec decision 1: hand-rolled
/// accessors for the estate's reference message set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    /// Market-data incremental refresh — see [`crate::sbe::md`].
    MdIncrementalRefresh,
}

impl Template {
    /// The template id written into the message header.
    pub const fn id(self) -> u16 {
        match self {
            Self::MdIncrementalRefresh => crate::sbe::md::TEMPLATE_ID,
        }
    }

    /// The fixed block length written into the message header.
    pub const fn block_len(self) -> u16 {
        match self {
            Self::MdIncrementalRefresh => crate::sbe::md::HEADER_BLOCK_LEN,
        }
    }
}

/// Bounds-checked SBE encoder over a caller-owned buffer.
///
/// Typical shape: [`Encoder::write_header`] first (which also fixes the
/// message's byte order for group dimensions), fixed fields, then
/// [`Encoder::open_group`] for repeating groups, then [`Encoder::write_data`].
/// Nothing is heap-allocated; the written region is reclaimed with
/// [`Encoder::written`].
///
/// [REQ-WIRE-001], [REQ-WIRE-004].
#[derive(Debug)]
pub struct Encoder<'a> {
    buf: &'a mut [u8],
    pos: usize,
    endianness: Endianness,
}

impl<'a> Encoder<'a> {
    /// Wrap a caller-owned buffer. The encoder starts little-endian; call
    /// [`Encoder::write_header`] first for schema-shaped frames.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            endianness: Endianness::Little,
        }
    }

    /// Bytes written so far.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes still writable.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// The message's byte order (fixed by [`Encoder::write_header`]; the
    /// group dimension uses it).
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Write the fixed-width message header for `template`.
    ///
    /// Sets the message's byte order: group dimensions and any field writes
    /// that pass [`self.endianness()`](Encoder::endianness) follow it.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when fewer than 8 bytes remain.
    pub fn write_header(
        &mut self,
        template: Template,
        endianness: Endianness,
    ) -> Result<(), WireError> {
        self.endianness = endianness;
        self.put_u16(template.block_len(), endianness)?;
        self.put_u16(template.id(), endianness)?;
        self.put_u16(SCHEMA_ID, endianness)?;
        self.put_u16(CURRENT_SCHEMA_VERSION, endianness)?;
        Ok(())
    }

    /// Write an `i64` field ([REQ-WIRE-004] — byte order explicit per write).
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when 8 bytes are not available.
    pub fn write_field_i64(&mut self, v: i64, endianness: Endianness) -> Result<(), WireError> {
        self.put_slice(&endianness.i64_bytes(v))
    }

    /// Write a `u64` field.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when 8 bytes are not available.
    pub fn write_field_u64(&mut self, v: u64, endianness: Endianness) -> Result<(), WireError> {
        self.put_slice(&endianness.u64_bytes(v))
    }

    /// Write an `i32` field.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when 4 bytes are not available.
    pub fn write_field_i32(&mut self, v: i32, endianness: Endianness) -> Result<(), WireError> {
        self.put_slice(&endianness.u32_bytes(v as u32))
    }

    /// Write a `u32` field.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when 4 bytes are not available.
    pub fn write_field_u32(&mut self, v: u32, endianness: Endianness) -> Result<(), WireError> {
        self.put_slice(&endianness.u32_bytes(v))
    }

    /// Write a `u16` field.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when 2 bytes are not available.
    pub fn write_field_u16(&mut self, v: u16, endianness: Endianness) -> Result<(), WireError> {
        self.put_slice(&endianness.u16_bytes(v))
    }

    /// Write a `u8` field (no endianness; the parameter is accepted for
    /// call-site symmetry with the typed field writers).
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when 1 byte is not available.
    pub fn write_field_u8(&mut self, v: u8, _endianness: Endianness) -> Result<(), WireError> {
        self.put_slice(&[v])
    }

    /// Write a varData field: `u16` length (in `endianness`) plus payload.
    ///
    /// # Errors
    /// - [`WireError::InsufficientBytes`] — payload exceeds `u16::MAX` (the
    ///   varData length field's capacity) or the buffer cannot hold the
    ///   encoded field.
    pub fn write_data(&mut self, v: &[u8], endianness: Endianness) -> Result<(), WireError> {
        let len = u16::try_from(v.len()).map_err(|_| WireError::InsufficientBytes {
            need: u16::MAX as usize + 1,
            have: v.len(),
        })?;
        self.put_slice(&endianness.u16_bytes(len))?;
        self.put_slice(v)
    }

    /// Open a repeating group: writes the 4-byte dimension block (declared
    /// block length + a zero placeholder count, in the message's byte order)
    /// and returns a writer that counts entries.
    ///
    /// `count_tag` is the group's dimension tag id (e.g. 268 for the
    /// reference `NoMDEntries`), used in typed errors.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when 4 bytes are not available.
    pub fn open_group(&mut self, count_tag: u16) -> Result<GroupWriter<'_, 'a>, WireError> {
        let count_off = self.pos;
        self.put_slice(&self.endianness.u16_bytes(DIM_BLOCK_LEN as u16))?;
        self.put_slice(&self.endianness.u16_bytes(0))?;
        Ok(GroupWriter {
            enc: self,
            count_off,
            count: 0,
            count_tag,
        })
    }

    /// The written region as a shared slice, consuming the encoder.
    pub fn written(self) -> &'a [u8] {
        self.buf.get(..self.pos).unwrap_or(&[])
    }

    fn put_slice(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let len = self.buf.len();
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: len,
            })?;
        let slot = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(WireError::InsufficientBytes {
                need: end,
                have: len,
            })?;
        slot.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    fn put_u16(&mut self, v: u16, e: Endianness) -> Result<(), WireError> {
        self.put_slice(&e.u16_bytes(v))
    }

    fn put_u16_at(&mut self, off: usize, v: u16, e: Endianness) -> Result<(), WireError> {
        let len = self.buf.len();
        let end = off.checked_add(2).ok_or(WireError::InsufficientBytes {
            need: usize::MAX,
            have: len,
        })?;
        let slot = self
            .buf
            .get_mut(off..end)
            .ok_or(WireError::InsufficientBytes {
                need: end,
                have: len,
            })?;
        slot.copy_from_slice(&e.u16_bytes(v));
        Ok(())
    }
}

/// Writer for one open repeating group: counts pushed entries and patches the
/// dimension's `numInGroup` on [`GroupWriter::finish`].
///
/// Entries are written by closures receiving the underlying
/// [`Encoder`], keeping a single bounds-checked write path
/// ([REQ-WIRE-001]).
#[derive(Debug)]
pub struct GroupWriter<'e, 'a> {
    enc: &'e mut Encoder<'a>,
    count_off: usize,
    count: u16,
    count_tag: u16,
}

impl<'e, 'a> GroupWriter<'e, 'a> {
    /// Push one entry: run `write` against the encoder, then count it.
    ///
    /// # Errors
    /// Whatever `write` yields ([`WireError::InsufficientBytes`] on a short
    /// buffer), or [`WireError::InvalidGroupCount`] when the count exceeds
    /// the dimension field's `u16` capacity.
    pub fn push_entry<F>(&mut self, write: F) -> Result<(), WireError>
    where
        F: FnOnce(&mut Encoder<'a>) -> Result<(), WireError>,
    {
        write(self.enc)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or(WireError::InvalidGroupCount {
                tag: self.count_tag,
                claimed: u16::MAX as usize + 1,
                remaining: u16::MAX as usize,
            })?;
        Ok(())
    }

    /// Entries pushed so far.
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Close the group: patch the dimension's `numInGroup` with the pushed
    /// count.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the dimension bytes are no
    /// longer writable (cannot happen for buffers this writer opened).
    pub fn finish(self) -> Result<(), WireError> {
        let e = self.enc.endianness();
        self.enc.put_u16_at(self.count_off + 2, self.count, e)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    #![allow(clippy::indexing_slicing)]

    use super::{Encoder, Template, DIM_BLOCK_LEN};
    use crate::error::WireError;
    use crate::sbe::{Endianness, HEADER_LEN};

    #[test]
    fn header_and_fields_land_in_order() {
        let mut out = [0u8; 32];
        let mut enc = Encoder::new(&mut out);
        enc.write_header(Template::MdIncrementalRefresh, Endianness::Big)
            .unwrap();
        assert_eq!(enc.pos(), HEADER_LEN);
        assert_eq!(enc.endianness(), Endianness::Big);
        enc.write_field_i64(-2, Endianness::Big).unwrap();
        assert_eq!(enc.pos(), HEADER_LEN + 8);
        assert_eq!(enc.remaining(), 32 - (HEADER_LEN + 8));
        let written = enc.written();
        assert_eq!(&written[..4], &[0, 16, 0, 1]); // block_len, template (BE)
        assert_eq!(&written[4..6], &[0x57, 0x4B]);
        assert_eq!(
            &written[8..16],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]
        ); // -2i64 BE
    }

    #[test]
    fn short_buffer_is_insufficient_not_panic() {
        let mut out = [0u8; 10];
        let mut enc = Encoder::new(&mut out);
        enc.write_header(Template::MdIncrementalRefresh, Endianness::Little)
            .unwrap();
        assert_eq!(
            enc.write_field_i64(1, Endianness::Little),
            Err(WireError::InsufficientBytes { need: 16, have: 10 })
        );
        assert_eq!(enc.pos(), HEADER_LEN); // failed write left pos untouched
    }

    #[test]
    fn group_patch_on_finish() {
        let mut out = [0u8; 64];
        let mut enc = Encoder::new(&mut out);
        enc.write_header(Template::MdIncrementalRefresh, Endianness::Little)
            .unwrap();
        let mut g = enc.open_group(268).unwrap();
        for _ in 0..3 {
            g.push_entry(|w| w.write_field_u8(1, Endianness::Little))
                .unwrap();
        }
        assert_eq!(g.count(), 3);
        g.finish().unwrap();
        let written = enc.written();
        let count_off = HEADER_LEN + 2;
        assert_eq!(
            &written[HEADER_LEN..count_off],
            &(DIM_BLOCK_LEN as u16).to_le_bytes()
        );
        assert_eq!(&written[count_off..count_off + 2], &3u16.to_le_bytes());
    }

    #[test]
    fn data_field_len_overflow_is_typed() {
        let mut out = [0u8; 8];
        let mut enc = Encoder::new(&mut out);
        let huge = [0u8; (u16::MAX as usize) + 1];
        assert!(matches!(
            enc.write_data(&huge, Endianness::Little),
            Err(WireError::InsufficientBytes { .. })
        ));
    }

    #[test]
    fn u16_max_data_field_fits_exactly() {
        // Capacity check without a 64 KiB stack array: claim a big buffer via
        // a boxed slice (tests may allocate).
        let mut buf = vec![0u8; 4 + u16::MAX as usize];
        let mut enc = Encoder::new(&mut buf);
        enc.write_data(&vec![7u8; u16::MAX as usize], Endianness::Little)
            .unwrap();
        assert_eq!(enc.pos(), 2 + u16::MAX as usize);
        let written = enc.written();
        assert_eq!(&written[..2], &u16::MAX.to_le_bytes());
    }
}
