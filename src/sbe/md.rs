//! The reference message-set accessor block: an SBE
//! `MDIncrementalRefresh`-shaped market-data frame (spec decision 1 —
//! hand-written accessors over the v1 message set, no codegen).
//!
//! # Reference schema layout (little- or big-endian *per frame*)
//!
//! ```text
//! off  size  field
//!   0    8   SBE header: block_len=16, template_id=1, schema_id=0x574B, version=1
//!   8    8   transact_time : u64   (FIX 4.4 analog: tag 60  TransactTime)
//!  16    8   security_id   : i64   (FIX 4.4 analog: tag 48  SecurityID)
//!  24    4   group dimension: block_len=4 (u16) + num_entries (u16)
//!               (FIX 4.4 analog: tag 268 NoMDEntries)
//!  28  24*n  MdEntry, one per group entry:
//!          +0   1  update_action : u8  (tag 279 MDUpdateAction: 0=New 1=Change 2=Delete)
//!          +1   1  entry_type    : u8  (tag 269 MDEntryType: b'0'=Bid b'1'=Offer)
//!          +2   6  padding (aligns price to +8)
//!          +8   8  price         : i64 (tag 270 MDEntryPx mantissa)
//!         +16   4  size          : u32 (tag 271 MDEntrySize)
//!         +20   4  order_id      : u32 (tag 37 OrderID)
//!  ..    2   text length   : u16  (tag 58 Text, varData)
//!  ..   len   text bytes
//! ```
//!
//! The byte order is declared **per frame** at the typed root
//! ([`MdIncrementalRefresh::root`]) and carried on every derived view
//! ([REQ-WIRE-004]).

use crate::error::WireError;
use crate::sbe::group::{DataField, GroupBlock, GroupIter};
use crate::sbe::header::{Decoded, HEADER_LEN};
use crate::sbe::Endianness;

/// Template id of the reference market-data incremental refresh block.
pub const TEMPLATE_ID: u16 = 1;
/// Fixed block length of the message (header excluded).
pub const HEADER_BLOCK_LEN: u16 = 16;
/// Group dimension width: `blockLength: u16 + numInGroup: u16`.
pub const DIM_LEN: usize = 4;
/// Fixed width of one [`MdEntry`].
pub const ENTRY_BLOCK_LEN: usize = 24;
/// Group dimension tag id — the FIX 4.4 `NoMDEntries` (268) analog; used as
/// the `tag` in [`WireError::InvalidGroupCount`].
pub const GROUP_TAG: u16 = 268;
/// Enum id of `MDUpdateAction` in typed errors (`InvalidEnum`).
pub const ENUM_ID_UPDATE_ACTION: u16 = 279;
/// Enum id of `MDEntryType` in typed errors (`InvalidEnum`).
pub const ENUM_ID_ENTRY_TYPE: u16 = 269;
/// Tag ids of the reference schema fields (documentation + corpus manifest).
pub mod tags {
    /// TransactTime (60).
    pub const TRANSACT_TIME: u16 = 60;
    /// SecurityID (48).
    pub const SECURITY_ID: u16 = 48;
    /// NoMDEntries (268) — the group dimension.
    pub const NO_MD_ENTRIES: u16 = 268;
    /// MDUpdateAction (279).
    pub const MD_UPDATE_ACTION: u16 = 279;
    /// MDEntryType (269).
    pub const MD_ENTRY_TYPE: u16 = 269;
    /// MDEntryPx (270).
    pub const MD_ENTRY_PX: u16 = 270;
    /// MDEntrySize (271).
    pub const MD_ENTRY_SIZE: u16 = 271;
    /// OrderID (37).
    pub const ORDER_ID: u16 = 37;
    /// Text (58) — the varData field.
    pub const TEXT: u16 = 58;
}

/// `MDUpdateAction` — the typed view of `MdEntry::update_action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateAction {
    /// Raw `0` — new entry.
    New,
    /// Raw `1` — change.
    Change,
    /// Raw `2` — delete.
    Delete,
}

impl UpdateAction {
    /// Typed view of a raw byte.
    ///
    /// # Errors
    /// [`WireError::InvalidEnum`] (enum id 279) for any raw value outside
    /// `0..=2`.
    pub fn from_raw(raw: u8) -> Result<Self, WireError> {
        match raw {
            0 => Ok(Self::New),
            1 => Ok(Self::Change),
            2 => Ok(Self::Delete),
            other => Err(WireError::InvalidEnum {
                enum_id: ENUM_ID_UPDATE_ACTION,
                raw: other as i64,
            }),
        }
    }

    /// The raw wire byte.
    pub fn raw(self) -> u8 {
        match self {
            Self::New => 0,
            Self::Change => 1,
            Self::Delete => 2,
        }
    }
}

/// `MDEntryType` — the typed view of `MdEntry::entry_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdEntryType {
    /// Raw `b'0'` — bid.
    Bid,
    /// Raw `b'1'` — offer.
    Offer,
}

impl MdEntryType {
    /// Typed view of a raw byte.
    ///
    /// # Errors
    /// [`WireError::InvalidEnum`] (enum id 269) for any byte other than
    /// `b'0'` / `b'1'`.
    pub fn from_raw(raw: u8) -> Result<Self, WireError> {
        match raw {
            b'0' => Ok(Self::Bid),
            b'1' => Ok(Self::Offer),
            other => Err(WireError::InvalidEnum {
                enum_id: ENUM_ID_ENTRY_TYPE,
                raw: other as i64,
            }),
        }
    }

    /// The raw wire byte.
    pub fn raw(self) -> u8 {
        match self {
            Self::Bid => b'0',
            Self::Offer => b'1',
        }
    }
}

/// Typed accessor block over a decoded `MDIncrementalRefresh` frame.
///
/// Views are lifetime-bound to the buffer ([REQ-WIRE-005]) and every field
/// access re-checks bounds ([REQ-WIRE-003]). Zero allocation, zero copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdIncrementalRefresh<'a> {
    buf: &'a [u8],
    off: usize,
    block_len: u16,
    endianness: Endianness,
}

impl<'a> MdIncrementalRefresh<'a> {
    /// Typed root: decode the header, pin the template, and return the
    /// message view.
    ///
    /// The frame's byte order is a parameter ([REQ-WIRE-004] — explicit per
    /// message block): pass the order the schema block declares. The
    /// resulting views read fields in that order.
    ///
    /// # Errors
    /// - [`WireError::InsufficientBytes`] — frame shorter than header plus
    ///   the declared fixed block, or the declared block cannot hold the
    ///   fixed fields.
    /// - [`WireError::UnsupportedSchemaVersion`] — version above the
    ///   supported maximum (from [`SbeHeader::decode`]).
    /// - [`WireError::UnknownMessageType`] — `template_id` is not this
    ///   block's [`TEMPLATE_ID`].
    ///
    /// [REQ-WIRE-004]: crate::req::WIRE_004
    pub fn root(
        buf: &'a [u8],
        endianness: Endianness,
    ) -> Result<Decoded<'a, MdIncrementalRefresh<'a>>, WireError> {
        let d = crate::sbe::SbeHeader::decode(buf, endianness)?;
        if d.view.template_id != TEMPLATE_ID {
            return Err(WireError::UnknownMessageType);
        }
        if d.view.block_len < HEADER_BLOCK_LEN {
            return Err(WireError::InsufficientBytes {
                need: HEADER_LEN + usize::from(HEADER_BLOCK_LEN),
                have: HEADER_LEN + usize::from(d.view.block_len),
            });
        }
        let block_end = HEADER_LEN + usize::from(d.view.block_len);
        if buf.len() < block_end {
            return Err(WireError::InsufficientBytes {
                need: block_end,
                have: buf.len(),
            });
        }
        Ok(Decoded {
            view: Self {
                buf,
                off: 0,
                block_len: d.view.block_len,
                endianness,
            },
            rest: d.rest,
        })
    }

    /// The frame's declared byte order.
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// The header's declared fixed-block length.
    pub fn block_len(&self) -> u16 {
        self.block_len
    }

    /// `TransactTime` (tag 60) — nanoseconds since epoch in the reference
    /// corpus.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the field is out of bounds.
    pub fn transact_time(&self) -> Result<u64, WireError> {
        let off = self
            .off
            .checked_add(8)
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: self.buf.len(),
            })?;
        self.endianness
            .u64_at(self.buf, off)
            .ok_or(WireError::InsufficientBytes {
                need: off + 8,
                have: self.buf.len(),
            })
    }

    /// `SecurityID` (tag 48).
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the field is out of bounds.
    pub fn security_id(&self) -> Result<i64, WireError> {
        let off = self
            .off
            .checked_add(16)
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: self.buf.len(),
            })?;
        self.endianness
            .i64_at(self.buf, off)
            .ok_or(WireError::InsufficientBytes {
                need: off + 8,
                have: self.buf.len(),
            })
    }

    /// Byte offset of the group dimension block.
    fn dim_off(&self) -> Result<usize, WireError> {
        let d = self
            .off
            .checked_add(HEADER_LEN)
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: self.buf.len(),
            })?
            .checked_add(self.block_len as usize)
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: self.buf.len(),
            })?;
        if self.buf.len() < d + DIM_LEN {
            return Err(WireError::InsufficientBytes {
                need: d + DIM_LEN,
                have: self.buf.len(),
            });
        }
        Ok(d)
    }

    /// Byte offset just past the last group entry (the varData region).
    fn entries_end(&self, dim_off: usize, num: usize) -> Result<usize, WireError> {
        dim_off
            .checked_add(DIM_LEN)
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: self.buf.len(),
            })?
            .checked_add(
                num.checked_mul(ENTRY_BLOCK_LEN)
                    .ok_or(WireError::InsufficientBytes {
                        need: usize::MAX,
                        have: self.buf.len(),
                    })?,
            )
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: self.buf.len(),
            })
    }

    /// The repeating group: `NoMDEntries` dimension then [`MdEntry`] blocks.
    ///
    /// # Errors
    /// - [`WireError::InsufficientBytes`] — dimension beyond the buffer.
    /// - [`WireError::InvalidGroupCount`] — the declared count does not fit
    ///   in the remaining bytes (claimed vs fittable).
    pub fn md_entries(&self) -> Result<GroupIter<'a, MdEntry<'a>>, WireError> {
        let dim = self.dim_off()?;
        let num = self
            .endianness
            .u16_at(
                self.buf,
                dim.checked_add(2).ok_or(WireError::InsufficientBytes {
                    need: usize::MAX,
                    have: self.buf.len(),
                })?,
            )
            .ok_or(WireError::InsufficientBytes {
                need: dim + DIM_LEN,
                have: self.buf.len(),
            })?;
        let claimed = num as usize;
        let available = self.buf.len().saturating_sub(dim + DIM_LEN);
        let fittable = available / ENTRY_BLOCK_LEN;
        if claimed > fittable {
            return Err(WireError::InvalidGroupCount {
                tag: GROUP_TAG,
                claimed,
                remaining: fittable,
            });
        }
        Ok(GroupIter::new(
            self.buf,
            dim + DIM_LEN,
            claimed,
            self.endianness,
        ))
    }

    /// The trailing `Text` varData field (tag 58) — `u16` length plus bytes,
    /// located after the group entries.
    ///
    /// # Errors
    /// - [`WireError::InsufficientBytes`] — the data field header or payload
    ///   is out of bounds.
    /// - [`WireError::InvalidGroupCount`] — the group dimension itself is
    ///   unusable (count does not fit).
    pub fn text_field(&self) -> Result<DataField<'a>, WireError> {
        let dim = self.dim_off()?;
        let num = self
            .endianness
            .u16_at(
                self.buf,
                dim.checked_add(2).ok_or(WireError::InsufficientBytes {
                    need: usize::MAX,
                    have: self.buf.len(),
                })?,
            )
            .ok_or(WireError::InsufficientBytes {
                need: dim + DIM_LEN,
                have: self.buf.len(),
            })?;
        let claimed = num as usize;
        let available = self.buf.len().saturating_sub(dim + DIM_LEN);
        let fittable = available / ENTRY_BLOCK_LEN;
        if claimed > fittable {
            return Err(WireError::InvalidGroupCount {
                tag: GROUP_TAG,
                claimed,
                remaining: fittable,
            });
        }
        let end = self.entries_end(dim, claimed)?;
        DataField::parse(self.buf, end, self.endianness)
    }
}

/// One repeating-group entry: `MDUpdateAction`, `MDEntryType`, `MDEntryPx`,
/// `MDEntrySize`, `OrderID` — see the [module layout](self#reference-schema).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdEntry<'a> {
    buf: &'a [u8],
    off: usize,
    endianness: Endianness,
}

impl<'a> MdEntry<'a> {
    const OFF_UPDATE_ACTION: usize = 0;
    const OFF_ENTRY_TYPE: usize = 1;
    const OFF_PRICE: usize = 8;
    const OFF_SIZE: usize = 16;
    const OFF_ORDER_ID: usize = 20;

    /// Raw `MDUpdateAction` byte (tag 279).
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the entry is out of bounds.
    pub fn update_action_raw(&self) -> Result<u8, WireError> {
        self.field_u8(Self::OFF_UPDATE_ACTION)
    }

    /// Typed [`UpdateAction`] (tag 279).
    ///
    /// # Errors
    /// [`WireError::InvalidEnum`] for out-of-range raw values;
    /// [`WireError::InsufficientBytes`] when out of bounds.
    pub fn update_action(&self) -> Result<UpdateAction, WireError> {
        UpdateAction::from_raw(self.update_action_raw()?)
    }

    /// Raw `MDEntryType` byte (tag 269).
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the entry is out of bounds.
    pub fn entry_type_raw(&self) -> Result<u8, WireError> {
        self.field_u8(Self::OFF_ENTRY_TYPE)
    }

    /// Typed [`MdEntryType`] (tag 269).
    ///
    /// # Errors
    /// [`WireError::InvalidEnum`] for out-of-range raw values;
    /// [`WireError::InsufficientBytes`] when out of bounds.
    pub fn entry_type(&self) -> Result<MdEntryType, WireError> {
        MdEntryType::from_raw(self.entry_type_raw()?)
    }

    /// `MDEntryPx` mantissa (tag 270).
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the field is out of bounds.
    pub fn price(&self) -> Result<i64, WireError> {
        let off = self.abs(Self::OFF_PRICE)?;
        self.endianness
            .i64_at(self.buf, off)
            .ok_or(WireError::InsufficientBytes {
                need: off + 8,
                have: self.buf.len(),
            })
    }

    /// `MDEntrySize` (tag 271).
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the field is out of bounds.
    pub fn size(&self) -> Result<u32, WireError> {
        let off = self.abs(Self::OFF_SIZE)?;
        self.endianness
            .u32_at(self.buf, off)
            .ok_or(WireError::InsufficientBytes {
                need: off + 4,
                have: self.buf.len(),
            })
    }

    /// `OrderID` (tag 37).
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the field is out of bounds.
    pub fn order_id(&self) -> Result<u32, WireError> {
        let off = self.abs(Self::OFF_ORDER_ID)?;
        self.endianness
            .u32_at(self.buf, off)
            .ok_or(WireError::InsufficientBytes {
                need: off + 4,
                have: self.buf.len(),
            })
    }

    fn abs(&self, rel: usize) -> Result<usize, WireError> {
        self.off
            .checked_add(rel)
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: self.buf.len(),
            })
    }

    fn field_u8(&self, rel: usize) -> Result<u8, WireError> {
        let off = self.abs(rel)?;
        self.buf
            .get(off)
            .copied()
            .ok_or(WireError::InsufficientBytes {
                need: off + 1,
                have: self.buf.len(),
            })
    }
}

impl<'a> GroupBlock<'a> for MdEntry<'a> {
    const BLOCK_LEN: usize = ENTRY_BLOCK_LEN;

    fn view(buf: &'a [u8], off: usize, endianness: Endianness) -> Result<Self, WireError> {
        let end = off
            .checked_add(ENTRY_BLOCK_LEN)
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: buf.len(),
            })?;
        if buf.get(off..end).is_none() {
            return Err(WireError::InsufficientBytes {
                need: end,
                have: buf.len(),
            });
        }
        Ok(Self {
            buf,
            off,
            endianness,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    #![allow(clippy::indexing_slicing)]

    use super::{MdEntry, MdEntryType, MdIncrementalRefresh, UpdateAction, ENTRY_BLOCK_LEN};
    use crate::error::WireError;
    use crate::sbe::encoder::Encoder;
    use crate::sbe::group::GroupBlock;
    use crate::sbe::{Endianness, Template};

    /// Encode a canonical frame via the Encoder; returns the written slice.
    fn frame(e: Endianness, out: &mut [u8]) -> usize {
        let mut enc = Encoder::new(out);
        enc.write_header(Template::MdIncrementalRefresh, e).unwrap();
        enc.write_field_u64(1_700_000_000_000_000_000, e).unwrap();
        enc.write_field_i64(-99, e).unwrap();
        let mut g = enc.open_group(super::GROUP_TAG).unwrap();
        g.push_entry(|w| {
            w.write_field_u8(UpdateAction::New.raw(), e)?;
            w.write_field_u8(MdEntryType::Bid.raw(), e)?;
            w.write_field_u16(0, e)?;
            w.write_field_u32(0, e)?;
            w.write_field_i64(123_456, e)?;
            w.write_field_u32(7, e)?;
            w.write_field_u32(42, e)
        })
        .unwrap();
        g.finish().unwrap();
        enc.write_data(b"abcd", e).unwrap();
        enc.pos()
    }

    #[test]
    fn root_and_accessors_le_and_be() {
        // REQ-WIRE-001 + REQ-WIRE-004 — same logical frame, both byte orders.
        for e in [Endianness::Little, Endianness::Big] {
            let mut out = [0u8; 128];
            let n = frame(e, &mut out);
            let d = MdIncrementalRefresh::root(&out[..n], e).unwrap();
            assert_eq!(d.view.endianness(), e);
            assert_eq!(d.view.transact_time().unwrap(), 1_700_000_000_000_000_000);
            assert_eq!(d.view.security_id().unwrap(), -99);
            let entries: Vec<_> = d.view.md_entries().unwrap().collect();
            assert_eq!(entries.len(), 1);
            let entry = entries.into_iter().next().unwrap().unwrap();
            assert_eq!(entry.update_action().unwrap(), UpdateAction::New);
            assert_eq!(entry.entry_type().unwrap(), MdEntryType::Bid);
            assert_eq!(entry.price().unwrap(), 123_456);
            assert_eq!(entry.size().unwrap(), 7);
            assert_eq!(entry.order_id().unwrap(), 42);
            let text = d.view.text_field().unwrap();
            assert_eq!(text.bytes(), b"abcd");
            assert_eq!(text.as_str().unwrap(), "abcd");
        }
    }

    #[test]
    fn wrong_template_is_unknown_message() {
        let mut out = [0u8; 64];
        {
            let mut enc = Encoder::new(&mut out);
            enc.write_header(Template::MdIncrementalRefresh, Endianness::Little)
                .unwrap();
        }
        // Patch template id to an unknown value (tests may index).
        out[2] = 0xFF;
        out[3] = 0xEE;
        assert_eq!(
            MdIncrementalRefresh::root(&out, Endianness::Little).map(|_| ()),
            Err(WireError::UnknownMessageType)
        );
    }

    #[test]
    fn short_block_is_insufficient() {
        let mut out = [0u8; 20]; // header + 12 < header + 16
        let mut enc = Encoder::new(&mut out);
        enc.write_header(Template::MdIncrementalRefresh, Endianness::Little)
            .unwrap();
        assert!(matches!(
            MdIncrementalRefresh::root(&out, Endianness::Little),
            Err(WireError::InsufficientBytes { .. })
        ));
    }

    #[test]
    fn group_count_overrun_is_typed() {
        // Dimension claims 2 entries; only 1 fits.
        let mut out = [0u8; 128];
        let mut enc = Encoder::new(&mut out);
        enc.write_header(Template::MdIncrementalRefresh, Endianness::Little)
            .unwrap();
        enc.write_field_u64(1, Endianness::Little).unwrap();
        enc.write_field_i64(1, Endianness::Little).unwrap();
        let mut g = enc.open_group(super::GROUP_TAG).unwrap();
        g.push_entry(|w| {
            w.write_field_u8(0, Endianness::Little)?;
            w.write_field_u8(b'0', Endianness::Little)?;
            w.write_field_u16(0, Endianness::Little)?;
            w.write_field_u32(0, Endianness::Little)?;
            w.write_field_i64(0, Endianness::Little)?;
            w.write_field_u32(0, Endianness::Little)?;
            w.write_field_u32(0, Endianness::Little)
        })
        .unwrap();
        g.finish().unwrap();
        let n = enc.pos();
        // Overwrite the count to claim 2 (tests may index).
        let count_off = 24 + 2;
        out[count_off] = 2;
        let frame = &out[..n];
        let d = MdIncrementalRefresh::root(frame, Endianness::Little).unwrap();
        // One 24-byte entry fits in the bytes after the dimension block.
        let fittable = (n - (24 + crate::sbe::encoder::DIM_BLOCK_LEN)) / ENTRY_BLOCK_LEN;
        assert_eq!(
            d.view.md_entries().map(|_| 0),
            Err(WireError::InvalidGroupCount {
                tag: super::GROUP_TAG,
                claimed: 2,
                remaining: fittable
            })
        );
    }

    #[test]
    fn bad_enum_is_invalid_enum() {
        let mut out = [0u8; 128];
        let mut enc = Encoder::new(&mut out);
        enc.write_header(Template::MdIncrementalRefresh, Endianness::Little)
            .unwrap();
        enc.write_field_u64(1, Endianness::Little).unwrap();
        enc.write_field_i64(1, Endianness::Little).unwrap();
        let mut g = enc.open_group(super::GROUP_TAG).unwrap();
        g.push_entry(|w| {
            w.write_field_u8(9, Endianness::Little)?; // invalid action
            w.write_field_u8(b'1', Endianness::Little)?;
            w.write_field_u16(0, Endianness::Little)?;
            w.write_field_u32(0, Endianness::Little)?;
            w.write_field_i64(0, Endianness::Little)?;
            w.write_field_u32(0, Endianness::Little)?;
            w.write_field_u32(0, Endianness::Little)
        })
        .unwrap();
        g.finish().unwrap();
        let d = MdIncrementalRefresh::root(&out, Endianness::Little).unwrap();
        let entry = d.view.md_entries().unwrap().next().unwrap().unwrap();
        assert_eq!(
            entry.update_action(),
            Err(WireError::InvalidEnum {
                enum_id: super::ENUM_ID_UPDATE_ACTION,
                raw: 9
            })
        );
        assert_eq!(entry.update_action_raw().unwrap(), 9);
    }

    #[test]
    fn every_truncation_is_typed_not_panic() {
        // REQ-WIRE-003 — exhaustive prefix sweep of a valid frame.
        let mut out = [0u8; 128];
        let n = frame(Endianness::Little, &mut out);
        for len in 0..n {
            let (slice, _) = out.split_at(len);
            // Must not panic; Ok or typed Err both acceptable.
            let _ = MdIncrementalRefresh::root(slice, Endianness::Little);
        }
    }

    #[test]
    fn entry_view_oob() {
        let buf = [0u8; ENTRY_BLOCK_LEN - 1];
        assert!(matches!(
            MdEntry::view(&buf, 0, Endianness::Little),
            Err(WireError::InsufficientBytes { .. })
        ));
    }
}
