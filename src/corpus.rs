//! Deterministic, seeded corpus generation from the reference schema —
//! test-support for golden SBE frames ([REQ-WIRE-007]).
//!
//! This is **not** a schema codegen (explicitly out of scope — spec decision
//! 1): it is a small generator that emits encoded frames plus the expected
//! accessor values, deterministically, from the documented reference layout
//! ([`crate::sbe::md`]). No `rand`: a fixed seed base feeds a Knuth-MMIX LCG.
//! CI regenerates and diffs (`corpus_regeneration_is_byte_identical`,
//! `tests/corpus.rs`) — any generator or codec change that alters output
//! bytes without a deliberate golden update fails the build.
//!
//! [REQ-WIRE-007]: crate::req::WIRE_007

use crate::error::WireError;
use crate::sbe::encoder::Encoder;
use crate::sbe::md::{MdEntryType, UpdateAction};
use crate::sbe::{Endianness, Template, CURRENT_SCHEMA_VERSION, SCHEMA_ID};

/// Base seed for the corpus — `"WIREKIT!"` bytes. Per-frame seeds derive as
/// `CORPUS_SEED ^ frame_index`, so adding frames never shifts earlier ones.
pub const CORPUS_SEED: u64 = 0x5749_5245_4B49_5421;
/// Frames in the corpus: three little-endian (the reference corpus order)
/// and one big-endian frame ([REQ-WIRE-004] coverage).
pub const CORPUS_FRAMES: usize = 4;
/// Maximum group entries per generated frame.
pub const MAX_CORPUS_ENTRIES: usize = 4;
/// Maximum varData text bytes per generated frame.
pub const MAX_CORPUS_TEXT: usize = 16;

/// A deterministic LCG (Knuth's MMIX constants). No `rand` — [REQ-WIRE-007]
/// mandates fixed seeds only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lcg64 {
    state: u64,
}

impl Lcg64 {
    /// Seed the generator.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Next raw 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    /// Next value in `0..n` (`0` when `n == 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

/// Expected accessor values for one generated group entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedEntry {
    /// `MDUpdateAction`.
    pub action: UpdateAction,
    /// `MDEntryType`.
    pub entry_type: MdEntryType,
    /// `MDEntryPx` mantissa.
    pub price: i64,
    /// `MDEntrySize`.
    pub size: u32,
    /// `OrderID`.
    pub order_id: u32,
}

/// Expected accessor values for one generated frame — what decoders must
/// observe in the emitted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedFrame {
    /// Declared byte order of the frame.
    pub endianness: Endianness,
    /// Header fields as written.
    pub block_len: u16,
    /// Template id as written.
    pub template_id: u16,
    /// Schema id as written.
    pub schema_id: u16,
    /// Schema version as written.
    pub version: u16,
    /// `TransactTime`.
    pub transact_time: u64,
    /// `SecurityID`.
    pub security_id: i64,
    /// Group entries (valid in `0..entry_count`).
    pub entries: [Option<ExpectedEntry>; MAX_CORPUS_ENTRIES],
    /// Number of entries actually written.
    pub entry_count: usize,
    /// varData `Text` payload (valid in `0..text_len`).
    pub text: [u8; MAX_CORPUS_TEXT],
    /// Number of text bytes written.
    pub text_len: usize,
}

/// Generate one seeded market-data frame into `out`, returning the byte
/// length written and the expected accessor values.
///
/// Draw order is fixed (transact_time, security_id, entry count, per-entry
/// fields, text length, text bytes) so regeneration is byte-identical.
///
/// # Errors
/// [`WireError::InsufficientBytes`] when `out` cannot hold the frame (~150
/// bytes suffices).
pub fn generate_md_frame(
    out: &mut [u8],
    rng: &mut Lcg64,
    endianness: Endianness,
) -> Result<(usize, ExpectedFrame), WireError> {
    let mut expected = ExpectedFrame {
        endianness,
        block_len: Template::MdIncrementalRefresh.block_len(),
        template_id: Template::MdIncrementalRefresh.id(),
        schema_id: SCHEMA_ID,
        version: CURRENT_SCHEMA_VERSION,
        transact_time: 0,
        security_id: 0,
        entries: [None; MAX_CORPUS_ENTRIES],
        entry_count: 0,
        text: [0; MAX_CORPUS_TEXT],
        text_len: 0,
    };

    expected.transact_time = rng.next_u64();
    expected.security_id = rng.next_u64() as i64;
    let n = rng.below((MAX_CORPUS_ENTRIES + 1) as u64) as usize;

    let mut enc = Encoder::new(out);
    enc.write_header(Template::MdIncrementalRefresh, endianness)?;
    enc.write_field_u64(expected.transact_time, endianness)?;
    enc.write_field_i64(expected.security_id, endianness)?;
    let mut group = enc.open_group(crate::sbe::md::GROUP_TAG)?;
    for slot in expected.entries.iter_mut().take(n) {
        let action_raw = rng.below(3) as u8;
        let action = match action_raw {
            0 => UpdateAction::New,
            1 => UpdateAction::Change,
            _ => UpdateAction::Delete,
        };
        let entry_type = if rng.below(2) == 0 {
            MdEntryType::Bid
        } else {
            MdEntryType::Offer
        };
        let price = rng.next_u64() as i64;
        let size = rng.next_u64() as u32;
        let order_id = rng.next_u64() as u32;
        group.push_entry(|w: &mut Encoder<'_>| {
            w.write_field_u8(action.raw(), endianness)?;
            w.write_field_u8(entry_type.raw(), endianness)?;
            w.write_field_u16(0, endianness)?; // padding
            w.write_field_u32(0, endianness)?; // padding
            w.write_field_i64(price, endianness)?;
            w.write_field_u32(size, endianness)?;
            w.write_field_u32(order_id, endianness)
        })?;
        *slot = Some(ExpectedEntry {
            action,
            entry_type,
            price,
            size,
            order_id,
        });
        expected.entry_count += 1;
    }
    group.finish()?;

    expected.text_len = rng.below((MAX_CORPUS_TEXT + 1) as u64) as usize;
    for slot in expected.text.iter_mut().take(expected.text_len) {
        // Printable ASCII, keeps manifests human-checkable.
        *slot = 0x20 + (rng.next_u64() % 0x5F) as u8;
    }
    let text = expected.text.get(..expected.text_len).unwrap_or(&[]);
    enc.write_data(text, endianness)?;

    Ok((enc.pos(), expected))
}

/// Serialize the full corpus: [`CORPUS_FRAMES`] frames, each `u32`-LE
/// length-prefixed, into `out`. Frame order: little-endian ×3, then one
/// big-endian frame. Returns the total byte length.
///
/// # Errors
/// [`WireError::InsufficientBytes`] when `out` cannot hold the corpus
/// (~600 bytes suffices).
pub fn generate_corpus(out: &mut [u8]) -> Result<usize, WireError> {
    let mut total = 0usize;
    let cap = out.len();
    for i in 0..CORPUS_FRAMES {
        let mut rng = Lcg64::new(CORPUS_SEED ^ (i as u64));
        let endianness = if i + 1 == CORPUS_FRAMES {
            Endianness::Big
        } else {
            Endianness::Little
        };
        // Frame region: 4-byte length prefix + frame.
        let region = out.get_mut(total..).ok_or(WireError::InsufficientBytes {
            need: total + 4,
            have: cap,
        })?;
        let mut scratch = [0u8; 256];
        let (n, _expected) = generate_md_frame(&mut scratch, &mut rng, endianness)?;
        // The corpus container is little-endian regardless of frame order.
        let prefix = (n as u32).to_le_bytes();
        region
            .get_mut(..4)
            .ok_or(WireError::InsufficientBytes {
                need: total + 4,
                have: cap,
            })?
            .copy_from_slice(&prefix);
        region
            .get_mut(4..4 + n)
            .ok_or(WireError::InsufficientBytes {
                need: total + 4 + n,
                have: cap,
            })?
            .copy_from_slice(scratch.get(..n).unwrap_or(&[]));
        total += 4 + n;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    #![allow(clippy::indexing_slicing)]

    use super::{generate_corpus, generate_md_frame, Lcg64, CORPUS_SEED};
    use crate::sbe::md::MdIncrementalRefresh;
    use crate::sbe::Endianness;

    #[test]
    fn generation_is_deterministic_and_seeded() {
        // REQ-WIRE-007 — same seed, byte-identical output; different seed,
        // different bytes.
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        let (na, ea) =
            generate_md_frame(&mut a, &mut Lcg64::new(CORPUS_SEED), Endianness::Little).unwrap();
        let (nb, eb) =
            generate_md_frame(&mut b, &mut Lcg64::new(CORPUS_SEED), Endianness::Little).unwrap();
        assert_eq!(na, nb);
        assert_eq!(&a[..na], &b[..nb]);
        assert_eq!(ea, eb);

        let mut c = [0u8; 256];
        let (nc, _ec) =
            generate_md_frame(&mut c, &mut Lcg64::new(CORPUS_SEED ^ 1), Endianness::Little)
                .unwrap();
        assert_ne!(&a[..na], &c[..nc]);
    }

    #[test]
    fn corpus_roundtrips_through_the_decoders() {
        // REQ-WIRE-007 + REQ-WIRE-001 — generated frames decode to exactly
        // the expected values (LE and BE).
        let mut out = [0u8; 1024];
        let n = generate_corpus(&mut out).unwrap();
        let mut pos = 0usize;
        for i in 0..super::CORPUS_FRAMES {
            let endianness = if i + 1 == super::CORPUS_FRAMES {
                Endianness::Big
            } else {
                Endianness::Little
            };
            let mut rng = Lcg64::new(CORPUS_SEED ^ (i as u64));
            let (_n, expected) = generate_md_frame(&mut [0u8; 256], &mut rng, endianness).unwrap();
            let flen = u32::from_le_bytes(out[pos..pos + 4].try_into().unwrap()) as usize;
            let frame = out[pos + 4..pos + 4 + flen].to_vec();
            let d = MdIncrementalRefresh::root(&frame, endianness).unwrap();
            assert_eq!(d.view.block_len(), expected.block_len);
            assert_eq!(d.view.transact_time().unwrap(), expected.transact_time);
            assert_eq!(d.view.security_id().unwrap(), expected.security_id);
            let entries: Vec<_> = d.view.md_entries().unwrap().collect();
            assert_eq!(entries.len(), expected.entry_count);
            for (k, e) in entries.into_iter().enumerate() {
                let e = e.unwrap();
                let x = expected.entries[k].unwrap();
                assert_eq!(e.update_action().unwrap(), x.action);
                assert_eq!(e.entry_type().unwrap(), x.entry_type);
                assert_eq!(e.price().unwrap(), x.price);
                assert_eq!(e.size().unwrap(), x.size);
                assert_eq!(e.order_id().unwrap(), x.order_id);
            }
            let text = d.view.text_field().unwrap();
            assert_eq!(text.len() as usize, expected.text_len);
            assert_eq!(text.bytes(), &expected.text[..expected.text_len]);
            pos += 4 + flen;
        }
        assert_eq!(pos, n);
    }
}
