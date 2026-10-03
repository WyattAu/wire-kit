//! SBE integration tests — REQ-WIRE-001/004 traceability anchors.

// Test harness: assertions legitimately panic; the decode paths under test
// (the lib target) remain lint-clean.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use proptest::prelude::*;
use wire_kit::corpus::{generate_md_frame, Lcg64, CORPUS_SEED, MAX_CORPUS_ENTRIES};
use wire_kit::error::WireError;
use wire_kit::sbe::encoder::Encoder;
use wire_kit::sbe::md::{
    MdEntry, MdEntryType, MdIncrementalRefresh, UpdateAction, ENTRY_BLOCK_LEN, GROUP_TAG,
    TEMPLATE_ID,
};
use wire_kit::sbe::{
    Decoded, Endianness, GroupBlock, SbeHeader, HEADER_LEN, MAX_SCHEMA_VERSION, SCHEMA_ID,
};

/// Build a canonical frame via the encoder; returns the written length.
fn encode_frame(
    out: &mut [u8],
    e: Endianness,
    transact_time: u64,
    security_id: i64,
    entries: &[(UpdateAction, MdEntryType, i64, u32, u32)],
    text: &[u8],
) -> usize {
    let mut enc = Encoder::new(out);
    enc.write_header(wire_kit::sbe::Template::MdIncrementalRefresh, e)
        .unwrap();
    enc.write_field_u64(transact_time, e).unwrap();
    enc.write_field_i64(security_id, e).unwrap();
    let mut g = enc.open_group(GROUP_TAG).unwrap();
    for (a, t, p, s, o) in entries {
        g.push_entry(|w: &mut Encoder<'_>| {
            w.write_field_u8(a.raw(), e)?;
            w.write_field_u8(t.raw(), e)?;
            w.write_field_u16(0, e)?;
            w.write_field_u32(0, e)?;
            w.write_field_i64(*p, e)?;
            w.write_field_u32(*s, e)?;
            w.write_field_u32(*o, e)
        })
        .unwrap();
    }
    g.finish().unwrap();
    enc.write_data(text, e).unwrap();
    enc.pos()
}

// REQ-WIRE-001 — SBE block encoding/decoding covers fixed-width message
// headers, repeating groups, and data fields; decode(encode(x)) == x.
// This is the spec's named traceability test (proptest round-trip, 500
// cases via the global config).
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(500))]

    #[test]
    fn sbe_roundtrip_header_group_datafield(
        transact_time in any::<u64>(),
        security_id in any::<i64>(),
        n_entries in 0usize..=MAX_CORPUS_ENTRIES,
        prices in proptest::collection::vec(any::<i64>(), MAX_CORPUS_ENTRIES),
        sizes in proptest::collection::vec(any::<u32>(), MAX_CORPUS_ENTRIES),
        order_ids in proptest::collection::vec(any::<u32>(), MAX_CORPUS_ENTRIES),
        actions in proptest::collection::vec(0u8..3, MAX_CORPUS_ENTRIES),
        entry_types in proptest::collection::vec(0u8..2, MAX_CORPUS_ENTRIES),
        text in proptest::collection::vec(any::<u8>(), 0..17),
    ) {
        let entries: Vec<_> = (0..n_entries)
            .map(|i| {
                (
                    UpdateAction::from_raw(actions[i]).unwrap(),
                    MdEntryType::from_raw(if entry_types[i] == 0 { b'0' } else { b'1' }).unwrap(),
                    prices[i],
                    sizes[i],
                    order_ids[i],
                )
            })
            .collect();

        for e in [Endianness::Little, Endianness::Big] {
            let mut out = [0u8; 512];
            let n = encode_frame(&mut out, e, transact_time, security_id, &entries, &text);

            // Header view — lifetime-bound, zero-copy.
            let Decoded { view: hdr, rest } = SbeHeader::decode(&out[..n], e).unwrap();
            prop_assert_eq!(hdr.block_len, 16);
            prop_assert_eq!(hdr.template_id, TEMPLATE_ID);
            prop_assert_eq!(hdr.schema_id, SCHEMA_ID);
            prop_assert_eq!(hdr.version, 1);
            prop_assert_eq!(rest.len(), n - HEADER_LEN);

            let d = MdIncrementalRefresh::root(&out[..n], e).unwrap();
            prop_assert_eq!(d.view.transact_time().unwrap(), transact_time);
            prop_assert_eq!(d.view.security_id().unwrap(), security_id);

            // Repeating group — per-entry bounds-checked, total.
            let group = d.view.md_entries().unwrap();
            prop_assert_eq!(group.remaining(), n_entries);
            let walked: Vec<_> = d.view.md_entries().unwrap().collect::<Result<Vec<_>, _>>().unwrap();
            prop_assert_eq!(walked.len(), n_entries);
            for (i, entry) in walked.iter().enumerate() {
                let (a, t, p, s, o) = &entries[i];
                prop_assert_eq!(entry.update_action().unwrap(), *a);
                prop_assert_eq!(entry.entry_type().unwrap(), *t);
                prop_assert_eq!(entry.price().unwrap(), *p);
                prop_assert_eq!(entry.size().unwrap(), *s);
                prop_assert_eq!(entry.order_id().unwrap(), *o);
            }

            // Data field — raw bytes and UTF-8 gate.
            let df = d.view.text_field().unwrap();
            prop_assert_eq!(df.bytes(), &text[..]);
            match core::str::from_utf8(&text) {
                Ok(s) => prop_assert_eq!(df.as_str().unwrap(), s),
                Err(_) => prop_assert_eq!(df.as_str(), Err(WireError::InvalidUtf8)),
            }
        }
    }
}

/// REQ-WIRE-004 — endianness explicit per block: golden big- and
/// little-endian frames carry identical logical values, both decoded.
#[test]
fn endianness_explicit_per_block() {
    let entries = [
        (
            UpdateAction::New,
            MdEntryType::Bid,
            4_100_000i64,
            5u32,
            11u32,
        ),
        (UpdateAction::Delete, MdEntryType::Offer, 4_200_000, 7, 12),
    ];
    let mut le = [0u8; 512];
    let mut be = [0u8; 512];
    let n_le = encode_frame(&mut le, Endianness::Little, 9_999, -7, &entries, b"ok");
    let n_be = encode_frame(&mut be, Endianness::Big, 9_999, -7, &entries, b"ok");
    assert_eq!(n_le, n_be);
    // Same logical content, different bytes — the byte order is real.
    assert_ne!(&le[..n_le], &be[..n_be]);
    // Cross-order decode: LE bytes read as BE are rejected at the header's
    // version gate (byte-swapped 0x0001 = 0x0100 > max) — proof the
    // endianness parameter is honored, not ignored.
    assert!(MdIncrementalRefresh::root(&le[..n_le], Endianness::Big).is_err());
    let right = MdIncrementalRefresh::root(&le[..n_le], Endianness::Little).unwrap();
    assert_eq!(right.view.transact_time().unwrap(), 9_999);

    for (buf, e) in [
        (&le[..n_le], Endianness::Little),
        (&be[..n_be], Endianness::Big),
    ] {
        let d = MdIncrementalRefresh::root(buf, e).unwrap();
        assert_eq!(d.view.transact_time().unwrap(), 9_999);
        assert_eq!(d.view.security_id().unwrap(), -7);
        let got: Vec<_> = d
            .view
            .md_entries()
            .unwrap()
            .map(|r| r.unwrap())
            .map(|m| {
                (
                    m.update_action().unwrap(),
                    m.entry_type().unwrap(),
                    m.price().unwrap(),
                    m.size().unwrap(),
                    m.order_id().unwrap(),
                )
            })
            .collect();
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0],
            (UpdateAction::New, MdEntryType::Bid, 4_100_000, 5, 11)
        );
        assert_eq!(
            got[1],
            (UpdateAction::Delete, MdEntryType::Offer, 4_200_000, 7, 12)
        );
    }

    // The header encode/decode pair agrees in both orders.
    let mut hdr = [0u8; HEADER_LEN];
    SbeHeader::encode(
        &mut hdr,
        wire_kit::sbe::Template::MdIncrementalRefresh,
        Endianness::Big,
    )
    .unwrap();
    let d = SbeHeader::decode(&hdr, Endianness::Big).unwrap();
    assert_eq!(d.view.endianness, Endianness::Big);
}

/// REQ-WIRE-003 — exhaustive truncation sweep: every prefix of a valid frame
/// yields Ok or a typed error, never a panic, in both byte orders.
#[test]
fn truncation_sweep_is_total() {
    let entries = [(
        UpdateAction::Change,
        MdEntryType::Offer,
        -1,
        u32::MAX,
        u32::MAX,
    )];
    let mut out = [0u8; 512];
    for e in [Endianness::Little, Endianness::Big] {
        let n = encode_frame(
            &mut out,
            e,
            u64::MAX,
            i64::MIN,
            &entries,
            &[0x80, 0xC3, 0x28],
        );
        for len in 0..n {
            let (slice, _) = out.split_at(len);
            let _ = MdIncrementalRefresh::root(slice, e);
            let _ = SbeHeader::decode(slice, e);
        }
    }
}

/// REQ-WIRE-003 — the dimension block itself truncated/malformed.
#[test]
fn malformed_dimensions_are_typed() {
    let entries = [(UpdateAction::New, MdEntryType::Bid, 1, 1, 1)];
    let mut out = [0u8; 512];
    let n = encode_frame(&mut out, Endianness::Little, 1, 2, &entries, b"");
    // Dimension count region truncated (no 4-byte dimension).
    let (cut, _) = out.split_at(24 + 2);
    let d = MdIncrementalRefresh::root(cut, Endianness::Little).unwrap();
    assert!(matches!(
        d.view.md_entries(),
        Err(WireError::InsufficientBytes { .. })
    ));
    // Valid frame still decodes with an empty text field.
    let d = MdIncrementalRefresh::root(&out[..n], Endianness::Little).unwrap();
    assert!(d.view.text_field().unwrap().is_empty());
}

/// The generator and the encoder agree — corpus frames decode through the
/// typed root (see also tests/corpus.rs for the golden diff).
#[test]
fn generated_frames_decode() {
    let mut scratch = [0u8; 256];
    let mut rng = Lcg64::new(CORPUS_SEED);
    let (n, expected) = generate_md_frame(&mut scratch, &mut rng, Endianness::Little).unwrap();
    let d = MdIncrementalRefresh::root(&scratch[..n], Endianness::Little).unwrap();
    assert_eq!(d.view.md_entries().unwrap().count(), expected.entry_count);
    assert_eq!(d.view.transact_time().unwrap(), expected.transact_time);
}

/// Entry views are portable through the trait object shape (GroupBlock).
#[test]
fn group_block_view_matches_iterator() {
    let entries = [(UpdateAction::Change, MdEntryType::Bid, 42, 1, 2)];
    let mut out = [0u8; 512];
    let n = encode_frame(&mut out, Endianness::Little, 5, 6, &entries, b"x");
    let _d = MdIncrementalRefresh::root(&out[..n], Endianness::Little).unwrap();
    let dim_off = HEADER_LEN + 16;
    let first = MdEntry::view(&out[..n], dim_off + 4, Endianness::Little).unwrap();
    assert_eq!(first.price().unwrap(), 42);
    assert_eq!(MdEntry::BLOCK_LEN, ENTRY_BLOCK_LEN);
    // Off-block view is a typed error.
    assert!(matches!(
        MdEntry::view(&out[..n], n, Endianness::Little),
        Err(WireError::InsufficientBytes { .. })
    ));
}

/// Version policy: `version > MAX` rejected at the header; equal accepted.
#[test]
fn schema_version_gate() {
    let mut out = [0u8; 512];
    let n = encode_frame(&mut out, Endianness::Little, 1, 1, &[], b"");
    let mut v = out;
    v[6] = (MAX_SCHEMA_VERSION + 1) as u8;
    v[7] = 0;
    assert_eq!(
        SbeHeader::decode(&v[..n], Endianness::Little),
        Err(WireError::UnsupportedSchemaVersion {
            schema_id: SCHEMA_ID,
            got: MAX_SCHEMA_VERSION + 1,
            max: MAX_SCHEMA_VERSION
        })
    );
    let mut v = out;
    v[6] = MAX_SCHEMA_VERSION as u8;
    v[7] = 0;
    assert!(SbeHeader::decode(&v[..n], Endianness::Little).is_ok());
}
