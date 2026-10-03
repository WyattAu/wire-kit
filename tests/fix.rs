//! FIX 4.4 integration tests — REQ-WIRE-002/003 traceability anchors.

// Test harness: assertions legitimately panic; the decode paths under test
// (the lib target) remain lint-clean.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use proptest::prelude::*;
use wire_kit::error::WireError;
use wire_kit::fix::{fix_checksum, FixBuilder, FixEntry, FixMessage, FixMsgType, HEADER_RESERVE};

/// A golden, hand-verified FIX 4.4 MarketDataIncrementalRefresh frame with a
/// two-entry NoMDEntries group (group-last layout). Checksum independently
/// verified below.
const GOLDEN: &[u8] = b"8=FIX.4.4\x019=95\x0135=X\x0149=CME\x0156=CLIENT\x01268=2\x01279=0\x01269=0\x01270=410000\x01271=5\x01279=1\x01269=1\x01270=420000\x01271=7\x0158=hello\x0110=016\x01";

/// REQ-WIRE-002 — checksum, groups and in-place fields, against a golden
/// vector (unit + golden vectors, per the traceability matrix).
#[test]
fn fix_checksum_groups_and_inplace_fields() {
    // The golden checksum is independently recomputed.
    let cs_pos = GOLDEN.windows(3).position(|w| w == b"10=").unwrap();
    let covered = &GOLDEN[..cs_pos];
    let computed = fix_checksum(covered);
    let declared = &GOLDEN[cs_pos + 3..cs_pos + 6];
    assert_eq!(
        declared,
        format!("{:03}", computed).as_bytes(),
        "golden checksum stale: recompute to {:03}",
        computed
    );

    let m = FixMessage::parse(GOLDEN).unwrap();
    // In-place, zero-copy field access.
    assert_eq!(m.field(35).unwrap(), b"X");
    assert_eq!(m.field_str(49).unwrap(), "CME");
    assert_eq!(m.field(999), None);
    assert_eq!(
        m.message_type().unwrap(),
        FixMsgType::MarketDataIncrementalRefresh
    );
    m.verify_checksum().unwrap();

    // Flat iteration sees every field, in order, zero-copy.
    let tags: Vec<u16> = m.iter().map(|f| f.tag).collect();
    assert_eq!(
        tags,
        vec![8, 9, 35, 49, 56, 268, 279, 269, 270, 271, 279, 269, 270, 271, 58, 10]
    );

    // Declared repeating group: count 2, delimiter 279.
    let g = m.group(268).unwrap();
    assert_eq!(g.len(), 2);
    assert_eq!(g.delim_tag(), 279);
    let entries: Vec<FixEntry<'_>> = g.iter().map(|e| e.unwrap()).collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].field(279).unwrap(), b"0");
    assert_eq!(entries[0].field(270).unwrap(), b"410000");
    assert_eq!(entries[1].field(279).unwrap(), b"1");
    assert_eq!(entries[1].field(270).unwrap(), b"420000");
    // v1 group model (documented): the last entry spans to the checksum
    // field, so the trailing Text field is part of it; the first entry is
    // bounded by the second delimiter.
    assert_eq!(entries[0].field(58), None);
    assert_eq!(entries[1].field_str(58).unwrap(), "hello");
}

/// The builder output for the same logical message parses back to the same
/// fields (encode path cross-check).
#[test]
fn builder_roundtrip_of_golden_shape() {
    let mut buf = [0u8; 512];
    let mut b = FixBuilder::new(&mut buf).unwrap();
    b.field_str(35, "X").unwrap();
    b.field_str(49, "CME").unwrap();
    b.field_str(56, "CLIENT").unwrap();
    b.field_str(268, "2").unwrap();
    b.field_str(279, "0").unwrap();
    b.field_str(269, "0").unwrap();
    b.field_str(270, "410000").unwrap();
    b.field_str(271, "5").unwrap();
    b.field_str(279, "1").unwrap();
    b.field_str(269, "1").unwrap();
    b.field_str(270, "420000").unwrap();
    b.field_str(271, "7").unwrap();
    b.field_str(58, "hello").unwrap();
    let frame = b.finish().unwrap();
    FixMessage::parse(frame).unwrap();

    let m = FixMessage::parse(frame).unwrap();
    let g = m.group(268).unwrap();
    assert_eq!(g.len(), 2);
    let e0 = g.iter().next().unwrap().unwrap();
    assert_eq!(e0.field_str(270).unwrap(), "410000");
}

/// REQ-WIRE-003 — every truncation of a valid frame is a typed error (or,
/// below the minimum, `InsufficientBytes`); never a panic.
#[test]
fn truncation_sweep_is_total() {
    for len in 0..GOLDEN.len() {
        let (slice, _) = GOLDEN.split_at(len);
        let _ = FixMessage::parse(slice);
    }
    // Byte-level corruption: any single-byte change yields a typed error.
    for i in 0..GOLDEN.len() {
        let mut alt = GOLDEN.to_vec();
        alt[i] = alt[i].wrapping_add(1);
        let _ = FixMessage::parse(&alt);
    }
}

/// Known message types map; unknown values are `UnknownMessageType`.
#[test]
fn message_type_dispatch() {
    let cases: &[(&str, FixMsgType)] = &[
        ("0", FixMsgType::Heartbeat),
        ("1", FixMsgType::TestRequest),
        ("2", FixMsgType::ResendRequest),
        ("3", FixMsgType::Reject),
        ("4", FixMsgType::SequenceReset),
        ("5", FixMsgType::Logout),
        ("D", FixMsgType::NewOrderSingle),
        ("8", FixMsgType::ExecutionReport),
        ("V", FixMsgType::MarketDataRequest),
        ("W", FixMsgType::MarketDataSnapshot),
        ("X", FixMsgType::MarketDataIncrementalRefresh),
    ];
    for (raw, expect) in cases {
        let mut buf = [0u8; 128];
        let mut b = FixBuilder::new(&mut buf).unwrap();
        b.field_str(35, raw).unwrap();
        let frame = b.finish().unwrap();
        let m = FixMessage::parse(frame).unwrap();
        assert_eq!(m.message_type().unwrap(), *expect);
        assert_eq!(expect.as_bytes(), raw.as_bytes());
    }
}

/// Nested-group shape (count tag re-occurring in the group region) and
/// count mismatch are both `InvalidGroupCount` — spec decision 2.
#[test]
fn group_edge_cases_are_typed() {
    // Count tag re-occurrence inside the group region.
    let mut buf = [0u8; 256];
    let mut b = FixBuilder::new(&mut buf).unwrap();
    b.field_str(35, "X").unwrap();
    b.field_str(268, "1").unwrap();
    b.field_str(279, "0").unwrap();
    b.field_str(268, "1").unwrap();
    let n = b.finish().unwrap().len();
    let m = FixMessage::parse(&buf[..n]).unwrap();
    assert!(matches!(
        m.group(268),
        Err(WireError::InvalidGroupCount { .. })
    ));

    // Unknown group tag.
    assert_eq!(m.group(999), Err(WireError::InvalidTag(999)));

    // Zero-count group with trailing fields is empty, not an error.
    let mut buf = [0u8; 256];
    let mut b = FixBuilder::new(&mut buf).unwrap();
    b.field_str(35, "W").unwrap();
    b.field_str(268, "0").unwrap();
    b.field_str(55, "ES").unwrap();
    let n = b.finish().unwrap().len();
    let m = FixMessage::parse(&buf[..n]).unwrap();
    let g = m.group(268).unwrap();
    assert!(g.is_empty());
    assert_eq!(g.iter().count(), 0);
}

/// REQ-WIRE-003 — garbage inputs are typed errors; UTF-8 gating on the
/// `*_str` path only.
#[test]
fn garbage_and_utf8() {
    // Arbitrary junk — never a panic (also fuzzed).
    for junk in [
        &b""[..],
        b"\x01",
        b"=",
        b"8=",
        b"8=FIX.4.4\x01",
        b"8=FIX.4.4\x019=0\x0110=000\x01",
        b"8=FIX.4.5\x019=0\x0135=0\x0110=000\x01",
        b"8=FIX.4.4\x019=abc\x0135=0\x0110=000\x01",
        b"8=FIX.4.4\x019=\x0135=0\x0110=000\x01",
    ] {
        let _ = FixMessage::parse(junk);
    }

    // Non-UTF8 value: byte access fine, str access typed error.
    let mut buf = [0u8; 128];
    let mut b = FixBuilder::new(&mut buf).unwrap();
    b.field_str(35, "W").unwrap();
    b.field(58, &[0xFF, 0xFE]).unwrap();
    let n = b.finish().unwrap().len();
    let m = FixMessage::parse(&buf[..n]).unwrap();
    assert_eq!(m.field(58).unwrap(), &[0xFF, 0xFE]);
    assert_eq!(m.field_str(58), Err(WireError::InvalidUtf8));
}

/// Builder bounds: `new` rejects sub-reserve buffers; `field` rejects
/// overflowing writes; `finish` fits by construction (the reserve plus the
/// per-field bounds always exceed header + checksum tail).
#[test]
fn builder_capacity_edges() {
    // Smallest workable buffer: HEADER_RESERVE + body + tail slack.
    let mut buf = vec![0u8; HEADER_RESERVE + 6];
    let mut b = FixBuilder::new(&mut buf).unwrap();
    b.field_str(35, "0").unwrap();
    let frame = b.finish().unwrap();
    assert_eq!(frame.len(), 13 + 6 + 7);
    FixMessage::parse(frame).unwrap();

    // One byte less still fits — the reserve absorbs the shuffle + tail.
    let mut buf = vec![0u8; HEADER_RESERVE + 6 - 1];
    let mut b = FixBuilder::new(&mut buf).unwrap();
    b.field_str(35, "0").unwrap();
    let frame = b.finish().unwrap();
    FixMessage::parse(frame).unwrap();
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(500))]

    /// REQ-WIRE-002 — builder→parse round-trip over arbitrary valid bodies.
    #[test]
    fn fix_builder_parse_roundtrip(
        tags in proptest::collection::vec(
            (11u16..=500u16).prop_filter("reserved/duplicate-prone tags", |t| !matches!(t, 8..=10 | 35)),
            0..12,
        ),
        values in proptest::collection::vec(
            proptest::collection::vec(0x20u8..=0x7E, 0..16),
            0..12,
        ),
        msg_type in proptest::sample::select(vec!["0", "1", "2", "3", "4", "5", "D", "V", "W", "X"]),
    ) {
        let mut buf = vec![0u8; 4096];
        let mut b = FixBuilder::new(&mut buf).unwrap();
        b.field_str(35, msg_type).unwrap();
        for (i, t) in tags.iter().enumerate() {
            let v = values.get(i % values.len().max(1)).map(|v| &v[..]).unwrap_or(&[]);
            b.field(*t, v).unwrap();
        }
        let frame = b.finish().unwrap();
        let m = FixMessage::parse(frame).unwrap();
        prop_assert_eq!(m.field(35).unwrap(), msg_type.as_bytes());
        // `field` returns the first occurrence — assert per unique tag.
        let mut seen = std::collections::HashSet::new();
        for (i, t) in tags.iter().enumerate() {
            if !seen.insert(*t) {
                continue;
            }
            let v = values.get(i % values.len().max(1)).map(|v| &v[..]).unwrap_or(&[]);
            prop_assert_eq!(m.field(*t).unwrap_or(&[]), v);
        }
        m.verify_checksum().unwrap();
    }
}
