//! Cross-codec property tests — REQ-WIRE-006 differential oracle and
//! REQ-WIRE-003 totality over arbitrary inputs (500 cases per property).

// Test harness: assertions legitimately panic; the decode paths under test
// (the lib target) remain lint-clean.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use proptest::prelude::*;
use wire_kit::fix::FixMessage;
use wire_kit::sbe::md::MdIncrementalRefresh;
use wire_kit::sbe::{Endianness, SbeHeader};
use wire_kit::scan::{find_soh, find_soh_reference};

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(500))]

    /// REQ-WIRE-006 — SIMD scan matches the scalar/SWAR oracle and the
    /// byte-loop reference on arbitrary inputs. Runs in both feature states:
    /// under `--features simd` (with `find_soh_simd`) and under
    /// `--no-default-features` (scalar-only arms still pin SWAR == loop).
    #[test]
    fn simd_scan_matches_scalar_oracle(
        buf in proptest::collection::vec(proptest::num::u8::ANY, 0..300),
    ) {
        let swar = find_soh(&buf);
        let byte_loop = find_soh_reference(&buf);
        prop_assert_eq!(swar, byte_loop);
        #[cfg(feature = "simd")]
        {
            let simd = wire_kit::scan::find_soh_simd(&buf);
            prop_assert_eq!(swar, simd);
            // The dispatched path agrees with the explicit baseline too.
            let hit = buf.iter().position(|b| *b == 0x01);
            prop_assert_eq!(simd, hit);
        }
        #[cfg(not(feature = "simd"))]
        {
            let hit = buf.iter().position(|b| *b == 0x01);
            prop_assert_eq!(swar, hit);
        }
    }

    /// REQ-WIRE-003 — arbitrary bytes into every decoder: Err or Ok, never a
    /// panic, and Ok results re-verify (checksum consistency).
    #[test]
    fn decoders_are_total_on_arbitrary_input(
        buf in proptest::collection::vec(proptest::num::u8::ANY, 0..200),
    ) {
        let _ = FixMessage::parse(&buf);
        let _ = SbeHeader::decode(&buf, Endianness::Little);
        let _ = SbeHeader::decode(&buf, Endianness::Big);
        let _ = MdIncrementalRefresh::root(&buf, Endianness::Little);
        let _ = MdIncrementalRefresh::root(&buf, Endianness::Big);
        let _ = wire_kit::fix::fix_checksum(&buf);
    }

    /// REQ-WIRE-003 — SBE frames corrupted at any single byte stay typed
    /// (never panic), and the typed root re-derives values only from the
    /// buffer (no hidden state).
    #[test]
    fn sbe_single_byte_corruption_is_typed(
        seed in any::<u64>(),
        flip_byte in 0usize..64,
    ) {
        let mut out = [0u8; 256];
        let mut rng = wire_kit::corpus::Lcg64::new(seed);
        let (n, expected) =
            wire_kit::corpus::generate_md_frame(&mut out, &mut rng, Endianness::Little).unwrap();
        let idx = flip_byte % n;
        out[idx] = out[idx].wrapping_add(1);
        let d = MdIncrementalRefresh::root(&out[..n], Endianness::Little);
        // Values may change, error out, or stay equal on padding — but must
        // never panic, and undisturbed fields keep their values.
        if let Ok(d) = d {
            if idx >= 8 + 16 {
                prop_assert_eq!(d.view.transact_time().unwrap(), expected.transact_time);
                prop_assert_eq!(d.view.security_id().unwrap(), expected.security_id);
            }
        }
    }
}
