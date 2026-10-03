//! SOH (`0x01`) delimiter scanning — scalar/SWAR reference plus `core::arch`
//! fast paths.
//!
//! [REQ-WIRE-006] — field scanning uses `core::arch` intrinsics where the
//! target provides them (behind the `simd` feature), with a scalar/SWAR
//! reference that is **always compiled** in every feature state and serves as
//! the differential oracle ([`find_soh`] / [`find_soh_reference`]). Both paths
//! are pinned to identical results by `simd_scan_matches_scalar_oracle`
//! (`tests/properties.rs`), which runs under `--features simd` *and*
//! `--no-default-features`.
//!
//! # Dispatch model (spec decision 3 — runtime detection under `std`)
//!
//! | Build | `find_soh_simd` behavior |
//! |---|---|
//! | `simd` + `std`, x86_64 | runtime-detected AVX2 → SSE2 (baseline) |
//! | `simd`, no `std`, x86_64 | SSE2 only (baseline, no detection needed) |
//! | `simd`, aarch64 | NEON (baseline on aarch64, no detection) |
//! | `simd`, other arches | scalar fallback (identical to the oracle) |
//! | no `simd` | n/a — [`find_soh`] is the only entry point |
//!
//! AVX2 without `std` would require compile-time `target-feature` selection,
//! which v1 does not do — the scalar/SSE2 paths keep `no_std` builds honest.
//!
//! [REQ-WIRE-006]: crate::req::WIRE_006

/// The FIX field separator.
pub(crate) const SOH: u8 = 0x01;

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGH: u64 = 0x8080_8080_8080_8080;
/// SOH replicated into every u64 lane (`SOH8 == ONES`, kept as a named alias
/// for the lane semantics below).
const SOH8: u64 = ONES;

/// Nonzero in every lane whose byte equals SOH. Classic `haszero` applied to
/// `word ^ SOH8`: a lane of `x = word ^ SOH8` is zero iff the original byte
/// is SOH; the borrow-based zero detector is exact for all byte values.
fn soh_lane_mask(word: u64) -> u64 {
    let x = word ^ SOH8;
    x.wrapping_sub(ONES) & !x & HIGH
}

/// Scalar/SWAR reference SOH scanner — the always-compiled oracle.
///
/// Eight bytes per step inside a `u64` (SWAR), byte loop for the tail.
/// Identical results to [`find_soh_reference`] and — under feature `simd` —
/// to `find_soh_simd`, on every input.
///
/// [REQ-WIRE-006]: crate::req::WIRE_006
pub fn find_soh(buf: &[u8]) -> Option<usize> {
    let mut chunk_off = 0usize;
    let mut chunks = buf.chunks_exact(8);
    for chunk in chunks.by_ref() {
        // chunks_exact(8) yields exactly-8-byte slices, so the conversion
        // cannot fail; `unwrap_or` (no `unwrap`) keeps the no-panic lint
        // contract and folds to a single load in codegen.
        let word = u64::from_le_bytes(chunk.try_into().unwrap_or([0u8; 8]));
        let m = soh_lane_mask(word);
        if m != 0 {
            let lane = (m.trailing_zeros() >> 3) as usize;
            return Some(chunk_off + lane);
        }
        chunk_off += 8;
    }
    find_soh_reference(chunks.remainder()).map(|i| chunk_off + i)
}

/// Plain byte-at-a-time reference scanner — the second oracle for the
/// differential property tests (SWAR vs byte-loop vs SIMD, three ways).
pub fn find_soh_reference(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|b| *b == SOH)
}

/// `core::arch` fast path — only available behind feature `simd`.
///
/// Runtime-dispatched where detection is possible (see the module-level
/// [dispatch model]); results are pinned identical to [`find_soh`] on every
/// input by the differential property tests.
///
/// [REQ-WIRE-006]: crate::req::WIRE_006
#[cfg(feature = "simd")]
pub fn find_soh_simd(buf: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    let scanned = x86::find(buf);
    #[cfg(target_arch = "aarch64")]
    let scanned = neon::find(buf);
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let scanned = find_soh(buf); // portable fallback: identical to the oracle
    scanned
}

/// The scanner the FIX parser uses: the SIMD path when the feature is on,
/// the SWAR oracle otherwise. `pub(crate)` — the public scanning surface is
/// `find_soh` / `find_soh_simd`, per the API sketch.
pub(crate) fn scan_soh(buf: &[u8]) -> Option<usize> {
    #[cfg(feature = "simd")]
    {
        find_soh_simd(buf)
    }
    #[cfg(not(feature = "simd"))]
    {
        find_soh(buf)
    }
}

/// x86_64 fast path. The only `unsafe` in the crate lives here; every block
/// is documented and bounded by a `get()`-proven chunk length.
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
mod x86 {
    #![allow(unsafe_code)]

    use core::arch::x86_64::{
        _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8, _mm256_set1_epi8,
        _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_set1_epi8,
    };

    /// AVX2 (32 lanes) → SSE2 (16 lanes) → scalar tail. AVX2 is selected by
    /// runtime detection under `std`; SSE2 is baseline on x86_64 and needs no
    /// detection in any build.
    pub fn find(buf: &[u8]) -> Option<usize> {
        #[cfg(feature = "std")]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                return find_lanes::<32>(buf);
            }
        }
        find_lanes::<16>(buf)
    }

    fn find_lanes<const N: usize>(buf: &[u8]) -> Option<usize> {
        let mut off = 0usize;
        while let Some(chunk) = buf.get(off..off + N) {
            if let Some(i) = scan_chunk::<N>(chunk) {
                return Some(off + i);
            }
            off += N;
        }
        super::find_soh(buf.get(off..).unwrap_or(&[])).map(|i| off + i)
    }

    fn scan_chunk<const N: usize>(chunk: &[u8]) -> Option<usize> {
        // SAFETY: SSE2 is baseline on x86_64; AVX2 support was checked by
        // `find` before selecting N = 32. `chunk` is exactly N in-bounds
        // bytes, and `_mm*_loadu_*` performs an unaligned load of exactly
        // those bytes.
        unsafe {
            if N == 32 {
                let v = _mm256_loadu_si256(chunk.as_ptr().cast());
                let m =
                    _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, _mm256_set1_epi8(SOH as i8))) as u32;
                if m != 0 {
                    return Some(m.trailing_zeros() as usize);
                }
            } else {
                let v = _mm_loadu_si128(chunk.as_ptr().cast());
                let m = _mm_movemask_epi8(_mm_cmpeq_epi8(v, _mm_set1_epi8(SOH as i8))) as u32;
                if m != 0 {
                    return Some(m.trailing_zeros() as usize);
                }
            }
        }
        None
    }

    const SOH: u8 = super::SOH;
}

/// aarch64 fast path — NEON is baseline, so no feature attribute and no
/// detection are needed.
#[cfg(all(feature = "simd", target_arch = "aarch64"))]
mod neon {
    use core::arch::aarch64::{vceqq_u8, vdupq_n_u8, vld1q_u8, vmaxvq_u8};

    const LANES: usize = 16;

    pub fn find(buf: &[u8]) -> Option<usize> {
        let mut off = 0usize;
        while let Some(chunk) = buf.get(off..off + LANES) {
            // SAFETY: `chunk` is exactly 16 bytes; `vld1q_u8` is an unaligned
            // 16-byte load, fully in-bounds here.
            let v = unsafe { vld1q_u8(chunk.as_ptr()) };
            let m = vceqq_u8(v, vdupq_n_u8(super::SOH));
            if vmaxvq_u8(m) != 0 {
                // Hit: resolve the lane by rescanning this chunk with the
                // scalar oracle — bounded to 16 bytes, identical result.
                return super::find_soh(chunk).map(|i| off + i);
            }
            off += LANES;
        }
        super::find_soh(buf.get(off..).unwrap_or(&[])).map(|i| off + i)
    }
}

#[cfg(test)]
mod tests {
    use super::{find_soh, find_soh_reference, SOH};

    #[test]
    fn swar_matches_byte_loop_on_systematic_shapes() {
        // REQ-WIRE-006 — scalar oracle agreement, dense sweep.
        let buf = [0u8; 48];
        for pos in 0..buf.len() {
            for start in 0..buf.len() {
                let mut shifted = [0u8; 48];
                let n = shifted.len();
                for (i, b) in buf.iter().enumerate() {
                    if let Some(slot) = shifted.get_mut((i + start) % n) {
                        *slot = *b;
                    }
                }
                if let Some(slot) = shifted.get_mut(pos) {
                    *slot = SOH;
                }
                assert_eq!(
                    find_soh(&shifted),
                    find_soh_reference(&shifted),
                    "divergence at pos {pos} start {start}"
                );
            }
        }
    }

    #[test]
    fn edges() {
        for empty in [&[][..], &[SOH][..], &[0u8, SOH][..]] {
            assert_eq!(find_soh(empty), find_soh_reference(empty));
        }
        let long = [0u8; 1024];
        assert_eq!(find_soh(&long), None);
        let mut tail = [0u8; 1025];
        tail[1024] = SOH;
        assert_eq!(find_soh(&tail), Some(1024));
        assert_eq!(find_soh_reference(&tail), Some(1024));
    }
}
