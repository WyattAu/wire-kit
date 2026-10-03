//! Criterion bench — SOH delimiter scanning: scalar SWAR oracle vs the
//! dispatched SIMD path (REQ-WIRE-006; FIX `find_soh` scalar vs simd GB/s is
//! a Tier A gate line).
//!
//! Methodology: the buffer is perturbed once per iteration (a rotating
//! position is rewritten) so the scan cannot be hoisted out of the bench
//! loop — a constant input lets LLVM sink the whole search into constants.

// Bench harness: assertion/unwrap ergonomics allowed; measured code is lib
// code, which remains lint-clean.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, missing_docs)] // criterion_group emits undocumented items

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wire_kit::scan::{find_soh, find_soh_reference};

/// FIX-shaped traffic: alternating printable fields and SOH delimiters.
fn fix_like(len: usize) -> Vec<u8> {
    let field = b"268=9";
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        v.extend_from_slice(field);
        v.push(0x01);
    }
    v.truncate(len);
    v
}

fn bench_find_soh(c: &mut Criterion) {
    let mut g = c.benchmark_group("scan_soh");
    for len in [64usize, 4096, 65_536] {
        let mut buf = fix_like(len);
        let mut flip = 0usize;
        g.throughput(criterion::Throughput::Bytes(buf.len() as u64));
        g.bench_function(format!("scalar_swar/{len}"), |b| {
            b.iter(|| {
                // Perturb one byte per iteration: never a SOH, position
                // rotates — the input changes, the search cannot hoist.
                buf[flip] = b'A' + (flip % 26) as u8;
                flip = (flip + 7) % buf.len();
                black_box(find_soh(black_box(&buf)))
            })
        });
        g.bench_function(format!("byte_loop/{len}"), |b| {
            b.iter(|| {
                buf[flip] = b'A' + (flip % 26) as u8;
                flip = (flip + 7) % buf.len();
                black_box(find_soh_reference(black_box(&buf)))
            })
        });
        #[cfg(feature = "simd")]
        g.bench_function(format!("simd_dispatch/{len}"), |b| {
            b.iter(|| {
                buf[flip] = b'A' + (flip % 26) as u8;
                flip = (flip + 7) % buf.len();
                black_box(wire_kit::scan::find_soh_simd(black_box(&buf)))
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench_find_soh);
criterion_main!(benches);
