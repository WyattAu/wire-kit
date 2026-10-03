//! Criterion bench — representative SBE market-data frame decode ns/op
//! (Tier A gate line: decode of a representative market-data frame).
//!
//! Methodology: 256 distinct generated frames are rotated per iteration so
//! the loads cannot be hoisted out of the bench loop — a single fixed frame
//! lets LLVM sink the whole decode into constants and report nonsense
//! sub-nanosecond times.

// Bench harness: assertion/unwrap ergonomics allowed; measured code is lib
// code, which remains lint-clean.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, missing_docs)] // criterion_group emits undocumented items

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wire_kit::corpus::{generate_md_frame, Lcg64, CORPUS_SEED};
use wire_kit::sbe::md::MdIncrementalRefresh;
use wire_kit::sbe::Endianness;

fn bench_sbe_decode(c: &mut Criterion) {
    // 256 distinct frames, each with a seeded entry count/fields.
    let frames: Vec<Vec<u8>> = (0..256u64)
        .map(|i| {
            let mut scratch = [0u8; 256];
            let mut rng = Lcg64::new(CORPUS_SEED ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let (n, _) = generate_md_frame(&mut scratch, &mut rng, Endianness::Little).unwrap();
            scratch[..n].to_vec()
        })
        .collect();
    let total: usize = frames.iter().map(|f| f.len()).sum();

    let mut g = c.benchmark_group("sbe_decode");
    g.throughput(criterion::Throughput::Bytes(total as u64 / 256));
    g.bench_function("md_incremental_refresh_root_walk", |b| {
        b.iter(|| {
            for frame in &frames {
                if let Ok(d) = MdIncrementalRefresh::root(black_box(frame), Endianness::Little) {
                    let _ = black_box(d.view.transact_time());
                    let _ = black_box(d.view.security_id());
                    if let Ok(entries) = d.view.md_entries() {
                        for e in entries.flatten() {
                            let _ = black_box(e.update_action());
                            let _ = black_box(e.entry_type());
                            let _ = black_box(e.price());
                            let _ = black_box(e.size());
                            let _ = black_box(e.order_id());
                        }
                    }
                    let _ = black_box(d.view.text_field());
                }
            }
        })
    });
    g.finish();
}

criterion_group!(benches, bench_sbe_decode);
criterion_main!(benches);
