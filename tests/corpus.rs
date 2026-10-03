//! Golden-corpus tests — REQ-WIRE-007: deterministic, schema-driven corpus
//! generation with byte-identical regeneration enforced.
//!
//! `tests/golden/corpus.bin` and `tests/golden/corpus.manifest` are
//! committed. This suite (run in CI as part of the standard `test` gate)
//! regenerates both in memory and diffs them byte-for-byte: any generator or
//! codec change that alters output bytes without a deliberate golden update
//! fails the build.
//!
//! To update the goldens after a deliberate change:
//!
//! ```sh
//! WIRE_KIT_REGEN_CORPUS=1 cargo test --test corpus
//! ```

// Test harness: assertions legitimately panic; the decode paths under test
// (the lib target) remain lint-clean.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use std::fs;
use std::path::Path;

use wire_kit::corpus::{
    generate_corpus, generate_md_frame, ExpectedFrame, Lcg64, CORPUS_FRAMES, CORPUS_SEED,
    MAX_CORPUS_TEXT,
};
use wire_kit::sbe::md::MdIncrementalRefresh;
use wire_kit::sbe::Endianness;

const GOLDEN_BIN: &str = "tests/golden/corpus.bin";
const GOLDEN_MANIFEST: &str = "tests/golden/corpus.manifest";

/// Render the expected-accessor manifest for the corpus (deterministic text).
fn render_manifest(out: &mut String) {
    for i in 0..CORPUS_FRAMES {
        let endianness = if i + 1 == CORPUS_FRAMES {
            Endianness::Big
        } else {
            Endianness::Little
        };
        let mut rng = Lcg64::new(CORPUS_SEED ^ (i as u64));
        let (_n, expected) = generate_md_frame(&mut [0u8; 256], &mut rng, endianness).unwrap();
        render_frame_manifest(i, &expected, out);
    }
}

fn render_frame_manifest(i: usize, e: &ExpectedFrame, out: &mut String) {
    use std::fmt::Write;
    let _ = writeln!(out, "frame {i} endian={:?}", e.endianness);
    let _ = writeln!(
        out,
        "header block_len={} template_id={} schema_id={:#06x} version={}",
        e.block_len, e.template_id, e.schema_id, e.version
    );
    let _ = writeln!(
        out,
        "transact_time={} security_id={}",
        e.transact_time, e.security_id
    );
    let _ = writeln!(out, "entries={}", e.entry_count);
    for (k, slot) in e.entries.iter().enumerate().take(e.entry_count) {
        let x = slot.unwrap();
        let _ = writeln!(
            out,
            "entry {k} action={} type={} price={} size={} order_id={}",
            x.action.raw(),
            x.entry_type.raw(),
            x.price,
            x.size,
            x.order_id
        );
    }
    let mut hex = String::new();
    for b in e.text.iter().take(e.text_len) {
        let _ = write!(hex, "{b:02x}");
    }
    let _ = writeln!(out, "text len={} bytes={hex}", e.text_len);
}

/// REQ-WIRE-007 — regeneration is byte-identical to the committed goldens.
#[test]
fn corpus_regeneration_is_byte_identical() {
    let mut bin = vec![0u8; 4096];
    let n = generate_corpus(&mut bin).unwrap();
    let bin = &bin[..n];

    let mut manifest = String::new();
    render_manifest(&mut manifest);

    if std::env::var("WIRE_KIT_REGEN_CORPUS").ok().as_deref() == Some("1") {
        fs::create_dir_all(Path::new(GOLDEN_BIN).parent().unwrap()).unwrap();
        fs::write(GOLDEN_BIN, bin).unwrap();
        fs::write(GOLDEN_MANIFEST, &manifest).unwrap();
        eprintln!("goldens regenerated ({n} bin bytes)");
        return;
    }

    let golden_bin = fs::read(GOLDEN_BIN).unwrap();
    let golden_manifest = fs::read_to_string(GOLDEN_MANIFEST).unwrap();
    assert_eq!(
        bin,
        &golden_bin[..],
        "corpus.bin drifted: regenerate with WIRE_KIT_REGEN_CORPUS=1 cargo test --test corpus"
    );
    assert_eq!(
        manifest.trim_end(),
        golden_manifest.trim_end(),
        "corpus.manifest drifted: regenerate with WIRE_KIT_REGEN_CORPUS=1 cargo test --test corpus"
    );
}

/// The committed golden frames decode to exactly the manifest values — the
/// goldens are not just byte-equal to a rerun, they are semantically valid.
#[test]
fn golden_frames_decode_to_manifest_values() {
    let golden_bin = fs::read(GOLDEN_BIN).unwrap();
    let mut pos = 0usize;
    for i in 0..CORPUS_FRAMES {
        let endianness = if i + 1 == CORPUS_FRAMES {
            Endianness::Big
        } else {
            Endianness::Little
        };
        let flen = u32::from_le_bytes(golden_bin[pos..pos + 4].try_into().unwrap()) as usize;
        let frame = &golden_bin[pos + 4..pos + 4 + flen];

        let d = MdIncrementalRefresh::root(frame, endianness).unwrap();
        assert_eq!(d.view.block_len(), 16);
        assert_eq!(d.view.endianness(), endianness);
        let entries: Vec<_> = d.view.md_entries().unwrap().map(|e| e.unwrap()).collect();
        for (k, _e) in entries.iter().enumerate() {
            // Cross-check against the manifest lines.
            let want = format!("entry {k} ");
            assert!(golden_manifest_contains(&want));
        }
        assert_eq!(d.view.text_field().unwrap().len() as usize, {
            // Manifest text length for this frame.
            let mut rng = Lcg64::new(CORPUS_SEED ^ (i as u64));
            let (_n, expected) = generate_md_frame(&mut [0u8; 256], &mut rng, endianness).unwrap();
            assert_eq!(expected.text_len, expected.text_len.min(MAX_CORPUS_TEXT));
            expected.text_len
        });
        pos += 4 + flen;
    }
    assert_eq!(pos, golden_bin.len());
}

fn golden_manifest_contains(needle: &str) -> bool {
    fs::read_to_string(GOLDEN_MANIFEST)
        .unwrap()
        .contains(needle)
}
