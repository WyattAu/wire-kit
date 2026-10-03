# wire-kit

Zero-copy binary wire codecs — SBE block encoding/decoding and FIX 4.4
tag=value, bounds-checked, allocation-free decode.

**Layer:** L1 — substrate · **Estate deps:** zero (by mandate — edge-format
leaf) · **Runtime deps:** zero · `no_std`-capable (`core` only;
`std` feature only for runtime SIMD detection).

Implements [`specs/wire-kit.md`](https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md)
(REQ-WIRE-001…007). Hand-rolled codecs per the spec's flagged decision 1 —
no SBE schema codegen in v1; the schema layer is used for **test corpus
generation only** ([REQ-WIRE-007]).

## What's here

| Module | Contents |
|---|---|
| `sbe` | fixed-width message header (`SbeHeader`/`HeaderView`), typed accessor blocks over `&[u8]` (`MdIncrementalRefresh`, `MdEntry`), total repeating-group iteration (`GroupIter`/`GroupBlock`), varData fields (`DataField`), and a bounds-checked `Encoder`/`GroupWriter` over `&mut [u8]` |
| `fix` | `FixMessage::parse` (canonical 4.4 shape + tag-10 checksum), in-place `field`/`field_str`, declared single-level groups (`group`/`FixGroup`/`FixEntry`), flat `iter`, known-type dispatch (`FixMsgType`), and a zero-alloc `FixBuilder` |
| `scan` | SOH delimiter search: `find_soh` (SWAR oracle, always compiled), `find_soh_reference` (byte loop), `find_soh_simd` (feature `simd`; SSE2/AVX2/NEON via `core::arch`) |
| `corpus` | deterministic seeded corpus generation from the reference schema ([REQ-WIRE-007]; LCG only, no `rand`) |
| `error` | `WireError` — the single typed, exhaustive error ([REQ-WIRE-003]) |

## Guarantees

- **Total decoders** ([REQ-WIRE-003]): malformed, truncated, or hostile input
  yields a typed `WireError` — never a panic, never an out-of-bounds read.
  Enforced by deny-level lints (`unwrap_used`/`expect_used`/`panic`/
  `indexing_slicing`) on the lib target, a cargo-fuzz target per decoder, and
  miri over the encode/decode suites.
- **Zero-copy views** ([REQ-WIRE-005]): accessors are lifetime-bound to the
  input buffer; a view that outlives its bytes is a compile error (trybuild
  test `views_borrow_not_own`).
- **Explicit endianness per block** ([REQ-WIRE-004]): every generic SBE entry
  point takes an `Endianness` parameter; integer conversion is exclusively
  `from_le_bytes`/`from_be_bytes` (no `byteorder`).
- **SIMD with a scalar oracle** ([REQ-WIRE-006]): the scalar/SWAR reference is
  always compiled; differential property tests pin identical results in both
  feature states.

## Usage

```rust
use wire_kit::corpus::{generate_md_frame, Lcg64, CORPUS_SEED};
use wire_kit::sbe::md::MdIncrementalRefresh;
use wire_kit::sbe::Endianness;

// A deterministic market-data frame (also the corpus generator).
let mut out = [0u8; 256];
let (n, _expected) =
    generate_md_frame(&mut out, &mut Lcg64::new(CORPUS_SEED), Endianness::Little).unwrap();

// Decode in place: typed views, zero allocation, zero copying.
let decoded = MdIncrementalRefresh::root(&out[..n], Endianness::Little).unwrap();
assert_eq!(decoded.view.endianness(), Endianness::Little);
let _ts = decoded.view.transact_time().unwrap();
for entry in decoded.view.md_entries().unwrap().flatten() {
    let _ = entry.update_action().unwrap();
    let _ = entry.price().unwrap();
}
let text = decoded.view.text_field().unwrap();
assert_eq!(text.as_str().unwrap(), text.as_str().unwrap_or(""));
```

```rust
use wire_kit::fix::{FixBuilder, FixMessage, FixMsgType};

let mut buf = [0u8; 128];
let mut b = FixBuilder::new(&mut buf).unwrap();
b.field_str(35, "X").unwrap();          // MsgType
b.field_str(268, "2").unwrap();         // NoMDEntries
b.field_str(279, "0").unwrap();         // group entry 1 ...
b.field_str(279, "1").unwrap();         // group entry 2 ...
let frame = b.finish().unwrap();        // prepends 8=/9=, appends 10=<checksum>

let m = FixMessage::parse(frame).unwrap();
assert_eq!(m.message_type().unwrap(), FixMsgType::MarketDataIncrementalRefresh);
m.verify_checksum().unwrap();
let g = m.group(268).unwrap();
assert_eq!(g.len(), 2);
let _ = m.field(279).unwrap();          // in-place, zero-copy
```

## v1 message set & limitations (spec decisions 1–2)

- The reference accessor block is an `MDIncrementalRefresh`-shaped market-data
  frame (CME MDP3-inspired layout, documented in [`sbe::md`]); generic
  primitives (header/group/data-field/encoder) are message-agnostic. The SBE
  schema→Rust codegen is explicitly out of scope.
- FIX groups: **single-level, declared** groups only; the count tag must match
  the entries found and must not re-occur inside the group region — violations
  are the typed `InvalidGroupCount` error. The last entry spans to the
  checksum field (place groups last in the body). Nested groups are rejected
  until spec'd.
- The tag-10 checksum is a **transport-integrity check only** — sum-mod-256 is
  trivially weak and is never tamper protection (see SECURITY.md).

## SIMD dispatch (spec decision 3)

| Build | `find_soh_simd` |
|---|---|
| `simd` + `std`, x86_64 | runtime-detected AVX2 → SSE2 (baseline) |
| `simd`, no `std`, x86_64 | SSE2 only (baseline; no detection) |
| `simd`, aarch64 | NEON (baseline; no detection) |
| `simd`, other | scalar fallback (identical to the oracle) |
| no `simd` | `find_soh` (SWAR) only |

The scalar/SWAR oracle is always compiled and is the differential reference;
`simd_scan_matches_scalar_oracle` (500 cases) runs under `--features simd`
and `--no-default-features`.

## Measured performance (methodology + numbers)

Criterion suites: `benches/scan.rs` (FIX `find_soh` scalar vs simd) and
`benches/sbe_decode.rs` (representative market-data frame ns/op, root + full
accessor walk over rotating distinct frames so loads cannot be hoisted).

Hardware/date: Intel i9-11980HK (16 threads, perf scaling governed), Linux,
rustc 1.98.1, 2026-10-03. **Caveat:** captured on a shared development machine
under load (LA > 30 on 16 cores); treat absolute values as upper bounds — CI
records the comparable baseline.

| Bench | Result |
|---|---|
| `find_soh` SWAR vs byte loop, 64 B FIX-shaped | 22 ns vs 99 ns (≈4.5×) |
| `find_soh_simd` (runtime-dispatched AVX2), 64 B | 39 ns — runtime dispatch overhead dominates below ~1 KiB |
| SBE `MdIncrementalRefresh` root + full walk (132 B, 4 entries) | ≈364 ns/frame with every accessor bounds-checked (≈3640 ns for 10 frames in-bench) |

Zero-alloc claims are proven by construction (`no_std` core, no `alloc` in the
decode path) and by the `zero-alloc` property tests; hot-path allocation
profiling is not needed where no allocation API is reachable.

## Gates (Tier A)

Full estate matrix via
[`engineering-standards/.github/workflows/rust-kit.yml`](https://github.com/WyattAu/engineering-standards/blob/main/.github/workflows/rust-kit.yml)
(pinned SHA): pedantic clippy surface, `unwrap_used`/`indexing_slicing`/`panic`
denied, coverage ≥ 90% per-config (see `COVERAGE-NOTES.md`), cargo-deny,
cargo-vet, miri over encode/decode suites, thumbv7em `--no-default-features`
gate (`#![no_std]` claimed), fuzz smoke (30 s per target, fleet §4),
corpus regen-diff in the standard test gate. **Loom is n/a** — the crate has
no shared-memory concurrency primitives (no atomics, no locks); rationale
recorded here per the applicability split.

## License

Dual-licensed under MIT or Apache-2.0.

[REQ-WIRE-003]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-004]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-005]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-006]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-007]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
