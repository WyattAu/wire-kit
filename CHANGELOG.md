# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning:
[SemVer](https://semver.org/).

## [0.1.0] — 2026-10-03

Initial release. Implements `specs/wire-kit.md` (REQ-WIRE-001…007) — L1
substrate, zero estate deps, zero runtime deps.

### Added

- **SBE** ([REQ-WIRE-001], [REQ-WIRE-005]): fixed-width message header decode
  (`SbeHeader::decode` → `Decoded<HeaderView>`), lifetime-bound typed accessor
  block `MdIncrementalRefresh`/`MdEntry` (reference market-data message set,
  hand-rolled per spec decision 1), total `GroupIter` over `GroupBlock`
  entries, varData `DataField`, and a bounds-checked `Encoder`/`GroupWriter`
  over `&mut [u8]`.
- **FIX 4.4** ([REQ-WIRE-002]): `FixMessage::parse` (canonical
  `8`/`9`/`35` framing, tag-10 position and checksum verify), zero-copy
  `field`/`field_str`/`iter`, declared single-level repeating groups
  (`group`/`FixGroup`/`FixEntry`), `FixMsgType` dispatch, `fix_checksum`,
  and the zero-alloc `FixBuilder`.
- **Typed errors** ([REQ-WIRE-003]): exhaustive `WireError`
  (`InsufficientBytes`, `InvalidTag`, `BadChecksum`, `InvalidEnum`,
  `InvalidGroupCount`, `UnsupportedSchemaVersion`, `InvalidUtf8`,
  `UnknownMessageType`). Decoders are total — no panics, no OOB reads;
  deny-level panics/indexing/unwrap lints on the lib target; one cargo-fuzz
  target per decoder (`sbe_decode`, `fix_parse`, `find_soh`).
- **Endianness** ([REQ-WIRE-004]): explicit per message block
  (`Endianness` parameter on every generic entry point; carried on views);
  `from_le_bytes`/`from_be_bytes` only — byteorder-free.
- **SIMD scanning** ([REQ-WIRE-006]): feature-gated `core::arch` fast paths
  (SSE2/AVX2 on x86_64, NEON on aarch64) with the always-compiled SWAR oracle
  `find_soh` (+ `find_soh_reference` byte loop); runtime dispatch under `std`
  per spec decision 3; differential property tests in both feature states.
- **Corpus** ([REQ-WIRE-007]): deterministic seeded generation from the
  reference schema (LCG, no `rand`); committed goldens with a byte-identical
  regen-diff test in the standard gate.
- Gates: miri over encode/decode suites; coverage ≥ 90% per-config; thumbv7em
  `no_std` gate; fuzz smokes (30 s/target) in CI per fleet §4; criterion
  benches for the scan scalar-vs-simd line and SBE decode ns/op.

### Documented decisions (spec §Decisions)

1. **v1 message-set scope**: generic primitives + hand-written reference
   accessor block (`MdIncrementalRefresh`); no schema codegen.
2. **Nested FIX groups**: rejected with `InvalidGroupCount` until spec'd;
   single-level declared groups only.
3. **SIMD selection**: runtime dispatch under `std`; `no_std` builds use the
   scalar path or compile-time baseline SIMD (SSE2/NEON), documented.
4. **wasm**: no claim in v1 (no wasm gate).
5. **Error taxonomy**: single crate-level `WireError` (exhaustive).

[REQ-WIRE-001]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-002]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-003]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-004]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-005]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-006]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
[REQ-WIRE-007]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
