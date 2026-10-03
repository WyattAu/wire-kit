# Requirements — wire-kit

Numbered, testable requirements, quoted from
[`specs/wire-kit.md`](https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md).
Every requirement maps to at least one named test; every security-relevant
test cites at least one requirement. Threat IDs reference `SECURITY.md`.

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WIRE-001 | SBE block encoding/decoding covers fixed-width message headers, repeating groups, and data fields, as hand-rolled reader/writer over `&[u8]` — decode produces lifetime-bound accessor structs over the buffer with zero allocation and zero copying | MUST |
| REQ-WIRE-002 | FIX 4.4 tag=value codec encodes and decodes messages, verifies/computes the tag-10 checksum, exposes declared repeating groups, and provides in-place (zero-copy) field access | MUST |
| REQ-WIRE-004 | Endianness is explicit per message block: SBE fields honor the block's declared byte order (big/little), FIX is ASCII; all integer conversion uses `from_le_bytes`/`from_be_bytes` (no byteorder dependency) | MUST |
| REQ-WIRE-005 | Zero-copy read accessors are lifetime-bound to the input buffer (`Decoder<'a>`/`*View<'a>`), making dangling or outliving views unrepresentable in safe code | MUST |
| REQ-WIRE-006 | With feature `simd`: field scanning uses `core::arch` intrinsics where available (per-arch `#[cfg]`), with a scalar/SWAR fallback that is always compiled and produces identical results | MUST |
| REQ-WIRE-007 | SBE test corpora are generated deterministically (seeded, no `rand`) from schema descriptions, with byte-identical regeneration enforced in CI | MUST |

## Robustness (security-relevant)

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-WIRE-003 | All decoding is bounds-checked and total: every malformed input yields a typed `WireError` (`InsufficientBytes`, `InvalidTag`, `BadChecksum`, `InvalidEnum`, …); no decoder panics, wraps, or reads out of bounds, and every decoder has a cargo-fuzz target | MUST |

## Traceability matrix

| Requirement | Test (fn, file) | Property class |
|-------------|-----------------|----------------|
| REQ-WIRE-001 | `sbe_roundtrip_header_group_datafield` (`tests/sbe.rs`, proptest 500) | property (proptest roundtrip) |
| REQ-WIRE-002 | `fix_checksum_groups_and_inplace_fields` (`tests/fix.rs`), `fix_builder_parse_roundtrip` (proptest 500) | unit + golden vectors |
| REQ-WIRE-003 | fuzz `sbe_decode` / `fix_parse` / `find_soh` (`fuzz/`, CI 30 s smokes); `truncation_sweep_is_total` (`tests/sbe.rs`, `tests/fix.rs`); `decoders_are_total_on_arbitrary_input` (`tests/properties.rs`) | fuzz + miri (alignment/UB) |
| REQ-WIRE-004 | `endianness_explicit_per_block` (`tests/sbe.rs` — golden BE and LE frames both decoded) | unit |
| REQ-WIRE-005 | `views_borrow_not_own` (`tests/compile_fail.rs`, trybuild `tests/ui/view_outlives_buffer.rs`) | compile + unit |
| REQ-WIRE-006 | `simd_scan_matches_scalar_oracle` (`tests/properties.rs`, both feature states incl. `--no-default-features`) | property (differential) |
| REQ-WIRE-007 | `corpus_regeneration_is_byte_identical` (`tests/corpus.rs`, CI regen-diff over committed goldens) | determinism gate |

## Additional named tests beyond the matrix

- `schema_version_gate`, `malformed_dimensions_are_typed`,
  `generated_frames_decode`, `group_block_view_matches_iterator`
  (`tests/sbe.rs`)
- `groups_single_level_with_count_match`, `nested_group_shape_is_typed_error`
  (spec decision 2), `tampered_checksum_is_bad_checksum`,
  `structural_violations_are_typed`, `builder_capacity_edges`,
  `garbage_and_utf8`, `message_type_dispatch`, `empty_group_zero_count`
  (`tests/fix.rs`)
- `sbe_single_byte_corruption_is_typed` (`tests/properties.rs`)
- `golden_frames_decode_to_manifest_values` (`tests/corpus.rs`)
- In-crate unit tests per module (39), including the SWAR↔byte-loop
  systematic sweep in `src/scan.rs` and the exhaustive prefix sweeps in
  `src/sbe/md.rs` / `src/fix.rs`.
