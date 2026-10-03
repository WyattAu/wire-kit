# Coverage notes — wire-kit

Methodology per the gate plan (spec §Gate plan): **per-config measurement**.
`--all-features` unions cannot execute non-native intrinsic paths, so the
`simd`-gated code is assessed per configuration and the union-coverage
denominator is interpreted accordingly.

| Config | Command | Line coverage (2026-10-03, rustc 1.98.1) |
|---|---|---|
| all features (`std` + `simd`) | `cargo llvm-cov --all-features` | **96.12%** (1986 lines, 77 missed) |
| no default features (scalar, `no_std`) | `cargo llvm-cov --no-default-features` | scalar-only suite passes; `find_soh_simd` is cfg'd out entirely |

## SIMD branches in the denominator

The union (`--all-features`) build on an x86_64 host executes:

- the SWAR oracle and the byte-loop reference — always;
- the AVX2 intrinsic loop (runtime-detected on the host);
- **not** the SSE2 intrinsic loop (AVX2 was detected and chosen);
- **not** the aarch64 NEON module (cfg'd out on x86_64 — a different target
  cannot be executed by the union run at all).

Per the gate plan, the non-native intrinsic paths (SSE2 loop under AVX2
detection, and the whole NEON module) are therefore **excluded from the
union-coverage denominator by methodology** and documented here rather than
by coverage attributes (`#[coverage(off)]` is not yet stable on the
gate toolchain). Their correctness is pinned not by coverage but by:

- `simd_scan_matches_scalar_oracle` — differential property (500 cases) in
  both feature states;
- the `find_soh` fuzz target — asserts SIMD == SWAR == byte-loop on every
  input;
- unit tests that sweep SOH positions across lane boundaries (8/16/32-byte
  edges) for every oracle pair.

## Numbers

- TOTAL: 96.12% lines / 97.18% functions (gate: ≥ 90%).
- Weakest files and why: `scan.rs` 92.22% (the non-native SIMD paths above),
  `fix.rs` 93.47% (the builder's unreachable `finish` overflow arm — the
  reserve plus per-field bounds make the shuffle provably fit; documented in
  the builder rustdoc).

## Regenerating

```sh
cargo llvm-cov --all-features            # union view
cargo llvm-cov --no-default-features     # scalar / no_std view
```
