# Security Policy — wire-kit

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

Report privately via [GitHub security advisories] for this repository, or
email **wyatt_au@protonmail.com**. Do **not** open a public issue for
security reports.

You will receive an acknowledgement within **72 hours**. Coordinated
disclosure: we ask for up to 90 days before public disclosure while a
patch ships.

## Threat model

**I/O surface: untrusted input.** wire-kit's decoders process byte buffers
that originate from exchange feeds, shared-memory rings, and other
untrusted sources. The trust boundary is the *contents* of every `&[u8]`
handed to `FixMessage::parse`, `SbeHeader::decode`,
`MdIncrementalRefresh::root`, and the scanners. Callers control where the
bytes come from; wire-kit guarantees safety of the *decode* regardless.

| ID | Threat | Mitigation |
|----|--------|------------|
| T1 | Malformed/truncated frames drive a decoder out of bounds or into a panic (remote crash on hostile feed) | Totality by construction: bounds checked at every field access (`get()`-only access; `unwrap`/`expect`/`panic`/`indexing_slicing` denied at the lib target), exhaustive `WireError`, one cargo-fuzz target per decoder, 30 s CI smokes over committed seeds, miri over the encode/decode suites |
| T2 | Hostile group counts cause resource amplification (count × block size blowup, allocation storms) | Counts are validated against remaining buffer bytes **before** any iteration; the decoders allocate nothing (no `alloc` in the decode path), so amplification is bounded by the input buffer itself |
| T3 | Tag-10 checksum treated as tamper protection | Documented as a transport-integrity check only: sum-mod-256 is trivially weak and forgivable by an active attacker. Authenticity must come from the transport (TLS, multicast signing) — never from tag 10 |
| T4 | SIMD and scalar scans diverge on edge inputs (two decoders, two truths) | The scalar/SWAR path is the always-compiled oracle; `simd_scan_matches_scalar_oracle` (differential property, 500 cases) runs in both feature states; the fuzz target asserts equivalence on every input |
| T5 | Misaligned/UB reads in the `unsafe` SIMD fast path | `unsafe` is confined to the scan module (denied crate-wide, lifted with documented SAFETY blocks); loads are unaligned-but-in-bounds via `get()`-proven chunk lengths; miri runs the suites; odd-offset frames are in the fuzz seeds |
| T6 | Schema/version drift: decoder accepts wrong-version frames | The SBE header carries `schema_id` + `version`; versions above the supported maximum are rejected with `UnsupportedSchemaVersion`; template mismatches at typed roots reject with `UnknownMessageType` |

### Non-goals

- No secrets, no network access, no filesystem access in the library: the
  I/O surface is the caller's buffers and nothing else.
- The FIX session layer (logon/heartbeat/sequence state machines) is out of
  scope; this is the presentation codec only.
- Denial of service *by legitimate input size* is a caller concern: decode
  cost is linear in buffer length with no amplification, but callers still
  cap feed buffer sizes at the transport.

### Verification hooks

- `cargo fuzz run <target>` — `sbe_decode`, `fix_parse`, `find_soh`
  (seeds under `fuzz/corpus/`).
- `cargo +nightly miri test --lib` — encode/decode suites under miri.
- `cargo test` — totality sweeps (every truncation prefix of valid frames),
  differential SIMD/scalar properties, corpus regen-diff.

[GitHub security advisories]:
    https://github.com/WyattAu/wire-kit/security/advisories/new
