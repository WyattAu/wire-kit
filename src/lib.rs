//! Zero-copy binary wire codecs — SBE block encoding/decoding and FIX 4.4
//! tag=value, bounds-checked, allocation-free decode.
//!
//! wire-kit reads and writes exchange wire formats **in place**: a decoder is
//! a set of lifetime-bound accessor structs over `&[u8]` (and `&mut [u8]` for
//! the encoder) — decode touches nothing, allocates nothing, copies nothing
//! ([REQ-WIRE-001], [REQ-WIRE-005]). One buffer in, typed views out; the views
//! die with the borrow and can never outlive the buffer.
//!
//! # Totality ([REQ-WIRE-003])
//!
//! Every decoder is **total**: malformed, truncated, hostile input produces a
//! typed [`WireError`] — never a panic, never an out-of-bounds read. Bounds
//! are checked at every field access, so fuzzing any decoder asserts
//! `Err`-not-panic (see `fuzz/`).
//!
//! # Endianness ([REQ-WIRE-004])
//!
//! Endianness is explicit **per message block**, not a crate-global setting.
//! SBE schema blocks declare big- or little-endian fields; every generic
//! entry point ([`sbe::SbeHeader::decode`], [`sbe::Encoder::write_field_i64`],
//! …) takes an [`Endianness`] parameter, and the typed reference blocks
//! ([`sbe::MdIncrementalRefresh`]) embody their declared byte order in the
//! type itself. FIX 4.4 is ASCII tag=value and has none. All integer
//! conversion uses `from_le_bytes`/`from_be_bytes` — byteorder-free.
//!
//! # SIMD scanning ([REQ-WIRE-006])
//!
//! FIX `0x01` delimiter search uses `core::arch` intrinsics behind the `simd`
//! feature (SSE2/AVX2 on x86_64, NEON on aarch64), with a scalar/SWAR
//! reference ([`find_soh`]) that is **always compiled** and serves as the
//! differential oracle. Under `std`, the `simd` path runtime-dispatches via
//! `is_x86_feature_detected!`; `no_std` builds use the scalar path (or
//! compile-time baseline SIMD, documented in [`scan`]).
//!
//! # Corpus ([REQ-WIRE-007])
//!
//! Golden SBE test corpora are generated deterministically (seeded LCG, no
//! `rand`) from schema descriptions — see [`corpus`]. Test-support only:
//! wire-kit ships no SBE schema codegen.
//!
//! # Example
//!
//! ```rust
//! use wire_kit::corpus::{generate_md_frame, Lcg64, CORPUS_SEED};
//! use wire_kit::sbe::md::MdIncrementalRefresh;
//! use wire_kit::sbe::Endianness;
//!
//! // A deterministic market-data frame (the corpus generator itself).
//! let mut out = [0u8; 256];
//! let (n, expected) =
//!     generate_md_frame(&mut out, &mut Lcg64::new(CORPUS_SEED), Endianness::Little)?;
//!
//! // Decode in place: typed views, zero allocation, zero copying.
//! let decoded = MdIncrementalRefresh::root(&out[..n], Endianness::Little)?;
//! assert_eq!(decoded.view.transact_time()?, expected.transact_time);
//! for entry in decoded.view.md_entries()?.flatten() {
//!     let _ = entry.update_action()?; // bounds-checked, typed errors
//! }
//! let text = decoded.view.text_field()?;
//! assert_eq!(text.bytes(), &expected.text[..expected.text_len]);
//! # Ok::<(), wire_kit::WireError>(())
//! ```
//!
//! ```rust
//! use wire_kit::fix::{FixBuilder, FixMessage, FixMsgType};
//!
//! let mut buf = [0u8; 128];
//! let mut b = FixBuilder::new(&mut buf)?;
//! b.field_str(35, "X")?;  // MsgType
//! b.field_str(268, "2")?; // NoMDEntries
//! b.field_str(279, "0")?; // entry 1 (delimiter)
//! b.field_str(279, "1")?; // entry 2
//! let frame = b.finish()?; // prepends 8=/9=, appends 10=<checksum>
//!
//! let m = FixMessage::parse(frame)?;
//! assert_eq!(m.message_type()?, FixMsgType::MarketDataIncrementalRefresh);
//! m.verify_checksum()?;
//! assert_eq!(m.group(268)?.len(), 2);
//! # Ok::<(), wire_kit::WireError>(())
//! ```
//!
//! # Out of scope
//!
//! SBE schema→Rust codegen, the FIX session layer (logon/heartbeat/sequence
//! state machines), encryption, any transport, serde bridges. This crate is
//! the estate's edge-format leaf: consumers bring the buffers.
//!
//! # Layer
//!
//! L1 — substrate. Zero estate-internal dependencies, zero runtime external
//! dependencies.
//!
//! [REQ-WIRE-001]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
//! [REQ-WIRE-002]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
//! [REQ-WIRE-003]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
//! [REQ-WIRE-004]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
//! [REQ-WIRE-005]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
//! [REQ-WIRE-006]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md
//! [REQ-WIRE-007]: https://github.com/WyattAu/engineering-standards/blob/main/specs/wire-kit.md

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::indexing_slicing, clippy::undocumented_unsafe_blocks)]

pub mod corpus;
pub mod error;
pub mod fix;
pub mod sbe;
pub mod scan;

pub use error::WireError;
pub use sbe::Endianness;

/// Re-export of the crate's own requirement IDs, so downstream code can cite
/// the same traceability anchors the tests use.
pub mod req {
    /// REQ-WIRE-001 — SBE block codec, zero-copy decode.
    pub const WIRE_001: &str = "REQ-WIRE-001";
    /// REQ-WIRE-002 — FIX 4.4 tag=value codec.
    pub const WIRE_002: &str = "REQ-WIRE-002";
    /// REQ-WIRE-003 — total, bounds-checked decoding.
    pub const WIRE_003: &str = "REQ-WIRE-003";
    /// REQ-WIRE-004 — explicit per-block endianness.
    pub const WIRE_004: &str = "REQ-WIRE-004";
    /// REQ-WIRE-005 — lifetime-bound views.
    pub const WIRE_005: &str = "REQ-WIRE-005";
    /// REQ-WIRE-006 — SIMD scan with scalar oracle.
    pub const WIRE_006: &str = "REQ-WIRE-006";
    /// REQ-WIRE-007 — deterministic schema-driven corpus.
    pub const WIRE_007: &str = "REQ-WIRE-007";
}
