//! The fixed-width SBE message header and the generic [`Decoded`] wrapper.
//!
//! [REQ-WIRE-001] — fixed-width message headers. [REQ-WIRE-005] —
//! [`HeaderView`] borrows the input buffer: a view cannot outlive the bytes
//! it decodes, and dangling views are unrepresentable in safe code.

use crate::error::WireError;
use crate::sbe::{Endianness, CURRENT_SCHEMA_VERSION, MAX_SCHEMA_VERSION};

/// SBE message header width: `blockLength`, `templateId`, `schemaId`,
/// `version` — four `u16` fields.
pub const HEADER_LEN: usize = 8;

/// A typed view over a decoded SBE message header.
///
/// Lifetime-bound to the input buffer ([REQ-WIRE-005]); the whole input is
/// retained in [`HeaderView::buf`] so message-level views can be derived.
///
/// [REQ-WIRE-005]: crate::req::WIRE_005
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderView<'a> {
    /// Length of the fixed block that follows the header.
    pub block_len: u16,
    /// Message template id (the SBE notion of "message type").
    pub template_id: u16,
    /// Schema id carried by the frame (opaque to the generic decoder;
    /// typed roots pin it — see `md::TEMPLATE_ID` and `sbe::SCHEMA_ID`).
    pub schema_id: u16,
    /// Schema version of the frame.
    pub version: u16,
    /// The entire input buffer this header was decoded from.
    pub buf: &'a [u8],
    /// Byte order the header was decoded with ([REQ-WIRE-004] — explicit per
    /// block, carried on the view).
    pub endianness: Endianness,
}

impl HeaderView<'_> {
    /// Bytes of the input after the 8-byte header.
    pub fn rest(&self) -> &[u8] {
        self.buf.get(HEADER_LEN..).unwrap_or(&[])
    }
}

/// A decoded view paired with the bytes remaining after it.
///
/// Generic result of block decodes: `view` is lifetime-bound to the input,
/// `rest` is what is left after the decoded portion (empty for a header-only
/// decode of exactly one header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded<'a, T> {
    /// The typed view over the input buffer.
    pub view: T,
    /// Bytes remaining after the decoded portion.
    pub rest: &'a [u8],
}

/// Namespace type for SBE header decoding.
///
/// [REQ-WIRE-001], [REQ-WIRE-003], [REQ-WIRE-004].
///
/// [REQ-WIRE-001]: crate::req::WIRE_001
/// [REQ-WIRE-003]: crate::req::WIRE_003
/// [REQ-WIRE-004]: crate::req::WIRE_004
#[derive(Debug, Clone, Copy, Default)]
pub struct SbeHeader;

impl SbeHeader {
    /// Decode the fixed-width message header at the start of `buf`.
    ///
    /// Endianness is a parameter ([REQ-WIRE-004] — explicit per block; the
    /// API-sketch `decode(buf)` was refined into this signature deliberately).
    ///
    /// # Errors
    /// - [`WireError::InsufficientBytes`] when `buf` holds fewer than
    ///   [`HEADER_LEN`] bytes.
    /// - [`WireError::UnsupportedSchemaVersion`] when the frame declares a
    ///   version above [`MAX_SCHEMA_VERSION`] — the risk register's
    ///   wrong-version-frame guard.
    ///
    /// [REQ-WIRE-004]: crate::req::WIRE_004
    pub fn decode(
        buf: &[u8],
        endianness: Endianness,
    ) -> Result<Decoded<'_, HeaderView<'_>>, WireError> {
        let rest = buf.get(HEADER_LEN..).ok_or(WireError::InsufficientBytes {
            need: HEADER_LEN,
            have: buf.len(),
        })?;
        let block_len = endianness
            .u16_at(buf, 0)
            .ok_or(WireError::InsufficientBytes {
                need: HEADER_LEN,
                have: buf.len(),
            })?;
        let template_id = endianness
            .u16_at(buf, 2)
            .ok_or(WireError::InsufficientBytes {
                need: HEADER_LEN,
                have: buf.len(),
            })?;
        let schema_id = endianness
            .u16_at(buf, 4)
            .ok_or(WireError::InsufficientBytes {
                need: HEADER_LEN,
                have: buf.len(),
            })?;
        let version = endianness
            .u16_at(buf, 6)
            .ok_or(WireError::InsufficientBytes {
                need: HEADER_LEN,
                have: buf.len(),
            })?;
        if version > MAX_SCHEMA_VERSION {
            return Err(WireError::UnsupportedSchemaVersion {
                schema_id,
                got: version,
                max: MAX_SCHEMA_VERSION,
            });
        }
        Ok(Decoded {
            view: HeaderView {
                block_len,
                template_id,
                schema_id,
                version,
                buf,
                endianness,
            },
            rest,
        })
    }

    /// Encode a header into the leading [`HEADER_LEN`] bytes of `out` with
    /// the current schema constants. The generic counterpart of
    /// [`crate::sbe::Encoder::write_header`]; the [`Encoder`](crate::sbe::Encoder)
    /// form is preferred.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when `out` is shorter than
    /// [`HEADER_LEN`].
    pub fn encode(
        out: &mut [u8],
        template: crate::sbe::Template,
        endianness: Endianness,
    ) -> Result<(), WireError> {
        if out.len() < HEADER_LEN {
            return Err(WireError::InsufficientBytes {
                need: HEADER_LEN,
                have: out.len(),
            });
        }
        let mut pos = 0usize;
        let cap = out.len();
        for v in [
            template.block_len(),
            template.id(),
            crate::sbe::SCHEMA_ID,
            CURRENT_SCHEMA_VERSION,
        ] {
            let dst = out
                .get_mut(pos..pos + 2)
                .ok_or(WireError::InsufficientBytes {
                    need: HEADER_LEN,
                    have: cap,
                })?;
            dst.copy_from_slice(&endianness.u16_bytes(v));
            pos += 2;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Test harness: assertions legitimately panic; the decode paths under
    // test (lib code above) remain lint-clean.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    #![allow(clippy::indexing_slicing)]

    use super::{Decoded, SbeHeader, HEADER_LEN};
    use crate::error::WireError;
    use crate::sbe::{Endianness, Template, MAX_SCHEMA_VERSION};

    fn header_bytes(
        e: Endianness,
        block_len: u16,
        template_id: u16,
        schema_id: u16,
        version: u16,
    ) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        for (i, v) in [block_len, template_id, schema_id, version]
            .into_iter()
            .enumerate()
        {
            let b = e.u16_bytes(v);
            out[i * 2] = b[0];
            out[i * 2 + 1] = b[1];
        }
        out
    }

    #[test]
    fn header_roundtrips_both_endiannesses() {
        // REQ-WIRE-001 + REQ-WIRE-004 — identical logical header, both orders.
        for e in [Endianness::Little, Endianness::Big] {
            let buf = header_bytes(e, 16, 1, 0x574B, 1);
            let Decoded { view, rest } = SbeHeader::decode(&buf, e).unwrap();
            assert_eq!(view.block_len, 16);
            assert_eq!(view.template_id, 1);
            assert_eq!(view.schema_id, 0x574B);
            assert_eq!(view.version, 1);
            assert_eq!(view.endianness, e);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn truncated_header_is_insufficient_bytes() {
        let buf = header_bytes(Endianness::Little, 16, 1, 0x574B, 1);
        for n in 0..HEADER_LEN {
            let (slice, _) = buf.split_at(n);
            assert_eq!(
                SbeHeader::decode(slice, Endianness::Little),
                Err(WireError::InsufficientBytes {
                    need: HEADER_LEN,
                    have: n
                })
            );
        }
    }

    #[test]
    fn future_version_is_rejected() {
        let buf = header_bytes(Endianness::Little, 16, 1, 0x574B, MAX_SCHEMA_VERSION + 1);
        assert_eq!(
            SbeHeader::decode(&buf, Endianness::Little),
            Err(WireError::UnsupportedSchemaVersion {
                schema_id: 0x574B,
                got: MAX_SCHEMA_VERSION + 1,
                max: MAX_SCHEMA_VERSION
            })
        );
    }

    #[test]
    fn encode_matches_decode() {
        let mut out = [0u8; HEADER_LEN];
        SbeHeader::encode(&mut out, Template::MdIncrementalRefresh, Endianness::Big).unwrap();
        let d = SbeHeader::decode(&out, Endianness::Big).unwrap();
        assert_eq!(d.view.template_id, Template::MdIncrementalRefresh.id());
        assert_eq!(d.view.block_len, Template::MdIncrementalRefresh.block_len());
        // REQ-WIRE-003 — errors, not panics, on short output.
        assert!(
            SbeHeader::encode(&mut [], Template::MdIncrementalRefresh, Endianness::Little).is_err()
        );
    }
}
