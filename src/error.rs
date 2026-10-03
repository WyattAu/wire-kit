//! Typed, exhaustive error taxonomy for every decoder in the crate.
//!
//! [REQ-WIRE-003] — all decoding is bounds-checked and total: every malformed
//! input yields one of these variants. No decoder panics, wraps, or reads out
//! of bounds. The enum is deliberately **exhaustive** (no `#[non_exhaustive]`):
//! callers are expected to match every variant, and a new variant is a
//! semver-minor event by design.
//!
//! `InsufficientBytes.have` conventions: for SBE accessors it is the full
//! buffer length and `need` the required absolute end offset; for FIX
//! framing it is the bytes actually available. Doc comments on the producing
//! functions pin the semantics.
//!
//! [REQ-WIRE-003]: crate::req::WIRE_003

use core::fmt;

/// The single crate-level error for both codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// A structure declared (or a read required) more bytes than the buffer
    /// holds. Truncated frames surface here — including a FIX field missing
    /// its final SOH terminator.
    InsufficientBytes {
        /// Number of bytes the structure requires.
        need: usize,
        /// Number of bytes actually available.
        have: usize,
    },
    /// FIX: an unknown tag or a tag in an illegal position; also the catch-all
    /// for a malformed field (missing `=`, non-numeric tag or count, value
    /// containing SOH). `0` marks a tag that could not be parsed at all.
    /// SBE: a group whose leading/count tag has no match in the frame.
    InvalidTag(u16),
    /// FIX tag 10: the computed sum-mod-256 does not match the declared
    /// checksum. Transport-integrity signal only — never tamper protection
    /// (the tag-10 checksum is trivially weak by design; see SECURITY.md).
    BadChecksum {
        /// Checksum computed over the covered byte range.
        got: u8,
        /// Checksum declared in the tag-10 field.
        want: u8,
    },
    /// An enum-like field carried a raw value outside its declared range.
    /// `enum_id` is the schema identifier of the enum (the reference schema
    /// uses the corresponding FIX tag numbers).
    InvalidEnum {
        /// Schema id of the enum field.
        enum_id: u16,
        /// Raw value that is out of range.
        raw: i64,
    },
    /// A repeating group's declared count does not match what the frame can
    /// deliver: `claimed` entries declared, only `remaining` actually present
    /// (or fittable in the remaining bytes). Nested FIX groups are rejected
    /// with this variant in v1 until spec'd (documented limitation).
    InvalidGroupCount {
        /// The group's count tag (FIX) or dimension tag id (SBE).
        tag: u16,
        /// Declared number of entries.
        claimed: usize,
        /// Entries actually present / fittable.
        remaining: usize,
    },
    /// An SBE frame's schema version is newer than this codec supports, or a
    /// typed root was applied to a frame carrying a different schema id.
    /// `schema_id` is the id from the frame header, `got` the frame version,
    /// `max` the highest version this codec decodes.
    UnsupportedSchemaVersion {
        /// Schema id from the frame header.
        schema_id: u16,
        /// Version from the frame header (or the offending id on mismatch).
        got: u16,
        /// Maximum version this build supports.
        max: u16,
    },
    /// A text field does not hold valid UTF-8 (only surfaces from the
    /// `*_str` accessors; raw byte access is always available).
    InvalidUtf8,
    /// A message type (FIX tag 35, or an SBE template id at a typed root)
    /// outside the v1 message set.
    UnknownMessageType,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::InsufficientBytes { need, have } => {
                write!(f, "insufficient bytes: need {need}, have {have}")
            }
            WireError::InvalidTag(tag) => write!(f, "invalid FIX/SBE tag or field: {tag}"),
            WireError::BadChecksum { got, want } => {
                write!(f, "bad checksum: computed {got:#04x}, declared {want:#04x}")
            }
            WireError::InvalidEnum { enum_id, raw } => {
                write!(f, "invalid enum value {raw} for enum {enum_id}")
            }
            WireError::InvalidGroupCount {
                tag,
                claimed,
                remaining,
            } => write!(
                f,
                "invalid group count: tag {tag} claims {claimed}, {remaining} present"
            ),
            WireError::UnsupportedSchemaVersion {
                schema_id,
                got,
                max,
            } => write!(
                f,
                "unsupported schema: id {schema_id:#06x} version {got} (max {max})"
            ),
            WireError::InvalidUtf8 => write!(f, "text field is not valid UTF-8"),
            WireError::UnknownMessageType => write!(f, "unknown message type"),
        }
    }
}

impl core::error::Error for WireError {}

#[cfg(test)]
mod tests {
    use super::WireError;

    #[test]
    fn display_is_informative_and_total() {
        // REQ-WIRE-003 — every variant renders without panicking.
        let cases = [
            WireError::InsufficientBytes { need: 8, have: 3 },
            WireError::InvalidTag(35),
            WireError::BadChecksum {
                got: 0xAB,
                want: 0xCD,
            },
            WireError::InvalidEnum {
                enum_id: 279,
                raw: 9,
            },
            WireError::InvalidGroupCount {
                tag: 268,
                claimed: 3,
                remaining: 1,
            },
            WireError::UnsupportedSchemaVersion {
                schema_id: 0x574B,
                got: 2,
                max: 1,
            },
            WireError::InvalidUtf8,
            WireError::UnknownMessageType,
        ];
        for e in cases {
            let s = e.to_string();
            assert!(!s.is_empty(), "{e:?} rendered empty");
        }
    }
}
