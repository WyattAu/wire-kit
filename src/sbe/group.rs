//! Repeating groups and data fields — the generic SBE group machinery.
//!
//! [REQ-WIRE-001] — repeating groups and data fields. Iteration is total:
//! every entry is bounds-checked on construction ([REQ-WIRE-003]), and an
//! iterator over an under-sized region yields typed errors rather than
//! panicking or reading out of bounds.

use core::marker::PhantomData;

use crate::error::WireError;
use crate::sbe::Endianness;

/// A fixed-width SBE group entry block that can be viewed over a buffer.
///
/// Typed group blocks implement this so [`GroupIter`] can walk entries
/// generically; `view` must be total — bounds errors are
/// [`WireError::InsufficientBytes`], never panics ([REQ-WIRE-003]). The
/// message's declared byte order is threaded through ([REQ-WIRE-004]).
///
/// [REQ-WIRE-003]: crate::req::WIRE_003
/// [REQ-WIRE-004]: crate::req::WIRE_004
pub trait GroupBlock<'a>: Sized {
    /// Fixed byte length of one entry.
    const BLOCK_LEN: usize;

    /// View the entry starting at `off` in `buf`, reading fields in the
    /// message block's declared byte order.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the entry's bytes are not fully
    /// in bounds.
    fn view(buf: &'a [u8], off: usize, endianness: Endianness) -> Result<Self, WireError>;
}

/// Total iterator over SBE repeating-group entries.
///
/// Created by typed blocks (e.g. `MdIncrementalRefresh::md_entries`) after
/// the group dimension has been validated; per-entry bounds are still checked
/// at every step ([REQ-WIRE-003] — totality by construction). On the first
/// bounds failure the iterator yields `Some(Err(_))` and then terminates.
///
/// [REQ-WIRE-003]: crate::req::WIRE_003
#[derive(Debug)]
pub struct GroupIter<'a, T> {
    buf: &'a [u8],
    off: usize,
    remaining: usize,
    endianness: Endianness,
    _marker: PhantomData<fn() -> T>,
}

impl<'a, T> GroupIter<'a, T> {
    /// Internal constructor (typed blocks expose it through their own API).
    pub(crate) fn new(buf: &'a [u8], off: usize, remaining: usize, endianness: Endianness) -> Self {
        Self {
            buf,
            off,
            remaining,
            endianness,
            _marker: PhantomData,
        }
    }

    /// Entries not yet yielded.
    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

impl<'a, T: GroupBlock<'a>> Iterator for GroupIter<'a, T> {
    type Item = Result<T, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let item = T::view(self.buf, self.off, self.endianness);
        if item.is_ok() {
            // `off + BLOCK_LEN` cannot overflow: the entry fit inside `buf`,
            // whose length is bounded by `isize::MAX`.
            self.off += T::BLOCK_LEN;
        }
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, T: GroupBlock<'a>> ExactSizeIterator for GroupIter<'a, T> {}

/// An SBE data (varData) field: a `u16` length followed by that many raw
/// bytes. Length is validated at construction, so [`DataField::bytes`] is
/// always exactly [`DataField::len`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataField<'a> {
    len: u16,
    bytes: &'a [u8],
}

impl<'a> DataField<'a> {
    /// Parse a length-prefixed data field at `off`.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the length prefix or the payload
    /// extends past the buffer.
    pub(crate) fn parse(
        buf: &'a [u8],
        off: usize,
        endianness: Endianness,
    ) -> Result<Self, WireError> {
        let need2 = off.saturating_add(2);
        let len = endianness
            .u16_at(buf, off)
            .ok_or(WireError::InsufficientBytes {
                need: need2,
                have: buf.len(),
            })?;
        let start = off.checked_add(2).ok_or(WireError::InsufficientBytes {
            need: usize::MAX,
            have: buf.len(),
        })?;
        let end = start
            .checked_add(len as usize)
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: buf.len(),
            })?;
        let bytes = buf.get(start..end).ok_or(WireError::InsufficientBytes {
            need: end,
            have: buf.len(),
        })?;
        Ok(Self { len, bytes })
    }

    /// Payload length in bytes (always `bytes().len()`).
    pub fn len(&self) -> u16 {
        self.len
    }

    /// True when the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The raw payload, zero-copy ([REQ-WIRE-001]).
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The payload as UTF-8. Raw byte access remains available via
    /// [`DataField::bytes`] — decoding to `&str` is the caller's explicit
    /// choice.
    ///
    /// # Errors
    /// [`WireError::InvalidUtf8`] when the payload is not valid UTF-8.
    pub fn as_str(&self) -> Result<&'a str, WireError> {
        core::str::from_utf8(self.bytes).map_err(|_| WireError::InvalidUtf8)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    #![allow(clippy::indexing_slicing)]

    use super::{DataField, GroupBlock, GroupIter};
    use crate::error::WireError;
    use crate::sbe::Endianness;

    struct Pair<'a> {
        _buf: &'a [u8],
    }

    impl<'a> GroupBlock<'a> for Pair<'a> {
        const BLOCK_LEN: usize = 2;

        fn view(buf: &'a [u8], off: usize, _e: crate::sbe::Endianness) -> Result<Self, WireError> {
            if buf.get(off..off + 2).is_none() {
                return Err(WireError::InsufficientBytes {
                    need: off + 2,
                    have: buf.len(),
                });
            }
            Ok(Self { _buf: buf })
        }
    }

    #[test]
    fn group_iter_is_total_and_exact() {
        // REQ-WIRE-001 + REQ-WIRE-003 — bounded iteration, typed errors.
        let buf = [0u8; 5]; // 2 full pairs + 1 truncated
        let mut it = GroupIter::<Pair<'_>>::new(&buf, 0, 3, crate::sbe::Endianness::Little);
        assert_eq!(it.size_hint(), (3, Some(3)));
        assert!(it.next().unwrap().is_ok());
        assert!(it.next().unwrap().is_ok());
        let third = it.next().unwrap();
        assert_eq!(
            third.map(|_| ()),
            Err(WireError::InsufficientBytes {
                need: 4 + 2,
                have: 5
            })
        );
        assert!(it.next().is_none());
        assert_eq!(it.remaining(), 0);
    }

    #[test]
    fn empty_group_iter_yields_none() {
        let buf = [0u8; 0];
        let mut it: GroupIter<Pair<'_>> = GroupIter::new(&buf, 0, 0, crate::sbe::Endianness::Big);
        assert!(it.next().is_none());
    }

    #[test]
    fn data_field_parse_and_utf8_gate() {
        let mut buf = [0u8; 16];
        assert_eq!(Endianness::Little.u16_bytes(5), [5, 0]);
        buf[..2].copy_from_slice(&Endianness::Little.u16_bytes(5));
        buf[2..7].copy_from_slice(b"hello");
        let df = DataField::parse(&buf, 0, Endianness::Little).unwrap();
        assert_eq!(df.len(), 5);
        assert_eq!(df.bytes(), b"hello");
        assert_eq!(df.as_str().unwrap(), "hello");
        // Invalid UTF-8 → InvalidUtf8, not a panic (byte access still fine).
        let mut bad = [0u8; 4];
        bad[..2].copy_from_slice(&Endianness::Little.u16_bytes(2));
        bad[2] = 0xFF;
        bad[3] = 0xFE;
        let dfb = DataField::parse(&bad, 0, Endianness::Little).unwrap();
        assert_eq!(dfb.as_str(), Err(WireError::InvalidUtf8));
        assert_eq!(dfb.bytes(), &[0xFF, 0xFE]);
        // Truncations are typed errors.
        for n in 0..7 {
            assert!(matches!(
                DataField::parse(&buf[..n], 0, Endianness::Little),
                Err(WireError::InsufficientBytes { .. })
            ));
        }
    }

    #[test]
    fn empty_data_field() {
        let buf = [0u8; 2];
        let df = DataField::parse(&buf, 0, Endianness::Little).unwrap();
        assert!(df.is_empty());
        assert_eq!(df.as_str().unwrap(), "");
    }
}
