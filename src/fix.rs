//! FIX 4.4 tag=value codec — SOH-delimited fields, in-place field access,
//! tag-10 checksum, declared repeating groups, and a zero-alloc builder.
//!
//! [REQ-WIRE-002] — encodes and decodes messages, verifies/computes the
//! tag-10 checksum, exposes declared repeating groups, and provides in-place
//! (zero-copy) field access. FIX 4.4 is ASCII tag=value: it has no
//! endianness ([REQ-WIRE-004]).
//!
//! # Frame model (v1)
//!
//! `parse` enforces the canonical 4.4 shape: `8=FIX.4.4`, `9=<BodyLength>`,
//! `35=<MsgType>` as the first three fields, arbitrary body fields, and the
//! `10=<checksum>` field last. `BodyLength` is used for framing (it must land
//! exactly on the checksum field) and the checksum is verified against the
//! bytes before it. Tags 8, 9, and 10 are reserved — encountering them in the
//! body is [`WireError::InvalidTag`].
//!
//! # Groups (spec decision 2 — single-level, nesting typed-err'd)
//!
//! [`FixMessage::group`] takes the count tag (`NoX`, e.g. 268); entries are
//! delimited by the first member tag (the field immediately following the
//! count). The declared count must match the entries found, and the count
//! tag must not re-occur inside the group region — either violation yields
//! [`WireError::InvalidGroupCount`]. Nested groups are not interpreted in v1;
//! the last entry extends to the checksum field, so place groups last in the
//! body. Schema-driven member-tag sets are future work.
//!
//! [REQ-WIRE-002]: crate::req::WIRE_002
//! [REQ-WIRE-004]: crate::req::WIRE_004

use crate::error::WireError;
use crate::scan::{scan_soh, SOH};

/// The `BeginString` this codec accepts.
pub const BEGIN_STRING: &[u8] = b"FIX.4.4";

/// Bytes reserved ahead of the body when building: `8=FIX.4.4␁9=␁` plus a
/// 20-digit `usize` and slack.
pub const HEADER_RESERVE: usize = 40;

/// FIX transport checksum: the byte-sum mod 256 over the covered range
/// (everything from `8=` through the SOH before `10=`). Public for
/// cross-verification; **transport-integrity only, never tamper protection**
/// (see SECURITY.md).
#[must_use]
pub fn fix_checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, b| acc.wrapping_add(*b))
}

/// One scanned field: tag plus the value's byte range and the offset just
/// past the field's SOH.
struct RawField {
    tag: u16,
    val: core::ops::Range<usize>,
    end: usize,
}

/// Scan the field starting at `pos` in `buf`.
///
/// # Errors
/// - [`WireError::InsufficientBytes`] — no terminating SOH (truncation).
/// - [`WireError::InvalidTag`] — no `=` before a SOH, empty/oversized/
///   non-numeric tag, or a `0` tag.
fn next_field(buf: &[u8], pos: usize) -> Result<RawField, WireError> {
    let region = buf.get(pos..).ok_or(WireError::InsufficientBytes {
        need: pos + 1,
        have: buf.len(),
    })?;
    let mut eq_rel = None;
    for (i, b) in region.iter().enumerate() {
        if *b == b'=' {
            eq_rel = Some(i);
            break;
        }
        if *b == SOH {
            // SOH before '=' — a tag may never contain one.
            return Err(WireError::InvalidTag(0));
        }
    }
    let eq = eq_rel.ok_or(WireError::InsufficientBytes {
        need: buf.len().saturating_add(1),
        have: buf.len(),
    })?;
    let tag = parse_tag(region.get(..eq).unwrap_or(&[]))?;
    let val_start =
        pos.checked_add(eq)
            .and_then(|s| s.checked_add(1))
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: buf.len(),
            })?;
    let tail = buf.get(val_start..).ok_or(WireError::InsufficientBytes {
        need: val_start + 1,
        have: buf.len(),
    })?;
    let soh_rel = scan_soh(tail).ok_or(WireError::InsufficientBytes {
        need: buf.len().saturating_add(1),
        have: buf.len(),
    })?;
    let val_end = val_start
        .checked_add(soh_rel)
        .ok_or(WireError::InsufficientBytes {
            need: usize::MAX,
            have: buf.len(),
        })?;
    Ok(RawField {
        tag,
        val: val_start..val_end,
        end: val_end + 1, // the SOH itself
    })
}

/// Parse an ASCII decimal tag: 1..=5 digits, no sign, no leading zero beyond
/// a single `"0"` (which is itself an invalid tag number).
fn parse_tag(bytes: &[u8]) -> Result<u16, WireError> {
    if bytes.is_empty() || bytes.len() > 5 {
        return Err(WireError::InvalidTag(0));
    }
    if bytes.len() > 1 && bytes.first() == Some(&b'0') {
        return Err(WireError::InvalidTag(0));
    }
    let mut acc: u32 = 0;
    for b in bytes {
        if !b.is_ascii_digit() {
            return Err(WireError::InvalidTag(0));
        }
        acc = acc * 10 + u32::from(b - b'0');
    }
    let tag = u16::try_from(acc).map_err(|_| WireError::InvalidTag(0))?;
    if tag == 0 {
        return Err(WireError::InvalidTag(0));
    }
    Ok(tag)
}

/// Parse an ASCII decimal `usize` body-length/count value.
fn parse_ascii_usize(bytes: &[u8]) -> Result<usize, WireError> {
    if bytes.is_empty() {
        return Err(WireError::InvalidTag(0));
    }
    let mut acc: usize = 0;
    for b in bytes {
        if !b.is_ascii_digit() {
            return Err(WireError::InvalidTag(0));
        }
        acc = acc.checked_mul(10).ok_or(WireError::InvalidTag(0))?;
        acc = acc
            .checked_add(usize::from(b - b'0'))
            .ok_or(WireError::InvalidTag(0))?;
    }
    Ok(acc)
}

/// Number of minimal ASCII digits needed for `v` (at least 1).
fn digit_count(v: usize) -> usize {
    let mut n = 1usize;
    let mut rest = v / 10;
    while rest > 0 {
        n += 1;
        rest /= 10;
    }
    n
}

/// Write `v` as minimal ASCII digits into `out` starting at `start` (up to
/// 20 digits); returns the number of digits written.
fn write_digits_at(out: &mut [u8], start: usize, v: usize) -> usize {
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    let mut rest = v;
    loop {
        if let Some(slot) = tmp.get_mut(n) {
            *slot = b'0' + (rest % 10) as u8;
        }
        n += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    for k in 0..n {
        if let Some(src) = tmp.get(n - 1 - k) {
            if let Some(dst) = out.get_mut(start + k) {
                *dst = *src;
            }
        }
    }
    n
}

/// A parsed, fully validated FIX 4.4 message — a zero-copy view over the
/// input buffer ([REQ-WIRE-005]: lifetime-bound, allocation-free).
///
/// Construct with [`FixMessage::parse`] (or [`FixBuilder::finish`] output fed
/// back through `parse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixMessage<'a> {
    buf: &'a [u8],
    body_start: usize,
    checksum_off: usize,
}

impl<'a> FixMessage<'a> {
    /// Parse and fully validate a FIX 4.4 frame: canonical header order
    /// (`8`, `9`, `35`), `BodyLength` framing, tag-10 position, and the
    /// checksum.
    ///
    /// # Errors
    /// - [`WireError::InsufficientBytes`] — the frame is truncated (including
    ///   a missing final SOH).
    /// - [`WireError::InvalidTag`] — non-canonical structure: wrong header
    ///   tags/order, reserved tags in the body, fields overrunning the
    ///   declared `BodyLength`, malformed tags, or trailing bytes after the
    ///   checksum field.
    /// - [`WireError::BadChecksum`] — computed tag-10 checksum mismatch.
    ///
    /// [REQ-WIRE-003]: crate::req::WIRE_003
    pub fn parse(buf: &'a [u8]) -> Result<Self, WireError> {
        let f8 = next_field(buf, 0)?;
        if f8.tag != 8 {
            return Err(WireError::InvalidTag(f8.tag));
        }
        if buf.get(f8.val.clone()) != Some(BEGIN_STRING) {
            return Err(WireError::InvalidTag(8));
        }
        let f9 = next_field(buf, f8.end)?;
        if f9.tag != 9 {
            return Err(WireError::InvalidTag(f9.tag));
        }
        let body_len = parse_ascii_usize(buf.get(f9.val.clone()).unwrap_or(&[]))
            .map_err(|_| WireError::InvalidTag(9))?;
        let body_start = f9.end;
        let checksum_off =
            body_start
                .checked_add(body_len)
                .ok_or(WireError::InsufficientBytes {
                    need: usize::MAX,
                    have: buf.len(),
                })?;
        if checksum_off > buf.len() {
            return Err(WireError::InsufficientBytes {
                need: checksum_off,
                have: buf.len(),
            });
        }

        // MsgType must be present as the first body-region field.
        if body_start >= checksum_off {
            return Err(WireError::InvalidTag(35));
        }
        let f35 = next_field(buf, body_start)?;
        if f35.tag != 35 {
            return Err(WireError::InvalidTag(f35.tag));
        }
        if f35.end > checksum_off {
            return Err(WireError::InvalidTag(35));
        }

        // Body fields up to the checksum field.
        let mut pos = f35.end;
        while pos < checksum_off {
            let f = next_field(buf, pos)?;
            if matches!(f.tag, 8..=10) {
                return Err(WireError::InvalidTag(f.tag));
            }
            if f.end > checksum_off {
                // Field overruns the declared BodyLength.
                return Err(WireError::InvalidTag(f.tag));
            }
            pos = f.end;
        }

        // The checksum field, exactly at checksum_off, ending the buffer.
        let f10 = next_field(buf, checksum_off)?;
        if f10.tag != 10 {
            return Err(WireError::InvalidTag(f10.tag));
        }
        if f10.end != buf.len() {
            return Err(WireError::InvalidTag(10));
        }
        let declared = parse_ascii_usize(buf.get(f10.val.clone()).unwrap_or(&[]))
            .map_err(|_| WireError::InvalidTag(10))?;
        if declared > u8::MAX as usize {
            return Err(WireError::InvalidTag(10));
        }
        let covered = buf
            .get(..checksum_off)
            .ok_or(WireError::InsufficientBytes {
                need: checksum_off,
                have: buf.len(),
            })?;
        let computed = fix_checksum(covered);
        if computed != declared as u8 {
            return Err(WireError::BadChecksum {
                got: computed,
                want: declared as u8,
            });
        }

        Ok(Self {
            buf,
            body_start,
            checksum_off,
        })
    }

    /// The first field with this tag, as raw bytes — in-place, zero-copy.
    /// Includes header fields (`8`, `9`, `35`, `10`).
    #[must_use]
    pub fn field(&self, tag: u16) -> Option<&'a [u8]> {
        let mut pos = 0usize;
        while pos < self.buf.len() {
            let f = next_field(self.buf, pos).ok()?;
            if f.tag == tag {
                return self.buf.get(f.val);
            }
            pos = f.end;
        }
        None
    }

    /// The first field with this tag as UTF-8.
    ///
    /// # Errors
    /// - [`WireError::InvalidTag`] — tag absent.
    /// - [`WireError::InvalidUtf8`] — value is not valid UTF-8.
    pub fn field_str(&self, tag: u16) -> Result<&'a str, WireError> {
        let v = self.field(tag).ok_or(WireError::InvalidTag(tag))?;
        core::str::from_utf8(v).map_err(|_| WireError::InvalidUtf8)
    }

    /// The declared repeating group for `leading_tag` (the `NoX` count tag,
    /// e.g. `268`).
    ///
    /// # Errors
    /// - [`WireError::InvalidTag`] — the tag does not appear in the body.
    /// - [`WireError::InvalidGroupCount`] — the declared count does not match
    ///   the entries found, or the count tag re-occurs inside the group
    ///   region (nested-group attempt — v1 rejects; spec decision 2).
    pub fn group(&self, leading_tag: u16) -> Result<FixGroup<'a>, WireError> {
        // Locate the count field (first occurrence in the body region).
        let mut pos = self.body_start;
        let mut count_field = None;
        while pos < self.checksum_off {
            let f = next_field(self.buf, pos)?;
            if f.tag == leading_tag {
                count_field = Some(f);
                break;
            }
            pos = f.end;
        }
        let count = count_field.ok_or(WireError::InvalidTag(leading_tag))?;
        let claimed = parse_ascii_usize(self.buf.get(count.val.clone()).unwrap_or(&[]))
            .map_err(|_| WireError::InvalidTag(leading_tag))?;

        // The delimiter tag is the field right after the count.
        let delim = if count.end >= self.checksum_off {
            None
        } else {
            Some(next_field(self.buf, count.end)?)
        };
        let Some(delim) = delim else {
            if claimed == 0 {
                return Ok(FixGroup {
                    buf: self.buf,
                    delim_tag: leading_tag,
                    first_delim: self.checksum_off,
                    count: 0,
                    body_end: self.checksum_off,
                });
            }
            return Err(WireError::InvalidGroupCount {
                tag: leading_tag,
                claimed,
                remaining: 0,
            });
        };
        let delim_tag = delim.tag;
        if delim_tag == leading_tag {
            // A count field immediately followed by itself is malformed.
            return Err(WireError::InvalidTag(leading_tag));
        }
        if claimed == 0 {
            // Zero entries: the walk is skipped — trailing body fields belong
            // to the surrounding message, not to this (empty) group.
            return Ok(FixGroup {
                buf: self.buf,
                delim_tag,
                first_delim: self.checksum_off,
                count: 0,
                body_end: self.checksum_off,
            });
        }

        // Walk the group region: count delimiter occurrences, reject
        // re-occurrences of the leading (count) tag — the nested-group shape.
        let mut entries = 0usize;
        let mut first_delim = None;
        let mut pos = count.end;
        while pos < self.checksum_off {
            let f = next_field(self.buf, pos)?;
            if f.tag == delim_tag {
                if first_delim.is_none() {
                    first_delim = Some(pos);
                }
                entries += 1;
            } else if f.tag == leading_tag {
                return Err(WireError::InvalidGroupCount {
                    tag: leading_tag,
                    claimed,
                    remaining: entries,
                });
            }
            pos = f.end;
        }

        if entries != claimed {
            return Err(WireError::InvalidGroupCount {
                tag: leading_tag,
                claimed,
                remaining: entries,
            });
        }
        Ok(FixGroup {
            buf: self.buf,
            delim_tag,
            first_delim: first_delim.unwrap_or(self.checksum_off),
            count: claimed,
            body_end: self.checksum_off,
        })
    }

    /// Recompute the checksum over the covered byte range and compare with
    /// the declared tag-10 value.
    ///
    /// # Errors
    /// [`WireError::BadChecksum`] on mismatch; [`WireError::InvalidTag`] if
    /// the tag-10 field is somehow unreadable.
    pub fn verify_checksum(&self) -> Result<(), WireError> {
        let declared_raw = self.field(10).ok_or(WireError::InvalidTag(10))?;
        let declared = parse_ascii_usize(declared_raw).map_err(|_| WireError::InvalidTag(10))?;
        let covered = self
            .buf
            .get(..self.checksum_off)
            .ok_or(WireError::InsufficientBytes {
                need: self.checksum_off,
                have: self.buf.len(),
            })?;
        let got = fix_checksum(covered);
        if got != declared as u8 {
            return Err(WireError::BadChecksum {
                got,
                want: declared as u8,
            });
        }
        Ok(())
    }

    /// Flat tag=value scan over every field of the message (header through
    /// checksum), SOH-delimited — zero-copy.
    #[must_use]
    pub fn iter(&self) -> FixFieldIter<'a> {
        FixFieldIter {
            buf: self.buf,
            pos: 0,
        }
    }

    /// The raw bytes of the whole frame.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// Typed view of tag 35.
    ///
    /// # Errors
    /// [`WireError::UnknownMessageType`] — a type outside the known 4.4 set;
    /// [`WireError::InvalidTag`] — tag 35 absent.
    pub fn message_type(&self) -> Result<FixMsgType, WireError> {
        let v = self.field(35).ok_or(WireError::InvalidTag(35))?;
        FixMsgType::from_bytes(v)
    }
}

/// Known FIX 4.4 application message types (the presentation subset v1
/// names). [REQ-WIRE-002]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixMsgType {
    /// `0` — Heartbeat.
    Heartbeat,
    /// `1` — TestRequest.
    TestRequest,
    /// `2` — ResendRequest.
    ResendRequest,
    /// `3` — Reject.
    Reject,
    /// `4` — SequenceReset.
    SequenceReset,
    /// `5` — Logout.
    Logout,
    /// `D` — NewOrderSingle.
    NewOrderSingle,
    /// `8` — ExecutionReport.
    ExecutionReport,
    /// `V` — MarketDataRequest.
    MarketDataRequest,
    /// `W` — MarketDataSnapshotFullRefresh.
    MarketDataSnapshot,
    /// `X` — MarketDataIncrementalRefresh.
    MarketDataIncrementalRefresh,
}

impl FixMsgType {
    /// Typed view of a tag-35 value.
    ///
    /// # Errors
    /// [`WireError::UnknownMessageType`] for any value outside the known set.
    pub fn from_bytes(v: &[u8]) -> Result<Self, WireError> {
        match v {
            b"0" => Ok(Self::Heartbeat),
            b"1" => Ok(Self::TestRequest),
            b"2" => Ok(Self::ResendRequest),
            b"3" => Ok(Self::Reject),
            b"4" => Ok(Self::SequenceReset),
            b"5" => Ok(Self::Logout),
            b"D" => Ok(Self::NewOrderSingle),
            b"8" => Ok(Self::ExecutionReport),
            b"V" => Ok(Self::MarketDataRequest),
            b"W" => Ok(Self::MarketDataSnapshot),
            b"X" => Ok(Self::MarketDataIncrementalRefresh),
            _ => Err(WireError::UnknownMessageType),
        }
    }

    /// The tag-35 wire value.
    #[must_use]
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Heartbeat => b"0",
            Self::TestRequest => b"1",
            Self::ResendRequest => b"2",
            Self::Reject => b"3",
            Self::SequenceReset => b"4",
            Self::Logout => b"5",
            Self::NewOrderSingle => b"D",
            Self::ExecutionReport => b"8",
            Self::MarketDataRequest => b"V",
            Self::MarketDataSnapshot => b"W",
            Self::MarketDataIncrementalRefresh => b"X",
        }
    }
}

/// One field of a parsed message: tag and zero-copy value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixField<'a> {
    /// The tag number.
    pub tag: u16,
    /// The raw value bytes (between `=` and SOH).
    pub value: &'a [u8],
}

/// Flat, infallible iterator over a validated message's fields.
#[derive(Debug, Clone)]
pub struct FixFieldIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for FixFieldIter<'a> {
    type Item = FixField<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let f = next_field(self.buf, self.pos).ok()?;
        let value = self.buf.get(f.val.clone())?;
        self.pos = f.end;
        Some(FixField { tag: f.tag, value })
    }
}

/// A declared repeating group: fixed entry count, each entry a zero-copy
/// byte span. See the [module docs](self#groups-spec-decision-2--single-level-nesting-typed-errd)
/// for the v1 group model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixGroup<'a> {
    buf: &'a [u8],
    delim_tag: u16,
    first_delim: usize,
    count: usize,
    body_end: usize,
}

impl<'a> FixGroup<'a> {
    /// Declared (and verified) entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// True when the group declares zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The delimiter tag (the group's first member field).
    #[must_use]
    pub fn delim_tag(&self) -> u16 {
        self.delim_tag
    }

    /// Total iteration over entries; per-entry structure was validated at
    /// `parse`, so items are infallible, but the type keeps `Result` for
    /// symmetry with [`crate::sbe::GroupIter`] and total error taxonomy.
    #[must_use]
    pub fn iter(&self) -> FixGroupIter<'a> {
        FixGroupIter {
            buf: self.buf,
            delim_tag: self.delim_tag,
            pos: self.first_delim,
            remaining: self.count,
            body_end: self.body_end,
        }
    }
}

impl<'a> IntoIterator for &'a FixGroup<'a> {
    type Item = Result<FixEntry<'a>, WireError>;
    type IntoIter = FixGroupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over a group's entries.
#[derive(Debug, Clone)]
pub struct FixGroupIter<'a> {
    buf: &'a [u8],
    delim_tag: u16,
    pos: usize,
    remaining: usize,
    body_end: usize,
}

impl<'a> Iterator for FixGroupIter<'a> {
    type Item = Result<FixEntry<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        // Find the entry start (a delimiter field) and its end (the next
        // delimiter field or the body end).
        let mut start = None;
        let mut pos = self.pos;
        while pos < self.body_end {
            let f = match next_field(self.buf, pos) {
                Ok(f) => f,
                Err(e) => return Some(Err(e)),
            };
            if f.tag == self.delim_tag {
                start = Some(pos);
                break;
            }
            pos = f.end;
        }
        let Some(s) = start else {
            return Some(Err(WireError::InvalidTag(self.delim_tag)));
        };
        let mut end = self.body_end;
        let mut pos = s;
        let mut seen_first = false;
        while pos < self.body_end {
            let f = match next_field(self.buf, pos) {
                Ok(f) => f,
                Err(e) => return Some(Err(e)),
            };
            if f.tag == self.delim_tag {
                if seen_first {
                    end = pos;
                    break;
                }
                seen_first = true;
            }
            pos = f.end;
        }
        self.pos = end;
        let span = self.buf.get(s..end).ok_or(WireError::InsufficientBytes {
            need: end,
            have: self.buf.len(),
        });
        match span {
            Ok(span) => Some(Ok(FixEntry { span })),
            Err(e) => Some(Err(e)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a> ExactSizeIterator for FixGroupIter<'a> {}

/// One group entry — a zero-copy byte span over complete `tag=value␁`
/// fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixEntry<'a> {
    span: &'a [u8],
}

impl<'a> FixEntry<'a> {
    /// The first field with this tag inside the entry, zero-copy.
    #[must_use]
    pub fn field(&self, tag: u16) -> Option<&'a [u8]> {
        let mut pos = 0usize;
        while pos < self.span.len() {
            let f = next_field(self.span, pos).ok()?;
            if f.tag == tag {
                return self.span.get(f.val);
            }
            pos = f.end;
        }
        None
    }

    /// The first field with this tag inside the entry as UTF-8.
    ///
    /// # Errors
    /// [`WireError::InvalidTag`] — tag absent; [`WireError::InvalidUtf8`] —
    /// not valid UTF-8.
    pub fn field_str(&self, tag: u16) -> Result<&'a str, WireError> {
        let v = self.field(tag).ok_or(WireError::InvalidTag(tag))?;
        core::str::from_utf8(v).map_err(|_| WireError::InvalidUtf8)
    }

    /// The entry's raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.span
    }
}

/// Zero-allocation FIX 4.4 builder over a caller-owned `&mut [u8]`.
///
/// Fields are appended after a reserved header region; [`FixBuilder::finish`]
/// prepends `8=FIX.4.4`, `9=<BodyLength>` (via a bounded `copy_within`
/// shuffle) and appends `10=<checksum>` — producing a byte-for-byte
/// `FixMessage::parse`-valid frame ([REQ-WIRE-002]).
#[derive(Debug)]
pub struct FixBuilder<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> FixBuilder<'a> {
    /// Wrap a caller-owned buffer.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] when the buffer is smaller than
    /// [`HEADER_RESERVE`] (no room for even the frame header).
    pub fn new(buf: &'a mut [u8]) -> Result<Self, WireError> {
        if buf.len() < HEADER_RESERVE {
            return Err(WireError::InsufficientBytes {
                need: HEADER_RESERVE,
                have: buf.len(),
            });
        }
        Ok(Self {
            buf,
            pos: HEADER_RESERVE,
        })
    }

    /// Append one body field: `tag=value␁`.
    ///
    /// # Errors
    /// - [`WireError::InsufficientBytes`] — the buffer cannot hold the field.
    /// - [`WireError::InvalidTag`] — `value` contains SOH (would corrupt the
    ///   framing) or `tag` is 0.
    pub fn field(&mut self, tag: u16, value: &[u8]) -> Result<(), WireError> {
        if tag == 0 {
            return Err(WireError::InvalidTag(0));
        }
        if value.contains(&SOH) {
            return Err(WireError::InvalidTag(tag));
        }
        let nd = digit_count(tag as usize);
        let need = self
            .pos
            .checked_add(nd)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(value.len()))
            .and_then(|n| n.checked_add(1))
            .ok_or(WireError::InsufficientBytes {
                need: usize::MAX,
                have: self.buf.len(),
            })?;
        if need > self.buf.len() {
            return Err(WireError::InsufficientBytes {
                need,
                have: self.buf.len(),
            });
        }
        let nd = write_digits_at(self.buf, self.pos, tag as usize);
        let mut cursor = self.pos + nd;
        if let Some(slot) = self.buf.get_mut(cursor) {
            *slot = b'=';
        }
        cursor += 1;
        for v in value {
            if let Some(slot) = self.buf.get_mut(cursor) {
                *slot = *v;
            }
            cursor += 1;
        }
        if let Some(slot) = self.buf.get_mut(cursor) {
            *slot = SOH;
        }
        self.pos = need;
        Ok(())
    }

    /// Append one body field from a `&str` (same framing rules as
    /// [`FixBuilder::field`]).
    ///
    /// # Errors
    /// As [`FixBuilder::field`].
    pub fn field_str(&mut self, tag: u16, value: &str) -> Result<(), WireError> {
        self.field(tag, value.as_bytes())
    }

    /// Frame the message: prepend the canonical header (`8=FIX.4.4`,
    /// `9=<len>`), append `10=<checksum>`, and return the finished frame.
    /// The output parses with [`FixMessage::parse`] whenever at least tag 35
    /// was added.
    ///
    /// # Errors
    /// [`WireError::InsufficientBytes`] — the buffer cannot hold the header,
    /// checksum field, or the shuffled body.
    pub fn finish(self) -> Result<&'a [u8], WireError> {
        let body_len = self.pos - HEADER_RESERVE;
        let mut hdr = [0u8; HEADER_RESERVE];
        let prefix = b"8=FIX.4.4\x01";
        let mut h = 0usize;
        for b in prefix {
            if let Some(slot) = hdr.get_mut(h) {
                *slot = *b;
            }
            h += 1;
        }
        if let Some(slot) = hdr.get_mut(h) {
            *slot = b'9';
        }
        h += 1;
        if let Some(slot) = hdr.get_mut(h) {
            *slot = b'=';
        }
        h += 1;
        let nd = write_digits_at(&mut hdr, h, body_len);
        h += nd;
        if let Some(slot) = hdr.get_mut(h) {
            *slot = SOH;
        }
        h += 1;
        let header_len = h;

        // Shuffle the body up to make room for the header.
        if header_len > HEADER_RESERVE {
            return Err(WireError::InsufficientBytes {
                need: self.pos - HEADER_RESERVE + header_len,
                have: self.buf.len(),
            });
        }
        let body_end = self.pos - HEADER_RESERVE + header_len;
        self.buf.copy_within(HEADER_RESERVE..self.pos, header_len);
        for (i, b) in hdr.iter().take(header_len).enumerate() {
            if let Some(slot) = self.buf.get_mut(i) {
                *slot = *b;
            }
        }

        // Checksum covers everything before the 10= tag.
        let covered = self
            .buf
            .get(..body_end)
            .ok_or(WireError::InsufficientBytes {
                need: body_end,
                have: self.buf.len(),
            })?;
        let sum = fix_checksum(covered);
        let tail = *b"10=";
        let mut out_end = body_end;
        for t in tail {
            if let Some(slot) = self.buf.get_mut(out_end) {
                *slot = t;
            }
            out_end += 1;
        }
        let hundreds = (sum / 100) % 10;
        let tens = (sum / 10) % 10;
        let ones = sum % 10;
        for d in [b'0' + hundreds, b'0' + tens, b'0' + ones] {
            if let Some(slot) = self.buf.get_mut(out_end) {
                *slot = d;
            }
            out_end += 1;
        }
        if let Some(slot) = self.buf.get_mut(out_end) {
            *slot = SOH;
        }
        out_end += 1;
        if out_end > self.buf.len() {
            return Err(WireError::InsufficientBytes {
                need: out_end,
                have: self.buf.len(),
            });
        }
        Ok(self.buf.get(..out_end).unwrap_or(&[]))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    #![allow(clippy::indexing_slicing)]

    use super::{fix_checksum, FixBuilder, FixEntry, FixMessage, FixMsgType, HEADER_RESERVE};
    use crate::error::WireError;

    /// Build a canonical NewOrderSingle via the builder; returns its length.
    fn nso(buf: &mut [u8]) -> usize {
        let mut b = FixBuilder::new(buf).unwrap();
        b.field_str(35, "D").unwrap();
        b.field_str(49, "SENDER").unwrap();
        b.field_str(56, "TARGET").unwrap();
        b.field_str(11, "ORD-1").unwrap();
        b.field_str(54, "1").unwrap();
        b.field_str(38, "100").unwrap();
        let frame = b.finish().unwrap();
        frame.len()
    }

    #[test]
    fn checksum_is_sum_mod_256() {
        // REQ-WIRE-002 — cross-verified against a manual fold.
        let bytes = b"8=FIX.4.4\x0135=D\x01";
        let manual = bytes.iter().fold(0u32, |a, b| a + u32::from(*b)) as u8;
        assert_eq!(fix_checksum(bytes), manual);
        assert_eq!(fix_checksum(&[]), 0);
        // Overflow behavior: 256 ones fold to 0.
        let ones = [1u8; 256];
        assert_eq!(fix_checksum(&ones), 0);
    }

    #[test]
    fn parse_builder_output_and_read_fields_inplace() {
        // REQ-WIRE-002 — checksum, groups and in-place fields (flat shape).
        let mut buf = [0u8; 256];
        let n = nso(&mut buf);
        let m = FixMessage::parse(&buf[..n]).unwrap();
        assert_eq!(m.field(35).unwrap(), b"D");
        assert_eq!(m.field_str(11).unwrap(), "ORD-1");
        assert_eq!(m.field(54).unwrap(), b"1");
        assert_eq!(m.message_type().unwrap(), FixMsgType::NewOrderSingle);
        m.verify_checksum().unwrap();
        let tags: Vec<u16> = m.iter().map(|f| f.tag).collect();
        assert_eq!(tags.first(), Some(&8));
        assert_eq!(tags.last(), Some(&10));
        assert_eq!(m.iter().count(), 9); // 8,9,35,49,56,11,54,38,10
    }

    #[test]
    fn groups_single_level_with_count_match() {
        // REQ-WIRE-002 — NoMDEntries (268) group, group-last layout.
        let mut buf = [0u8; 512];
        let mut b = FixBuilder::new(&mut buf).unwrap();
        b.field_str(35, "X").unwrap();
        b.field_str(49, "CME").unwrap();
        b.field_str(268, "2").unwrap();
        b.field_str(279, "0").unwrap();
        b.field_str(269, "0").unwrap();
        b.field_str(279, "1").unwrap();
        b.field_str(269, "1").unwrap();
        let n = b.finish().unwrap().len();
        let m = FixMessage::parse(&buf[..n]).unwrap();
        assert_eq!(
            m.message_type().unwrap(),
            FixMsgType::MarketDataIncrementalRefresh
        );
        let g = m.group(268).unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g.delim_tag(), 279);
        let entries: Vec<FixEntry<'_>> = g.iter().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].field(269).unwrap(), b"0");
        assert_eq!(entries[1].field(269).unwrap(), b"1");
        assert_eq!(entries[0].field(999), None);
        let _ = entries[0].as_bytes();
    }

    #[test]
    fn group_count_mismatch_is_typed() {
        // Claims 2 entries, delivers 1.
        let mut buf = [0u8; 512];
        let mut b = FixBuilder::new(&mut buf).unwrap();
        b.field_str(35, "X").unwrap();
        b.field_str(268, "2").unwrap();
        b.field_str(279, "0").unwrap();
        b.field_str(269, "0").unwrap();
        let n = b.finish().unwrap().len();
        let m = FixMessage::parse(&buf[..n]).unwrap();
        assert_eq!(
            m.group(268),
            Err(WireError::InvalidGroupCount {
                tag: 268,
                claimed: 2,
                remaining: 1
            })
        );
    }

    #[test]
    fn nested_group_shape_is_typed_error() {
        // Spec decision 2 — count tag re-occurring inside the group region
        // (the nesting shape) is rejected with InvalidGroupCount.
        let mut buf = [0u8; 512];
        let mut b = FixBuilder::new(&mut buf).unwrap();
        b.field_str(35, "X").unwrap();
        b.field_str(268, "1").unwrap();
        b.field_str(279, "0").unwrap(); // delimiter
        b.field_str(268, "1").unwrap(); // nested count inside the entry span
        let n = b.finish().unwrap().len();
        let m = FixMessage::parse(&buf[..n]).unwrap();
        assert!(matches!(
            m.group(268),
            Err(WireError::InvalidGroupCount { .. })
        ));
    }

    #[test]
    fn tampered_checksum_is_bad_checksum() {
        let mut buf = [0u8; 256];
        let n = nso(&mut buf);
        // Flip one covered body byte — the declared checksum no longer
        // matches the computed one (a single-byte change always shifts the
        // byte-sum).
        buf[20] = buf[20].wrapping_add(1);
        assert!(matches!(
            FixMessage::parse(&buf[..n]),
            Err(WireError::BadChecksum { .. })
        ));
    }

    #[test]
    fn every_truncation_is_typed() {
        // REQ-WIRE-003 — exhaustive prefix sweep: Err or Ok, never panic.
        let mut buf = [0u8; 256];
        let n = nso(&mut buf);
        for len in 0..n {
            let (slice, _) = buf.split_at(len);
            let _ = FixMessage::parse(slice);
        }
    }

    #[test]
    fn structural_violations_are_typed() {
        let mut buf = [0u8; 128];
        let n = nso(&mut buf);

        // Not starting with 8=...
        let mut alt = buf;
        alt[0] = b'9';
        assert!(matches!(
            FixMessage::parse(&alt[..n]),
            Err(WireError::InvalidTag(_))
        ));

        // Wrong BeginString.
        let mut alt = buf;
        alt[2] = b'X';
        assert!(matches!(
            FixMessage::parse(&alt[..n]),
            Err(WireError::InvalidTag(8))
        ));

        // Reserved tag in the body: rewrite 54=1 → 10=1. Reserved-tag
        // rejection happens during the body walk, before checksum verify.
        let mut alt = buf;
        let pos = alt.windows(5).position(|w| w == b"54=1\x01").unwrap();
        alt[pos] = b'1';
        alt[pos + 1] = b'0';
        assert!(matches!(
            FixMessage::parse(&alt[..n]),
            Err(WireError::InvalidTag(10))
        ));

        // Trailing garbage after the checksum field.
        let mut alt = buf;
        alt[n] = 0x20;
        assert!(matches!(
            FixMessage::parse(&alt[..n + 1]),
            Err(WireError::InvalidTag(10))
        ));

        // Missing MsgType: 35=D retagged to 95=D.
        let mut alt = buf;
        let pos = alt.windows(5).position(|w| w == b"35=D\x01").unwrap();
        alt[pos] = b'9';
        assert!(matches!(
            FixMessage::parse(&alt[..n]),
            Err(WireError::InvalidTag(95))
        ));
    }

    #[test]
    fn builder_bounds_and_so_h_rejection() {
        let mut small = [0u8; HEADER_RESERVE - 1];
        assert!(matches!(
            FixBuilder::new(&mut small),
            Err(WireError::InsufficientBytes { .. })
        ));
        let mut buf = [0u8; 128];
        let mut b = FixBuilder::new(&mut buf).unwrap();
        assert_eq!(b.field(35, b"x\x01y"), Err(WireError::InvalidTag(35)));
        assert_eq!(b.field(0, b"x"), Err(WireError::InvalidTag(0)));
        // Short buffer for a big field.
        let mut tiny = [0u8; HEADER_RESERVE + 2];
        let mut b = FixBuilder::new(&mut tiny).unwrap();
        assert!(matches!(
            b.field(35, b"ABCDE"),
            Err(WireError::InsufficientBytes { .. })
        ));
    }

    #[test]
    fn builder_output_renders_exact_frame() {
        let mut buf = [0u8; 64];
        let mut b = FixBuilder::new(&mut buf).unwrap();
        b.field_str(35, "0").unwrap();
        let frame = b.finish().unwrap();
        let expected_prefix = b"8=FIX.4.4\x019=5\x0135=0\x01";
        assert!(frame.starts_with(expected_prefix));
        assert_eq!(frame.len(), expected_prefix.len() + 7); // + "10=nnn\x01"
        FixMessage::parse(frame).unwrap();
    }

    #[test]
    fn unknown_message_type_is_typed() {
        let mut buf = [0u8; 128];
        let mut b = FixBuilder::new(&mut buf).unwrap();
        b.field_str(35, "ZZ").unwrap();
        let n = b.finish().unwrap().len();
        let m = FixMessage::parse(&buf[..n]).unwrap();
        assert_eq!(m.message_type(), Err(WireError::UnknownMessageType));
        // Non-UTF8 field value → InvalidUtf8.
        let mut alt = buf;
        let pos = alt.windows(5).position(|w| w == b"35=ZZ").unwrap();
        alt[pos + 3] = 0xFF;
        // Fix the checksum by rebuilding bytes before 10=.
        let cs_pos = n - 7; // "10=xxx\x01"
        let sum = fix_checksum(&alt[..cs_pos]);
        alt[cs_pos + 3] = b'0' + (sum / 100) % 10;
        alt[cs_pos + 4] = b'0' + (sum / 10) % 10;
        alt[cs_pos + 5] = b'0' + sum % 10;
        let m = FixMessage::parse(&alt[..n]).unwrap();
        assert_eq!(m.field_str(35), Err(WireError::InvalidUtf8));
    }

    #[test]
    fn empty_group_zero_count() {
        let mut buf = [0u8; 128];
        let mut b = FixBuilder::new(&mut buf).unwrap();
        b.field_str(35, "X").unwrap();
        b.field_str(268, "0").unwrap();
        b.field_str(55, "AFTER").unwrap(); // trailing field after empty group
        let n = b.finish().unwrap().len();
        let m = FixMessage::parse(&buf[..n]).unwrap();
        let g = m.group(268).unwrap();
        assert!(g.is_empty());
        assert_eq!(g.iter().count(), 0);
    }
}
