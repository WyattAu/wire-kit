//! REQ-WIRE-005 — views borrow, not own: a view that outlives its buffer is
//! a compile error (trybuild).

// Test harness: assertions legitimately panic; the lib target stays
// lint-clean.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
fn views_borrow_not_own() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
