//! Domain-separation helpers shared by all hybrid signature suites.
//!
//! The hybrid constructions in this crate sign a domain-bound message `M'`
//! rather than the caller's raw message `M`. This prevents cross-suite replay
//! and binds signatures to an optional application context.

use alloc::vec::Vec;

/// Domain-separated message binding per the hybrid signature spec.
///
/// M' = Prefix(0x01) || Label || len(ctx) || ctx || msg
///
/// The label binds the signature to a specific hybrid construction,
/// preventing cross-context replay between different hybrid schemes.
// TODO: Perhaps implement a signing context helper similar to `schnorrkel::context::SigningContext` and `schnorrkel::context::SigningTranscript`. TBD
// NOTE: This is allocated on the heap.
///
/// # Panics
///
/// Panics if `ctx.len() > 255`, because the current wire format encodes the
/// context length in a single byte.
pub fn prepare_message(version: u8, label: &[u8], msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    assert!(ctx.len() <= 255, "ctx must be at most 255 bytes");
    let mut out = Vec::with_capacity(1 + label.len() + 1 + ctx.len() + msg.len());
    out.push(version);
    out.extend_from_slice(label);
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(msg);
    out
}
