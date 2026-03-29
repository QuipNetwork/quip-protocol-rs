use alloc::vec::Vec;

/// Domain-separated message binding per the hybrid signature spec.
///
/// M' = Prefix(0x01) || Label || len(ctx) || ctx || msg
///
/// The label binds the signature to a specific hybrid construction,
/// preventing cross-context replay between different hybrid schemes.
// TODO: Perhaps implement a signing context helper similar to `schnorrkel::context::SigningContext` and `schnorrkel::context::SigningTranscript`. TBD
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
