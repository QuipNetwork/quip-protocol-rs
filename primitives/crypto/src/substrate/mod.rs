//! Substrate-facing crypto wrappers for hybrid signature suites.
//!
//! These types are meant to look like normal `sp_core` crypto modules so they
//! can be wrapped later with `sp_application_crypto::app_crypto!`.
//!
//! The module currently provides:
//! - [`ed25519_mldsa44`]: a GRANDPA-oriented wrapper around the H1 suite
//! - [`sr25519_mldsa44`]: a BABE-oriented wrapper around the H3 suite

pub(crate) mod signature;
pub mod ed25519_mldsa44;
pub mod sr25519_mldsa44;
