//! Substrate-facing crypto wrappers for hybrid signature suites.
//!
//! These types are meant to look like normal `sp_core` crypto modules so they
//! can be wrapped later with `sp_application_crypto::app_crypto!`.
//!
//! The module currently provides:
//! - [`sr25519_mldsa44`]: a BABE-oriented wrapper around the H3 suite

pub mod sr25519_mldsa44;
