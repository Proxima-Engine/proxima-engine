//! Standalone MySQL protocol primitives for the Proxima MySQL gateway.
//!
//! This crate intentionally does not depend on the PostgreSQL protocol/session
//! implementation. Parsing is bounded and rejects malformed or unsupported
//! packets before they can influence tenant routing.

pub mod auth;
pub mod listener;
pub mod isolation;
pub mod protocol;
pub mod provisioning;
pub mod tenant;
pub mod upstream;
