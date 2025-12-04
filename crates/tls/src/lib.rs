#![allow(clippy::missing_errors_doc)]
#![forbid(clippy::unwrap_used)]

pub mod cipher_suite;
pub(crate) mod macros;
pub(crate) mod parse;
pub mod record;
pub(crate) mod util;

pub const LEGACY_VERSION: u16 = 0x0303;
pub const LEGACY_VERSION_BYTES: &[u8] = &[0x03, 0x03];
