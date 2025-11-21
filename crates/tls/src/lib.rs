#![allow(clippy::missing_errors_doc)]
#![forbid(clippy::unwrap_used)]

pub(crate) mod macros;
pub(crate) mod parse;
pub mod record;
pub(crate) mod util;

#[derive(Debug)]
pub struct CipherSuite {
    pub aead_algorithm: u8,
    pub hkdf_hash: u8,
}

pub const LEGACY_VERSION: u16 = 0x0303;
pub const LEGACY_VERSION_BYTES: &[u8] = &[0x03, 0x03];
