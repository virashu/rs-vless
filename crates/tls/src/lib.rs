pub mod handshake;
pub(crate) mod macros;
pub(crate) mod parse;
pub(crate) mod util;

#[derive(Debug)]
pub struct CipherSuite {
    pub aead_algorithm: u8,
    pub hkdf_hash: u8,
}
