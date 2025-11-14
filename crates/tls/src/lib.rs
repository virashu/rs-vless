pub mod handshake;
pub(crate) mod macros;

#[derive(Debug)]
pub struct CipherSuite {
    pub aead_algorithm: u8,
    pub hkdf_hash: u8,
}
