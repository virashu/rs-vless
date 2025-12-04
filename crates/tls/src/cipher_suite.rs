#[derive(Debug)]
pub struct CipherSuite {
    pub aead_algorithm: u8,
    pub hkdf_hash: u8,
}

pub const TLS_AES_256_GCM_SHA348: CipherSuite = CipherSuite {
    aead_algorithm: 0x13,
    hkdf_hash: 0x02,
};
