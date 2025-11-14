use anyhow::Result;

use crate::macros::auto_try_from;

auto_try_from! {
    #[repr(u16)]
    #[allow(non_camel_case_types)]
    #[derive(Debug)]
    pub enum SignatureScheme {
        /* RSASSA-PKCS1-v1_5 algorithms */
        rsa_pkcs1_sha256 = 0x0401,
        rsa_pkcs1_sha384 = 0x0501,
        rsa_pkcs1_sha512 = 0x0601,

        /* ECDSA algorithms */
        ecdsa_secp256r1_sha256 = 0x0403,
        ecdsa_secp384r1_sha384 = 0x0503,
        ecdsa_secp521r1_sha512 = 0x0603,

        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        rsa_pss_rsae_sha256 = 0x0804,
        rsa_pss_rsae_sha384 = 0x0805,
        rsa_pss_rsae_sha512 = 0x0806,

        /* EdDSA algorithms */
        ed25519 = 0x0807,
        ed448 = 0x0808,

        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        rsa_pss_pss_sha256 = 0x0809,
        rsa_pss_pss_sha384 = 0x080a,
        rsa_pss_pss_sha512 = 0x080b,

        /* Legacy algorithms */
        rsa_pkcs1_sha1 = 0x0201,
        ecdsa_sha1 = 0x0203,
    }
}

#[derive(Debug)]
pub struct SignatureAlgorithms {
    length: u16,
    pub supported_signature_algorithms: Box<[SignatureScheme]>,
}

impl SignatureAlgorithms {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let length = u16::from_be_bytes([raw[0], raw[1]]);

        let supported_signature_algorithms_length = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        let supported_signature_algorithms = raw[4..(supported_signature_algorithms_length + 4)]
            .chunks_exact(2)
            .filter_map(|c| SignatureScheme::try_from(u16::from_be_bytes([c[0], c[1]])).ok())
            .collect();

        Ok(Self {
            length,
            supported_signature_algorithms,
        })
    }

    pub fn size(&self) -> usize {
        self.length as usize + 2
    }
}
