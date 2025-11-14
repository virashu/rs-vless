use std::sync::Arc;

use crate::CipherSuite;

#[derive(Debug)]
pub struct ServerHello {
    pub random: Arc<[u8; 32]>,
    pub legacy_session_id_echo: Arc<[u8]>,
    pub cipher_suite: CipherSuite,
    pub extensions: Arc<[u8]>,
}

impl ServerHello {
    pub fn new(
        random: &[u8; 32],
        legacy_session_id_echo: &[u8],
        cipher_suite: CipherSuite,
        extensions: &[u8],
    ) -> Self {
        Self {
            random: Arc::from(*random),
            legacy_session_id_echo: Arc::from(legacy_session_id_echo),
            cipher_suite,
            extensions: Arc::from(extensions),
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn to_raw(&self) -> Box<[u8]> {
        let mut res = Vec::new();

        res.extend([0x03, 0x03]);

        res.extend(self.random.as_ref());

        res.extend((self.legacy_session_id_echo.len() as u8).to_be_bytes());
        res.extend(self.legacy_session_id_echo.as_ref());

        res.push(self.cipher_suite.aead_algorithm);
        res.push(self.cipher_suite.hkdf_hash);

        res.push(0);

        res.extend((self.extensions.len() as u16).to_be_bytes());
        res.extend(self.extensions.as_ref());

        res.into_boxed_slice()
    }
}
