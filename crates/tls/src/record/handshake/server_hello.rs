use super::extension::ServerHelloExtension;
use crate::CipherSuite;

#[derive(Debug)]
pub struct ServerHello {
    pub random: Box<[u8; 32]>,
    pub legacy_session_id_echo: Box<[u8]>,
    pub cipher_suite: CipherSuite,
    pub extensions: Box<[ServerHelloExtension]>,
}

impl ServerHello {
    pub fn new(
        random: &[u8; 32],
        legacy_session_id_echo: &[u8],
        cipher_suite: CipherSuite,
        extensions: &[ServerHelloExtension],
    ) -> Self {
        Self {
            random: Box::from(*random),
            legacy_session_id_echo: Box::from(legacy_session_id_echo),
            cipher_suite,
            extensions: Box::from(extensions.to_owned()),
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

        let extensions_length = self.extensions.iter().fold(0, |acc, e| acc + e.size()) as u16;
        res.extend(extensions_length.to_be_bytes());
        res.extend(
            self.extensions
                .iter()
                .flat_map(ServerHelloExtension::to_raw),
        );

        res.into_boxed_slice()
    }
}
