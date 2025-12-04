use anyhow::Result;

use super::extension::{
    KeyShareEntry, KeyShareServerHello, PreSharedKeyExtensionServerHello,
    SupportedVersionsServerHello, extension_types,
};
use crate::{cipher_suite::CipherSuite, parse::RawSize};

#[derive(Clone, Debug)]
pub enum ServerHelloExtensionContent {
    /// ID: 41
    PreSharedKey(PreSharedKeyExtensionServerHello),
    /// ID: 43
    SupportedVersions(SupportedVersionsServerHello),
    /// ID: 51
    KeyShare(KeyShareServerHello),
}

#[derive(Clone, Debug)]
pub struct ServerHelloExtension {
    length: u16,

    pub content: ServerHelloExtensionContent,
}

impl ServerHelloExtension {
    pub fn new_supported_versions(version: u16) -> Self {
        Self {
            length: 2,
            content: ServerHelloExtensionContent::SupportedVersions(SupportedVersionsServerHello {
                selected_version: version,
            }),
        }
    }

    pub fn new_key_share(share: KeyShareEntry) -> Result<Self> {
        Ok(Self {
            length: share.size().try_into()?,
            content: ServerHelloExtensionContent::KeyShare(KeyShareServerHello {
                server_share: share,
            }),
        })
    }

    pub fn length(&self) -> u16 {
        self.length
    }

    pub fn size(&self) -> usize {
        self.length as usize + 4
    }

    pub fn to_raw(&self) -> Box<[u8]> {
        match &self.content {
            ServerHelloExtensionContent::PreSharedKey(_e) => {
                todo!()
            }
            ServerHelloExtensionContent::SupportedVersions(e) => [
                extension_types::SUPPORTED_VERSIONS.to_be_bytes(),
                self.length.to_be_bytes(),
                e.selected_version.to_be_bytes(),
            ]
            .concat()
            .into(),
            ServerHelloExtensionContent::KeyShare(e) => {
                let mut res = Vec::new();

                res.extend(extension_types::KEY_SHARE.to_be_bytes());
                res.extend(self.length.to_be_bytes());
                res.extend(e.server_share.to_raw());

                res.into_boxed_slice()
            }
        }
    }
}

#[derive(Clone, Debug)]
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
