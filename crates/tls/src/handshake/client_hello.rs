use anyhow::{Result, bail};

use crate::{
    CipherSuite,
    handshake::extension::ClientHelloExtension,
    parse::Parse,
    util::{opaque_vec_8, opaque_vec_16},
};

#[derive(Debug)]
pub struct ClientHello {
    length: u32,

    pub random: Box<[u8; 32]>,
    pub legacy_session_id: Box<[u8]>,
    pub cipher_suites: Box<[CipherSuite]>,
    pub legacy_compression_methods: Box<[u8]>,
    pub extensions: Box<[ClientHelloExtension]>,
}

impl Parse for ClientHello {
    fn parse(raw: &[u8]) -> Result<Self> {
        let length = u32::from_be_bytes([0, raw[0], raw[1], raw[2]]);

        let legacy_version = u16::from_be_bytes([raw[3], raw[4]]);
        if legacy_version != 0x0303 {
            bail!("Invalid legacy version: {legacy_version} (should be equal 0x0303)");
        }

        let random = Box::new(raw[5..(5 + 32)].try_into()?);

        let mut offset: usize = 5 + 32;

        let (size, legacy_session_id) = opaque_vec_8(&raw[offset..]);
        offset += size;

        let (size, cipher_suites_raw) = opaque_vec_16(&raw[offset..]);
        offset += size;
        let cipher_suites = cipher_suites_raw
            .chunks(2)
            .map(|x| CipherSuite {
                aead_algorithm: x[0],
                hkdf_hash: x[1],
            })
            .collect();

        let (size, legacy_compression_methods) = opaque_vec_8(&raw[offset..]);
        offset += size;

        let (_, extensions_raw) = opaque_vec_16(&raw[offset..]);

        // Parse extensions
        let total_length = extensions_raw.len();
        let mut parsed_length = 0;
        let mut extensions = Vec::new();
        while parsed_length < total_length {
            match ClientHelloExtension::parse(&extensions_raw[parsed_length..]) {
                Ok(ext) => {
                    tracing::trace!(
                        "Parsed extension: {} ({} bytes body)",
                        ext.content.as_ref(),
                        ext.size() - 4
                    );
                    parsed_length += ext.size();
                    extensions.push(ext);
                }
                Err(err) => {
                    tracing::warn!("Failed to parse extension: {err:?}");
                    parsed_length +=
                        ClientHelloExtension::size_raw(&extensions_raw[parsed_length..]);
                }
            }
        }

        if parsed_length != total_length {
            tracing::error!("Unparsed extension parts left ({parsed_length}/{total_length})");
        }

        Ok(Self {
            length,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions: extensions.into_boxed_slice(),
        })
    }

    fn size(&self) -> usize {
        self.length as usize + 3
    }
}
