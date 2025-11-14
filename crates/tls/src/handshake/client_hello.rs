use anyhow::{Result, bail};

use std::sync::Arc;

use crate::{CipherSuite, handshake::extension::Extension};

#[derive(Debug)]
pub struct ClientHello {
    pub random: Arc<[u8; 32]>,
    pub legacy_session_id: Arc<[u8]>,
    pub cipher_suites: Arc<[CipherSuite]>,
    pub legacy_compression_methods: Arc<[u8]>,
    pub extensions: Box<[Extension]>,
}

impl ClientHello {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let mut offset: usize = 0;

        let legacy_version = u16::from_be_bytes([raw[0], raw[1]]);
        if legacy_version != 0x0303 {
            bail!("Invalid legacy version: {legacy_version} (should be equal 0x0303)");
        }
        offset += 2;

        let random = Arc::new(raw[(offset)..(offset + 32)].try_into()?);
        offset += 32;

        let legacy_session_id_length = raw[offset] as usize;
        offset += 1;
        let legacy_session_id = raw[offset..(offset + legacy_session_id_length)].into();
        offset += legacy_session_id_length;

        let cipher_suites_length = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
        offset += 2;
        let cipher_suites = raw[offset..(offset + cipher_suites_length)]
            .chunks(2)
            .map(|x| CipherSuite {
                aead_algorithm: x[0],
                hkdf_hash: x[1],
            })
            .collect();
        offset += cipher_suites_length;

        let legacy_compression_methods_length = raw[offset] as usize;
        offset += 1;
        let legacy_compression_methods =
            raw[offset..(offset + legacy_compression_methods_length)].into();
        offset += legacy_compression_methods_length;

        let extensions_length = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
        offset += 2;
        let extensions_raw = &raw[offset..(offset + extensions_length)];

        // Parse extensions
        let mut total_length = 0;
        let mut extensions = Vec::new();
        while total_length < extensions_length {
            match Extension::from_raw(&extensions_raw[total_length..]) {
                Ok(ext) => {
                    total_length += ext.size();
                    extensions.push(ext);
                }
                Err(err) => {
                    tracing::warn!("Failed to parse extension: {err}");
                    total_length += Extension::size_raw(&extensions_raw[total_length..]);
                }
            }
        }

        Ok(Self {
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions: extensions.into_boxed_slice(),
        })
    }
}
