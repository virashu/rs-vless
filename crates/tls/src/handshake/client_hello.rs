use anyhow::{Result, bail};

use crate::{
    CipherSuite,
    handshake::extension::Extension,
    util::{opaque_vec_8, opaque_vec_16},
};

use super::extension::ExtParent;

#[derive(Debug)]
pub struct ClientHello {
    pub random: Box<[u8; 32]>,
    pub legacy_session_id: Box<[u8]>,
    pub cipher_suites: Box<[CipherSuite]>,
    pub legacy_compression_methods: Box<[u8]>,
    pub extensions: Box<[Extension]>,
}

impl ClientHello {
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let legacy_version = u16::from_be_bytes([raw[0], raw[1]]);
        if legacy_version != 0x0303 {
            bail!("Invalid legacy version: {legacy_version} (should be equal 0x0303)");
        }

        let random = Box::new(raw[2..(2 + 32)].try_into()?);

        let mut offset: usize = 34;

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
            match Extension::from_raw(&extensions_raw[parsed_length..], ExtParent::Client) {
                Ok(ext) => {
                    parsed_length += ext.size();
                    extensions.push(ext);
                }
                Err(err) => {
                    tracing::warn!("Failed to parse extension: {err}");
                    parsed_length += Extension::size_raw(&extensions_raw[parsed_length..]);
                }
            }
        }

        if parsed_length != total_length {
            tracing::error!("Unparsed extension parts left ({parsed_length}/{total_length})");
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
